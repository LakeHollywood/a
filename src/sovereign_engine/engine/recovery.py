"""``Recover(E_n, I_{n+1})`` -- the open recovery function.

The Recovery Contract is *open*: the engine may always ask for recovery, but
recovery itself confers no authority.  Formally, for the last durable epoch
``E_n`` and the void interval ``I_{n+1}``::

    Recover(E_n, I_{n+1}) -> (C_{n+1}, D_{n+1})

where ``C_{n+1}`` is a :class:`RehydratedContext` (state continuity) and
``D_{n+1}`` is a *directive* drawn from ``{QUARANTINE_HOLD, SAFE_FALLBACK}``.
There is no third element: the codomain contains no authorization type, so
authority cannot leak through the recovery path (Invariant Theorem 3).

Consequences implemented here:

* Rehydration reads only durable state; it never touches the gate ledger or
  any historical grant.
* A recovered machine resumes in ``SAFE_STATE`` (fallback available) or
  ``QUARANTINED`` (no legal fallback edge); resuming in an operational state
  is not expressible.
* Continuing work after recovery requires a genuinely new
  :class:`LiveAuthorization` minted against a fresh attestation in the current
  window -- exactly what ABIDE REC-01 asserts must happen.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from sovereign_engine.engine.quarantine import (
    QuarantineAction,
    QuarantineManager,
    QuarantineRecord,
)
from sovereign_engine.gate.sts_clock import SynchronizedTemporalState
from sovereign_engine.types.evidence import RehydratedContext, rehydrate
from sovereign_engine.types.transitions import (
    EligibilityVerdict,
    KNOWN_STATES,
    RecoveryIntent,
    StateTransitionRequest,
    TransitionKind,
)


class RecoveryContractViolation(RuntimeError):
    """Raised when a caller tries to use recovery as an authority channel."""


@dataclass(frozen=True, slots=True)
class Recovered:
    """Result of ``Recover(E_n, I_{n+1})``: context plus directive only."""

    context: RehydratedContext
    directive: EligibilityVerdict
    resulting_state: str
    record: QuarantineRecord | None = None
    intent_id: str = ""

    @property
    def authority_granted(self) -> bool:
        """Always ``False`` -- present so auditors can assert it explicitly."""
        return False

    def as_record(self) -> dict[str, Any]:
        return {
            "intent_id": self.intent_id,
            "origin_epoch": self.context.origin_epoch,
            "resume_epoch": self.context.resume_epoch,
            "source_digest": self.context.source_digest,
            "authority_inherited": self.context.authority_inherited,
            "directive": self.directive.value,
            "resulting_state": self.resulting_state,
            "quarantine": self.record.as_record() if self.record else None,
        }


@dataclass(frozen=True, slots=True)
class DurableEpoch:
    """What survived the crash: the last durably-written epoch ``E_n``."""

    epoch: int
    state_vector: Mapping[str, Any] = field(default_factory=dict)
    written_at_tick: int = 0


def build_recovery_intent(
    *,
    interval_id: str,
    durable: DurableEpoch,
    resume_epoch: int,
    requested_to_state: str = "SAFE_STATE",
    diagnostics: Mapping[str, Any] | None = None,
    void_interval_seconds: float = 0.0,
) -> RecoveryIntent:
    """Rehydrate ``E_n`` and wrap it in an open recovery request ``R``."""
    context = rehydrate(
        origin_epoch=durable.epoch,
        resume_epoch=resume_epoch,
        state_vector=durable.state_vector,
        void_interval_seconds=void_interval_seconds,
    )
    return RecoveryIntent(
        interval_id=interval_id,
        last_durable_epoch=durable.epoch,
        resume_epoch=resume_epoch,
        context=context,
        requested_to_state=requested_to_state,
        diagnostics=dict(diagnostics or {}),
    )


def recover(
    *,
    durable: DurableEpoch,
    intent: RecoveryIntent,
    prior_state: str,
    sts: SynchronizedTemporalState,
    quarantine: QuarantineManager | None = None,
    resource: str = "engine",
) -> Recovered:
    """Execute the open recovery contract for one void interval.

    ``prior_state`` is the state the machine believes it was in before the
    void; because the void makes that belief unverifiable, recovery never
    trusts it as an authority source -- it is used only to pick the safest
    reachable resting state.
    """
    if not isinstance(intent.context, RehydratedContext):
        raise RecoveryContractViolation(
            "recovery input must be a RehydratedContext"
        )
    if intent.context.authority_inherited:
        # Unreachable by construction; kept as an explicit tripwire so any
        # future tampering fails loudly rather than silently granting.
        raise RecoveryContractViolation(
            "rehydrated context claims inherited authority"
        )
    if prior_state not in KNOWN_STATES:
        raise RecoveryContractViolation(f"unknown prior state {prior_state!r}")
    if intent.resume_epoch <= intent.last_durable_epoch:
        raise RecoveryContractViolation(
            "resume_epoch must lie strictly beyond the durable epoch"
        )

    manager = quarantine or QuarantineManager()
    epoch = sts.epoch
    target = intent.requested_to_state

    # Fallback is permitted only along safety-reducing edges into a known
    # state; otherwise the contract mandates a hold.
    if target not in KNOWN_STATES:
        record = manager.hold(
            resource=resource,
            epoch=epoch,
            reason=f"recovery {intent.interval_id}: unknown fallback target {target!r}",
        )
        return Recovered(
            context=intent.context,
            directive=EligibilityVerdict.QUARANTINE_HOLD,
            resulting_state="QUARANTINED",
            record=record,
            intent_id=intent.interval_id,
        )

    record = manager.safe_fallback(
        resource=resource,
        epoch=epoch,
        reason=(
            f"recovery {intent.interval_id}: rehydrated from epoch "
            f"{intent.last_durable_epoch} across void into {target}"
        ),
        from_state=prior_state,
        to_state=target,
    )
    if record.directive is QuarantineAction.SAFE_FALLBACK:
        manager.complete_fallback(resource=resource, epoch=epoch)
        return Recovered(
            context=intent.context,
            directive=EligibilityVerdict.SAFE_FALLBACK,
            resulting_state=target,
            record=record,
            intent_id=intent.interval_id,
        )

    return Recovered(
        context=intent.context,
        directive=EligibilityVerdict.QUARANTINE_HOLD,
        resulting_state="QUARANTINED",
        record=record,
        intent_id=intent.interval_id,
    )


def require_live_authorization_for_resume(
    intent: RecoveryIntent,
) -> StateTransitionRequest:
    """Return the *shape* of the request an operator must satisfy post-recovery.

    Deliberately unbuildable as an eligible transition: the ``authorization``
    slot is left ``None``, so feeding this straight into the predicate yields
    ``QUARANTINE_HOLD``.  Only a minted :class:`LiveAuthorization` can fill it.
    """
    from sovereign_engine.types.evidence import LiveEvidence  # local: avoid cycle noise

    placeholder = LiveEvidence(
        subject="<pending-live-attestation>",
        action=TransitionKind.RECOVERY.value,
        resource="<pending>",
        attested_epoch=intent.resume_epoch,
        window_id="<pending-window>",
        nonce="<pending-nonce>",
    )
    return StateTransitionRequest(
        from_state="SAFE_STATE",
        to_state="IDLE",
        kind=TransitionKind.RECOVERY,
        live_evidence=placeholder,
        recovery_intent=intent,
        parameters={"principal": "<pending-live-attestation>", "resource": "engine"},
        request_id=f"resume-{intent.interval_id}",
    )


__all__ = [
    "RecoveryContractViolation",
    "Recovered",
    "DurableEpoch",
    "build_recovery_intent",
    "recover",
    "require_live_authorization_for_resume",
]
