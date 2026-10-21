"""``EngineTransitionGate`` -- the stateful wrapper around the pure predicate.

The gate owns:

* the current machine state ``S``,
* the STS clock,
* the single-use :class:`GateLedger`,
* the quarantine manager.

Its only public verb is :meth:`attempt`, which never raises for policy
reasons: every outcome (eligible / denied / hold / fallback) is returned as a
:class:`TransitionOutcome` so callers cannot accidentally treat an exception
path as "probably allowed".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from sovereign_engine.engine.quarantine import (
    QuarantineAction,
    QuarantineManager,
    QuarantineRecord,
    QuarantineState,
)
from sovereign_engine.gate.predicate import GateLedger, evaluate_predicate
from sovereign_engine.gate.sts_clock import SynchronizedTemporalState
from sovereign_engine.types.transitions import (
    EligibilityVerdict,
    StateTransitionRequest,
    TransitionEligibility,
    TransitionKind,
)


@dataclass(frozen=True, slots=True)
class TransitionOutcome:
    """Everything the engine learned from one ``attempt()`` call."""

    eligibility: TransitionEligibility
    executed: bool
    prior_state: str
    resulting_state: str
    quarantine: QuarantineRecord | None = None

    @property
    def verdict(self) -> EligibilityVerdict:
        return self.eligibility.verdict

    def as_record(self) -> dict[str, Any]:
        record = dict(self.eligibility.as_record())
        record.update(
            {
                "executed": self.executed,
                "prior_state": self.prior_state,
                "resulting_state": self.resulting_state,
                "quarantine": (
                    self.quarantine.as_record() if self.quarantine else None
                ),
            }
        )
        return record


@dataclass
class EngineTransitionGate:
    """Holds ``S`` and mediates every proposed transition through ``P``."""

    sts: SynchronizedTemporalState
    ledger: GateLedger = field(default_factory=GateLedger)
    quarantine: QuarantineManager = field(default_factory=QuarantineManager)
    state: str = "IDLE"
    audit_log: list[dict[str, Any]] = field(default_factory=list)

    # -- introspection -----------------------------------------------------

    def current_state(self) -> str:
        return self.state

    def records(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self.audit_log)

    # -- the only verb ------------------------------------------------------

    def attempt(self, request: StateTransitionRequest) -> TransitionOutcome:
        """Evaluate ``P`` for ``request`` and apply the resulting directive."""
        prior = self.state

        # A live hold on the target resource short-circuits everything except
        # the transitions that *resolve* the hold.
        blocked = self._blocked_by_hold(request)
        if blocked is not None:
            self.audit_log.append(blocked.as_record())
            return blocked

        eligibility = evaluate_predicate(
            state=prior, request=request, sts=self.sts, ledger=self.ledger
        )

        outcome = self._apply(eligibility, request, prior)
        self.audit_log.append(outcome.as_record())
        return outcome

    # -- internals ----------------------------------------------------------

    def _apply(
        self,
        eligibility: TransitionEligibility,
        request: StateTransitionRequest,
        prior: str,
    ) -> TransitionOutcome:
        resource = str(request.parameters.get("resource", "")) or prior

        if eligibility.eligible:
            self.state = request.to_state
            return TransitionOutcome(
                eligibility=eligibility,
                executed=True,
                prior_state=prior,
                resulting_state=self.state,
            )

        if eligibility.verdict is EligibilityVerdict.SAFE_FALLBACK:
            record = self.quarantine.safe_fallback(
                resource=resource,
                epoch=eligibility.evaluated_epoch,
                reason=eligibility.reason,
                from_state=prior,
                to_state=request.recovery_intent.requested_to_state
                if request.recovery_intent
                else "SAFE_STATE",
            )
            if record.directive is QuarantineAction.SAFE_FALLBACK:
                self.state = request.recovery_intent.requested_to_state  # type: ignore[union-attr]
                self.quarantine.complete_fallback(
                    resource=resource, epoch=eligibility.evaluated_epoch
                )
                landed = TransitionEligibility(
                    verdict=eligibility.verdict,
                    eligible=False,
                    reason=eligibility.reason,
                    request_id=eligibility.request_id,
                    evaluated_epoch=eligibility.evaluated_epoch,
                    window_id=eligibility.window_id,
                    binding_digest_expected=eligibility.binding_digest_expected,
                    binding_digest_observed=eligibility.binding_digest_observed,
                    quarantine_directive="SAFE_FALLBACK",
                    evidence=eligibility.evidence,
                )
                return TransitionOutcome(
                    eligibility=landed,
                    executed=True,
                    prior_state=prior,
                    resulting_state=self.state,
                    quarantine=record,
                )
            # Not safety-reducing: held instead, no movement.
            self.state = "QUARANTINED"
            return TransitionOutcome(
                eligibility=eligibility,
                executed=False,
                prior_state=prior,
                resulting_state=self.state,
                quarantine=record,
            )

        if eligibility.verdict is EligibilityVerdict.QUARANTINE_HOLD or (
            eligibility.quarantine_directive == "QUARANTINE_HOLD"
        ):
            record = self.quarantine.hold(
                resource=resource,
                epoch=eligibility.evaluated_epoch,
                reason=eligibility.reason,
            )
            self.state = "QUARANTINED"
            return TransitionOutcome(
                eligibility=eligibility,
                executed=False,
                prior_state=prior,
                resulting_state=self.state,
                quarantine=record,
            )

        # Plain denial: no state change, no actuation.
        return TransitionOutcome(
            eligibility=eligibility,
            executed=False,
            prior_state=prior,
            resulting_state=prior,
        )

    def _blocked_by_hold(
        self, request: StateTransitionRequest
    ) -> TransitionOutcome | None:
        resource = str(request.parameters.get("resource", "")) or self.state
        hold = self.quarantine.active_hold(resource)
        if hold is None:
            return None
        if request.kind in (
            TransitionKind.SAFE_FALLBACK,
            TransitionKind.QUARANTINE_HOLD,
        ):
            return None
        eligibility = TransitionEligibility(
            verdict=EligibilityVerdict.DENIED_NO_LIVE_AUTHORIZATION,
            eligible=False,
            reason=(
                f"resource {resource!r} is under QUARANTINE_HOLD ({hold.hold_id}) "
                "issued at epoch {0}: release requires a fresh live authorization".format(
                    hold.epoch
                )
            ),
            request_id=request.request_id,
            evaluated_epoch=self.sts.epoch,
            window_id=self.sts.current_window().window_id,
            quarantine_directive="QUARANTINE_HOLD",
            evidence=("HOLD_ACTIVE",),
        )
        return TransitionOutcome(
            eligibility=eligibility,
            executed=False,
            prior_state=self.state,
            resulting_state=self.state,
            quarantine=hold,
        )

    # -- operator path ------------------------------------------------------

    def release_hold(
        self, *, resource: str, request: StateTransitionRequest
    ) -> TransitionOutcome:
        """Attempt to release a hold by running the full predicate first."""
        outcome = self.attempt(request)
        hold = self.quarantine.active_hold(resource)
        if hold is None:
            raise ValueError(f"no active hold for {resource!r}")
        authorized = outcome.eligibility.eligible
        assert outcome.eligibility.request_id is not None
        record = self.quarantine.release(
            resource=resource,
            epoch=self.sts.epoch,
            authorization_id=(
                request.authorization.authorization_id
                if authorized and request.authorization
                else ""
            ),
            authorized=authorized,
        )
        final = TransitionEligibility(
            verdict=outcome.eligibility.verdict,
            eligible=authorized,
            reason=(
                "hold released under live authorization"
                if authorized
                else "release denied: hold escalated"
            ),
            request_id=request.request_id,
            evaluated_epoch=self.sts.epoch,
            window_id=self.sts.current_window().window_id,
            quarantine_directive="" if authorized else "QUARANTINE_HOLD",
            evidence=outcome.eligibility.evidence,
        )
        result = TransitionOutcome(
            eligibility=final,
            executed=authorized,
            prior_state=self.state,
            resulting_state=self.state,
            quarantine=record,
        )
        self.audit_log.append(result.as_record())
        if authorized:
            self.state = "IDLE"
        return result

    def quarantine_snapshot(self) -> Mapping[str, dict[str, Any]]:
        return self.quarantine.snapshot()

    def is_held(self, resource: str) -> bool:
        return self.quarantine.state_of(resource) in (
            QuarantineState.HELD,
            QuarantineState.FALLING_BACK,
        )


__all__ = ["TransitionOutcome", "EngineTransitionGate"]
