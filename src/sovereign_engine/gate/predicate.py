"""The deterministic authority predicate ``P(S, E_hist, E_live, A_live, R)``.

Frozen spec shape (SAIL-SPEC-2026-FROZEN §4)::

    P(S, E_hist, E_live, A_live, R) =
          T_state(S, request)                 # S is a known state, edge legal
        ∧ L_live(E_live)                      # live attestation well-formed
        ∧ W_epoch(E_live, A_live, STS)        # inside the current epoch window
        ∧ B_bind(A_live, request)             # four-way scope binding matches
        ∧ C_consumed(A_live, E_live)          # neither grant nor nonce replayed
        ∧ O_origin(E_live, A_live, request)   # principal/epoch provenance
        → ELIGIBLE
      otherwise DENIED* / QUARANTINE_HOLD / SAFE_FALLBACK

Properties enforced here:

* **Pure**: no I/O, no clock reads other than through the injected STS object,
  no mutation of the request.  The only side effect is recording consumed
  nonces into an explicit :class:`GateLedger` supplied by the caller, so the
  function stays referentially transparent given identical ledgers.
* **Fail closed**: any unexpected condition yields a denial verdict; there is
  no code path that returns ``ELIGIBLE`` by default.
* **Content-blind**: two objects with identical bytes but different classes
  produce different verdicts, because class tags and temporal bindings are
  part of the conjuncts (ABIDE A1/A3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from sovereign_engine.gate.sts_clock import (
    EpochWindow,
    SynchronizedTemporalState,
    TemporalDriftError,
)
from sovereign_engine.types.authorization import LiveAuthorization, derive_binding_digest
from sovereign_engine.types.evidence import (
    EvidenceClass,
    HistoricalEvidence,
    LiveEvidence,
    RehydratedContext,
)
from sovereign_engine.types.transitions import (
    EligibilityVerdict,
    KNOWN_STATES,
    RecoveryIntent,
    StateTransitionRequest,
    TransitionEligibility,
    TransitionKind,
)

#: Legal edges of the sovereign state machine (frozen vocabulary).  Anything
#: not listed here is illegal and cannot be authorized by any grant.
LEGAL_EDGES: frozenset[tuple[str, str]] = frozenset(
    {
        ("IDLE", "ARMED"),
        ("ARMED", "EXECUTING"),
        ("ARMED", "IDLE"),
        ("EXECUTING", "SAFE_STATE"),
        ("EXECUTING", "SUSPENDED"),
        ("EXECUTING", "QUARANTINED"),
        ("SUSPENDED", "ARMED"),
        ("SUSPENDED", "SAFE_STATE"),
        ("SUSPENDED", "QUARANTINED"),
        ("QUARANTINED", "SAFE_STATE"),
        ("QUARANTINED", "IDLE"),
        ("SAFE_STATE", "IDLE"),
        ("VOID", "SAFE_STATE"),
        ("VOID", "QUARANTINED"),
    }
)


@dataclass
class GateLedger:
    """Explicit single-use bookkeeping passed in by the engine.

    Kept separate from the predicate so that ``evaluate_predicate`` can be
    called in "what-if" mode (dry run) without burning nonces.
    """

    spent_nonces: set[tuple[str, str, str]] = field(default_factory=set)
    spent_authorizations: set[str] = field(default_factory=set)

    def nonce_spent(self, key: tuple[str, str, str]) -> bool:
        return key in self.spent_nonces

    def authorization_spent(self, authorization_id: str) -> bool:
        return authorization_id in self.spent_authorizations

    def consume(
        self, *, nonce_key: tuple[str, str, str], authorization_id: str | None
    ) -> None:
        self.spent_nonces.add(nonce_key)
        if authorization_id is not None:
            self.spent_authorizations.add(authorization_id)


@dataclass(frozen=True, slots=True)
class GateInputs:
    """Named bundle mirroring the predicate signature for audit output."""

    state: str
    historical: tuple[HistoricalEvidence, ...]
    live: LiveEvidence
    authorization: LiveAuthorization | None
    recovery: RecoveryIntent | None


@dataclass(frozen=True, slots=True)
class PredicateResult:
    """Raw predicate output before quarantine policy is applied."""

    eligible: bool
    verdict: EligibilityVerdict
    reason: str
    facts: Mapping[str, Any] = field(default_factory=dict)


def _result(
    eligible: bool, verdict: EligibilityVerdict, reason: str, **facts: Any
) -> PredicateResult:
    return PredicateResult(eligible=eligible, verdict=verdict, reason=reason, facts=facts)


# ---------------------------------------------------------------------------
# Individual conjuncts -- exposed separately so tests can assert *which*
# conjunct rejected an adversarial vector, not merely that it was rejected.
# ---------------------------------------------------------------------------


def conjunct_state(state: str, request: StateTransitionRequest) -> PredicateResult:
    if state not in KNOWN_STATES or request.from_state != state:
        return _result(
            False,
            EligibilityVerdict.DENIED_PROVENANCE,
            f"state mismatch: gate holds {state!r}, request asserts {request.from_state!r}",
        )
    if (request.from_state, request.to_state) not in LEGAL_EDGES:
        return _result(
            False,
            EligibilityVerdict.DENIED_UNBORG_TYPE,
            f"illegal edge {request.from_state}->{request.to_state} is not authorizable",
        )
    return _result(True, EligibilityVerdict.ELIGIBLE, "state conjunct satisfied")


def conjunct_live(
    live: Any, request: StateTransitionRequest, sts: SynchronizedTemporalState
) -> PredicateResult:
    if isinstance(live, HistoricalEvidence):
        return _result(
            False,
            EligibilityVerdict.DENIED_STALE_EVIDENCE,
            "E_hist content cannot satisfy the E_live conjunct (A1.1)",
        )
    if isinstance(live, RehydratedContext):
        return _result(
            False,
            EligibilityVerdict.DENIED_STALE_EVIDENCE,
            "rehydrated context cannot satisfy the E_live conjunct (REC-01)",
        )
    if not isinstance(live, LiveEvidence):
        return _result(
            False,
            EligibilityVerdict.DENIED_UNBORG_TYPE,
            f"E_live slot requires LiveEvidence, got {type(live).__name__}",
        )
    if live.evidence_class is not EvidenceClass.LIVE:
        return _result(
            False,
            EligibilityVerdict.DENIED_UNBORG_TYPE,
            "live evidence carries an inconsistent class tag",
        )
    if live.spent:
        return _result(
            False, EligibilityVerdict.DENIED_REPLAY, "attestation already consumed"
        )
    try:
        if not sts.validate_attestation(live.attested_epoch, live.window_id):
            return _result(
                False,
                EligibilityVerdict.DENIED_EPOCH_WINDOW,
                "attestation is outside the current STS epoch window",
            )
    except TemporalDriftError as exc:
        return _result(
            False, EligibilityVerdict.DENIED_EPOCH_WINDOW, f"STS drift: {exc}"
        )
    if (
        live.subject != request.parameters.get("principal", live.subject)
        or live.action != request.kind.value
    ):
        return _result(
            False,
            EligibilityVerdict.DENIED_PROVENANCE,
            "attestation subject/action does not match the transition request",
        )
    return _result(True, EligibilityVerdict.ELIGIBLE, "live conjunct satisfied")


def conjunct_window(
    authorization: LiveAuthorization | None,
    live: LiveEvidence,
    sts: SynchronizedTemporalState,
) -> PredicateResult:
    if authorization is None:
        return _result(
            True, EligibilityVerdict.ELIGIBLE, "no grant to time-check (open recovery)"
        )
    try:
        window: EpochWindow = sts.current_window()
    except TemporalDriftError as exc:
        return _result(
            False, EligibilityVerdict.DENIED_EPOCH_WINDOW, f"STS drift: {exc}"
        )
    if authorization.epoch.window_id != window.window_id:
        return _result(
            False,
            EligibilityVerdict.DENIED_EPOCH_WINDOW,
            "authorization bound to a closed epoch window",
        )
    if live.window_id != authorization.epoch.window_id:
        return _result(
            False,
            EligibilityVerdict.DENIED_EPOCH_WINDOW,
            "attestation window differs from the authorization window",
        )
    return _result(True, EligibilityVerdict.ELIGIBLE, "epoch window conjunct satisfied")


def conjunct_binding(
    authorization: LiveAuthorization | None, request: StateTransitionRequest
) -> PredicateResult:
    if authorization is None:
        return _result(
            False,
            EligibilityVerdict.DENIED_NO_LIVE_AUTHORIZATION,
            "no live authorization present: the A conjunct cannot be satisfied",
        )
    params = request.parameters
    principal = str(params.get("principal", ""))
    resource = str(params.get("resource", ""))
    device_id = str(params.get("device_id", ""))
    target_ok = authorization.covers_target(
        TargetScope_ref(principal, resource, device_id)
    )
    transition_ok = authorization.covers_transition(
        request.from_state, request.to_state, request.kind.value
    )
    payload_ok = authorization.payload.admits(dict(params.get("payload", {})))
    recomputed = derive_binding_digest(
        target=authorization.target,
        payload=authorization.payload,
        transition=authorization.transition,
        epoch=authorization.epoch,
        attestation_nonce=authorization.attestation_nonce,
    )
    digest_ok = recomputed == authorization.binding_digest
    if not (target_ok and transition_ok and payload_ok and digest_ok):
        failed = [
            name
            for name, ok in (
                ("TARGET", target_ok),
                ("TRANSITION", transition_ok),
                ("PAYLOAD", payload_ok),
                ("DIGEST", digest_ok),
            )
            if not ok
        ]
        return _result(
            False,
            EligibilityVerdict.DENIED_SCOPE_SUBSTITUTION,
            "scope substitution detected: " + "/".join(failed),
            scopes_failed=tuple(failed),
        )
    return _result(True, EligibilityVerdict.ELIGIBLE, "binding conjunct satisfied")


def conjunct_consumed(
    authorization: LiveAuthorization | None,
    live: LiveEvidence,
    ledger: GateLedger,
) -> PredicateResult:
    if ledger.nonce_spent(live.replay_key):
        return _result(
            False,
            EligibilityVerdict.DENIED_REPLAY,
            "attestation nonce already used inside this window (A4)",
        )
    if authorization is not None:
        if authorization.consumed:
            return _result(
                False,
                EligibilityVerdict.DENIED_REPLAY,
                "authorization token already consumed",
            )
        if ledger.authorization_spent(authorization.authorization_id):
            return _result(
                False,
                EligibilityVerdict.DENIED_REPLAY,
                "authorization id already redeemed against the ledger",
            )
    return _result(True, EligibilityVerdict.ELIGIBLE, "single-use conjunct satisfied")


def conjunct_origin(
    authorization: LiveAuthorization | None,
    live: LiveEvidence,
    request: StateTransitionRequest,
) -> PredicateResult:
    """Provenance identity check (ABIDE A3).

    The attesting principal must be the same identity the authorization was
    minted for, and both must trace to the current epoch's origin.  A perfect
    forgery of *content* still fails here because identity is bound into the
    digest inputs, not read from the payload.
    """
    if authorization is not None:
        if authorization.target.principal != live.subject:
            return _result(
                False,
                EligibilityVerdict.DENIED_PROVENANCE,
                "attesting principal differs from the authorization principal",
            )
        if authorization.epoch.epoch != live.attested_epoch:
            return _result(
                False,
                EligibilityVerdict.DENIED_PROVENANCE,
                "authorization epoch origin differs from attestation origin",
            )
    return _result(True, EligibilityVerdict.ELIGIBLE, "provenance conjunct satisfied")


# Local indirection so the binding conjunct can build a comparable target
# without importing the whole scope vocabulary into the public surface.
def TargetScope_ref(principal: str, resource: str, device_id: str):  # noqa: ANN201
    from sovereign_engine.types.authorization import TargetScope

    return TargetScope(principal=principal, resource=resource, device_id=device_id)


# ---------------------------------------------------------------------------
# The predicate
# ---------------------------------------------------------------------------


def evaluate_predicate(
    *,
    state: str,
    request: StateTransitionRequest,
    sts: SynchronizedTemporalState,
    ledger: GateLedger,
    dry_run: bool = False,
) -> TransitionEligibility:
    """Evaluate ``P(S, E_hist, E_live, A_live, R)`` for one transition request.

    ``E_hist`` is deliberately *not* consulted by any conjunct: historical
    evidence may accompany a request for audit richness, but it has no binding
    effect.  ``R`` selects the quarantine/fallback directive when ``A_live`` is
    absent; it never relaxes a conjunct.
    """
    conjuncts: Sequence[tuple[str, PredicateResult]] = [
        ("T_state", conjunct_state(state, request)),
        ("L_live", conjunct_live(request.live_evidence, request, sts)),
        ("W_epoch", conjunct_window(request.authorization, request.live_evidence, sts)),
        ("C_consumed", conjunct_consumed(request.authorization, request.live_evidence, ledger)),
        ("O_origin", conjunct_origin(request.authorization, request.live_evidence, request)),
        ("B_bind", conjunct_binding(request.authorization, request)),
    ]

    window_id = ""
    evaluated_epoch = sts.epoch
    try:
        window_id = sts.current_window().window_id
    except TemporalDriftError:
        window_id = "<unsynchronized>"

    observed_digest = (
        request.authorization.binding_digest if request.authorization else ""
    )
    expected_digest = ""
    if request.authorization is not None:
        expected_digest = derive_binding_digest(
            target=request.authorization.target,
            payload=request.authorization.payload,
            transition=request.authorization.transition,
            epoch=request.authorization.epoch,
            attestation_nonce=request.authorization.attestation_nonce,
        )

    for name, outcome in conjuncts:
        if not outcome.eligible:
            verdict, reason, directive = _classify_failure(
                name, outcome, request
            )
            return TransitionEligibility(
                verdict=verdict,
                eligible=False,
                reason=reason,
                request_id=request.request_id,
                evaluated_epoch=evaluated_epoch,
                window_id=window_id,
                binding_digest_expected=expected_digest,
                binding_digest_observed=observed_digest,
                quarantine_directive=directive,
                evidence=(f"{name}:{outcome.verdict.value}",),
            )

    if not dry_run:
        ledger.consume(
            nonce_key=request.live_evidence.replay_key,
            authorization_id=(
                request.authorization.authorization_id
                if request.authorization
                else None
            ),
        )

    return TransitionEligibility(
        verdict=EligibilityVerdict.ELIGIBLE,
        eligible=True,
        reason="all predicate conjuncts satisfied",
        request_id=request.request_id,
        evaluated_epoch=evaluated_epoch,
        window_id=window_id,
        binding_digest_expected=expected_digest,
        binding_digest_observed=observed_digest,
        evidence=tuple(name for name, _ in conjuncts),
    )


def _classify_failure(
    conjunct_name: str,
    outcome: PredicateResult,
    request: StateTransitionRequest,
) -> tuple[EligibilityVerdict, str, str]:
    """Map a failed conjunct onto a verdict plus quarantine directive.

    Open-recovery requests (``A_live is None``, ``R`` present) never receive a
    plain denial: the contract requires them to land in ``QUARANTINE_HOLD`` or
    ``SAFE_FALLBACK`` so the machine always has a defined resting state.
    """
    verdict = outcome.verdict
    reason = outcome.reason
    if request.is_open_recovery:
        if request.recovery_intent is not None and (
            request.recovery_intent.requested_to_state in KNOWN_STATES
            and (request.from_state, request.recovery_intent.requested_to_state)
            in LEGAL_EDGES
        ):
            return (
                EligibilityVerdict.SAFE_FALLBACK,
                f"open recovery for {request.recovery_intent.interval_id}: "
                f"{reason}; falling back to "
                f"{request.recovery_intent.requested_to_state}",
                "SAFE_FALLBACK",
            )
        return (
            EligibilityVerdict.QUARANTINE_HOLD,
            f"open recovery with no legal fallback edge: {reason}",
            "QUARANTINE_HOLD",
        )
    if conjunct_name == "B_bind" and verdict is EligibilityVerdict.DENIED_NO_LIVE_AUTHORIZATION:
        return verdict, reason, "QUARANTINE_HOLD"
    return verdict, reason, ""


__all__ = [
    "LEGAL_EDGES",
    "GateLedger",
    "GateInputs",
    "PredicateResult",
    "evaluate_predicate",
    "conjunct_state",
    "conjunct_live",
    "conjunct_window",
    "conjunct_binding",
    "conjunct_consumed",
    "conjunct_origin",
]
