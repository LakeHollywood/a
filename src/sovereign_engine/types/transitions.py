"""Transition vocabulary: requests, eligibility, and the enums they use.

``StateTransitionRequest`` is the *only* carrier that reaches the predicate.
Its slots are typed at construction time:

    S        -> current state (str, must be a known machine state)
    E_hist   -> Sequence[HistoricalEvidence]   (telemetry/advisory only)
    E_live   -> LiveEvidence                   (single fresh attestation)
    A_live   -> LiveAuthorization | None       (None => recovery intent R)
    R        -> RecoveryIntent | None          (open recovery request)

Any attempt to bind a wrong-typed object raises ``TypeError`` immediately --
before the gate ever sees the request.  That is the structural half of ABIDE
A1/A3/REC-01 conformance; the behavioural half lives in ``gate.predicate``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from sovereign_engine.types.authorization import LiveAuthorization
from sovereign_engine.types.evidence import (
    HistoricalEvidence,
    LiveEvidence,
    RehydratedContext,
)


class TransitionKind(str, Enum):
    """Why the machine wants to move."""

    OPERATIONAL = "OPERATIONAL"
    RECOVERY = "RECOVERY"
    SAFE_FALLBACK = "SAFE_FALLBACK"
    QUARANTINE_HOLD = "QUARANTINE_HOLD"


class EligibilityVerdict(str, Enum):
    """Terminal verdicts the predicate can return."""

    ELIGIBLE = "ELIGIBLE"
    DENIED_NO_LIVE_AUTHORIZATION = "DENIED_NO_LIVE_AUTHORIZATION"
    DENIED_STALE_EVIDENCE = "DENIED_STALE_EVIDENCE"
    DENIED_SCOPE_SUBSTITUTION = "DENIED_SCOPE_SUBSTITUTION"
    DENIED_REPLAY = "DENIED_REPLAY"
    DENIED_EPOCH_WINDOW = "DENIED_EPOCH_WINDOW"
    DENIED_PROVENANCE = "DENIED_PROVENANCE"
    DENIED_UNBORG_TYPE = "DENIED_UNBORG_TYPE"
    QUARANTINE_HOLD = "QUARANTINE_HOLD"
    SAFE_FALLBACK = "SAFE_FALLBACK"


#: Machine states recognised by the engine (frozen vocabulary).
KNOWN_STATES: tuple[str, ...] = (
    "IDLE",
    "ARMED",
    "EXECUTING",
    "SUSPENDED",
    "QUARANTINED",
    "SAFE_STATE",
    "VOID",
)


@dataclass(frozen=True, slots=True)
class RecoveryIntent:
    """``R`` -- an *open* recovery request for interval ``I_{n+1}``.

    An open recovery contract means the engine acknowledges it needs authority
    it does not currently hold.  Carrying ``R`` never relaxes the A conjunct:
    with ``A_live is None`` the predicate's only possible outcomes are
    ``QUARANTINE_HOLD`` or ``SAFE_FALLBACK`` (Recovery Contract Theorem 1).
    """

    interval_id: str
    last_durable_epoch: int
    resume_epoch: int
    context: RehydratedContext
    requested_to_state: str = "SAFE_STATE"
    diagnostics: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.interval_id:
            raise ValueError("recovery intent requires an interval_id")
        if self.resume_epoch <= self.last_durable_epoch:
            raise ValueError(
                "resume_epoch must be strictly after last_durable_epoch"
            )
        if not isinstance(self.context, RehydratedContext):
            raise TypeError(
                "RecoveryIntent.context must be a RehydratedContext, got "
                f"{type(self.context).__name__}"
            )


@dataclass(frozen=True, slots=True)
class StateTransitionRequest:
    """The fully-typed input bundle for one gate evaluation."""

    from_state: str
    to_state: str
    kind: TransitionKind
    live_evidence: LiveEvidence
    historical_evidence: tuple[HistoricalEvidence, ...] = ()
    authorization: LiveAuthorization | None = None
    recovery_intent: RecoveryIntent | None = None
    parameters: Mapping[str, Any] = field(default_factory=dict)
    request_id: str = ""

    def __post_init__(self) -> None:
        if self.from_state not in KNOWN_STATES or self.to_state not in KNOWN_STATES:
            raise ValueError(
                f"unknown machine state in request: {self.from_state!r} -> "
                f"{self.to_state!r}"
            )
        if not isinstance(self.live_evidence, LiveEvidence):
            raise TypeError(
                "E_live slot accepts LiveEvidence only; got "
                f"{type(self.live_evidence).__name__}. Historical records and "
                "rehydrated contexts cannot satisfy a live conjunct."
            )
        for item in self.historical_evidence:
            if not isinstance(item, HistoricalEvidence):
                raise TypeError(
                    "E_hist slot accepts HistoricalEvidence only; got "
                    f"{type(item).__name__}"
                )
        if self.authorization is not None and not isinstance(
            self.authorization, LiveAuthorization
        ):
            raise TypeError(
                "A_live slot accepts LiveAuthorization only; got "
                f"{type(self.authorization).__name__}"
            )
        if self.recovery_intent is not None and not isinstance(
            self.recovery_intent, RecoveryIntent
        ):
            raise TypeError(
                "R slot accepts RecoveryIntent only; got "
                f"{type(self.recovery_intent).__name__}"
            )
        if self.kind is TransitionKind.RECOVERY and self.recovery_intent is None:
            raise ValueError("RECOVERY transitions must carry an explicit R")

    @property
    def is_open_recovery(self) -> bool:
        """True when the request admits it has no live authority."""
        return self.authorization is None and self.recovery_intent is not None


@dataclass(frozen=True, slots=True)
class TransitionEligibility:
    """The gate's answer, as data (never as an exception)."""

    verdict: EligibilityVerdict
    eligible: bool
    reason: str
    request_id: str
    evaluated_epoch: int
    window_id: str
    binding_digest_expected: str = ""
    binding_digest_observed: str = ""
    quarantine_directive: str = ""
    evidence: Sequence[str] = ()

    def as_record(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "eligible": self.eligible,
            "reason": self.reason,
            "request_id": self.request_id,
            "evaluated_epoch": self.evaluated_epoch,
            "window_id": self.window_id,
            "binding_digest_expected": self.binding_digest_expected,
            "binding_digest_observed": self.binding_digest_observed,
            "quarantine_directive": self.quarantine_directive,
            "evidence": list(self.evidence),
        }


__all__ = [
    "TransitionKind",
    "EligibilityVerdict",
    "KNOWN_STATES",
    "RecoveryIntent",
    "StateTransitionRequest",
    "TransitionEligibility",
]
