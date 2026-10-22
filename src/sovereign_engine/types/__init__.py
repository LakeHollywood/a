"""Structural type boundaries for the SAIL authority model.

Three evidence classes exist and they are *not* interchangeable:

``HistoricalEvidence``
    Records of what was observed / decided in the past.  Immutable, always
    carries an ``as_of_epoch`` strictly in the past relative to the STS clock
    at evaluation time.  Historical evidence can inform telemetry, audit and
    recommendation; it can NEVER satisfy a live-authorization conjunct of the
    predicate (ABIDE A1.1).

``LiveEvidence``
    Freshly attested observations inside the current STS epoch window.  Only
    this class may bind to a transition as ``E_live``.

``RehydratedContext``
    A context reconstructed after a crash/void interval (``E_n -> I_{n+1}``).
    Rehydration restores *state*; it never restores *authority*.  A
    ``RehydratedContext`` is typed so that it cannot be passed where a
    ``LiveAuthorization`` is required (ABIDE REC-01).

The modules here use frozen dataclasses plus explicit enum tags so that any
attempt to launder one class into another requires a deliberate, auditable
conversion function -- never an implicit cast.
"""

from __future__ import annotations

from sovereign_engine.types.authorization import (
    AuthorizationEpoch,
    LiveAuthorization,
    PayloadScope,
    TargetScope,
    TransitionScope,
)
from sovereign_engine.types.evidence import (
    EvidenceClass,
    HistoricalEvidence,
    LiveEvidence,
    RehydratedContext,
    historical_to_recommendation,
    rehydrate,
)
from sovereign_engine.types.transitions import (
    EligibilityVerdict,
    RecoveryIntent,
    StateTransitionRequest,
    TransitionEligibility,
    TransitionKind,
)

__all__ = [
    "AuthorizationEpoch",
    "LiveAuthorization",
    "PayloadScope",
    "TargetScope",
    "TransitionScope",
    "EvidenceClass",
    "HistoricalEvidence",
    "LiveEvidence",
    "RehydratedContext",
    "historical_to_recommendation",
    "rehydrate",
    "EligibilityVerdict",
    "RecoveryIntent",
    "StateTransitionRequest",
    "TransitionEligibility",
    "TransitionKind",
]
