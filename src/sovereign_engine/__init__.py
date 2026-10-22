"""Sovereign Engine -- core primitives for the SAIL authority boundary.

The package implements the frozen SAIL specification as a set of strictly
isolated structural type boundaries and a deterministic predicate gate:

* ``sovereign_engine.types``      -- evidence / authorization / transition
  types.  Historical evidence, live evidence and live authorization are
  *distinct types*; no implicit coercion exists between them (ABIDE A1/A3).
* ``sovereign_engine.gate``       -- the pure predicate ``P(S, E_hist,
  E_live, A_live, R)`` and the Synchronized Temporal State (STS) epoch
  bounded windows (ABIDE A4).
* ``sovereign_engine.engine``     -- state machine plumbing: quarantine
  management, the engine transition gate and the open recovery function
  ``Recover(E_n, I_{n+1})`` (ABIDE REC-01).
* ``sovereign_engine.execution``  -- the physical actuator boundary; locks
  here are the only sanctioned path to hardware side effects.

Everything re-exported at package level is read-only vocabulary: importing
``sovereign_engine`` never performs I/O and never mutates global state.
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
)
from sovereign_engine.types.transitions import (
    EligibilityVerdict,
    RecoveryIntent,
    StateTransitionRequest,
    TransitionEligibility,
    TransitionKind,
)
from sovereign_engine.engine.recovery import (
    DurableEpoch,
    Recovered,
    RecoveryContractViolation,
    build_recovery_intent,
    recover,
    require_live_authorization_for_resume,
)
from sovereign_engine.execution.boundary import (
    ActuationPermit,
    ExecutionBoundary,
    PhysicalLockState,
    UnauthorizedActuationError,
)
from sovereign_engine.gate.predicate import (
    LEGAL_EDGES,
    GateInputs,
    GateLedger,
    PredicateResult,
    evaluate_predicate,
)
from sovereign_engine.gate.sts_clock import (
    EpochWindow,
    SynchronizedTemporalState,
    TemporalDriftError,
)
from sovereign_engine.engine.quarantine import (
    QuarantineAction,
    QuarantineManager,
    QuarantineState,
)
from sovereign_engine.engine.quarantine import (
    QuarantineAction,
    QuarantineManager,
    QuarantineRecord,
    QuarantineState,
)
from sovereign_engine.engine.transition_gate import (
    EngineTransitionGate,
    TransitionOutcome,
)
from sovereign_engine.types.transitions import (
    EligibilityVerdict,
    RecoveryIntent,
    StateTransitionRequest,
    TransitionEligibility,
    TransitionKind,
)

__version__ = "2026.09.26-frozen"

__all__ = [
    "__version__",
    # types.evidence
    "EvidenceClass",
    "HistoricalEvidence",
    "LiveEvidence",
    "RehydratedContext",
    # types.authorization
    "AuthorizationEpoch",
    "LiveAuthorization",
    "PayloadScope",
    "TargetScope",
    "TransitionScope",
    # types.transitions
    "EligibilityVerdict",
    "RecoveryIntent",
    "StateTransitionRequest",
    "TransitionEligibility",
    "TransitionKind",
    # gate
    "LEGAL_EDGES",
    "GateInputs",
    "GateLedger",
    "PredicateResult",
    "evaluate_predicate",
    "EpochWindow",
    "SynchronizedTemporalState",
    "TemporalDriftError",
    # engine
    "QuarantineAction",
    "QuarantineManager",
    "QuarantineRecord",
    "QuarantineState",
    "EngineTransitionGate",
    "TransitionOutcome",
    "DurableEpoch",
    "Recovered",
    "RecoveryContractViolation",
    "build_recovery_intent",
    "recover",
    "require_live_authorization_for_resume",
    # execution
    "ActuationPermit",
    "ExecutionBoundary",
    "PhysicalLockState",
    "UnauthorizedActuationError",
]
