"""Engine plumbing: quarantine, transition gate and open recovery."""

from __future__ import annotations

from sovereign_engine.engine.quarantine import (
    SAFETY_REDUCING_EDGES,
    QuarantineAction,
    QuarantineManager,
    QuarantineRecord,
    QuarantineState,
)
from sovereign_engine.engine.recovery import (
    DurableEpoch,
    Recovered,
    RecoveryContractViolation,
    build_recovery_intent,
    recover,
    require_live_authorization_for_resume,
)
from sovereign_engine.engine.transition_gate import (
    EngineTransitionGate,
    TransitionOutcome,
)

__all__ = [
    "SAFETY_REDUCING_EDGES",
    "QuarantineAction",
    "QuarantineManager",
    "QuarantineRecord",
    "QuarantineState",
    "DurableEpoch",
    "Recovered",
    "RecoveryContractViolation",
    "build_recovery_intent",
    "recover",
    "require_live_authorization_for_resume",
    "EngineTransitionGate",
    "TransitionOutcome",
]
