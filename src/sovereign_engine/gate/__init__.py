"""Deterministic authority evaluation surface.

``gate`` exposes exactly two things the engine is allowed to consult before a
state transition: the pure predicate and the STS clock.  Nothing in this
package performs I/O or holds mutable global state (the single-use ledger is
always passed in explicitly by the calling engine).
"""

from __future__ import annotations

from sovereign_engine.gate.predicate import (
    LEGAL_EDGES,
    GateInputs,
    GateLedger,
    PredicateResult,
    evaluate_predicate,
)
from sovereign_engine.gate.sts_clock import (
    DEFAULT_WINDOW_TICKS,
    EpochWindow,
    SynchronizedTemporalState,
    TemporalDriftError,
)

__all__ = [
    "LEGAL_EDGES",
    "GateInputs",
    "GateLedger",
    "PredicateResult",
    "evaluate_predicate",
    "DEFAULT_WINDOW_TICKS",
    "EpochWindow",
    "SynchronizedTemporalState",
    "TemporalDriftError",
]
