"""Actuator & hardware interface boundary."""

from __future__ import annotations

from sovereign_engine.execution.boundary import (
    ActuationPermit,
    ExecutionBoundary,
    PhysicalLockState,
    UnauthorizedActuationError,
)

__all__ = [
    "ActuationPermit",
    "ExecutionBoundary",
    "PhysicalLockState",
    "UnauthorizedActuationError",
]
