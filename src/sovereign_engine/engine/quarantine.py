"""Quarantine management: ``QUARANTINE_HOLD`` and ``SAFE_FALLBACK``.

When the predicate cannot certify authority, the machine must still land in a
*defined* resting state -- it is never left "wherever it was" with an unclear
obligation.  Two directives exist:

``QUARANTINE_HOLD``
    Freeze the affected context.  No actuation is permitted, no state advance
    occurs, and every subsequent request touching the quarantined resource is
    denied until an operator releases it with a *live* authorization.

``SAFE_FALLBACK``
    Move to the declared safe state (a legal edge, evaluated without requiring
    operational authority because it reduces risk).  Fallback is only granted
    for edges registered as safety-reducing.

The manager records full lineage so recovery can reason about *why* a hold
exists; the record itself is never an authorization.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping


class QuarantineState(str, Enum):
    FREE = "FREE"
    HELD = "HELD"
    FALLING_BACK = "FALLING_BACK"
    RELEASED = "RELEASED"


class QuarantineAction(str, Enum):
    HOLD = "HOLD"
    SAFE_FALLBACK = "SAFE_FALLBACK"
    RELEASE = "RELEASE"
    ESCALATE = "ESCALATE"


#: Edges that reduce risk and are therefore permitted without an operational
#: grant.  Anything not listed here requires the full predicate to pass.
SAFETY_REDUCING_EDGES: frozenset[tuple[str, str]] = frozenset(
    {
        ("EXECUTING", "SAFE_STATE"),
        ("SUSPENDED", "SAFE_STATE"),
        ("QUARANTINED", "SAFE_STATE"),
        ("VOID", "SAFE_STATE"),
        ("EXECUTING", "QUARANTINED"),
        ("SUSPENDED", "QUARANTINED"),
    }
)


def _hold_id(resource: str, epoch: int, reason: str) -> str:
    material = json.dumps(
        {"resource": resource, "epoch": epoch, "reason": reason},
        sort_keys=True,
    )
    return "qh-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True, slots=True)
class QuarantineRecord:
    """Immutable audit record of one hold / fallback decision."""

    hold_id: str
    resource: str
    directive: QuarantineAction
    state: QuarantineState
    epoch: int
    reason: str
    released_epoch: int | None = None
    release_authorization_id: str | None = None

    def as_record(self) -> dict[str, Any]:
        return {
            "hold_id": self.hold_id,
            "resource": self.resource,
            "directive": self.directive.value,
            "state": self.state.value,
            "epoch": self.epoch,
            "reason": self.reason,
            "released_epoch": self.released_epoch,
            "release_authorization_id": self.release_authorization_id,
        }


@dataclass
class QuarantineManager:
    """Tracks holds per resource and mediates their (authorized) release."""

    _holds: dict[str, QuarantineRecord] = field(default_factory=dict)
    _history: list[QuarantineRecord] = field(default_factory=list)

    # -- queries -----------------------------------------------------------

    def state_of(self, resource: str) -> QuarantineState:
        record = self._holds.get(resource)
        if record is None:
            return QuarantineState.FREE
        return record.state

    def active_hold(self, resource: str) -> QuarantineRecord | None:
        record = self._holds.get(resource)
        if record is not None and record.state in (
            QuarantineState.HELD,
            QuarantineState.FALLING_BACK,
        ):
            return record
        return None

    @property
    def history(self) -> tuple[QuarantineRecord, ...]:
        return tuple(self._history)

    def blocks(self, resource: str) -> bool:
        """True when any pending hold forbids progress for ``resource``."""
        return self.active_hold(resource) is not None

    # -- directives --------------------------------------------------------

    def hold(
        self, *, resource: str, epoch: int, reason: str
    ) -> QuarantineRecord:
        """Place a QUARANTINE_HOLD on ``resource`` (fail-closed default)."""
        record = QuarantineRecord(
            hold_id=_hold_id(resource, epoch, reason),
            resource=resource,
            directive=QuarantineAction.HOLD,
            state=QuarantineState.HELD,
            epoch=epoch,
            reason=reason,
        )
        self._holds[resource] = record
        self._history.append(record)
        return record

    def safe_fallback(
        self,
        *,
        resource: str,
        epoch: int,
        reason: str,
        from_state: str,
        to_state: str,
    ) -> QuarantineRecord:
        """Direct a fallback move, but only along a safety-reducing edge."""
        if (from_state, to_state) not in SAFETY_REDUCING_EDGES:
            # A "fallback" that is not risk-reducing is an ordinary transition
            # and must go through the predicate; refuse and hold instead.
            return self.hold(
                resource=resource,
                epoch=epoch,
                reason=(
                    f"requested fallback edge {from_state}->{to_state} is not "
                    f"safety-reducing; held instead of fallen back ({reason})"
                ),
            )
        record = QuarantineRecord(
            hold_id=_hold_id(resource, epoch, reason),
            resource=resource,
            directive=QuarantineAction.SAFE_FALLBACK,
            state=QuarantineState.FALLING_BACK,
            epoch=epoch,
            reason=reason,
        )
        self._holds[resource] = record
        self._history.append(record)
        return record

    def complete_fallback(self, *, resource: str, epoch: int) -> QuarantineRecord:
        """Mark a fallback as landed; the hold becomes an explicit RELEASED."""
        current = self.active_hold(resource)
        if current is None or current.directive is not QuarantineAction.SAFE_FALLBACK:
            raise ValueError(f"no pending safe fallback for {resource!r}")
        record = QuarantineRecord(
            hold_id=current.hold_id,
            resource=resource,
            directive=QuarantineAction.SAFE_FALLBACK,
            state=QuarantineState.RELEASED,
            epoch=current.epoch,
            reason=current.reason,
            released_epoch=epoch,
            release_authorization_id=None,
        )
        self._holds.pop(resource, None)
        self._history.append(record)
        return record

    def release(
        self,
        *,
        resource: str,
        epoch: int,
        authorization_id: str,
        authorized: bool,
    ) -> QuarantineRecord:
        """Release a hold.  Requires a *live*, predicate-verified authorization.

        ``authorized`` is supplied by the engine after it has run the full
        predicate against the release transition; the manager never infers
        authority from the mere presence of an id string.
        """
        current = self.active_hold(resource)
        if current is None:
            raise ValueError(f"no active hold to release for {resource!r}")
        if not authorized or not authorization_id:
            # Failed release attempt: re-hold with escalated lineage.
            record = QuarantineRecord(
                hold_id=current.hold_id,
                resource=resource,
                directive=QuarantineAction.ESCALATE,
                state=QuarantineState.HELD,
                epoch=epoch,
                reason=(
                    f"release attempt rejected (no live authorization); hold "
                    f"escalated from epoch {current.epoch}"
                ),
            )
            self._holds[resource] = record
            self._history.append(record)
            return record
        record = QuarantineRecord(
            hold_id=current.hold_id,
            resource=resource,
            directive=QuarantineAction.RELEASE,
            state=QuarantineState.RELEASED,
            epoch=current.epoch,
            reason=current.reason,
            released_epoch=epoch,
            release_authorization_id=authorization_id,
        )
        self._holds.pop(resource, None)
        self._history.append(record)
        return record

    def snapshot(self) -> Mapping[str, dict[str, Any]]:
        return {
            resource: record.as_record()
            for resource, record in self._holds.items()
        }


__all__ = [
    "QuarantineState",
    "QuarantineAction",
    "SAFETY_REDUCING_EDGES",
    "QuarantineRecord",
    "QuarantineManager",
]
