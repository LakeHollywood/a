"""Physical execution boundary locks -- the actuator's last line of defence.

The gate can say "eligible"; this module is what actually lets current flow to
an actuator.  It re-checks independently of the gate:

* The transition must have been *executed* under an eligible verdict, and the
  caller must present the **binding digest** the gate recorded for that
  decision.  A digest that was never issued cannot be computed by a caller who
  does not hold the real scope tuple, so presenting it is proof-of-gate-passage.
* Locks are single-use per (digest, epoch window): once consumed, an identical
  replay raises :class:`UnauthorizedActuationError`.
* ``engage`` refuses unless the machine state matches the digest's transition
  origin, i.e. you cannot actuate from a state the authorization was not minted
  in.

Nothing here reads historical evidence or rehydrated contexts; there is no API
that accepts them at all.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping


class PhysicalLockState(str, Enum):
    OPEN = "OPEN"          # energized, may actuate
    ENGAGED = "ENGAGED"    # mid-actuation, held until completion
    SEALED = "SEALED"      # de-energized safe condition (no actuation)


class UnauthorizedActuationError(RuntimeError):
    """Raised when an actuation request fails boundary verification."""


@dataclass(frozen=True, slots=True)
class ActuationPermit:
    """What the engine hands the boundary layer after an eligible transition."""

    binding_digest: str
    window_id: str
    epoch: int
    expected_state: str
    resource: str

    def as_record(self) -> dict[str, Any]:
        return {
            "binding_digest": self.binding_digest,
            "window_id": self.window_id,
            "epoch": self.epoch,
            "expected_state": self.expected_state,
            "resource": self.resource,
        }


@dataclass
class ExecutionBoundary:
    """Hardware interlock with independent verification of gate decisions."""

    lock_state: PhysicalLockState = PhysicalLockState.SEALED
    issued_permits: set[tuple[str, str]] = field(default_factory=set)
    redeemed_permits: set[tuple[str, str]] = field(default_factory=set)
    observations: list[dict[str, Any]] = field(default_factory=list)
    _hardware: Callable[[str], None] | None = None

    # -- issuance -----------------------------------------------------------

    def issue_permit(
        self,
        *,
        binding_digest: str,
        window_id: str,
        epoch: int,
        expected_state: str,
        resource: str,
    ) -> ActuationPermit:
        """Register a permit the gate earned by returning ``ELIGIBLE``.

        The boundary keeps only the digest *and its context*; it never stores
        authorizations or evidence, so nothing here can be mined for reuse.
        """
        if not binding_digest or not window_id:
            raise UnauthorizedActuationError("permit requires digest and window")
        self.issued_permits.add((binding_digest, window_id))
        return ActuationPermit(
            binding_digest=binding_digest,
            window_id=window_id,
            epoch=epoch,
            expected_state=expected_state,
            resource=resource,
        )

    # -- queries ------------------------------------------------------------

    @property
    def sealed(self) -> bool:
        return self.lock_state is PhysicalLockState.SEALED

    def seal(self) -> None:
        """De-energize.  Always permitted: sealing reduces risk."""
        self._transition_to(PhysicalLockState.SEALED, reason="sealed")

    def verify(self, permit: ActuationPermit, *, current_state: str) -> bool:
        """Non-consuming check used by tests/auditors."""
        key = (permit.binding_digest, permit.window_id)
        return (
            key in self.issued_permits
            and key not in self.redeemed_permits
            and permit.expected_state == current_state
            and not self.sealed
        )

    # -- actuation ----------------------------------------------------------

    def engage(
        self, permit: ActuationPermit, *, current_state: str, payload: Mapping[str, Any] | None = None
    ) -> dict[str, Any]:
        """Run the physical action guarded by this boundary.

        Raises :class:`UnauthorizedActuationError` on any mismatch; there is no
        boolean "force" argument.
        """
        key = (permit.binding_digest, permit.window_id)
        if self.sealed:
            self._observe("REFUSED", permit, "boundary sealed (SAFE_STATE interlock)")
            raise UnauthorizedActuationError(
                "physical lock is SEALED: actuation requires a live permit"
            )
        if key not in self.issued_permits:
            self._observe("REFUSED", permit, "digest never issued by the gate")
            raise UnauthorizedActuationError(
                "no such actuation permit: digest was never issued"
            )
        if key in self.redeemed_permits:
            self._observe("REFUSED", permit, "permit already redeemed (replay)")
            raise UnauthorizedActuationError(
                "permit replay detected: this digest/window was already used"
            )
        if permit.expected_state != current_state:
            self._observe(
                "REFUSED",
                permit,
                f"state drift: permit minted in {permit.expected_state}, "
                f"machine is in {current_state}",
            )
            raise UnauthorizedActuationError(
                "permit does not match the machine's current state"
            )

        self.redeemed_permits.add(key)
        self._transition_to(PhysicalLockState.ENGAGED, reason="engaged")
        try:
            if self._hardware is not None:
                self._hardware(permit.resource)
            result = {
                "actuated": True,
                "resource": permit.resource,
                "payload": dict(payload or {}),
                "permit": permit.as_record(),
            }
            self._observe("ACTUATED", permit, "ok")
            return result
        finally:
            self._transition_to(PhysicalLockState.SEALED, reason="re-sealed")

    # -- internals ----------------------------------------------------------

    def _transition_to(self, target: PhysicalLockState, *, reason: str) -> None:
        self.lock_state = target
        self.observations.append({"lock_state": target.value, "reason": reason})

    def _observe(
        self, outcome: str, permit: ActuationPermit, detail: str
    ) -> None:
        self.observations.append(
            {
                "outcome": outcome,
                "detail": detail,
                "permit": permit.as_record(),
            }
        )


__all__ = [
    "PhysicalLockState",
    "UnauthorizedActuationError",
    "ActuationPermit",
    "ExecutionBoundary",
]
