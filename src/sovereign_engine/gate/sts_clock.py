"""Synchronized Temporal State (STS): epoch-bounded authorization windows.

The STS clock is the engine's single source of temporal truth.  Authority is
only ever valid *inside* a window; when the window closes, every grant bound
to it becomes inert regardless of how authentic its content is (ABIDE A4).

Design notes:

* Epochs are monotonic integers; windows are opaque ids derived from the
  epoch plus the clock's boot nonce so that ids cannot be forged by a caller
  that merely knows the epoch number.
* ``window_for`` raises :class:`TemporalDriftError` when asked about an epoch
  the clock has not synchronized -- drift and desynchronization fail closed.
* The clock never grants authority; it only answers "which window is now".
"""

from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass
from typing import Final


#: Nominal window length in epochs-worth of ticks (frozen spec constant).
DEFAULT_WINDOW_TICKS: Final[int] = 8


class TemporalDriftError(RuntimeError):
    """Raised when the clock is unsynchronized or queried out of range."""


@dataclass(frozen=True, slots=True)
class EpochWindow:
    """A closed interval of ticks ``[start_tick, end_tick)`` with an id."""

    epoch: int
    start_tick: int
    end_tick: int
    window_id: str

    def contains_tick(self, tick: int) -> bool:
        return self.start_tick <= tick < self.end_tick

    def __str__(self) -> str:  # pragma: no cover - debug helper
        return f"EpochWindow(epoch={self.epoch}, id={self.window_id})"


class SynchronizedTemporalState:
    """Deterministic STS clock used by the gate to bound authority windows.

    Tests drive time explicitly via :meth:`advance`; there is no wall-clock
    dependency inside the predicate path, which keeps gate evaluation pure.
    """

    def __init__(
        self,
        *,
        boot_nonce: str = "sts-boot",
        epoch: int = 0,
        tick: int = 0,
        window_ticks: int = DEFAULT_WINDOW_TICKS,
        synchronized: bool = True,
    ) -> None:
        if window_ticks <= 0:
            raise ValueError("window_ticks must be positive")
        self._boot_nonce = boot_nonce
        self._epoch = epoch
        self._tick = tick
        self._window_ticks = window_ticks
        self._synchronized = synchronized
        self._counter = itertools.count(1)

    # -- introspection -----------------------------------------------------

    @property
    def epoch(self) -> int:
        return self._epoch

    @property
    def tick(self) -> int:
        return self._tick

    @property
    def window_ticks(self) -> int:
        return self._window_ticks

    @property
    def synchronized(self) -> bool:
        return self._synchronized

    def window_id_for(self, epoch: int) -> str:
        """Deterministic, unforgeable-ish id for ``epoch``'s window."""
        material = f"{self._boot_nonce}|{epoch}"
        return "win-" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]

    def current_window(self) -> EpochWindow:
        self._require_sync()
        start = self._tick - (self._tick % self._window_ticks)
        return EpochWindow(
            epoch=self._epoch,
            start_tick=start,
            end_tick=start + self._window_ticks,
            window_id=self.window_id_for(self._epoch),
        )

    # -- progression -------------------------------------------------------

    def advance(self, ticks: int = 1) -> EpochWindow:
        """Move the clock forward, rolling into a new epoch at each boundary.

        Crossing a window boundary increments the epoch, which invalidates
        every authorization bound to the previous window id.
        """
        if ticks < 0:
            raise ValueError("time cannot move backwards")
        self._require_sync()
        previous_boundary = self._tick // self._window_ticks
        self._tick += ticks
        if self._tick // self._window_ticks > previous_boundary:
            self._epoch += 1
        return self.current_window()

    def resynchronize(self, *, synchronized: bool = True) -> None:
        """Flag the clock as (un)synchronized.  Unsynchronized => fail closed."""
        self._synchronized = synchronized

    def consume_slot(self) -> int:
        """Monotonic slot counter used by the gate for single-use bookkeeping."""
        return next(self._counter)

    # -- validation --------------------------------------------------------

    def validate_attestation(self, attestation_epoch: int, window_id: str) -> bool:
        """True iff ``window_id`` is the *current* window and epochs match."""
        self._require_sync()
        current = self.current_window()
        return attestation_epoch == current.epoch and window_id == current.window_id

    def _require_sync(self) -> None:
        if not self._synchronized:
            raise TemporalDriftError(
                "STS clock unsynchronized: temporal judgements fail closed"
            )
        if self._tick < 0 or self._epoch < 0:
            raise TemporalDriftError("STS clock state is out of range")


__all__ = [
    "DEFAULT_WINDOW_TICKS",
    "TemporalDriftError",
    "EpochWindow",
    "SynchronizedTemporalState",
]
