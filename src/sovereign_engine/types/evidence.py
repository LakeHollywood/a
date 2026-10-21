"""Evidence classes and the strict isolation between them.

Invariant (SAIL-SPEC 2026, frozen): *content never carries authority*.  The
bytes of an attestation may be byte-identical across classes; what differs is
the class tag and the temporal binding.  Therefore ``HistoricalEvidence`` and
``LiveEvidence`` are separate frozen types with **no shared base other than
``object``** -- structural code that consumes one cannot accidentally accept
the other, and the predicate's conjuncts are typed to demand the right class.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class EvidenceClass(str, Enum):
    """Explicit tag used in audit records; never inferred from content."""

    HISTORICAL = "HISTORICAL"
    LIVE = "LIVE"
    REHYDRATED = "REHYDRATED"


#: Maximum permitted skew between an attestation timestamp and the STS clock
#: for the attestation to still be classifiable as live (seconds).  Fixed by
#: the frozen spec; changing it is a spec amendment, not a tuning knob.
LIVE_WINDOW_MAX_SECONDS: Final[float] = 120.0


def _fingerprint(payload: Mapping[str, Any]) -> str:
    """Deterministic SHA-256 over a canonically encoded payload.

    Canonical encoding is ``sorted(key=json-ish)`` repr -- sufficient for
    equality/dedup inside the engine and stable across processes.
    """
    canonical = "|".join(
        f"{k}={payload[k]!r}" for k in sorted(payload, key=str)
    )
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class HistoricalEvidence:
    """A record of something observed or decided in a previous epoch.

    ``as_of_epoch`` is the STS epoch in which the observation was taken.  It
    is retained for provenance/telemetry only.  Binding this type into the
    ``E_live`` slot of a transition request is a *type error* enforced at
    construction of :class:`~sovereign_engine.types.transitions.StateTransitionRequest`.
    """

    subject: str
    action: str
    resource: str
    as_of_epoch: int
    payload: Mapping[str, Any] = field(default_factory=dict)
    digest: str = ""
    evidence_class: EvidenceClass = EvidenceClass.HISTORICAL

    def __post_init__(self) -> None:
        if self.evidence_class is not EvidenceClass.HISTORICAL:
            # Laundering guard: the tag is fixed for this class.
            raise TypeError(
                "HistoricalEvidence cannot carry a non-historical class tag"
            )
        object.__setattr__(self, "digest", _fingerprint(dict(self.payload)))

    @property
    def identity(self) -> tuple[str, str, str, int]:
        """Provenance key: who/what/where/when the record was taken."""
        return (self.subject, self.action, self.resource, self.as_of_epoch)

    def telemetry_projection(self) -> dict[str, Any]:
        """Non-authorizing projection suitable for logs/dashboards.

        Deliberately omits anything the gate could mistake for a live grant:
        the projection is ``dict``, and the predicate never reads dicts.
        """
        return {
            "evidence_class": self.evidence_class.value,
            "subject": self.subject,
            "action": self.action,
            "resource": self.resource,
            "as_of_epoch": self.as_of_epoch,
            "digest": self.digest,
            "authority": "NONE",
        }


@dataclass(frozen=True, slots=True)
class LiveEvidence:
    """A freshly attested observation bound to the current STS epoch window.

    A live attestation is single-use: once consumed by a transition it is
    marked spent by the gate (see ``predicate.consume_attestation``), so an
    authentic replay inside the window still fails (ABIDE A4).
    """

    subject: str
    action: str
    resource: str
    attested_epoch: int
    window_id: str
    nonce: str
    payload: Mapping[str, Any] = field(default_factory=dict)
    digest: str = ""
    spent: bool = False
    evidence_class: EvidenceClass = EvidenceClass.LIVE

    def __post_init__(self) -> None:
        if self.evidence_class is not EvidenceClass.LIVE:
            raise TypeError("LiveEvidence cannot carry a non-live class tag")
        if not self.nonce:
            raise ValueError("live attestation requires a nonce")
        if not self.window_id:
            raise ValueError("live attestation requires an STS window id")
        object.__setattr__(self, "digest", _fingerprint(dict(self.payload)))

    @property
    def replay_key(self) -> tuple[str, str, str]:
        """Key the gate uses to reject second use of the same attestation."""
        return (self.window_id, self.nonce, self.digest)


@dataclass(frozen=True, slots=True)
class RehydratedContext:
    """State reconstructed from ``E_n`` after a void interval ``I_{n+1}``.

    Carries continuity of *state* only.  ``authority_inherited`` is hard-coded
    False and is not a settable field: there is no constructor path, property,
    or copy mechanism that yields a ``LiveAuthorization`` from this type.
    Recovery must obtain a genuinely new authorization for ``I_{n+1}``
    (ABIDE REC-01 / Recovery Contract Theorem 3).
    """

    origin_epoch: int
    resume_epoch: int
    state_vector: Mapping[str, Any] = field(default_factory=dict)
    source_digest: str = ""
    void_interval_seconds: float = 0.0
    evidence_class: EvidenceClass = EvidenceClass.REHYDRATED

    @property
    def authority_inherited(self) -> bool:
        """Structurally always ``False`` -- rehydration restores state only.

        Exposed as a read-only property (not a dataclass field) so no
        constructor argument, ``object.__setattr__`` on a frozen slot, or
        ``dataclasses.replace`` can flip it: the value is computed, never
        stored.
        """
        return False

    def __post_init__(self) -> None:
        if self.evidence_class is not EvidenceClass.REHYDRATED:
            raise TypeError(
                "RehydratedContext cannot carry a non-rehydrated class tag"
            )
        if self.resume_epoch <= self.origin_epoch:
            raise ValueError(
                "rehydration requires resume_epoch strictly after origin_epoch"
            )
        if not self.source_digest:
            object.__setattr__(
                self,
                "source_digest",
                _fingerprint(
                    {
                        "origin": self.origin_epoch,
                        "resume": self.resume_epoch,
                        "state": dict(self.state_vector),
                    }
                ),
            )

    def summary_fields(self) -> Sequence[str]:
        return ("origin_epoch", "resume_epoch", "source_digest")


# ---------------------------------------------------------------------------
# Sanctioned conversions.  These are the ONLY supported ways to move data
# between evidence classes, and each returns a *non-authorizing* product.
# ---------------------------------------------------------------------------


def historical_to_recommendation(evidence: HistoricalEvidence) -> dict[str, Any]:
    """Project historical evidence into a recommendation vector (A1.2).

    Recommendations influence *planning*, never *authorization*: the return
    type is a plain mapping that the predicate refuses to bind.  There is no
    ``recommendation_to_authorization`` counterpart, by design.
    """
    if not isinstance(evidence, HistoricalEvidence):
        raise TypeError("only HistoricalEvidence may be projected as a recommendation")
    projection = evidence.telemetry_projection()
    projection["role"] = "RECOMMENDATION"
    projection["binding_effect"] = "NONE"
    return projection


def rehydrate(
    *,
    origin_epoch: int,
    resume_epoch: int,
    state_vector: Mapping[str, Any],
    void_interval_seconds: float = 0.0,
) -> RehydratedContext:
    """Build the post-void context from the last durable epoch (REC-01)."""
    return RehydratedContext(
        origin_epoch=origin_epoch,
        resume_epoch=resume_epoch,
        state_vector=dict(state_vector),
        void_interval_seconds=float(void_interval_seconds),
    )
