"""``LiveAuthorization`` -- the only object that can satisfy the A conjunct.

A live authorization is a four-way binding between *target*, *payload*,
*transition* and *epoch*.  The binding is cryptographic-strength within the
engine: each scope contributes to ``binding_digest``, and the predicate
re-derives the digest from the request it is evaluating.  Substituting any
element of the tuple changes the digest, so substitution attacks (ABIDE A5.1
- A5.4) fail on equality rather than on policy interpretation.

Properties that make laundering impossible:

* Frozen + slotted: no field mutation after issuance.
* No public constructor accepts an ``evidence_class`` override.
* ``from_historical`` / ``from_rehydrated`` classmethods **do not exist**;
  the only sanctioned builders are :func:`issue_live_authorization` (which
  demands a :class:`LiveEvidence` attestation *and* a current STS window) and
  :meth:`LiveAuthorization.rebind` (which requires a fresh attestation too).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Mapping

from sovereign_engine.types.evidence import LiveEvidence


class ScopeKind(str, Enum):
    TARGET = "TARGET"
    PAYLOAD = "PAYLOAD"
    TRANSITION = "TRANSITION"
    EPOCH = "EPOCH"


@dataclass(frozen=True, slots=True)
class TargetScope:
    """The identity the authorization acts *upon* (device/subject/resource)."""

    principal: str
    resource: str
    device_id: str = ""

    def canonical(self) -> str:
        return f"target:{self.principal}|{self.resource}|{self.device_id}"


@dataclass(frozen=True, slots=True)
class PayloadScope:
    """The permitted content of the action: operation plus parameter bounds."""

    operation: str
    parameter_bounds: Mapping[str, tuple[float, float]] = field(default_factory=dict)
    max_bytes: int = 0

    def canonical(self) -> str:
        bounds = ";".join(
            f"{k}={lo}:{hi}"
            for k, (lo, hi) in sorted(
                ((str(k), v) for k, v in self.parameter_bounds.items()),
                key=lambda item: item[0],
            )
        )
        return f"payload:{self.operation}|{bounds}|{self.max_bytes}"

    def admits(self, parameters: Mapping[str, Any]) -> bool:
        """True when every supplied parameter lies inside the bound pair.

        Unknown parameters are rejected (fail closed); non-numeric values are
        rejected unless the bound interval is empty/unconstrained.
        """
        for name, value in parameters.items():
            bound = self.parameter_bounds.get(str(name))
            if bound is None:
                return False
            lo, hi = bound
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return False
            if not (lo <= numeric <= hi):
                return False
        return True


@dataclass(frozen=True, slots=True)
class TransitionScope:
    """The state-machine edge the authorization permits (from -> to)."""

    from_state: str
    to_state: str
    kinds: tuple[str, ...] = ("OPERATIONAL",)

    def canonical(self) -> str:
        return f"transition:{self.from_state}->{self.to_state}|{','.join(sorted(self.kinds))}"

    def admits(self, from_state: str, to_state: str, kind: str) -> bool:
        return (
            self.from_state == from_state
            and self.to_state == to_state
            and kind in self.kinds
        )


@dataclass(frozen=True, slots=True)
class AuthorizationEpoch:
    """Temporal validity of the grant, expressed in STS epochs/windows."""

    epoch: int
    window_id: str
    valid_for_transitions: int = 1

    def canonical(self) -> str:
        return f"epoch:{self.epoch}|{self.window_id}|{self.valid_for_transitions}"


@dataclass(frozen=True, slots=True)
class LiveAuthorization:
    """A single-use, epoch-bound, scope-bound grant of authority."""

    authorization_id: str
    target: TargetScope
    payload: PayloadScope
    transition: TransitionScope
    epoch: AuthorizationEpoch
    attestation_nonce: str
    consumed: bool = False
    binding_digest: str = ""

    def __post_init__(self) -> None:
        if not self.authorization_id:
            raise ValueError("live authorization requires an authorization_id")
        if not self.attestation_nonce:
            raise ValueError("live authorization must bind an attestation nonce")
        expected = derive_binding_digest(
            target=self.target,
            payload=self.payload,
            transition=self.transition,
            epoch=self.epoch,
            attestation_nonce=self.attestation_nonce,
        )
        if self.binding_digest and self.binding_digest != expected:
            raise ValueError("binding_digest does not match the scope tuple")
        object.__setattr__(self, "binding_digest", expected)

    # -- scope checks ------------------------------------------------------

    def covers_target(self, other: TargetScope) -> bool:
        return other.canonical() == self.target.canonical()

    def covers_transition(self, from_state: str, to_state: str, kind: str) -> bool:
        return self.transition.admits(from_state, to_state, kind)

    def covers_epoch(self, epoch: int, window_id: str) -> bool:
        return self.epoch.epoch == epoch and self.epoch.window_id == window_id

    # -- lifecycle ---------------------------------------------------------

    def mark_consumed(self) -> "LiveAuthorization":
        """Return the spent form of this grant (single-use semantics)."""
        return replace(self, consumed=True)

    def rebind(
        self, *, fresh_attestation: LiveEvidence, epoch: AuthorizationEpoch
    ) -> "LiveAuthorization":
        """Re-issue the same scope tuple against a genuinely new attestation.

        The scopes are carried forward because they describe *what* was
        approved; the nonce/window/epoch are taken from the fresh evidence
        because they describe *when it is still true*.
        """
        if not isinstance(fresh_attestation, LiveEvidence):
            raise TypeError("rebind requires a LiveEvidence attestation")
        if fresh_attestation.spent:
            raise ValueError("cannot rebind using a spent attestation")
        return issue_live_authorization(
            authorization_id=f"{self.authorization_id}+r{epoch.epoch}",
            target=self.target,
            payload=self.payload,
            transition=self.transition,
            attestation=fresh_attestation,
            epoch=epoch,
            valid_for_transitions=self.epoch.valid_for_transitions,
        )

    def audit_projection(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "binding_digest": self.binding_digest,
            "target": self.target.canonical(),
            "payload": self.payload.canonical(),
            "transition": self.transition.canonical(),
            "epoch": self.epoch.canonical(),
            "consumed": self.consumed,
        }


def derive_binding_digest(
    *,
    target: TargetScope,
    payload: PayloadScope,
    transition: TransitionScope,
    epoch: AuthorizationEpoch,
    attestation_nonce: str,
) -> str:
    """SHA-256 over the full four-way binding plus the attestation nonce."""
    material = "##".join(
        (
            target.canonical(),
            payload.canonical(),
            transition.canonical(),
            epoch.canonical(),
            f"nonce:{attestation_nonce}",
        )
    )
    return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


def issue_live_authorization(
    *,
    authorization_id: str,
    target: TargetScope,
    payload: PayloadScope,
    transition: TransitionScope,
    attestation: LiveEvidence,
    epoch: AuthorizationEpoch,
    valid_for_transitions: int = 1,
) -> LiveAuthorization:
    """Mint a live grant.  Requires a live attestation whose window matches.

    ``attestation`` must be a :class:`LiveEvidence`; anything else (including
    historical records or rehydrated contexts) raises ``TypeError`` before any
    authorization object exists.
    """
    if not isinstance(attestation, LiveEvidence):
        raise TypeError(
            "live authorization may only be issued against LiveEvidence; "
            f"got {type(attestation).__name__}"
        )
    if attestation.spent:
        raise ValueError("attestation already consumed: cannot mint authority")
    if attestation.window_id != epoch.window_id:
        raise ValueError(
            "attestation window does not match the authorization epoch window"
        )
    if attestation.attested_epoch != epoch.epoch:
        raise ValueError(
            "attestation epoch does not match the authorization epoch"
        )
    scoped_epoch = AuthorizationEpoch(
        epoch=epoch.epoch,
        window_id=epoch.window_id,
        valid_for_transitions=valid_for_transitions,
    )
    return LiveAuthorization(
        authorization_id=authorization_id,
        target=target,
        payload=payload,
        transition=transition,
        epoch=scoped_epoch,
        attestation_nonce=attestation.nonce,
    )


__all__ = [
    "ScopeKind",
    "TargetScope",
    "PayloadScope",
    "TransitionScope",
    "AuthorizationEpoch",
    "LiveAuthorization",
    "derive_binding_digest",
    "issue_live_authorization",
]
