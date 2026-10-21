"""Shared fixtures and builders for the Sovereign Engine conformance suite.

ABIDE vectors are declared as *hostile bundles*: each test constructs a
transition request that is well-formed in every superficial respect (identical
payload bytes, valid digests, plausible epochs) and violates exactly one
authority conjunct.  The builders here make that pattern mechanical.

Nothing in this module grants authority; ``make_authorization`` merely wraps
the sanctioned minting path (:func:`issue_live_authorization`).
"""

from __future__ import annotations

from typing import Any, Mapping

import pytest

from sovereign_engine.engine.quarantine import QuarantineManager
from sovereign_engine.engine.transition_gate import EngineTransitionGate
from sovereign_engine.execution.boundary import ExecutionBoundary, PhysicalLockState
from sovereign_engine.gate.predicate import GateLedger
from sovereign_engine.gate.sts_clock import SynchronizedTemporalState
from sovereign_engine.types.authorization import (
    AuthorizationEpoch,
    LiveAuthorization,
    PayloadScope,
    TargetScope,
    TransitionScope,
    issue_live_authorization,
)
from sovereign_engine.types.evidence import (
    HistoricalEvidence,
    LiveEvidence,
    RehydratedContext,
    rehydrate,
)
from sovereign_engine.types.transitions import (
    RecoveryIntent,
    StateTransitionRequest,
    TransitionKind,
)

PRINCIPAL = "unit-alpha"
RESOURCE = "actuator-01"
DEVICE = "dev-7732"


# ---------------------------------------------------------------------------
# clock / container fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(name="sts")
def _sts() -> SynchronizedTemporalState:
    """Deterministic STS clock starting at epoch 0, tick 0."""
    return SynchronizedTemporalState(boot_nonce="conformance-boot", epoch=0, tick=0)


@pytest.fixture(name="ledger")
def _ledger() -> GateLedger:
    return GateLedger()


@pytest.fixture(name="quarantine")
def _quarantine() -> QuarantineManager:
    return QuarantineManager()


@pytest.fixture(name="gate")
def _gate(
    sts: SynchronizedTemporalState,
    ledger: GateLedger,
    quarantine: QuarantineManager,
) -> EngineTransitionGate:
    return EngineTransitionGate(sts=sts, ledger=ledger, quarantine=quarantine)


@pytest.fixture(name="boundary")
def _boundary() -> ExecutionBoundary:
    """Boundary wired to a fake hardware sink that records actuations."""
    seen: list[str] = []
    boundary = ExecutionBoundary(lock_state=PhysicalLockState.OPEN)
    boundary._hardware = lambda name: seen.append(name)  # type: ignore[assignment]
    boundary.actuations = seen  # type: ignore[attr-defined]
    return boundary


# ---------------------------------------------------------------------------
# evidence builders
# ---------------------------------------------------------------------------


def make_live(
    sts: SynchronizedTemporalState,
    *,
    subject: str = PRINCIPAL,
    action: str = TransitionKind.OPERATIONAL.value,
    resource: str = RESOURCE,
    nonce: str = "n-1",
    payload: Mapping[str, Any] | None = None,
    window_id: str | None = None,
    attested_epoch: int | None = None,
) -> LiveEvidence:
    """Attestation bound to the current window unless explicitly overridden."""
    window = sts.current_window()
    return LiveEvidence(
        subject=subject,
        action=action,
        resource=resource,
        attested_epoch=window.epoch if attested_epoch is None else attested_epoch,
        window_id=window.window_id if window_id is None else window_id,
        nonce=nonce,
        payload=dict(payload or {"telemetry": "nominal"}),
    )


def make_historical(
    *,
    subject: str = PRINCIPAL,
    action: str = TransitionKind.OPERATIONAL.value,
    resource: str = RESOURCE,
    as_of_epoch: int = 0,
    payload: Mapping[str, Any] | None = None,
) -> HistoricalEvidence:
    return HistoricalEvidence(
        subject=subject,
        action=action,
        resource=resource,
        as_of_epoch=as_of_epoch,
        payload=dict(payload or {"telemetry": "nominal"}),
    )


def make_rehydrated(
    *, origin: int = 0, resume: int = 1, state: Mapping[str, Any] | None = None
) -> RehydratedContext:
    return rehydrate(
        origin_epoch=origin,
        resume_epoch=resume,
        state_vector=dict(state or {"position": 12.5}),
    )


def same_content_as(live: LiveEvidence, *, as_of_epoch: int) -> HistoricalEvidence:
    """Historical record whose payload bytes match a live attestation (A1.1)."""
    return HistoricalEvidence(
        subject=live.subject,
        action=live.action,
        resource=live.resource,
        as_of_epoch=as_of_epoch,
        payload=dict(live.payload),
    )


# ---------------------------------------------------------------------------
# authorization builders
# ---------------------------------------------------------------------------


def make_scopes(
    *,
    principal: str = PRINCIPAL,
    resource: str = RESOURCE,
    device_id: str = DEVICE,
    from_state: str = "ARMED",
    to_state: str = "EXECUTING",
    kinds: tuple[str, ...] = (TransitionKind.OPERATIONAL.value,),
    bounds: Mapping[str, tuple[float, float]] | None = None,
    operation: str = "actuate",
) -> tuple[TargetScope, PayloadScope, TransitionScope]:
    return (
        TargetScope(principal=principal, resource=resource, device_id=device_id),
        PayloadScope(
            operation=operation,
            parameter_bounds=dict(bounds or {"torque_nm": (0.0, 40.0)}),
            max_bytes=256,
        ),
        TransitionScope(from_state=from_state, to_state=to_state, kinds=kinds),
    )


def make_authorization(
    sts: SynchronizedTemporalState,
    *,
    authorization_id: str = "auth-1",
    attestation: LiveEvidence | None = None,
    scopes: tuple[TargetScope, PayloadScope, TransitionScope] | None = None,
    valid_for_transitions: int = 1,
) -> LiveAuthorization:
    """Mint a grant through the only sanctioned path (requires live evidence)."""
    target, payload, transition = scopes or make_scopes()
    evidence = attestation or make_live(sts)
    epoch = AuthorizationEpoch(
        epoch=evidence.attested_epoch, window_id=evidence.window_id
    )
    return issue_live_authorization(
        authorization_id=authorization_id,
        target=target,
        payload=payload,
        transition=transition,
        attestation=evidence,
        epoch=epoch,
        valid_for_transitions=valid_for_transitions,
    )


def make_request(
    sts: SynchronizedTemporalState,
    *,
    from_state: str = "ARMED",
    to_state: str = "EXECUTING",
    kind: TransitionKind = TransitionKind.OPERATIONAL,
    authorization: LiveAuthorization | None = None,
    attestation: LiveEvidence | None = None,
    historical: tuple[HistoricalEvidence, ...] = (),
    recovery_intent: RecoveryIntent | None = None,
    parameters: Mapping[str, Any] | None = None,
    request_id: str = "req-1",
    nonce: str = "n-1",
) -> StateTransitionRequest:
    """Well-formed by default; every slot is overridable per attack vector."""
    live = attestation or make_live(sts, action=kind.value, nonce=nonce)
    base: dict[str, Any] = {
        "principal": live.subject,
        "resource": live.resource,
        "device_id": DEVICE,
        "payload": {"torque_nm": 20.0},
    }
    base.update(dict(parameters or {}))
    return StateTransitionRequest(
        from_state=from_state,
        to_state=to_state,
        kind=kind,
        live_evidence=live,
        historical_evidence=historical,
        authorization=authorization,
        recovery_intent=recovery_intent,
        parameters=base,
        request_id=request_id,
    )


def authorize_step(
    gate: EngineTransitionGate,
    sts: SynchronizedTemporalState,
    *,
    from_state: str,
    to_state: str,
    authorization_id: str,
    nonce: str,
    kinds: tuple[str, ...] = (TransitionKind.OPERATIONAL.value,),
    bounds: Mapping[str, tuple[float, float]] | None = None,
    parameters: Mapping[str, Any] | None = None,
    principal: str = PRINCIPAL,
    resource: str = RESOURCE,
) -> Any:
    """Run one legitimately authorized transition (positive-control plumbing)."""
    attestation = make_live(
        sts, subject=principal, resource=resource,
        action=TransitionKind.OPERATIONAL.value, nonce=nonce,
    )
    scopes = make_scopes(
        principal=principal,
        resource=resource,
        from_state=from_state,
        to_state=to_state,
        kinds=kinds,
        bounds=bounds,
    )
    authorization = make_authorization(
        sts,
        authorization_id=authorization_id,
        attestation=attestation,
        scopes=scopes,
    )
    request = make_request(
        sts,
        from_state=from_state,
        to_state=to_state,
        authorization=authorization,
        attestation=attestation,
        nonce=nonce,
        parameters={"principal": principal, "resource": resource, **(parameters or {})},
        request_id=f"{authorization_id}-req",
    )
    return gate.attempt(request)


@pytest.fixture(name="armed_gate")
def _armed_gate(
    gate: EngineTransitionGate, sts: SynchronizedTemporalState
) -> EngineTransitionGate:
    """Gate preconditioned to ``ARMED`` via legitimate IDLE->ARMED."""
    outcome = authorize_step(
        gate, sts, from_state="IDLE", to_state="ARMED",
        authorization_id="auth-arm", nonce="n-arm",
    )
    assert outcome.executed, outcome.eligibility.reason
    return gate


__all__: list[str] = [
    "PRINCIPAL",
    "RESOURCE",
    "DEVICE",
    "make_live",
    "make_historical",
    "make_rehydrated",
    "same_content_as",
    "make_scopes",
    "make_authorization",
    "make_request",
    "authorize_step",
]
