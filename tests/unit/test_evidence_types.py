"""Unit tests for the evidence type boundary (SAIL-SPEC §2, ABIDE A1/A3).

Each test is Arrange / Act / Assert with no shared mutable state: the types
themselves must refuse laundering, independent of how the gate is configured.
"""

from __future__ import annotations

import dataclasses

import pytest

from sovereign_engine.types.evidence import (
    EvidenceClass,
    HistoricalEvidence,
    LiveEvidence,
    RehydratedContext,
    historical_to_recommendation,
    rehydrate,
)
from tests.sovereign.fixtures import make_historical, make_live, make_rehydrated


class TestHistoricalEvidence:
    def test_carries_historical_tag_and_digest(self, sts):
        # Arrange
        record = make_historical(as_of_epoch=4, payload={"telemetry": "nominal"})

        # Act
        projection = record.telemetry_projection()

        # Assert
        assert record.evidence_class is EvidenceClass.HISTORICAL
        assert record.digest.startswith("sha256:")
        assert projection["authority"] == "NONE"
        assert projection["as_of_epoch"] == 4

    def test_identical_payload_yields_identical_digest(self):
        # Arrange / Act
        first = make_historical(payload={"a": 1, "b": 2})
        second = make_historical(payload={"b": 2, "a": 1})

        # Assert: content fingerprinting is order-independent
        assert first.digest == second.digest

    def test_class_tag_cannot_be_overridden(self):
        # Arrange / Act / Assert
        with pytest.raises(TypeError):
            HistoricalEvidence(
                subject="s",
                action="OPERATIONAL",
                resource="r",
                as_of_epoch=1,
                evidence_class=EvidenceClass.LIVE,
            )


class TestLiveEvidence:
    def test_requires_nonce_and_window(self, sts):
        # Arrange / Act / Assert
        with pytest.raises(ValueError):
            LiveEvidence(
                subject="s", action="OPERATIONAL", resource="r",
                attested_epoch=sts.epoch, window_id="w", nonce="",
            )
        with pytest.raises(ValueError):
            LiveEvidence(
                subject="s", action="OPERATIONAL", resource="r",
                attested_epoch=sts.epoch, window_id="", nonce="n",
            )

    def test_missing_required_arguments_is_a_type_error(self):
        # Arrange / Act / Assert: a live attestation cannot be built from
        # epoch+payload alone; window and nonce are mandatory identity parts.
        with pytest.raises(TypeError):
            LiveEvidence(  # type: ignore[call-arg]
                subject="s", action="OPERATIONAL", resource="r", attested_epoch=1
            )

    def test_replay_key_binds_window_nonce_and_content(self, sts):
        # Arrange
        live = make_live(sts, nonce="n-77")

        # Act
        key = live.replay_key

        # Assert
        assert key == (live.window_id, "n-77", live.digest)

    def test_same_content_different_window_is_a_different_key(self, sts):
        # Arrange
        inside = make_live(sts, nonce="n-1")
        sts.advance(8)  # rolls into a new epoch/window
        later = make_live(sts, nonce="n-1", payload=dict(inside.payload))

        # Act / Assert: identical bytes, different temporal binding
        assert inside.digest == later.digest
        assert inside.replay_key != later.replay_key


class TestRehydratedContext:
    def test_authority_inherited_is_structurally_false(self):
        # Arrange
        ctx = make_rehydrated(origin=3, resume=9)

        # Act / Assert
        assert ctx.authority_inherited is False

    def test_inherited_flag_cannot_be_forced_through_constructor(self):
        # Arrange / Act / Assert: no keyword exists, so injection fails closed.
        with pytest.raises(TypeError):
            RehydratedContext(
                origin_epoch=1, resume_epoch=2, authority_inherited=True
            )

    def test_inherited_flag_cannot_be_mutated_after_construction(self):
        # Arrange
        ctx = make_rehydrated()

        # Act / Assert: it is a computed property on a frozen slotted class.
        with pytest.raises((AttributeError, dataclasses.FrozenInstanceError)):
            object.__setattr__(ctx, "authority_inherited", True)
        assert ctx.authority_inherited is False

    def test_resume_epoch_must_follow_origin(self):
        # Arrange / Act / Assert
        with pytest.raises(ValueError):
            rehydrate(origin_epoch=5, resume_epoch=5, state_vector={})

    def test_class_tag_cannot_be_swapped(self):
        # Arrange / Act / Assert
        with pytest.raises(TypeError):
            RehydratedContext(
                origin_epoch=1,
                resume_epoch=2,
                evidence_class=EvidenceClass.LIVE,
            )


class TestSanctionedConversions:
    def test_historical_projects_to_non_binding_recommendation(self):
        # Arrange
        record = make_historical(payload={"advice": "increase torque"})

        # Act
        recommendation = historical_to_recommendation(record)

        # Assert
        assert recommendation["role"] == "RECOMMENDATION"
        assert recommendation["binding_effect"] == "NONE"

    def test_only_historical_evidence_may_be_projected(self, sts):
        # Arrange
        live = make_live(sts)

        # Act / Assert
        with pytest.raises(TypeError):
            historical_to_recommendation(live)  # type: ignore[arg-type]

    def test_evidence_classes_are_pairwise_distinct_types(self):
        # Arrange / Act / Assert: no subclassing shortcuts exist between the
        # three classes -- isinstance must never cross the boundary.
        assert not issubclass(LiveEvidence, HistoricalEvidence)
        assert not issubclass(HistoricalEvidence, LiveEvidence)
        assert not issubclass(RehydratedContext, LiveEvidence)
        assert not issubclass(LiveEvidence, RehydratedContext)
