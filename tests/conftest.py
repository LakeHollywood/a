"""Shared fixtures for the containerized STS/SEAL validation harness.

Works identically inside docker-compose (python:3.11-slim test-runner) and
on bare metal (Orin rig / local dev), because the suite depends only on the
stdlib + the repo itself. External services (Postgres/Kafka) are treated as
hostile variables, never as requirements.
"""

from __future__ import annotations

import os
import sys

import pytest

# Make `bench.*` importable when pytest runs from /app inside the container
# or from any cwd on the host.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from bench.sts_time import AssuranceLedger, STSMonotonicClock  # noqa: E402

# Declare tests.sovereign.fixtures as a global pytest plugin for all subtrees.
# Pytest loads root-level pytest_plugins before initiating collection, so the
# shared Sovereign Engine fixtures (sts, gate, quarantine, boundary,
# armed_gate) become universally discoverable across tests/unit/,
# tests/abide/, and tests/harness/ without duplicating conftest.py shims in
# every subtree.  Single source of truth: tests/sovereign/fixtures.py remains
# the authoritative definition file.  Note: the sovereign suite's ``ledger``
# fixture (sovereign_engine.gate.predicate.GateLedger) intentionally shadows
# the bench ``ledger`` fixture below for tests that request it; the bench
# AssuranceLedger remains available via direct import where needed.
pytest_plugins = ["tests.sovereign.fixtures"]


@pytest.fixture()
def clock():
    """Root-of-trust monotonic clock (CLOCK_MONOTONIC_RAW backed)."""
    return STSMonotonicClock()


@pytest.fixture()
def ledger(tmp_path):
    led = AssuranceLedger(str(tmp_path / "ledger.db"))
    yield led
    led.close()


def external_services_configured() -> bool:
    """True only inside the compose harness, where DB_URL/KAFKA_* are set."""
    return bool(os.environ.get("DB_URL")) and bool(
        os.environ.get("KAFKA_BOOTSTRAP_SERVERS"))
