"""Pytest configuration for the Sovereign Engine conformance suite.

Makes ``src/`` importable without an install step and re-exports the shared
fixtures so every sub-package (``tests/unit``, ``tests/abide``,
``tests/harness``) can use them by name.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# Re-export fixtures by name so pytest collects them for this package tree.
from tests.sovereign.fixtures import (  # noqa: E402,F401
    DEVICE,
    PRINCIPAL,
    RESOURCE,
    _armed_gate,
    _boundary,
    _gate,
    _ledger,
    _quarantine,
    _sts,
    authorize_step,
    make_authorization,
    make_historical,
    make_live,
    make_rehydrated,
    make_request,
    make_scopes,
    same_content_as,
)
