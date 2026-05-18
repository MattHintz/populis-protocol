from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT / "scripts"))

import dump_a5_roster_candidate_fixture


def test_fixture_matches_committed_file() -> None:
    expected = dump_a5_roster_candidate_fixture.build_fixture()
    fixture_path = dump_a5_roster_candidate_fixture.fixture_destination()
    if not fixture_path.exists():
        pytest.fail(
            f"Portal fixture file is missing at {fixture_path}.\n"
            "Run `python scripts/dump_a5_roster_candidate_fixture.py` to regenerate it."
        )
    on_disk = json.loads(fixture_path.read_text())
    assert on_disk == expected, (
        "Portal A.5 roster candidate fixture is out of sync with the Python driver.\n"
        "Run `python scripts/dump_a5_roster_candidate_fixture.py` and commit the diff."
    )


def test_fixture_remains_unsigned_and_unbroadcast() -> None:
    fixture = dump_a5_roster_candidate_fixture.build_fixture()
    encoded = json.dumps(fixture).lower()
    assert "aggregatedsignature" not in encoded
    assert "signature" not in encoded
    assert "broadcast" not in encoded
    assert "jwt" not in encoded
    assert "secret" not in encoded


def test_fixture_includes_real_agg_sig_me_binding_case() -> None:
    fixture = dump_a5_roster_candidate_fixture.build_fixture()
    cases = fixture["cases"]
    agg_cases = [
        case
        for case in cases
        if case["expected"]["bounded_mips_execution_report"]["agg_sig_me_conditions"]
    ]
    assert len(agg_cases) == 1
    case = agg_cases[0]
    binding_hash = case["request"]["verifiedSpendBuilderIntake"]["roster_transition"][
        "roster_update_binding_hash"
    ]
    agg_sig_me = case["expected"]["bounded_mips_execution_report"]["agg_sig_me_conditions"]
    assert agg_sig_me == [
        {
            "public_key": "0x" + "42" * 48,
            "message": binding_hash,
        }
    ]
