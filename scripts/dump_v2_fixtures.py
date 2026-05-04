"""Generate fixture file for the portal's TS port of admin_authority_v2_driver.

The TS service in ``populis_portal`` reproduces a subset of the Python
driver helpers (``compute_state_hash``, ``compute_admins_hash``,
``compute_pending_ops_hash``, ``admin_authority_v2_inner_mod_hash``,
``make_inner_puzzle_hash``) so that the portal can construct + verify
v2 admin authority spends entirely client-side without depending on
the Populis API.

This script writes a JSON fixture mapping each helper to a list of
``(input, expected_output)`` cases.  The portal's Karma test reads
the fixture and asserts the TS implementation produces matching hex.

Usage::

    cd populis_protocol
    .venv/bin/python scripts/dump_v2_fixtures.py

The fixture is also exported by the regression test in
``tests/test_v2_fixtures.py`` so CI re-checks it on every PR.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from chia_rs.sized_bytes import bytes32

from populis_puzzles.admin_authority_v2_driver import (
    DEFAULT_COOLDOWN_BLOCKS,
    DEFAULT_MAX_ADMINS,
    DEFAULT_MAX_KEYS_PER_ADMIN,
    DEFAULT_PGT_GOVERNANCE_PUZZLE_HASH,
    DEFAULT_RECOVERY_TIMEOUT_BLOCKS,
    EMPTY_LIST_HASH,
    AdminRecord,
    PendingOp,
    admin_authority_v2_inner_mod_hash,
    compute_admins_hash,
    compute_pending_ops_hash,
    compute_state_hash,
    make_inner_puzzle_hash,
)


def _hex(b: bytes) -> str:
    return "0x" + b.hex()


def build_fixture() -> dict[str, Any]:
    """Compute every fixture case using the production Python helpers.

    Returns:
        A dict ready to be serialised to JSON. The portal's Karma test
        deserialises this and asserts the TS implementation matches.

    Cases are chosen to cover:
      * ``mod_hash`` — the bare uncurried inner mod tree hash. Crucial
        because it's curried into every v2 inner puzzle; getting it
        wrong silently breaks every spend.
      * ``empty_list_hash`` — the sentinel ``sha256tree(())``. Portal
        needs this for the default ``pending_ops_hash`` of a freshly
        launched singleton.
      * ``state_hash`` — sha256tree of the 4-tuple
        (mips_root_hash, admins_hash, pending_ops_hash, version).
        Five cases vary each field independently to catch a TS port
        getting the field order wrong.
      * ``admins_hash`` — sha256tree of an N-element list of
        AdminRecord triples. Cases: empty list, single record with
        one leaf, two records each with two leaves.
      * ``pending_ops_hash`` — sha256tree of an N-element list of
        PendingOp 4-tuples. Cases: empty list, one ADD op,
        one REMOVE op, mixed list of two.
      * ``inner_puzzle_hash`` — full ``make_inner_puzzle_hash`` for
        the default policy + a custom policy.  This binds the entire
        curry-order contract: any TS drift in the curry sequence
        will surface here.
    """
    # Sentinel 32-byte hashes (distinct so a TS port that swaps two
    # fields in the curry order produces a different output).
    h1 = bytes32(b"\x11" * 32)
    h2 = bytes32(b"\x22" * 32)
    h3 = bytes32(b"\x33" * 32)
    h4 = bytes32(b"\x44" * 32)

    state_cases: list[dict[str, Any]] = []
    for mips, admins, pending, version, label in (
        (h1, h2, EMPTY_LIST_HASH, 1, "fresh-launch-default"),
        (h1, h2, EMPTY_LIST_HASH, 7, "version-bumped"),
        (h1, h2, h3, 1, "with-pending-op"),
        (h2, h1, EMPTY_LIST_HASH, 1, "swapped-mips-and-admins"),
        (h4, h3, h2, 99, "all-distinct-fields"),
    ):
        state_cases.append(
            {
                "label": label,
                "input": {
                    "mips_root_hash": _hex(mips),
                    "admins_hash": _hex(admins),
                    "pending_ops_hash": _hex(pending),
                    "authority_version": version,
                },
                "expected": _hex(
                    compute_state_hash(
                        mips_root_hash=mips,
                        admins_hash=admins,
                        pending_ops_hash=pending,
                        authority_version=version,
                    )
                ),
            }
        )

    admins_cases: list[dict[str, Any]] = []
    for admins, label in (
        ([], "empty"),
        ([AdminRecord(admin_idx=0, leaves=(h1,), m_within=1)], "single-one-leaf"),
        (
            [
                AdminRecord(admin_idx=0, leaves=(h1, h2), m_within=2),
                AdminRecord(admin_idx=1, leaves=(h3, h4), m_within=1),
            ],
            "two-with-two-leaves",
        ),
    ):
        admins_cases.append(
            {
                "label": label,
                "input": [
                    {
                        "admin_idx": a.admin_idx,
                        "leaves": [_hex(leaf) for leaf in a.leaves],
                        "m_within": a.m_within,
                    }
                    for a in admins
                ],
                "expected": _hex(compute_admins_hash(admins)),
            }
        )

    pending_cases: list[dict[str, Any]] = []
    for ops, label in (
        ([], "empty"),
        (
            [PendingOp(admin_idx=0, op_kind=1, target_hash=h1, activates_at=1024)],
            "single-add",
        ),
        (
            [PendingOp(admin_idx=2, op_kind=2, target_hash=h2, activates_at=5040)],
            "single-remove",
        ),
        (
            [
                PendingOp(admin_idx=0, op_kind=1, target_hash=h1, activates_at=1024),
                PendingOp(admin_idx=1, op_kind=2, target_hash=h2, activates_at=2048),
            ],
            "mixed-add-and-remove",
        ),
    ):
        pending_cases.append(
            {
                "label": label,
                "input": [
                    {
                        "admin_idx": op.admin_idx,
                        "op_kind": op.op_kind,
                        "target_hash": _hex(op.target_hash),
                        "activates_at": op.activates_at,
                    }
                    for op in ops
                ],
                "expected": _hex(compute_pending_ops_hash(ops)),
            }
        )

    inner_puzzle_cases: list[dict[str, Any]] = []
    for params, label in (
        (
            {
                "mips_root_hash": h1,
                "admins_hash": h2,
                "pending_ops_hash": EMPTY_LIST_HASH,
                "authority_version": 1,
            },
            "default-policy-fresh-launch",
        ),
        (
            {
                "mips_root_hash": h2,
                "admins_hash": h3,
                "pending_ops_hash": h4,
                "authority_version": 42,
                "max_admins": 7,
                "max_keys_per_admin": 5,
                "cooldown_blocks": 100,
                "recovery_timeout_blocks": 1000,
                "pgt_governance_puzzle_hash": h1,
            },
            "custom-policy-with-pending-op",
        ),
    ):
        inner_puzzle_cases.append(
            {
                "label": label,
                "input": {
                    k: (_hex(v) if isinstance(v, (bytes, bytes32)) else v)
                    for k, v in params.items()
                },
                "expected": _hex(make_inner_puzzle_hash(**params)),
            }
        )

    return {
        # Constants surfaced for the TS port to embed verbatim.
        "constants": {
            "mod_hash": _hex(admin_authority_v2_inner_mod_hash()),
            "empty_list_hash": _hex(EMPTY_LIST_HASH),
            "default_max_admins": DEFAULT_MAX_ADMINS,
            "default_max_keys_per_admin": DEFAULT_MAX_KEYS_PER_ADMIN,
            "default_cooldown_blocks": DEFAULT_COOLDOWN_BLOCKS,
            "default_recovery_timeout_blocks": DEFAULT_RECOVERY_TIMEOUT_BLOCKS,
            "default_pgt_governance_puzzle_hash": _hex(
                DEFAULT_PGT_GOVERNANCE_PUZZLE_HASH
            ),
        },
        "state_hash": state_cases,
        "admins_hash": admins_cases,
        "pending_ops_hash": pending_cases,
        "inner_puzzle_hash": inner_puzzle_cases,
    }


def fixture_destination() -> Path:
    """Resolve the canonical destination inside the portal repo."""
    repo_root = Path(__file__).resolve().parents[2]
    return (
        repo_root
        / "populis_portal"
        / "src"
        / "app"
        / "services"
        / "admin-authority-v2"
        / "admin-authority-v2.fixtures.json"
    )


def main() -> None:
    fixture = build_fixture()
    dest = fixture_destination()
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(fixture, indent=2, sort_keys=False) + "\n")
    print(f"wrote fixture to {dest}")
    print(
        f"  mod_hash={fixture['constants']['mod_hash']}, "
        f"{len(fixture['state_hash'])} state cases, "
        f"{len(fixture['admins_hash'])} admins cases, "
        f"{len(fixture['pending_ops_hash'])} pending cases, "
        f"{len(fixture['inner_puzzle_hash'])} inner-puzzle cases"
    )


if __name__ == "__main__":
    main()
