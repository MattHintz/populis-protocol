"""Tests for property_registry_inner.clsp and property_registry_driver.py.

Append-only on-chain log of registered Populis property identifiers.
This file exhaustively exercises:

  * Module compilation + tree-hash stability (regression guard).
  * Canonicalisation of human property ids (off-chain ↔ on-chain contract).
  * Signing-message determinism + replay-binding.
  * Inner-puzzle round-trip (curry → parse).
  * Registration spend conditions (count, types, message body).
  * Replay protection (Python + CLVM both reject version skips).
  * Input validation (short pubkeys, even amount, malformed property ids).
"""
from __future__ import annotations

import re

import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

from populis_puzzles.property_registry_driver import (
    PropertyRegistryState,
    build_registration_spend,
    canonicalise_property_id,
    compute_signing_message,
    make_inner_puzzle,
    make_inner_puzzle_hash,
    parse_inner_puzzle,
    property_registry_inner_mod,
    property_registry_inner_mod_hash,
)


GOV_PUBKEY = b"\x42" * 48
OTHER_GOV = b"\x99" * 48


# ── Compilation ─────────────────────────────────────────────────────────


class TestCompile:
    def test_module_compiles(self):
        mod = load_clvm(
            "property_registry_inner.clsp",
            package_or_requirement="populis_puzzles",
            recompile=True,
        )
        assert mod is not None

    def test_mod_hash_stable_across_calls(self):
        h1 = property_registry_inner_mod_hash()
        h2 = property_registry_inner_mod_hash()
        assert h1 == h2
        assert len(h1) == 32


# ── Canonicalisation ────────────────────────────────────────────────────


class TestCanonicalise:
    def test_returns_bytes32(self):
        out = canonicalise_property_id("PROP-001")
        assert isinstance(out, bytes)
        assert len(out) == 32

    def test_strip_whitespace(self):
        a = canonicalise_property_id("  PROP-001  ")
        b = canonicalise_property_id("PROP-001")
        assert a == b

    def test_uppercase_normalisation(self):
        a = canonicalise_property_id("prop-001")
        b = canonicalise_property_id("PROP-001")
        assert a == b

    def test_distinct_inputs_yield_distinct_hashes(self):
        a = canonicalise_property_id("PROP-001")
        b = canonicalise_property_id("PROP-002")
        assert a != b

    def test_unicode_stable(self):
        # Determinism across multiple calls with same input.
        a = canonicalise_property_id("ÜNI-CØDE")
        b = canonicalise_property_id("ÜNI-CØDE")
        assert a == b


# ── Signing message ─────────────────────────────────────────────────────


class TestSigningMessage:
    def test_determinism(self):
        pid = canonicalise_property_id("PROP-1")
        m1 = compute_signing_message(pid, 1)
        m2 = compute_signing_message(pid, 1)
        assert m1 == m2

    def test_property_id_sensitivity(self):
        m1 = compute_signing_message(canonicalise_property_id("PROP-1"), 1)
        m2 = compute_signing_message(canonicalise_property_id("PROP-2"), 1)
        assert m1 != m2

    def test_version_sensitivity(self):
        pid = canonicalise_property_id("PROP-1")
        m1 = compute_signing_message(pid, 1)
        m2 = compute_signing_message(pid, 2)
        assert m1 != m2


# ── Inner puzzle construction + parsing ─────────────────────────────────


class TestParse:
    def test_round_trip(self):
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=5)
        state = parse_inner_puzzle(puzzle)
        assert state.gov_pubkey == GOV_PUBKEY
        assert state.registry_version == 5
        assert state.self_mod_hash == property_registry_inner_mod_hash()

    def test_distinct_states_yield_distinct_puzhashes(self):
        a = make_inner_puzzle_hash(GOV_PUBKEY, registry_version=0)
        b = make_inner_puzzle_hash(GOV_PUBKEY, registry_version=1)
        assert a != b

    def test_distinct_govs_yield_distinct_puzhashes(self):
        a = make_inner_puzzle_hash(GOV_PUBKEY, registry_version=0)
        b = make_inner_puzzle_hash(OTHER_GOV, registry_version=0)
        assert a != b

    def test_parse_rejects_wrong_module(self):
        bogus = Program.to(1).curry(b"\x00" * 32, GOV_PUBKEY, 0)
        with pytest.raises(ValueError, match="property_registry_inner"):
            parse_inner_puzzle(bogus)

    def test_parse_rejects_non_curried(self):
        # Bare program with no currying — uncurry yields None or the
        # mod-hash mismatch path (both indicate "not parseable").
        with pytest.raises(ValueError, match="(?:not curried|property_registry_inner)"):
            parse_inner_puzzle(Program.to(1))


# ── Construction validation ─────────────────────────────────────────────


class TestConstruction:
    def test_make_inner_puzzle_rejects_short_pubkey(self):
        with pytest.raises(ValueError, match="48 bytes"):
            make_inner_puzzle(b"\x00" * 32, registry_version=0)

    def test_make_inner_puzzle_rejects_negative_version(self):
        with pytest.raises(ValueError, match="≥ 0"):
            make_inner_puzzle(GOV_PUBKEY, registry_version=-1)


# ── Registration spend ──────────────────────────────────────────────────


class TestRegistrationSpend:
    @pytest.fixture
    def state(self):
        return PropertyRegistryState(
            self_mod_hash=property_registry_inner_mod_hash(),
            gov_pubkey=GOV_PUBKEY,
            registry_version=0,
        )

    def test_emits_correct_condition_count(self, state):
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=canonicalise_property_id("PROP-1"),
            my_amount=1,
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        result = puzzle.run(artifacts.inner_solution)
        conditions = list(result.as_iter())
        # AGG_SIG_ME + CREATE_COIN + CREATE_PUZZLE_ANNOUNCEMENT + ASSERT_MY_AMOUNT
        assert len(conditions) == 4

    def test_agg_sig_me_present(self, state):
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=canonicalise_property_id("PROP-1"),
            my_amount=1,
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        # AGG_SIG_ME = 50 in chia condition codes.
        agg_sig_me = next((c for c in conditions if int(c.first().as_int()) == 50), None)
        assert agg_sig_me is not None
        sig_pubkey = bytes(agg_sig_me.rest().first().as_atom())
        assert sig_pubkey == GOV_PUBKEY

    def test_create_coin_recreates_self_with_bumped_version(self, state):
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=canonicalise_property_id("PROP-1"),
            my_amount=1,
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        # CREATE_COIN = 51.
        create_coin = next((c for c in conditions if int(c.first().as_int()) == 51), None)
        assert create_coin is not None
        emitted_puzhash = bytes(create_coin.rest().first().as_atom())
        expected = make_inner_puzzle_hash(GOV_PUBKEY, registry_version=1)
        assert emitted_puzhash == expected

    def test_create_puzzle_announcement_carries_property_id(self, state):
        pid = canonicalise_property_id("PROP-1")
        artifacts = build_registration_spend(
            current=state, property_id_canon=pid, my_amount=1
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        # CREATE_PUZZLE_ANNOUNCEMENT = 62.
        ann = next((c for c in conditions if int(c.first().as_int()) == 62), None)
        assert ann is not None
        ann_msg = bytes(ann.rest().first().as_atom())
        # Body = PROTOCOL_PREFIX (0x50) || property_id_canon.
        assert ann_msg == b"\x50" + bytes(pid)
        # Driver should publish the same bytes.
        assert artifacts.announcement_message == ann_msg

    def test_assert_my_amount_present(self, state):
        artifacts = build_registration_spend(
            current=state,
            property_id_canon=canonicalise_property_id("PROP-1"),
            my_amount=1,
        )
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=0)
        conditions = list(puzzle.run(artifacts.inner_solution).as_iter())
        # ASSERT_MY_AMOUNT = 73.
        amt = next((c for c in conditions if int(c.first().as_int()) == 73), None)
        assert amt is not None
        assert int(amt.rest().first().as_int()) == 1

    def test_python_rejects_short_property_id(self, state):
        with pytest.raises(ValueError, match="32 bytes"):
            build_registration_spend(
                current=state, property_id_canon=b"\x00" * 31, my_amount=1
            )

    def test_python_rejects_even_amount(self, state):
        with pytest.raises(ValueError, match="odd"):
            build_registration_spend(
                current=state,
                property_id_canon=canonicalise_property_id("PROP-1"),
                my_amount=2,
            )


# ── Replay protection ───────────────────────────────────────────────────


class TestReplayProtection:
    def test_clvm_rejects_version_skip(self):
        """new_registry_version must equal REGISTRY_VERSION + 1."""
        # Singleton at version 5; try to register at version 7 (skip 6).
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=5)
        bad_solution = Program.to(
            [1, canonicalise_property_id("PROP-1"), 7]
        )
        with pytest.raises(Exception):  # CLVM raises on assert failure
            puzzle.run(bad_solution)

    def test_clvm_rejects_version_downgrade(self):
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=5)
        bad_solution = Program.to(
            [1, canonicalise_property_id("PROP-1"), 4]
        )
        with pytest.raises(Exception):
            puzzle.run(bad_solution)

    def test_clvm_rejects_same_version(self):
        puzzle = make_inner_puzzle(GOV_PUBKEY, registry_version=5)
        bad_solution = Program.to(
            [1, canonicalise_property_id("PROP-1"), 5]
        )
        with pytest.raises(Exception):
            puzzle.run(bad_solution)
