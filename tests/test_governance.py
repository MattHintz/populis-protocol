"""Unit tests for governance_singleton_inner.clsp.

Tests verify:
  1. Propose case requires DID co-spend announcement (with state recreation)
  2. Execute settlement requires quorum and produces announcement
  3. Execute freeze requires quorum and produces announcement
  4. Below-quorum settlement fails
  5. Invalid spend case fails
  6. Protocol prefix on announcements
  7. REMARK driver hints present
  8. State recreation via curry_hashes (PROPOSAL_HASH curried state)
  9. Execute mint requires quorum and produces SEND_MESSAGE
"""
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

GOV_INNER_MOD: Program = load_clvm(
    "governance_singleton_inner.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)

# Test constants
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
LAUNCHER_PUZZLE_HASH = bytes32(b"\x02" * 32)
GOV_LAUNCHER_ID = bytes32(b"\xab" * 32)
GOV_SINGLETON_STRUCT = Program.to((SINGLETON_MOD_HASH, (GOV_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH)))
PROTOCOL_DID_PUZHASH = bytes32(b"\x03" * 32)
QUORUM_BPS = 5000  # 50%
GOV_MOD_HASH = GOV_INNER_MOD.get_tree_hash()

# Spend case constants
GOV_SPEND_PROPOSE = 1
GOV_SPEND_EXECUTE_SETTLEMENT = 2
GOV_SPEND_EXECUTE_FREEZE = 3
GOV_SPEND_EXECUTE_MINT = 4

# Protocol prefix
PROTOCOL_PREFIX = b"\x50"


def curry_gov(proposal_hash=0) -> Program:
    """Curry governance with MOD_HASH, immutable params, and PROPOSAL_HASH state."""
    return GOV_INNER_MOD.curry(
        GOV_MOD_HASH,
        GOV_SINGLETON_STRUCT,
        PROTOCOL_DID_PUZHASH,
        QUORUM_BPS,
        proposal_hash,
    )


def make_gov_solution(my_id, my_inner_puzhash, my_amount, spend_case, params_list):
    return Program.to([
        my_id, my_inner_puzhash, my_amount,
        spend_case, params_list,
    ])


class TestGovernancePropose:
    """Test SPEND CASE 1 — PROPOSE."""

    def test_propose_returns_conditions(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        proposal_hash = bytes32(b"\xaa" * 32)
        did_inner_puzhash = bytes32(b"\xbb" * 32)

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_PROPOSE, [proposal_hash, did_inner_puzhash],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 7 conditions: CREATE_COIN, ASSERT_PUZZLE_ANNOUNCEMENT, CREATE_PUZZLE_ANNOUNCEMENT,
        #               REMARK, ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conditions) == 7
        # CREATE_COIN (recreate with new PROPOSAL_HASH)
        assert conditions[0][0] == bytes([51])
        # ASSERT_PUZZLE_ANNOUNCEMENT (DID must announce, prefixed)
        assert conditions[1][0] == bytes([63])
        # CREATE_PUZZLE_ANNOUNCEMENT (prefixed)
        assert conditions[2][0] == bytes([62])
        assert conditions[2][1][:1] == PROTOCOL_PREFIX
        # REMARK
        assert conditions[3][0] == bytes([1])

        # State recreation: new governance should have the proposal_hash
        expected_new = curry_gov(proposal_hash=proposal_hash)
        assert conditions[0][1] == expected_new.get_tree_hash()


class TestGovernanceSettlement:
    """Test SPEND CASE 2 — EXECUTE_SETTLEMENT (batch)."""

    def test_settlement_at_quorum_passes(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        splitxch_root_hash = bytes32(b"\xdd" * 32)
        total_settlement_amount = 150000
        num_deeds = 3

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_EXECUTE_SETTLEMENT,
            [splitxch_root_hash, total_settlement_amount, num_deeds, QUORUM_BPS],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 6 conditions: CREATE_COIN, SEND_MESSAGE (pool), REMARK,
        #               ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conditions) == 6
        # CREATE_COIN (recreate with PROPOSAL_HASH=0)
        assert conditions[0][0] == bytes([51])
        # SEND_MESSAGE 0x10 (CHIP-25 message to pool — batch settlement)
        assert conditions[1][0] == bytes([66])
        assert conditions[1][1] == bytes([0x10])
        assert conditions[1][2][:1] == PROTOCOL_PREFIX

        # State recreation: clears back to proposal_hash=0
        expected_new = curry_gov(proposal_hash=0)
        assert conditions[0][1] == expected_new.get_tree_hash()

    def test_settlement_above_quorum_passes(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_EXECUTE_SETTLEMENT,
            [bytes32(b"\xdd" * 32), 150000, 3, 7500],  # 75% > 50%
        )
        result = curried.run(sol)
        assert len(result.as_python()) == 6

    def test_settlement_below_quorum_fails(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_EXECUTE_SETTLEMENT,
            [bytes32(b"\xdd" * 32), 150000, 3, 4999],  # 49.99% < 50%
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestGovernanceFreeze:
    """Test SPEND CASE 3 — EXECUTE_FREEZE."""

    def test_freeze_at_quorum_passes(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_EXECUTE_FREEZE,
            [0, QUORUM_BPS],  # freeze with exact quorum
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 6 conditions
        assert len(conditions) == 6
        # CREATE_COIN (recreate)
        assert conditions[0][0] == bytes([51])
        # SEND_MESSAGE 0x10 (CHIP-25 message to pool)
        assert conditions[1][0] == bytes([66])
        assert conditions[1][1] == bytes([0x10])
        assert conditions[1][2][:1] == PROTOCOL_PREFIX

    def test_freeze_below_quorum_fails(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_EXECUTE_FREEZE,
            [0, 2000],  # 20% < 50% quorum
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestGovernanceMint:
    """Test SPEND CASE 4 — EXECUTE_MINT."""

    def test_mint_at_quorum_passes(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        singleton_full_puzzle_hash = bytes32(b"\xcc" * 32)

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_EXECUTE_MINT,
            [singleton_full_puzzle_hash, QUORUM_BPS],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 6 conditions: CREATE_COIN, SEND_MESSAGE, REMARK,
        #               ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conditions) == 6
        # CREATE_COIN (recreate with PROPOSAL_HASH=0)
        assert conditions[0][0] == bytes([51])
        # SEND_MESSAGE 0x10 (CHIP-25 message to DID)
        assert conditions[1][0] == bytes([66])
        assert conditions[1][1] == bytes([0x10])
        assert conditions[1][2][:1] == PROTOCOL_PREFIX
        # REMARK
        assert conditions[2][0] == bytes([1])

        # State recreation: clears back to proposal_hash=0
        expected_new = curry_gov(proposal_hash=0)
        assert conditions[0][1] == expected_new.get_tree_hash()

    def test_mint_above_quorum_passes(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_EXECUTE_MINT,
            [bytes32(b"\xcc" * 32), 7500],  # 75% > 50%
        )
        result = curried.run(sol)
        assert len(result.as_python()) == 6

    def test_mint_below_quorum_fails(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            GOV_SPEND_EXECUTE_MINT,
            [bytes32(b"\xcc" * 32), 4999],  # 49.99% < 50%
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestGovernanceGating:
    """Test that invalid spend cases fail."""

    def test_invalid_spend_case_fails(self):
        curried = curry_gov(proposal_hash=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_gov_solution(
            my_id, my_inner_puzhash, 1,
            99, [],
        )
        with pytest.raises(ValueError):
            curried.run(sol)
