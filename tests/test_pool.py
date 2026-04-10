"""Unit tests for pool_singleton_inner.clsp — the pool state machine.

Tests run curried puzzles via Program.run() to verify:
  1. Deposit case produces correct conditions when ACTIVE (with state recreation)
  2. Deposit case fails when FROZEN
  3. Redeem case produces correct conditions when ACTIVE (with state recreation)
  4. Generate-offer case produces correct conditions
  5. Governance case produces conditions (freeze/unfreeze)
  6. Invalid spend case fails
  7. Protocol prefix on announcements
  8. REMARK driver hints present
  9. State recreation via curry_hashes (CREATE_COIN with new inner puzzle hash)
"""
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

POOL_INNER_MOD: Program = load_clvm(
    "pool_singleton_inner.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)

# Test constants
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
LAUNCHER_PUZZLE_HASH = bytes32(b"\x02" * 32)
POOL_LAUNCHER_ID = bytes32(b"\xbb" * 32)
POOL_SINGLETON_STRUCT = Program.to((SINGLETON_MOD_HASH, (POOL_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH)))
PROTOCOL_DID_PUZHASH = bytes32(b"\x03" * 32)
TOKEN_TAIL_HASH = bytes32(b"\x04" * 32)
CAT_MOD_HASH = bytes32(b"\x05" * 32)
OFFER_MOD_HASH = bytes32(b"\x06" * 32)
P2_VAULT_MOD_HASH = bytes32(b"\x07" * 32)
FP_SCALE = 1000
MOD_HASH = POOL_INNER_MOD.get_tree_hash()

# Spend case constants
POOL_SPEND_DEPOSIT = 1
POOL_SPEND_REDEEM = 2
POOL_SPEND_SETTLEMENT = 3
POOL_SPEND_GOVERNANCE = 4
POOL_SPEND_GENERATE_OFFER = 5

POOL_ACTIVE = 1
POOL_FROZEN = 0

# Protocol prefix
PROTOCOL_PREFIX = b"\x50"


def curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0) -> Program:
    """Curry pool with MOD_HASH, immutable params, and mutable state."""
    return POOL_INNER_MOD.curry(
        MOD_HASH,
        POOL_SINGLETON_STRUCT,
        PROTOCOL_DID_PUZHASH,
        TOKEN_TAIL_HASH,
        CAT_MOD_HASH,
        OFFER_MOD_HASH,
        P2_VAULT_MOD_HASH,
        FP_SCALE,
        pool_status,
        tvl,
        deed_count,
    )


def make_pool_solution(my_id, my_inner_puzhash, my_amount,
                       spend_case, params_list):
    """Build solution — state is now curried, not in solution."""
    return Program.to([
        my_id, my_inner_puzhash, my_amount,
        spend_case, params_list,
    ])


class TestPoolDeposit:
    """Test SPEND CASE 1 — DEPOSIT."""

    def test_deposit_active_returns_conditions(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xdd" * 32)
        deed_par_value = 100000
        depositor_puzhash = bytes32(b"\xee" * 32)
        token_coin_id = bytes32(b"\xff" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_DEPOSIT, [deed_id, deed_par_value, depositor_puzhash, token_coin_id],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 7 conditions: CREATE_COIN, CREATE_PUZZLE_ANNOUNCEMENT (token mint),
        #               SEND_MESSAGE, REMARK, ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conditions) == 7
        # CREATE_COIN (recreate with updated state via curry_hashes)
        assert conditions[0][0] == bytes([51])
        # CREATE_PUZZLE_ANNOUNCEMENT (token mint authorization)
        assert conditions[1][0] == bytes([62])
        assert conditions[1][1][:1] == PROTOCOL_PREFIX
        # SEND_MESSAGE 0x10 (CHIP-25 message to deed)
        assert conditions[2][0] == bytes([66])
        assert conditions[2][1] == bytes([0x10])  # mode: sender commits puzzle_hash
        assert conditions[2][2][:1] == PROTOCOL_PREFIX
        # REMARK (driver hint with new state)
        assert conditions[3][0] == bytes([1])  # REMARK = 1
        # ASSERT_MY_COIN_ID
        assert conditions[4][0] == bytes([70])
        assert conditions[4][1] == my_id
        # ASSERT_MY_AMOUNT
        assert conditions[5][0] == bytes([73])
        # ASSERT_MY_PUZZLEHASH
        assert conditions[6][0] == bytes([72])

    def test_deposit_frozen_fails(self):
        curried = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_DEPOSIT, [bytes32(b"\xdd" * 32), 100000, bytes32(b"\xee" * 32), bytes32(b"\xff" * 32)],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_deposit_state_recreation(self):
        """Verify CREATE_COIN puzzle hash matches expected new state curry."""
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_par_value = 100000

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_DEPOSIT, [bytes32(b"\xdd" * 32), deed_par_value, bytes32(b"\xee" * 32), bytes32(b"\xff" * 32)],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # The CREATE_COIN puzzle hash should match a pool curried with new state
        expected_new = curry_pool(pool_status=POOL_ACTIVE, tvl=deed_par_value, deed_count=1)
        assert conditions[0][1] == expected_new.get_tree_hash()


class TestPoolRedeem:
    """Test SPEND CASE 2 — REDEEM."""

    def test_redeem_active_returns_conditions(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=100000, deed_count=1)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xdd" * 32)
        deed_par_value = 100000
        vault_launcher_id = bytes32(b"\xee" * 32)
        token_coin_id = bytes32(b"\xff" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_REDEEM, [deed_id, deed_par_value, vault_launcher_id, LAUNCHER_PUZZLE_HASH, token_coin_id],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 7 conditions
        assert len(conditions) == 7
        # CREATE_COIN (recreate with updated state)
        assert conditions[0][0] == bytes([51])
        # CREATE_PUZZLE_ANNOUNCEMENT (token melt authorization)
        assert conditions[1][0] == bytes([62])
        assert conditions[1][1][:1] == PROTOCOL_PREFIX
        # SEND_MESSAGE 0x10 (CHIP-25 message to deed)
        assert conditions[2][0] == bytes([66])
        assert conditions[2][1] == bytes([0x10])  # mode: sender commits puzzle_hash
        assert conditions[2][2][:1] == PROTOCOL_PREFIX

        # State recreation: new pool should have tvl=0, deed_count=0
        expected_new = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert conditions[0][1] == expected_new.get_tree_hash()

    def test_redeem_frozen_fails(self):
        curried = curry_pool(pool_status=POOL_FROZEN, tvl=100000, deed_count=1)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_REDEEM, [bytes32(b"\xdd" * 32), 100000, bytes32(b"\xee" * 32), LAUNCHER_PUZZLE_HASH, bytes32(b"\xff" * 32)],
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestPoolGenerateOffer:
    """Test SPEND CASE 5 — GENERATE_OFFER (Chia native offer settlement)."""

    def test_generate_offer_returns_conditions(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=100000, deed_count=1)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        deed_id = bytes32(b"\xdd" * 32)
        deed_par_value = 100000
        buyer_vault_launcher_id = bytes32(b"\xee" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GENERATE_OFFER, [deed_id, deed_par_value, buyer_vault_launcher_id, LAUNCHER_PUZZLE_HASH],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 7 conditions: CREATE_COIN, ASSERT_PUZZLE_ANNOUNCEMENT, SEND_MESSAGE,
        #               REMARK, ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conditions) == 7
        # CREATE_COIN (state recreation: deed leaves pool)
        assert conditions[0][0] == bytes([51])
        # ASSERT_PUZZLE_ANNOUNCEMENT (verify token payment via CAT settlement to protocol treasury)
        assert conditions[1][0] == bytes([63])  # ASSERT_PUZZLE_ANNOUNCEMENT
        # SEND_MESSAGE 0x10 (tell deed to release to buyer)
        assert conditions[2][0] == bytes([66])  # SEND_MESSAGE
        assert conditions[2][1] == bytes([0x10])
        assert conditions[2][2][:1] == PROTOCOL_PREFIX
        # REMARK
        assert conditions[3][0] == bytes([1])

        # State recreation: deed leaves pool (tvl - par_value, count - 1)
        expected_new = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        assert conditions[0][1] == expected_new.get_tree_hash()

    def test_generate_offer_frozen_fails(self):
        curried = curry_pool(pool_status=POOL_FROZEN, tvl=100000, deed_count=1)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GENERATE_OFFER, [bytes32(b"\xdd" * 32), 100000, bytes32(b"\xee" * 32), LAUNCHER_PUZZLE_HASH],
        )
        with pytest.raises(ValueError):
            curried.run(sol)

    def test_generate_offer_empty_pool_fails(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GENERATE_OFFER, [bytes32(b"\xdd" * 32), 100000, bytes32(b"\xee" * 32), LAUNCHER_PUZZLE_HASH],
        )
        with pytest.raises(ValueError):
            curried.run(sol)


class TestPoolGovernance:
    """Test SPEND CASE 4 — GOVERNANCE."""

    def test_governance_returns_conditions(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        gov_singleton_struct = Program.to((SINGLETON_MOD_HASH, (bytes32(b"\xab" * 32), LAUNCHER_PUZZLE_HASH)))
        gov_inner_puzhash = bytes32(b"\xac" * 32)

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            POOL_SPEND_GOVERNANCE, [POOL_FROZEN, gov_inner_puzhash, gov_singleton_struct],
        )
        result = curried.run(sol)
        conditions = result.as_python()

        # 6 conditions
        assert len(conditions) == 6
        # CREATE_COIN (recreate with new status)
        assert conditions[0][0] == bytes([51])
        # RECEIVE_MESSAGE 0x10 (CHIP-25 message from governance)
        assert conditions[1][0] == bytes([67])
        assert conditions[1][1] == bytes([0x10])  # mode: sender commits puzzle_hash
        # REMARK
        assert conditions[2][0] == bytes([1])

        # State recreation: new pool should be FROZEN with same tvl/count
        expected_new = curry_pool(pool_status=POOL_FROZEN, tvl=0, deed_count=0)
        assert conditions[0][1] == expected_new.get_tree_hash()


class TestPoolGating:
    """Test that invalid spend cases fail."""

    def test_invalid_spend_case_fails(self):
        curried = curry_pool(pool_status=POOL_ACTIVE, tvl=0, deed_count=0)
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()

        sol = make_pool_solution(
            my_id, my_inner_puzhash, 1,
            99, [],
        )
        with pytest.raises(ValueError):
            curried.run(sol)
