"""Unit tests for vault_singleton_inner.clsp, p2_vault.clsp, and p2_pool.clsp.

Tests run curried puzzles directly via Program.run() to verify:
  1. Vault deposit-to-pool case ('o') produces correct conditions
  2. Vault receive-from-pool case ('i') produces correct conditions
  3. Vault accept-offer case ('a') produces correct conditions
  4. Invalid spend case raises
  5. p2_vault produces correct escrow conditions
  6. p2_pool produces correct escrow conditions
  7. Protocol prefix on announcements
  8. REMARK driver hints present
"""
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

# Load compiled puzzles
VAULT_INNER_MOD: Program = load_clvm(
    "vault_singleton_inner.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)
P2_VAULT_MOD: Program = load_clvm(
    "p2_vault.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)

# ── Test constants ──
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
LAUNCHER_PUZZLE_HASH = bytes32(b"\x02" * 32)
VAULT_LAUNCHER_ID = bytes32(b"\xaa" * 32)
POOL_LAUNCHER_ID = bytes32(b"\xbb" * 32)
OWNER_PUBKEY = bytes(48)  # 48-byte G1Element placeholder
DEED_LAUNCHER_ID = bytes32(b"\xdd" * 32)
POOL_INNER_PUZHASH = bytes32(b"\xcc" * 32)

VAULT_SINGLETON_STRUCT = Program.to((SINGLETON_MOD_HASH, (VAULT_LAUNCHER_ID, LAUNCHER_PUZZLE_HASH)))

# Spend case constants
SPEND_DEPOSIT_TO_POOL = 0x6f   # 'o'
SPEND_RECEIVE_FROM_POOL = 0x69  # 'i'
SPEND_ACCEPT_OFFER = 0x61       # 'a'

# Protocol prefix (must match utility_macros.clib PROTOCOL_PREFIX = 0x50)
PROTOCOL_PREFIX = b"\x50"


def curry_vault() -> Program:
    """Curry vault_singleton_inner with test parameters."""
    return VAULT_INNER_MOD.curry(
        VAULT_SINGLETON_STRUCT,
        OWNER_PUBKEY,
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )


def curry_p2_vault() -> Program:
    """Curry p2_vault with test parameters."""
    return P2_VAULT_MOD.curry(
        SINGLETON_MOD_HASH,
        VAULT_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )


class TestVaultCompile:
    """Verify vault puzzles compile and curry correctly."""

    def test_vault_mod_loads(self):
        assert VAULT_INNER_MOD is not None

    def test_p2_vault_mod_loads(self):
        assert P2_VAULT_MOD is not None

    def test_vault_curry_produces_program(self):
        curried = curry_vault()
        assert curried.get_tree_hash() != VAULT_INNER_MOD.get_tree_hash()

    def test_p2_vault_curry_produces_program(self):
        curried = curry_p2_vault()
        assert curried.get_tree_hash() != P2_VAULT_MOD.get_tree_hash()


class TestVaultDepositToPool:
    """Test SPEND CASE 'o' — deposit deed to pool."""

    def test_deposit_returns_conditions(self):
        curried = curry_vault()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1

        sol = Program.to([
            my_id, my_inner_puzhash, my_amount,
            SPEND_DEPOSIT_TO_POOL,
            [DEED_LAUNCHER_ID, POOL_INNER_PUZHASH],
        ])
        result = curried.run(sol)
        conditions = result.as_python()

        # 7 conditions: AGG_SIG_ME, CREATE_PUZZLE_ANNOUNCEMENT, CREATE_COIN (recreate),
        #               REMARK, ASSERT_MY_COIN_ID, ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH
        assert len(conditions) == 7

        # AGG_SIG_ME (owner must sign)
        assert conditions[0][0] == bytes([50])
        # CREATE_PUZZLE_ANNOUNCEMENT (prefixed)
        assert conditions[1][0] == bytes([62])
        assert conditions[1][1][:1] == PROTOCOL_PREFIX
        # CREATE_COIN (recreate vault singleton)
        assert conditions[2][0] == bytes([51])
        assert conditions[2][1] == my_inner_puzhash
        # REMARK (driver hint)
        assert conditions[3][0] == bytes([1])  # REMARK = 1
        # ASSERT_MY_COIN_ID
        assert conditions[4][0] == bytes([70])
        assert conditions[4][1] == my_id
        # ASSERT_MY_AMOUNT
        assert conditions[5][0] == bytes([73])
        # ASSERT_MY_PUZZLEHASH
        assert conditions[6][0] == bytes([72])


class TestVaultReceiveFromPool:
    """Test SPEND CASE 'i' — receive deed from pool."""

    def test_receive_returns_conditions(self):
        curried = curry_vault()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1

        sol = Program.to([
            my_id, my_inner_puzhash, my_amount,
            SPEND_RECEIVE_FROM_POOL,
            [DEED_LAUNCHER_ID, POOL_INNER_PUZHASH],
        ])
        result = curried.run(sol)
        conditions = result.as_python()

        # 7 conditions
        assert len(conditions) == 7

        # AGG_SIG_ME
        assert conditions[0][0] == bytes([50])
        # ASSERT_PUZZLE_ANNOUNCEMENT (pool must announce redeem, prefixed)
        assert conditions[1][0] == bytes([63])
        # CREATE_COIN (recreate)
        assert conditions[2][0] == bytes([51])
        # REMARK
        assert conditions[3][0] == bytes([1])


class TestVaultAcceptOffer:
    """Test SPEND CASE 'a' — accept pool offer (secondary purchase)."""

    def test_accept_offer_returns_conditions(self):
        curried = curry_vault()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1
        token_amount = 100000

        sol = Program.to([
            my_id, my_inner_puzhash, my_amount,
            SPEND_ACCEPT_OFFER,
            [DEED_LAUNCHER_ID, token_amount, POOL_INNER_PUZHASH],
        ])
        result = curried.run(sol)
        conditions = result.as_python()

        # 7 conditions
        assert len(conditions) == 7
        # AGG_SIG_ME
        assert conditions[0][0] == bytes([50])
        # ASSERT_PUZZLE_ANNOUNCEMENT (pool must announce offer)
        assert conditions[1][0] == bytes([63])
        # CREATE_COIN (recreate)
        assert conditions[2][0] == bytes([51])
        # REMARK
        assert conditions[3][0] == bytes([1])


class TestVaultGating:
    """Test that invalid spend cases fail."""

    def test_invalid_spend_case_fails(self):
        curried = curry_vault()
        my_id = bytes32(b"\x11" * 32)
        my_inner_puzhash = curried.get_tree_hash()
        my_amount = 1

        sol = Program.to([
            my_id, my_inner_puzhash, my_amount,
            0x74,  # 't' — not a valid vault spend case
            [DEED_LAUNCHER_ID],
        ])
        with pytest.raises(ValueError):
            curried.run(sol)


class TestP2Vault:
    """Test p2_vault escrow puzzle."""

    def test_p2_vault_returns_conditions(self):
        curried = curry_p2_vault()
        vault_inner_puzhash = bytes32(b"\xee" * 32)
        vault_coin_id = bytes32(b"\x11" * 32)
        nft_launcher_id = DEED_LAUNCHER_ID
        nft_inner_puzhash = bytes32(b"\xff" * 32)
        nft_amount = 1
        next_puzzlehash = bytes32(b"\x99" * 32)

        sol = Program.to([
            vault_inner_puzhash,
            vault_coin_id,
            nft_launcher_id,
            nft_inner_puzhash,
            nft_amount,
            next_puzzlehash,
        ])
        result = curried.run(sol)
        conditions = result.as_python()

        # p2_vault produces 5 conditions:
        # ASSERT_MY_AMOUNT, ASSERT_MY_PUZZLEHASH, ASSERT_PUZZLE_ANNOUNCEMENT, CREATE_COIN, CREATE_COIN_ANNOUNCEMENT
        assert len(conditions) == 5

        # ASSERT_MY_AMOUNT
        assert conditions[0][0] == bytes([73])
        # ASSERT_MY_PUZZLEHASH
        assert conditions[1][0] == bytes([72])
        # ASSERT_PUZZLE_ANNOUNCEMENT (prefixed)
        assert conditions[2][0] == bytes([63])
        # CREATE_COIN (move NFT to next_puzzlehash)
        assert conditions[3][0] == bytes([51])
        assert conditions[3][1] == next_puzzlehash
        # CREATE_COIN_ANNOUNCEMENT (prefixed)
        assert conditions[4][0] == bytes([60])
        assert conditions[4][1][:1] == PROTOCOL_PREFIX


P2_POOL_MOD: Program = load_clvm(
    "p2_pool.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)


class TestP2Pool:
    """Test p2_pool escrow puzzle."""

    def test_p2_pool_returns_conditions(self):
        curried = P2_POOL_MOD.curry(
            SINGLETON_MOD_HASH,
            POOL_LAUNCHER_ID,
            LAUNCHER_PUZZLE_HASH,
        )
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        pool_coin_id = bytes32(b"\x22" * 32)
        deed_launcher_id = DEED_LAUNCHER_ID
        deed_inner_puzhash = bytes32(b"\xff" * 32)
        deed_amount = 1
        next_puzzlehash = bytes32(b"\x99" * 32)

        sol = Program.to([
            pool_inner_puzhash,
            pool_coin_id,
            deed_launcher_id,
            deed_inner_puzhash,
            deed_amount,
            next_puzzlehash,
        ])
        result = curried.run(sol)
        conditions = result.as_python()

        # p2_pool produces 5 conditions
        assert len(conditions) == 5

        # ASSERT_MY_AMOUNT
        assert conditions[0][0] == bytes([73])
        # ASSERT_MY_PUZZLEHASH
        assert conditions[1][0] == bytes([72])
        # ASSERT_PUZZLE_ANNOUNCEMENT (pool singleton must co-spend, prefixed)
        assert conditions[2][0] == bytes([63])
        # CREATE_COIN (move deed to next destination)
        assert conditions[3][0] == bytes([51])
        assert conditions[3][1] == next_puzzlehash
        # CREATE_COIN_ANNOUNCEMENT (prefixed)
        assert conditions[4][0] == bytes([60])
        assert conditions[4][1][:1] == PROTOCOL_PREFIX
