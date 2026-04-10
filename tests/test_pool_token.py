"""Unit tests for pool_token_tail.clsp — the CAT tail for ungated pool tokens.

Tests verify:
  1. Mint case requires pool singleton announcement (with protocol prefix)
  2. Melt case requires pool singleton announcement (with protocol prefix)
  3. Transfer case returns empty conditions (ungated)
"""
import pytest
from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm
from chia_rs.sized_bytes import bytes32

POOL_TOKEN_TAIL_MOD: Program = load_clvm(
    "pool_token_tail.clsp",
    package_or_requirement="populis_puzzles",
    recompile=True,
)

# Test constants
SINGLETON_MOD_HASH = bytes32(b"\x01" * 32)
POOL_LAUNCHER_ID = bytes32(b"\xbb" * 32)
LAUNCHER_PUZZLE_HASH = bytes32(b"\x02" * 32)


def curry_tail() -> Program:
    return POOL_TOKEN_TAIL_MOD.curry(
        SINGLETON_MOD_HASH,
        POOL_LAUNCHER_ID,
        LAUNCHER_PUZZLE_HASH,
    )


class TestPoolTokenTailMint:
    """Test mint case (mint_or_melt = 1)."""

    def test_mint_returns_conditions(self):
        curried = curry_tail()
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        pool_coin_id = bytes32(b"\x22" * 32)
        my_coin_id = bytes32(b"\x33" * 32)
        amount = 100000

        sol = Program.to([pool_inner_puzhash, pool_coin_id, my_coin_id, 1, amount])
        result = curried.run(sol)
        conditions = result.as_python()

        # Mint: 2 conditions — ASSERT_MY_COIN_ID + ASSERT_PUZZLE_ANNOUNCEMENT
        assert len(conditions) == 2
        assert conditions[0][0] == bytes([70])  # ASSERT_MY_COIN_ID
        assert conditions[0][1] == my_coin_id
        assert conditions[1][0] == bytes([63])  # ASSERT_PUZZLE_ANNOUNCEMENT


class TestPoolTokenTailMelt:
    """Test melt case (mint_or_melt = -1)."""

    def test_melt_returns_conditions(self):
        curried = curry_tail()
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        pool_coin_id = bytes32(b"\x22" * 32)
        my_coin_id = bytes32(b"\x33" * 32)
        amount = 50000

        sol = Program.to([pool_inner_puzhash, pool_coin_id, my_coin_id, -1, amount])
        result = curried.run(sol)
        conditions = result.as_python()

        assert len(conditions) == 2
        assert conditions[0][0] == bytes([70])  # ASSERT_MY_COIN_ID
        assert conditions[1][0] == bytes([63])  # ASSERT_PUZZLE_ANNOUNCEMENT


class TestPoolTokenTailTransfer:
    """Test transfer case (mint_or_melt = 0) — ungated."""

    def test_transfer_returns_empty(self):
        curried = curry_tail()
        pool_inner_puzhash = bytes32(b"\xcc" * 32)
        pool_coin_id = bytes32(b"\x22" * 32)
        my_coin_id = bytes32(b"\x33" * 32)

        sol = Program.to([pool_inner_puzhash, pool_coin_id, my_coin_id, 0, 0])
        result = curried.run(sol)
        conditions = result.as_python()

        # Transfer: nil — no restrictions (Chialisp () = b'')
        assert conditions == b""
