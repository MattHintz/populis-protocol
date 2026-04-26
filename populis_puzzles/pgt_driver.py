"""Python driver helpers for the Populis Governance Token (PGT).

PGT is a CAT2 token with a fixed-supply genesis-by-coin-id TAIL.  Every PGT
coin carries the populis governance machinery as its CAT inner puzzle:

  - pgt_free_inner.clsp wraps PGT in TRANSFER / LOCK modes (free state).
  - pgt_locked_inner.clsp wraps PGT in RELEASE_DEADLINE / RELEASE_EXEC modes
    (locked state, committed to a specific proposal).

This module exposes:

  - pgt_tail_puzzle / pgt_tail_hash         — TAIL construction
  - pgt_free_inner_puzzle / pgt_free_inner_hash
  - pgt_locked_inner_puzzle / pgt_locked_inner_hash
  - make_cat_truths                         — synthetic Truths for unit tests
  - PROPOSAL_TRACKER_STRUCT helper          — singleton struct factory
"""
from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from populis_puzzles import load_puzzle


# ── Module-level caches of the compiled programs ─────────────────────────────
_PGT_TAIL_MOD: Program | None = None
_PGT_FREE_INNER_MOD: Program | None = None
_PGT_LOCKED_INNER_MOD: Program | None = None
_TRACKER_MOD: Program | None = None


def proposal_tracker_mod() -> Program:
    """Return the compiled (uncurried) governance_singleton_inner.clsp Program.

    This is the v2 governance puzzle ("proposal tracker") with PGT-backed
    voting.  It replaces the legacy raw-vote_weight puzzle (CRITICAL-3 audit fix).
    """
    global _TRACKER_MOD
    if _TRACKER_MOD is None:
        _TRACKER_MOD = load_puzzle("governance_singleton_inner.clsp")
    return _TRACKER_MOD


def pgt_tail_mod() -> Program:
    """Return the compiled (uncurried) pgt_tail.clsp Program."""
    global _PGT_TAIL_MOD
    if _PGT_TAIL_MOD is None:
        _PGT_TAIL_MOD = load_puzzle("pgt_tail.clsp")
    return _PGT_TAIL_MOD


def pgt_free_inner_mod() -> Program:
    """Return the compiled (uncurried) pgt_free_inner.clsp Program."""
    global _PGT_FREE_INNER_MOD
    if _PGT_FREE_INNER_MOD is None:
        _PGT_FREE_INNER_MOD = load_puzzle("pgt_free_inner.clsp")
    return _PGT_FREE_INNER_MOD


def pgt_locked_inner_mod() -> Program:
    """Return the compiled (uncurried) pgt_locked_inner.clsp Program."""
    global _PGT_LOCKED_INNER_MOD
    if _PGT_LOCKED_INNER_MOD is None:
        _PGT_LOCKED_INNER_MOD = load_puzzle("pgt_locked_inner.clsp")
    return _PGT_LOCKED_INNER_MOD


# ── PGT spend-case constants (must match the .clsp `defconstant`s) ───────────
PGT_TRANSFER = 1
PGT_LOCK = 2

PGT_RELEASE_DEADLINE = 1
PGT_RELEASE_EXEC = 2

# Proposal tracker spend cases
TRK_PROPOSE = 1
TRK_VOTE = 2
TRK_EXECUTE = 3
TRK_EXPIRE = 4

# Bill operation tags (single ASCII bytes)
BILL_MINT = b"M"     # 0x4d
BILL_FREEZE = b"F"   # 0x46
BILL_SETTLE = b"S"   # 0x53


# ── Singleton-struct construction ────────────────────────────────────────────
SINGLETON_LAUNCHER_HASH = bytes32.fromhex(
    "eff07522495060c066f66f32acc2a77e3a3e737aca8baea4d1a64ea4cdc13da9"
)


def make_proposal_tracker_struct(
    singleton_mod_hash: bytes32,
    tracker_launcher_id: bytes32,
    launcher_puzzle_hash: bytes32 = SINGLETON_LAUNCHER_HASH,
) -> Program:
    """Build the PROPOSAL_TRACKER_STRUCT used by the PGT inner puzzles.

    Layout: (SINGLETON_MOD_HASH (TRACKER_LAUNCHER_ID . LAUNCHER_PUZZLE_HASH)).
    Same shape as Chia's standard SINGLETON_STRUCT.
    """
    return Program.to((singleton_mod_hash, (tracker_launcher_id, launcher_puzzle_hash)))


def pgt_tail_puzzle(genesis_coin_id: bytes32) -> Program:
    """Return the PGT TAIL curried with the given genesis coin id.

    Args:
        genesis_coin_id: bytes32 coin id of the unique XCH coin that bootstraps
            PGT into circulation at protocol launch.

    Returns:
        Curried TAIL Program.  Its tree hash is the value used as TOKEN_TAIL_HASH
        in any contract that curries the PGT tail (e.g. governance, vote escrow).
    """
    if not isinstance(genesis_coin_id, bytes) or len(genesis_coin_id) != 32:
        raise ValueError("genesis_coin_id must be 32 bytes")
    return pgt_tail_mod().curry(genesis_coin_id)


def pgt_tail_hash(genesis_coin_id: bytes32) -> bytes32:
    """Return the puzzle tree hash of the curried PGT TAIL."""
    return pgt_tail_puzzle(genesis_coin_id).get_tree_hash()


# ── PGT free-state inner puzzle ──────────────────────────────────────────────
def pgt_free_inner_puzzle(
    locked_mod_hash: bytes32,
    proposal_tracker_struct: Program,
    inner_puzzle_hash: bytes32,
) -> Program:
    """Curry pgt_free_inner.clsp for a specific PGT owner.

    Args:
        locked_mod_hash: tree hash of the (uncurried) pgt_locked_inner module
            — needed for re-curry computations on LOCK transitions.
        proposal_tracker_struct: singleton struct of the proposal tracker.
        inner_puzzle_hash: the owner's user puzzle hash (e.g. p2_delegated).

    Returns:
        A curried pgt_free_inner Program.  Wrap it in CAT2(PGT_TAIL_HASH, ...)
        to get the on-chain puzzle.
    """
    mod = pgt_free_inner_mod()
    mod_hash = mod.get_tree_hash()
    return mod.curry(
        mod_hash,
        locked_mod_hash,
        proposal_tracker_struct,
        inner_puzzle_hash,
    )


def pgt_free_inner_hash(
    locked_mod_hash: bytes32,
    proposal_tracker_struct: Program,
    inner_puzzle_hash: bytes32,
) -> bytes32:
    """Tree hash of the curried pgt_free_inner.  Used to derive CAT puzzle hash."""
    return pgt_free_inner_puzzle(
        locked_mod_hash, proposal_tracker_struct, inner_puzzle_hash
    ).get_tree_hash()


# ── PGT locked-state inner puzzle ────────────────────────────────────────────
def pgt_locked_inner_puzzle(
    free_mod_hash: bytes32,
    proposal_tracker_struct: Program,
    inner_puzzle_hash: bytes32,
    lock_proposal_hash: bytes32,
    lock_deadline: int,
) -> Program:
    """Curry pgt_locked_inner.clsp for a specific locked PGT coin."""
    mod = pgt_locked_inner_mod()
    mod_hash = mod.get_tree_hash()
    return mod.curry(
        mod_hash,
        free_mod_hash,
        proposal_tracker_struct,
        inner_puzzle_hash,
        lock_proposal_hash,
        lock_deadline,
    )


def pgt_locked_inner_hash(
    free_mod_hash: bytes32,
    proposal_tracker_struct: Program,
    inner_puzzle_hash: bytes32,
    lock_proposal_hash: bytes32,
    lock_deadline: int,
) -> bytes32:
    return pgt_locked_inner_puzzle(
        free_mod_hash,
        proposal_tracker_struct,
        inner_puzzle_hash,
        lock_proposal_hash,
        lock_deadline,
    ).get_tree_hash()


# ── Proposal tracker singleton inner puzzle ──────────────────────────────────
def proposal_tracker_inner_puzzle(
    singleton_struct: Program,
    pgt_free_mod_hash: bytes32,
    pgt_locked_mod_hash: bytes32,
    cat_mod_hash: bytes32,
    pgt_tail_hash: bytes32,
    protocol_did_puzhash: bytes32,
    pool_singleton_struct: Program,
    quorum_bps: int,
    voting_window_seconds: int,
    pgt_total_supply: int,
    min_proposal_stake: int,
    proposal_hash: int = 0,
    bill_operation: int = 0,
    vote_tally: int = 0,
    voting_deadline: int = 0,
) -> Program:
    """Curry the proposal tracker singleton inner puzzle.

    All immutable params come first, followed by the four state fields
    (proposal_hash, bill_operation, vote_tally, voting_deadline).  When idle,
    the four state fields are 0; when an active proposal exists, they hold
    the proposal hash, the bill tuple, the accumulated PGT mojos, and the
    voting deadline (absolute seconds).

    `min_proposal_stake` is the minimum first-vote PGT mojos required to
    open a new proposal (anti-spam; the locked PGT is returned on EXEC or
    EXPIRE so this is a stake-deposit, not a fee).  Suggested testnet
    default: 10_000 (= 1% of 1M PGT total supply).
    """
    mod = proposal_tracker_mod()
    mod_hash = mod.get_tree_hash()
    return mod.curry(
        mod_hash,
        singleton_struct,
        pgt_free_mod_hash,
        pgt_locked_mod_hash,
        cat_mod_hash,
        pgt_tail_hash,
        protocol_did_puzhash,
        pool_singleton_struct,
        quorum_bps,
        voting_window_seconds,
        pgt_total_supply,
        min_proposal_stake,
        proposal_hash,
        bill_operation,
        vote_tally,
        voting_deadline,
    )


def proposal_tracker_inner_hash(*args, **kwargs) -> bytes32:
    return proposal_tracker_inner_puzzle(*args, **kwargs).get_tree_hash()


# ── Bill operation builders ──────────────────────────────────────────────────
def bill_mint(deed_full_puzzle_hash: bytes32) -> Program:
    """MINT bill: governance approves spawning a deed at the given full ph."""
    return Program.to((BILL_MINT, (deed_full_puzzle_hash, 0)))


def bill_freeze(new_pool_status: int) -> Program:
    """FREEZE bill: governance toggles pool status (0 = FROZEN, 1 = ACTIVE)."""
    return Program.to((BILL_FREEZE, (new_pool_status, 0)))


def bill_settle(splitxch_root: bytes32, total_amount: int, num_deeds: int) -> Program:
    """SETTLE bill: governance approves a batch settlement."""
    return Program.to((BILL_SETTLE, (splitxch_root, (total_amount, (num_deeds, 0)))))


def proposal_hash_from_bill(bill: Program) -> bytes32:
    """The proposal hash is sha256tree of the bill operation."""
    return bytes32(bill.get_tree_hash())


# ── CAT-wrapped PGT helpers (for tests / drivers building announcements) ─────
def cat_pgt_free_puzzle_hash(
    singleton_struct: Program,
    pgt_free_mod_hash: bytes32,
    pgt_locked_mod_hash: bytes32,
    cat_mod_hash: bytes32,
    pgt_tail_hash: bytes32,
    voter_inner_puzzle_hash: bytes32,
) -> bytes32:
    """Compute the on-chain puzzle hash of a CAT-wrapped PGT free coin owned
    by the given voter.  This is the announcement sender id used by the
    proposal tracker when asserting LOCK announcements.

    Mirrors the CLVM `curry_hashes` chain in governance_singleton_inner's
    `cat_pgt_free_puzhash` helper:

        curry_hashes(CAT_MOD_HASH,
            sha256(1, CAT_MOD_HASH),
            sha256(1, PGT_TAIL_HASH),
            curry_hashes(PGT_FREE_MOD_HASH,
                sha256(1, PGT_FREE_MOD_HASH),
                sha256(1, PGT_LOCKED_MOD_HASH),
                sha256tree(SINGLETON_STRUCT),
                sha256(1, voter_inner_puzhash)))

    Note that the puzzle uses raw `(sha256 1 X)` (not `tree_hash((q . X))`)
    for atom params, so we replicate that pattern here using the simple
    `curry_hashes` algorithm, NOT chia's standard `curry_and_treehash`
    which assumes `(q . X)` form.
    """
    import hashlib

    def sha256_pre(b: bytes) -> bytes32:
        """sha256(0x01 || X) — matches `(sha256 1 X)` in chialisp."""
        return bytes32(hashlib.sha256(b"\x01" + b).digest())

    def sha256tree(prog: Program) -> bytes32:
        """Compute tree hash of any Program (atom or pair)."""
        return bytes32(prog.get_tree_hash())

    def curry_hashes(mod_hash: bytes32, *param_hashes: bytes32) -> bytes32:
        """Replicates curry.clib's curry_hashes function exactly.

        tree_hash_of_apply(mod_hash, environment_hash) where
        environment_hash = calculate_hash_of_curried_parameters(params).
        """
        # constants from curry.clib's `constant_tree`:
        sha256_one = bytes32.fromhex(
            "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
        )
        sha256_one_one = bytes32.fromhex(
            "9dcf97a184f32623d11a73124ceb99a5709b083721e878a16d78f596718ba7b2"
        )
        # `(concat 2 (sha256 1 #a))` — used as prefix for `tree_hash_of_apply`
        two_sha256_one_a_kw = bytes.fromhex(
            "02a12871fee210fb8619291eaea194581cbd2531e4b23759d225f6806923f63222"
        )
        # `(concat 2 (sha256 1 #c))` — prefix for `update_hash_for_parameter_hash`
        two_sha256_one_c_kw = bytes.fromhex(
            "02a8d5dd63fba471ebcb1f3e8f7c1e1879b7152a6e7298a91ce119a63400ade7c5"
        )

        def hash_expression_F(a1: bytes, a2: bytes) -> bytes:
            # tree_hash of `((q . a1) a2)` given a1, a2 are the param values
            return hashlib.sha256(
                b"\x02"
                + hashlib.sha256(b"\x02" + sha256_one_one + a1).digest()
                + hashlib.sha256(b"\x02" + a2 + sha256_one).digest()
            ).digest()

        # Build environment hash recursively from right.
        env_hash = sha256_one_one  # tree_hash of `1` (the env)
        for ph in reversed(param_hashes):
            env_hash = hashlib.sha256(
                two_sha256_one_c_kw + hash_expression_F(ph, env_hash)
            ).digest()

        # Final apply: `(a (q . mod_hash) env)`
        return bytes32(
            hashlib.sha256(two_sha256_one_a_kw + hash_expression_F(mod_hash, env_hash)).digest()
        )

    # Inner: curry(PGT_FREE_MOD, PGT_FREE_MOD_HASH, PGT_LOCKED_MOD_HASH,
    #              SINGLETON_STRUCT, voter_inner_puzhash)
    pgt_free_h = curry_hashes(
        pgt_free_mod_hash,
        sha256_pre(pgt_free_mod_hash),
        sha256_pre(pgt_locked_mod_hash),
        sha256tree(singleton_struct),
        sha256_pre(voter_inner_puzzle_hash),
    )

    # Outer: curry(CAT_MOD, CAT_MOD_HASH, TAIL_HASH, INNER_HASH)
    return curry_hashes(
        cat_mod_hash,
        sha256_pre(cat_mod_hash),
        sha256_pre(pgt_tail_hash),
        pgt_free_h,
    )


# ── CAT2 Truths construction (testing helper) ────────────────────────────────
def make_cat_truths(
    inner_puzzle_hash: bytes32,
    cat_mod_hash: bytes32,
    cat_mod_hash_hash: bytes32,
    tail_hash: bytes32,
    my_id: bytes32,
    my_parent_info: bytes32,
    my_full_puzzle_hash: bytes32,
    my_amount: int,
) -> Program:
    """Build a synthetic CAT2 Truths struct for unit-testing TAIL puzzles.

    Layout (verbatim from cat_truths.clib comment):
      ((Inner_puzzle_hash . (MOD_hash . (MOD_hash_hash . TAIL_hash)))
       . (my_id . (my_parent_info my_full_puzhash my_amount)))

    cat_struct used here mirrors the 3-element layout assumed by the accessors
    (`cat_mod_hash_truth`, `cat_mod_hash_hash_truth`, `cat_tail_program_hash_truth`).
    """
    cat_struct = (cat_mod_hash, (cat_mod_hash_hash, tail_hash))
    coin_info = (my_parent_info, (my_full_puzzle_hash, (my_amount, 0)))
    truths = ((inner_puzzle_hash, cat_struct), (my_id, coin_info))
    return Program.to(truths)
