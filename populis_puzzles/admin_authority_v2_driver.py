"""Python driver for admin_authority_v2_inner.clsp (Phase 9-Hermes-C.3).

The v2 admin-authority singleton replaces v1's homegrown BLS allowlist with
a thin shim over CHIP-0043 MIPS. Each admin slot holds a ``OneOfN`` of
personal authentication methods (BLS, EIP-712, passkey, ...); the
protocol-level admin set is an ``MofN`` quorum over those slots.

Design reference:
    research/POPULIS_ADMIN_AUTHORITY_V2_DESIGN.md

This module exposes the off-chain construction of state and spends that
mirrors what the on-chain ``admin_authority_v2_inner.clsp`` puzzle expects.
The cross-repo contract is: any tree-hash this driver computes must match
exactly what the on-chain ``sha256tree`` calls produce. Tests in
``tests/test_admin_authority_v2.py`` enforce this end-to-end.

This iteration (C.3 step 1) covers OPERATIONAL spends (tag 0x01). Builders
for the remaining 5 spend tags land in subsequent iterations as their
runtime tests pass.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from populis_puzzles import load_puzzle


# ─────────────────────────────────────────────────────────────────────────
# On-chain constants (mirror the .clsp).
# ─────────────────────────────────────────────────────────────────────────

# Spend tags. Must match defconstants in admin_authority_v2_inner.clsp.
SPEND_OPERATIONAL = 0x01
SPEND_KEY_ADD_PROPOSE = 0x02
SPEND_KEY_ADD_ACTIVATE = 0x03
SPEND_KEY_ADD_VETO = 0x04
SPEND_KEY_REMOVE_QUORUM = 0x05
SPEND_KEY_REMOVE_EMERGENCY = 0x06

# Op-kind tags inside pending-ops entries.
OP_KIND_ADD = 0x01
OP_KIND_REMOVE = 0x02

# Confirmation window for PROPOSE-style spends. Must match PROPOSE_WINDOW
# in the puzzle. Reflects ~2 minutes at 24-second blocks.
PROPOSE_WINDOW = 8

# Pending-ops list capacity. Must match MAX_PENDING_OPS in the puzzle.
MAX_PENDING_OPS = 8

# sha256tree of the empty list (). Equivalent to the on-chain
# EMPTY_LIST_HASH constant, used as the curried PENDING_KEY_OPS_HASH when
# the singleton has no pending ops.
EMPTY_LIST_HASH: bytes32 = bytes32.fromhex(
    "4bf5122f344554c53bde2ebb8cd2b7e3d1600ad631c385a5d7cce23c7785459a"
)


# Default protocol-policy values. Operators can override at deployment
# time; these match the design doc's recommended defaults.
DEFAULT_MAX_ADMINS = 25
DEFAULT_MAX_KEYS_PER_ADMIN = 10
DEFAULT_COOLDOWN_BLOCKS = 1024  # ≈ 2 days at 24s blocks
DEFAULT_RECOVERY_TIMEOUT_BLOCKS = 5040  # ≈ 7 days
DEFAULT_PGT_GOVERNANCE_PUZZLE_HASH: bytes32 = bytes32(b"\x00" * 32)


# ─────────────────────────────────────────────────────────────────────────
# Module-level cache of the compiled program.
# ─────────────────────────────────────────────────────────────────────────

_ADMIN_AUTHORITY_V2_INNER_MOD: Program | None = None


def admin_authority_v2_inner_mod() -> Program:
    """Return the compiled (uncurried) admin_authority_v2_inner.clsp Program."""
    global _ADMIN_AUTHORITY_V2_INNER_MOD
    if _ADMIN_AUTHORITY_V2_INNER_MOD is None:
        _ADMIN_AUTHORITY_V2_INNER_MOD = load_puzzle("admin_authority_v2_inner.clsp")
    return _ADMIN_AUTHORITY_V2_INNER_MOD


def admin_authority_v2_inner_mod_hash() -> bytes32:
    """Tree hash of the uncurried inner mod (used as SELF_MOD_HASH curried arg)."""
    return bytes32(admin_authority_v2_inner_mod().get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Typed state.
#
# Admin records are 3-tuples (admin_idx, leaves, m_within). leaves is the
# flat list of member tree hashes (32 bytes each) representing the OneOfN
# of authentication methods this admin can sign with. m_within is the
# within-admin removal quorum (default 1 — single-key admins).
#
# Pending-op entries are 4-tuples (admin_idx, op_kind, target_hash,
# activates_at). They live in a flat list whose sha256tree is curried as
# PENDING_KEY_OPS_HASH.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AdminRecord:
    """One admin slot's state. Maps directly to a Chialisp record."""

    admin_idx: int
    leaves: tuple[bytes32, ...]
    m_within: int

    def to_program(self) -> Program:
        return Program.to([self.admin_idx, list(self.leaves), self.m_within])


@dataclass(frozen=True)
class PendingOp:
    """A pending key-rotation op awaiting activation or veto."""

    admin_idx: int
    op_kind: int  # OP_KIND_ADD | OP_KIND_REMOVE
    target_hash: bytes32
    activates_at: int

    def to_program(self) -> Program:
        return Program.to(
            [self.admin_idx, self.op_kind, self.target_hash, self.activates_at]
        )


def compute_admins_hash(admins: Sequence[AdminRecord]) -> bytes32:
    """sha256tree of the admins list. Matches on-chain ADMINS_HASH."""
    return bytes32(Program.to([a.to_program() for a in admins]).get_tree_hash())


def compute_pending_ops_hash(pending_ops: Sequence[PendingOp]) -> bytes32:
    """sha256tree of the pending-ops list. Empty list hashes to EMPTY_LIST_HASH."""
    if not pending_ops:
        return EMPTY_LIST_HASH
    return bytes32(
        Program.to([p.to_program() for p in pending_ops]).get_tree_hash()
    )


def compute_state_hash(
    mips_root_hash: bytes32,
    admins_hash: bytes32,
    pending_ops_hash: bytes32,
    authority_version: int,
) -> bytes32:
    """sha256tree of the (state) tuple announced for off-chain monitors.

    Mirrors the on-chain ``state-hash`` defun. Off-chain consumers
    decoding the singleton's puzzle announcement see this exact hash
    after the PROTOCOL_PREFIX + spend_tag bytes.
    """
    return bytes32(
        Program.to(
            [mips_root_hash, admins_hash, pending_ops_hash, authority_version]
        ).get_tree_hash()
    )


# ─────────────────────────────────────────────────────────────────────────
# Inner puzzle construction.
# ─────────────────────────────────────────────────────────────────────────


def make_inner_puzzle(
    *,
    mips_root_hash: bytes32,
    admins_hash: bytes32,
    pending_ops_hash: bytes32 = EMPTY_LIST_HASH,
    authority_version: int = 1,
    max_admins: int = DEFAULT_MAX_ADMINS,
    max_keys_per_admin: int = DEFAULT_MAX_KEYS_PER_ADMIN,
    cooldown_blocks: int = DEFAULT_COOLDOWN_BLOCKS,
    recovery_timeout_blocks: int = DEFAULT_RECOVERY_TIMEOUT_BLOCKS,
    pgt_governance_puzzle_hash: bytes32 = DEFAULT_PGT_GOVERNANCE_PUZZLE_HASH,
) -> Program:
    """Curry the v2 inner puzzle for a specific protocol-policy + state.

    Currying order MUST match admin_authority_v2_inner.clsp:

        SELF_MOD_HASH, MAX_ADMINS, MAX_KEYS_PER_ADMIN, COOLDOWN_BLOCKS,
        RECOVERY_TIMEOUT_BLOCKS, PGT_GOVERNANCE_PUZZLE_HASH,
        MIPS_ROOT_HASH, ADMINS_HASH, PENDING_KEY_OPS_HASH,
        AUTHORITY_VERSION
    """
    return admin_authority_v2_inner_mod().curry(
        admin_authority_v2_inner_mod_hash(),
        max_admins,
        max_keys_per_admin,
        cooldown_blocks,
        recovery_timeout_blocks,
        pgt_governance_puzzle_hash,
        mips_root_hash,
        admins_hash,
        pending_ops_hash,
        authority_version,
    )


def make_inner_puzzle_hash(**kwargs) -> bytes32:
    """Tree hash of the curried inner puzzle. Forwards all kwargs."""
    return bytes32(make_inner_puzzle(**kwargs).get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Spend builders.
#
# Each builder returns the SOLUTION program ready to feed into
# ``curried.run(solution)`` (in tests) or to attach to a CoinSpend (in
# production deployments).
# ─────────────────────────────────────────────────────────────────────────


def build_operational_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    mips_puzzle_reveal: Program,
    mips_solution: Program,
) -> Program:
    """Build the solution for an OPERATIONAL spend (tag 0x01).

    The shim runs ``(a mips_puzzle_reveal mips_solution)`` to obtain the
    user-authorised conditions, verifies sha256tree(mips_puzzle_reveal)
    matches the curried MIPS_ROOT_HASH, and wraps them with the shim's
    own self-recurry + announcement conditions.

    Args:
        my_amount: singleton coin amount (must be odd; identity assert).
        new_authority_version: strictly > current AUTHORITY_VERSION.
        mips_puzzle_reveal: the MIPS m_of_n tree (or any puzzle whose
            tree-hash matches MIPS_ROOT_HASH). For testing this can be a
            trivial constant puzzle.
        mips_solution: solution that, when run against the reveal,
            produces the conditions the shim wraps. For a constant
            puzzle this is typically nil.

    Returns:
        Program ready for ``curried.run(...)``.
    """
    return Program.to(
        [
            SPEND_OPERATIONAL,
            my_amount,
            new_authority_version,
            [mips_puzzle_reveal, mips_solution],
        ]
    )


def build_key_add_activate_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    admin_idx: int,
    op_kind: int,
    target_member_hash: bytes32,
    activates_at: int,
) -> Program:
    """Build the solution for a KEY_ADD_ACTIVATE spend (tag 0x03).

    Despite the name, this tag activates BOTH ADD and REMOVE pending ops
    (per design doc §5.8 polymorphic ACTIVATE). The op_kind discriminator
    selects which branch of the handler runs:

      OP_KIND_ADD:    appends target_member_hash to the admin's leaves.
      OP_KIND_REMOVE: removes target_member_hash from the admin's leaves.

    Permissionless spend — no signer authority required. The caller proves:
      1. The matching pending op exists in current_pending_ops_list.
      2. ASSERT_HEIGHT_ABSOLUTE activates_at — cooldown has elapsed.

    Args:
        op_kind: OP_KIND_ADD or OP_KIND_REMOVE; must match the pending op
            tuple's stored kind for lookup to succeed.
        target_member_hash: the leaf being added or removed.
        activates_at: cooldown end height; must match what was stored at
            PROPOSE / EMERGENCY time.
    """
    return Program.to(
        [
            SPEND_KEY_ADD_ACTIVATE,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                [p.to_program() for p in current_pending_ops],
                admin_idx,
                op_kind,
                target_member_hash,
                activates_at,
            ],
        ]
    )


## ─────────────────────────────────────────────────────────────────────────
## Migration helpers (v1 → v2)
##
## v1 admin_authority_inner.clsp is a flat BLS allowlist with a single
## quorum_m. v2 supports per-admin OneOfN of arbitrary auth methods
## (BLS, EIP-712, passkey, ...) under a protocol-level MofN quorum.
##
## The v1 → v2 migration story (per design doc §7):
##   1. Operator provisions a v2 singleton with launch state where each
##      v1 admin pubkey maps to a single-leaf OneOfN (admin_idx=N, leaves=
##      [hash(BlsMember(pk_N))], m_within=1).
##   2. v1 admins co-sign a "transfer of authority" v1 rotation spend
##      that includes a CREATE_PUZZLE_ANNOUNCEMENT carrying the v2
##      launcher_id; off-chain monitors and downstream contracts can
##      verify the migration by following both announcements.
##   3. Each v1 admin then independently uses KEY_ADD_PROPOSE / ACTIVATE
##      to add their EIP-712 / passkey / BLS-backup keys over time.
##
## These helpers cover step 1 (synthesising a v2 launch state from v1
## allowlist data) and provide a deterministic mapping that the
## migration tooling can audit against on-chain history.
## ─────────────────────────────────────────────────────────────────────────


def admin_record_for_single_leaf(
    admin_idx: int,
    member_tree_hash: bytes32,
    m_within: int = 1,
) -> AdminRecord:
    """Build an AdminRecord whose OneOfN has exactly one leaf.

    Use this for migration: each v1 BLS pubkey becomes a single-leaf
    admin record where the leaf is the curried BlsMember tree hash.
    Admins can later extend their leaves list via KEY_ADD_PROPOSE +
    KEY_ADD_ACTIVATE without going through PGT governance.
    """
    return AdminRecord(
        admin_idx=admin_idx,
        leaves=(member_tree_hash,),
        m_within=m_within,
    )


def launch_state_from_v1_allowlist(
    *,
    bls_member_hashes: Sequence[bytes32],
    quorum_m: int,
    initial_authority_version: int = 1,
) -> tuple[Sequence[AdminRecord], int]:
    """Synthesise a v2 launch state from a v1 BLS allowlist.

    Each v1 BLS admin pubkey becomes a single-leaf admin record. The
    caller is responsible for computing each ``BlsMember(pk).tree_hash``
    off-chain (typically via chia-wallet-sdk's BlsMember struct).

    The resulting admins list preserves v1's signer-index ordering so
    off-chain monitoring tooling can correlate v1 ALLOWLIST positions
    with v2 admin_idx values without ambiguity.

    Args:
        bls_member_hashes: ordered tuple of curried-BlsMember tree
            hashes, one per v1 admin. Position i becomes admin_idx=i in
            the v2 admins list.
        quorum_m: the v1 QUORUM_M, preserved as the protocol-level
            MIPS m-of-n threshold (returned for the caller to use when
            constructing MIPS_ROOT_HASH).
        initial_authority_version: starting AUTHORITY_VERSION for the
            v2 singleton. Defaults to 1; operators may want to set this
            to ``v1_authority_version + 1`` so the v2 singleton has a
            higher version than the v1 it supersedes.

    Returns:
        ``(admins, quorum_m)`` — pass ``admins`` to
        :func:`compute_admins_hash` to derive ADMINS_HASH, then use
        ``quorum_m`` when curry'ing the MIPS m_of_n tree.
    """
    if quorum_m < 1:
        raise ValueError(f"quorum_m must be >= 1, got {quorum_m}")
    if quorum_m > len(bls_member_hashes):
        raise ValueError(
            f"quorum_m ({quorum_m}) exceeds number of admins "
            f"({len(bls_member_hashes)})"
        )
    admins = tuple(
        admin_record_for_single_leaf(idx, h)
        for idx, h in enumerate(bls_member_hashes)
    )
    return admins, quorum_m


@dataclass(frozen=True)
class AdminAuthorityV2State:
    """Decoded state of an admin_authority_v2 singleton at a point in time.

    Mirrors the curried [STATE] slots of admin_authority_v2_inner.clsp:
    MIPS_ROOT_HASH, ADMINS_HASH, PENDING_KEY_OPS_HASH, AUTHORITY_VERSION.

    ``admins_revealed`` and ``pending_ops_revealed`` are populated when
    parsing from the full curried puzzle reveal (and the lists provided
    by an off-chain monitor); they're tuple()/() when only the hashes
    are known.
    """

    self_mod_hash: bytes32
    max_admins: int
    max_keys_per_admin: int
    cooldown_blocks: int
    recovery_timeout_blocks: int
    pgt_governance_puzzle_hash: bytes32
    mips_root_hash: bytes32
    admins_hash: bytes32
    pending_ops_hash: bytes32
    authority_version: int
    admins_revealed: tuple[AdminRecord, ...] = ()
    pending_ops_revealed: tuple[PendingOp, ...] = ()

    @property
    def state_hash(self) -> bytes32:
        """sha256tree of the state tuple — what the on-chain announcement
        carries after the PROTOCOL_PREFIX + spend_tag bytes.
        """
        return compute_state_hash(
            self.mips_root_hash,
            self.admins_hash,
            self.pending_ops_hash,
            self.authority_version,
        )


def parse_inner_puzzle(curried_inner_puzzle: Program) -> AdminAuthorityV2State:
    """Decompose a curried v2 inner puzzle back into typed state.

    Strictly validates the uncurried mod hash before returning state —
    otherwise the caller is parsing some other puzzle that happens to
    look like ours.

    Note: this only decodes the curried params (10 slots). The
    revealed admins / pending-ops lists are not part of the curried
    puzzle hash; they're supplied per-spend via solution and the
    state-hash check enforces consistency. Use the dedicated state
    fields ``admins_revealed`` / ``pending_ops_revealed`` if the
    caller has them from off-chain monitoring.

    Raises:
        ValueError: if the puzzle is not an instance of
            ``admin_authority_v2_inner.clsp``.
    """
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != admin_authority_v2_inner_mod_hash():
        raise ValueError(
            f"puzzle mod hash {mod.get_tree_hash().hex()} does not match "
            f"admin_authority_v2_inner.clsp ({admin_authority_v2_inner_mod_hash().hex()})"
        )
    args_list = list(args.as_iter())
    if len(args_list) != 10:
        raise ValueError(
            f"v2 inner puzzle has wrong number of curried args: "
            f"expected 10, got {len(args_list)}"
        )
    return AdminAuthorityV2State(
        self_mod_hash=bytes32(args_list[0].atom),
        max_admins=int(args_list[1].as_int()),
        max_keys_per_admin=int(args_list[2].as_int()),
        cooldown_blocks=int(args_list[3].as_int()),
        recovery_timeout_blocks=int(args_list[4].as_int()),
        pgt_governance_puzzle_hash=bytes32(args_list[5].atom),
        mips_root_hash=bytes32(args_list[6].atom),
        admins_hash=bytes32(args_list[7].atom),
        pending_ops_hash=bytes32(args_list[8].atom),
        authority_version=int(args_list[9].as_int()),
    )


def build_key_remove_emergency_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    admin_idx: int,
    approving_member_reveal: Program,
    approving_member_solution: Program,
    removed_member_hash: bytes32,
    current_block_height: int,
) -> Program:
    """Build the solution for a KEY_REMOVE_EMERGENCY spend (tag 0x06).

    Single-leaf authority + long cooldown (RECOVERY_TIMEOUT_BLOCKS).
    Use case: \"I lost my passkey, please remove the passkey eventually.\"
    The long cooldown gives a vigilant compromised-key attacker time
    to be vetoed by other leaves before the removal lands.

    Compared to KEY_REMOVE_QUORUM (which requires m_within co-signers
    but is instant), this trades immediacy for single-key UX. Admins
    with only one leaf cannot use this — I-2 invariant prevents
    emptying the OneOfN.

    State changes:
      - admins_list unchanged at PROPOSE time. Removal happens at
        ACTIVATE time (tag 0x03 with op_kind=OP_KIND_REMOVE).
      - A new pending REMOVE op appended with
        activates_at = current_block_height + RECOVERY_TIMEOUT_BLOCKS.
    """
    return Program.to(
        [
            SPEND_KEY_REMOVE_EMERGENCY,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                [p.to_program() for p in current_pending_ops],
                admin_idx,
                approving_member_reveal,
                approving_member_solution,
                removed_member_hash,
                current_block_height,
            ],
        ]
    )


def build_key_remove_quorum_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    admin_idx: int,
    removed_member_hash: bytes32,
    approving_pairs: Sequence[tuple[Program, Program]],
) -> Program:
    """Build the solution for a KEY_REMOVE_QUORUM spend (tag 0x05).

    Removing a leaf is destructive (lockout-risking); this spend
    requires m_within distinct co-signers from the SAME admin's OneOfN.
    A compromised key alone cannot remove other keys (T-KEY-3
    mitigation in design doc threat model).

    Args:
        approving_pairs: list of (member_reveal, member_solution)
            cons-pairs. Must contain at least m_within DISTINCT members
            of the affected admin's leaves; duplicates are rejected by
            the on-chain aggregator.
    """
    # Construct cons-pairs as Programs. Each pair is (reveal . solution),
    # which Program.to((reveal, solution)) builds correctly.
    pairs_program = Program.to(
        [(reveal, solution) for reveal, solution in approving_pairs]
    )
    return Program.to(
        [
            SPEND_KEY_REMOVE_QUORUM,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                admin_idx,
                removed_member_hash,
                pairs_program,
            ],
        ]
    )


def build_key_add_veto_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    admin_idx: int,
    approving_member_reveal: Program,
    approving_member_solution: Program,
    target_member_hash: bytes32,
    activates_at: int,
) -> Program:
    """Build the solution for a KEY_ADD_VETO spend (tag 0x04).

    Wide authority — ANY leaf of the affected admin's OneOfN can veto a
    pending ADD. This maximises the chance a legitimate user catches a
    malicious add during cooldown: even if the attacker compromised the
    leaf used at PROPOSE, the user's other leaves can still cancel.

    Args:
        target_member_hash: the leaf whose pending ADD is being cancelled
            (must match what was stored at PROPOSE).
        activates_at: cooldown end height (must match stored pending op).
    """
    return Program.to(
        [
            SPEND_KEY_ADD_VETO,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                [p.to_program() for p in current_pending_ops],
                admin_idx,
                approving_member_reveal,
                approving_member_solution,
                target_member_hash,
                activates_at,
            ],
        ]
    )


def build_key_add_propose_solution(
    *,
    my_amount: int,
    new_authority_version: int,
    current_admins: Sequence[AdminRecord],
    current_pending_ops: Sequence[PendingOp],
    admin_idx: int,
    approving_member_reveal: Program,
    approving_member_solution: Program,
    new_member_hash: bytes32,
    current_block_height: int,
) -> Program:
    """Build the solution for a KEY_ADD_PROPOSE spend (tag 0x02).

    The shim verifies the approving member is in the affected admin's
    OneOfN, runs the member to capture its emitted signature conditions,
    binds the spend's confirmation to ``[current_block_height,
    current_block_height + PROPOSE_WINDOW)`` via height assertions,
    then appends a new pending ADD op with
    ``activates_at = current_block_height + COOLDOWN_BLOCKS``.

    The signature-binding to the rotation intent is the off-chain
    builder's responsibility: the ``approving_member_solution`` should
    be constructed such that the member's signature targets exactly
    ``sha256(admin_idx . OP_KIND_ADD . new_member_hash . activates_at)``.
    For testing the puzzle's structural behaviour (not signature
    cryptography), any solution that produces emittable conditions is
    fine.

    Args:
        my_amount: singleton coin amount.
        new_authority_version: strictly > current.
        current_admins: revealed full admins list whose sha256tree must
            match the curried ADMINS_HASH.
        current_pending_ops: revealed full pending-ops list whose
            sha256tree must match the curried PENDING_KEY_OPS_HASH.
        admin_idx: which admin slot is gaining the leaf.
        approving_member_reveal: puzzle reveal of one leaf in admin's
            OneOfN whose tree hash is in that admin's leaves list.
        approving_member_solution: solution to run against the member.
        new_member_hash: 32-byte tree hash of the member to be added.
        current_block_height: user-claimed block height; the puzzle
            binds confirmation to this value via ASSERT_HEIGHT_ABSOLUTE
            + ASSERT_BEFORE_HEIGHT_ABSOLUTE so a malicious caller can't
            choose a stale value to bypass the cooldown.
    """
    return Program.to(
        [
            SPEND_KEY_ADD_PROPOSE,
            my_amount,
            new_authority_version,
            [
                [a.to_program() for a in current_admins],
                [p.to_program() for p in current_pending_ops],
                admin_idx,
                approving_member_reveal,
                approving_member_solution,
                new_member_hash,
                current_block_height,
            ],
        ]
    )
