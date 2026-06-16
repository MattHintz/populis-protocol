"""Python driver for vault_version_registry_inner.clsp (Brick 2).

The vault-version registry singleton publishes the canonical current vault
descriptor on-chain so any client can detect outdated vaults and offer a
decentralized, backend-free upgrade.  See
``research/POPULIS_VAULT_UPGRADE_DESIGN.md``.

Authorization is delegated to live singletons (the registry holds no key of its
own).  Per the resolved tiered governance model:

  * params-only FAST-TRACK  -> admin_authority_v2 quorum (code must be unchanged)
  * code-change ROUTINE     -> PGT proposal tracker EXECUTE (staked ratification)

The tier is an objective, CLVM-enforced property of the diff: the fast-track
spend case asserts the vault CODE hash (VAULT_INNER_MOD_HASH) is unchanged, so
a code change can never ship through the admin fast path.

This module mirrors ``protocol_config_driver.py``.  The matching tests in
``tests/test_vault_version_registry.py`` round-trip every function and assert
the off-chain content hash + announcement binding exactly equal the on-chain
CLVM behaviour.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.singleton_top_layer_v1_1 import (
    SINGLETON_LAUNCHER_HASH,
    SINGLETON_MOD_HASH,
)
from chia_rs.sized_bytes import bytes32

from populis_puzzles import load_puzzle


# ── Spend-case tags — MUST match the .clsp defconstants ─────────────────────
SPEND_PARAMS_FASTTRACK = 1
SPEND_CODE_ROUTINE = 2

# ── Approval path tags — MUST match the .clsp defconstants ──────────────────
TAG_FASTTRACK = bytes.fromhex("4654")  # "FT"
TAG_ROUTINE = bytes.fromhex("5254")  # "RT"

# ── Populis announcement namespace prefix (utility_macros.clib) ─────────────
PROTOCOL_PREFIX = bytes.fromhex("50")  # "P"

# Singletons use odd amounts to distinguish from regular coin lineage.
SINGLETON_AMOUNT = 1


# ── Module-level cache of the compiled program ──────────────────────────────
_VAULT_VERSION_REGISTRY_INNER_MOD: Program | None = None


def vault_version_registry_inner_mod() -> Program:
    """Return the compiled (uncurried) ``vault_version_registry_inner.clsp``."""
    global _VAULT_VERSION_REGISTRY_INNER_MOD
    if _VAULT_VERSION_REGISTRY_INNER_MOD is None:
        _VAULT_VERSION_REGISTRY_INNER_MOD = load_puzzle(
            "vault_version_registry_inner.clsp"
        )
    return _VAULT_VERSION_REGISTRY_INNER_MOD


def vault_version_registry_inner_mod_hash() -> bytes32:
    """Tree hash of the uncurried inner mod (SELF_MOD_HASH curried arg)."""
    return bytes32(vault_version_registry_inner_mod().get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Content hash — the off-chain <-> on-chain binding point.
# ─────────────────────────────────────────────────────────────────────────


def compute_content_hash(
    vault_inner_mod_hash: bytes32,
    canonical_params_hash: bytes32,
    vault_version: int,
) -> bytes32:
    """Deterministic hash of the registry state tuple.

    MUST match the on-chain ``content-hash`` defun in
    ``vault_version_registry_inner.clsp``.  The test suite enforces this by
    reading the value out of the puzzle's CREATE_PUZZLE_ANNOUNCEMENT.
    """
    return bytes32(
        Program.to(
            [vault_inner_mod_hash, canonical_params_hash, vault_version]
        ).get_tree_hash()
    )


# ─────────────────────────────────────────────────────────────────────────
# Inner puzzle construction.
# ─────────────────────────────────────────────────────────────────────────


def make_inner_puzzle(
    *,
    admin_authority_launcher_id: bytes32,
    governance_launcher_id: bytes32,
    vault_inner_mod_hash: bytes32,
    canonical_params_hash: bytes32,
    vault_version: int,
    singleton_mod_hash: bytes32 = bytes32(SINGLETON_MOD_HASH),
    launcher_puzzle_hash: bytes32 = bytes32(SINGLETON_LAUNCHER_HASH),
) -> Program:
    """Curry the inner puzzle for a specific registry state.

    Currying order MUST match ``vault_version_registry_inner.clsp``:

        SELF_MOD_HASH, SINGLETON_MOD_HASH, LAUNCHER_PUZZLE_HASH,
        ADMIN_AUTHORITY_LAUNCHER_ID, GOVERNANCE_LAUNCHER_ID,
        VAULT_INNER_MOD_HASH, CANONICAL_PARAMS_HASH, VAULT_VERSION
    """
    return vault_version_registry_inner_mod().curry(
        vault_version_registry_inner_mod_hash(),
        singleton_mod_hash,
        launcher_puzzle_hash,
        admin_authority_launcher_id,
        governance_launcher_id,
        vault_inner_mod_hash,
        canonical_params_hash,
        vault_version,
    )


def make_inner_puzzle_hash(**kwargs) -> bytes32:
    """Tree hash of the curried inner puzzle.  Forwards all kwargs."""
    return bytes32(make_inner_puzzle(**kwargs).get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# State parsing — recover typed state from an on-chain puzzle reveal.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class VaultVersionRegistryState:
    """Decoded state of a vault-version registry singleton.

    Mirrors the curried args of ``vault_version_registry_inner.clsp``.  The
    portal constructs one of these by calling :func:`parse_inner_puzzle` on the
    puzzle reveal it pulls from coinset.org, then compares
    ``vault_inner_mod_hash`` / ``canonical_params_hash`` against the user's live
    vault to decide whether an upgrade is available.
    """

    self_mod_hash: bytes32
    singleton_mod_hash: bytes32
    launcher_puzzle_hash: bytes32
    admin_authority_launcher_id: bytes32
    governance_launcher_id: bytes32
    vault_inner_mod_hash: bytes32
    canonical_params_hash: bytes32
    vault_version: int

    @property
    def content_hash(self) -> bytes32:
        """Recompute the content hash for this state."""
        return compute_content_hash(
            self.vault_inner_mod_hash,
            self.canonical_params_hash,
            self.vault_version,
        )


def parse_inner_puzzle(curried_inner_puzzle: Program) -> VaultVersionRegistryState:
    """Decompose a curried inner puzzle back into typed state.

    Strictly validates that the uncurried mod hashes back to our known module
    hash before returning state.

    Raises:
        ValueError: if the puzzle is not an instance of
            ``vault_version_registry_inner.clsp`` or any field is malformed.
    """
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != vault_version_registry_inner_mod_hash():
        raise ValueError(
            "puzzle reveal does not instantiate vault_version_registry_inner.clsp; "
            f"mod_hash={mod.get_tree_hash().hex()} expected="
            f"{vault_version_registry_inner_mod_hash().hex()}"
        )
    a = list(args.as_iter())
    if len(a) != 8:
        raise ValueError(
            f"vault_version_registry_inner expects 8 curried args, got {len(a)}"
        )
    state = VaultVersionRegistryState(
        self_mod_hash=bytes32(a[0].as_atom()),
        singleton_mod_hash=bytes32(a[1].as_atom()),
        launcher_puzzle_hash=bytes32(a[2].as_atom()),
        admin_authority_launcher_id=bytes32(a[3].as_atom()),
        governance_launcher_id=bytes32(a[4].as_atom()),
        vault_inner_mod_hash=bytes32(a[5].as_atom()),
        canonical_params_hash=bytes32(a[6].as_atom()),
        vault_version=int(a[7].as_int()),
    )
    return state


# ─────────────────────────────────────────────────────────────────────────
# Authorizer approval binding — what the authorizing singleton must announce.
# ─────────────────────────────────────────────────────────────────────────


def compute_approval_message(
    *,
    path_tag: bytes,
    vault_inner_mod_hash: bytes32,
    canonical_params_hash: bytes32,
    vault_version: int,
) -> bytes:
    """The message the authorizing singleton must CREATE_PUZZLE_ANNOUNCEMENT.

    ``PROTOCOL_PREFIX || path_tag || content_hash(new_state)``.  The admin
    authority (fast-track) or PGT proposal tracker (routine) emits exactly this
    from its quorum-authorized spend; the registry asserts a puzzle
    announcement keyed by it.
    """
    return (
        PROTOCOL_PREFIX
        + path_tag
        + bytes(
            compute_content_hash(
                vault_inner_mod_hash, canonical_params_hash, vault_version
            )
        )
    )


def compute_authorizer_announcement_id(
    *,
    authorizer_full_puzzle_hash: bytes32,
    path_tag: bytes,
    vault_inner_mod_hash: bytes32,
    canonical_params_hash: bytes32,
    vault_version: int,
) -> bytes32:
    """The ASSERT_PUZZLE_ANNOUNCEMENT id the registry emits.

    ``sha256(authorizer_full_puzzle_hash || approval_message)``.  Only a coin
    whose puzzle hash is ``authorizer_full_puzzle_hash`` (i.e. a real
    authorizer-lineage singleton) can satisfy it.
    """
    msg = compute_approval_message(
        path_tag=path_tag,
        vault_inner_mod_hash=vault_inner_mod_hash,
        canonical_params_hash=canonical_params_hash,
        vault_version=vault_version,
    )
    return bytes32(
        hashlib.sha256(bytes(authorizer_full_puzzle_hash) + msg).digest()
    )


# ─────────────────────────────────────────────────────────────────────────
# Publish spends — solution construction.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PublishSpendArtifacts:
    """Everything an operator needs to drive a publish spend.

    The driver stops short of building a full SpendBundle (which requires the
    singleton wrapper, lineage proof, and the co-spent authorizer).  The
    operator co-spends the authorizing singleton so that it emits
    ``CREATE_PUZZLE_ANNOUNCEMENT(approval_message)``.
    """

    inner_solution: Program
    """Solution to feed into the curried inner puzzle."""

    new_inner_puzzle_hash: bytes32
    """Tree hash of the next-state inner puzzle (CREATE_COIN destination)."""

    new_content_hash: bytes32
    """Public content_hash of the new state (published for off-chain readers)."""

    path_tag: bytes
    """Tier tag (FAST-TRACK or ROUTINE) bound into the approval message."""

    approval_message: bytes
    """The message the co-spent authorizing singleton must announce."""


def _build_publish(
    *,
    spend_case: int,
    current: VaultVersionRegistryState,
    authorizer_inner_puzzle_hash: bytes32,
    new_vault_inner_mod_hash: bytes32,
    new_canonical_params_hash: bytes32,
    new_vault_version: int,
    my_amount: int,
    path_tag: bytes,
) -> PublishSpendArtifacts:
    if new_vault_version <= current.vault_version:
        raise ValueError(
            "new_vault_version must strictly exceed current.vault_version "
            f"(got new={new_vault_version} current={current.vault_version})"
        )
    if my_amount % 2 == 0:
        raise ValueError(
            f"singleton amount must be odd (got {my_amount})"
        )
    for name, value in (
        ("authorizer_inner_puzzle_hash", authorizer_inner_puzzle_hash),
        ("new_vault_inner_mod_hash", new_vault_inner_mod_hash),
        ("new_canonical_params_hash", new_canonical_params_hash),
    ):
        if len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes, got {len(value)}")

    new_inner_puzzle_hash = make_inner_puzzle_hash(
        admin_authority_launcher_id=current.admin_authority_launcher_id,
        governance_launcher_id=current.governance_launcher_id,
        vault_inner_mod_hash=new_vault_inner_mod_hash,
        canonical_params_hash=new_canonical_params_hash,
        vault_version=new_vault_version,
        singleton_mod_hash=current.singleton_mod_hash,
        launcher_puzzle_hash=current.launcher_puzzle_hash,
    )
    new_content_hash = compute_content_hash(
        new_vault_inner_mod_hash, new_canonical_params_hash, new_vault_version
    )
    approval_message = compute_approval_message(
        path_tag=path_tag,
        vault_inner_mod_hash=new_vault_inner_mod_hash,
        canonical_params_hash=new_canonical_params_hash,
        vault_version=new_vault_version,
    )
    inner_solution = Program.to(
        [
            spend_case,
            my_amount,
            authorizer_inner_puzzle_hash,
            new_vault_inner_mod_hash,
            new_canonical_params_hash,
            new_vault_version,
        ]
    )
    return PublishSpendArtifacts(
        inner_solution=inner_solution,
        new_inner_puzzle_hash=new_inner_puzzle_hash,
        new_content_hash=new_content_hash,
        path_tag=path_tag,
        approval_message=approval_message,
    )


def build_fasttrack_spend(
    *,
    current: VaultVersionRegistryState,
    authorizer_inner_puzzle_hash: bytes32,
    new_canonical_params_hash: bytes32,
    new_vault_version: int,
    my_amount: int = SINGLETON_AMOUNT,
) -> PublishSpendArtifacts:
    """Params-only fast-track publish (admin_authority_v2 authorized).

    The vault CODE (``VAULT_INNER_MOD_HASH``) is preserved unchanged — the
    on-chain spend case asserts it, and we mirror that here by reusing
    ``current.vault_inner_mod_hash``.
    """
    return _build_publish(
        spend_case=SPEND_PARAMS_FASTTRACK,
        current=current,
        authorizer_inner_puzzle_hash=authorizer_inner_puzzle_hash,
        new_vault_inner_mod_hash=current.vault_inner_mod_hash,
        new_canonical_params_hash=new_canonical_params_hash,
        new_vault_version=new_vault_version,
        my_amount=my_amount,
        path_tag=TAG_FASTTRACK,
    )


def build_routine_spend(
    *,
    current: VaultVersionRegistryState,
    authorizer_inner_puzzle_hash: bytes32,
    new_vault_inner_mod_hash: bytes32,
    new_canonical_params_hash: bytes32,
    new_vault_version: int,
    my_amount: int = SINGLETON_AMOUNT,
) -> PublishSpendArtifacts:
    """Code-change routine publish (PGT proposal-tracker EXECUTE authorized)."""
    return _build_publish(
        spend_case=SPEND_CODE_ROUTINE,
        current=current,
        authorizer_inner_puzzle_hash=authorizer_inner_puzzle_hash,
        new_vault_inner_mod_hash=new_vault_inner_mod_hash,
        new_canonical_params_hash=new_canonical_params_hash,
        new_vault_version=new_vault_version,
        my_amount=my_amount,
        path_tag=TAG_ROUTINE,
    )
