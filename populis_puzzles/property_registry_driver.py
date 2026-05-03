"""Python driver for property_registry_inner.clsp (A.4).

The property-registry singleton is an append-only on-chain log of
canonicalised property identifiers.  It pairs with the A.1 mint
proposal singleton: a mint cannot be APPROVED for a property whose
registration has not been recorded on-chain (the A.1 puzzle
ASSERT_PUZZLE_ANNOUNCEMENT-s the registration announcement emitted
here).

Phase 3 V1 scope:
  * Append-only log; replay protection via monotonic version (which
    doubles as the registered-count).
  * Governance-gated registrations (single AGG_SIG_ME from GOV_PUBKEY).
  * Off-chain consumers index the announcements to build a full
    registered-property set.

Phase 3.5 work (deferred):
  * Extend curried state with a sorted-Merkle-tree root of registered
    property ids and require non-membership proofs on registration,
    making duplicate registrations consensus-impossible.

What this module exposes:
  * ``canonicalise_property_id`` — the on-chain ↔ off-chain canonical
    form contract; mirrors ``MintProposalStore.create``.
  * ``compute_signing_message`` — what GOV_PUBKEY's AGG_SIG_ME binds.
  * ``make_inner_puzzle`` / ``make_inner_puzzle_hash``.
  * ``parse_inner_puzzle`` — recover typed state.
  * ``build_registration_spend`` — solution + signing message.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from populis_puzzles import load_puzzle


_PROPERTY_REGISTRY_INNER_MOD: Program | None = None


def property_registry_inner_mod() -> Program:
    """Return the compiled (uncurried) ``property_registry_inner.clsp`` Program."""
    global _PROPERTY_REGISTRY_INNER_MOD
    if _PROPERTY_REGISTRY_INNER_MOD is None:
        _PROPERTY_REGISTRY_INNER_MOD = load_puzzle("property_registry_inner.clsp")
    return _PROPERTY_REGISTRY_INNER_MOD


def property_registry_inner_mod_hash() -> bytes32:
    """Tree hash of the uncurried inner mod (used as ``SELF_MOD_HASH`` curried arg)."""
    return bytes32(property_registry_inner_mod().get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Canonicalisation — the off-chain ↔ on-chain form contract.
# ─────────────────────────────────────────────────────────────────────────


def canonicalise_property_id(human_id: str) -> bytes32:
    """Convert a human-typed property identifier into the canonical
    on-chain form.

    Pipeline:

        human_id  ──strip()──►  ──upper()──►  utf8 encode  ──sha256──►  bytes32

    The strip-and-upper canonicalisation matches the off-chain
    ``MintProposalStore.create`` (POP-CANON-014 fix) so the same human
    string always maps to the same bytes32 regardless of casing or
    surrounding whitespace.

    The sha256 step is what makes the result a fixed-length bytes32
    suitable for use as the ``property_id_canon`` puzzle parameter and
    the announcement message body.

    Args:
        human_id: The user-typed property identifier string.

    Returns:
        Deterministic bytes32 derived from the canonicalised human id.
    """
    canon = human_id.strip().upper()
    return bytes32(hashlib.sha256(canon.encode("utf-8")).digest())


# ─────────────────────────────────────────────────────────────────────────
# Signing message.
# ─────────────────────────────────────────────────────────────────────────


def compute_signing_message(
    property_id_canon: bytes32,
    new_registry_version: int,
) -> bytes32:
    """The message GOV_PUBKEY's AGG_SIG_ME binds to.

    Mirrors the on-chain ``signing-message`` defun in
    ``property_registry_inner.clsp``.  Binding to BOTH the property id
    AND the new version means a stolen signature from one registration
    cannot be replayed against a different property OR a different
    version slot.
    """
    msg_program = Program.to([property_id_canon, new_registry_version])
    return bytes32(msg_program.get_tree_hash())


# ─────────────────────────────────────────────────────────────────────────
# Inner puzzle construction.
# ─────────────────────────────────────────────────────────────────────────


def make_inner_puzzle(
    gov_pubkey: bytes,
    registry_version: int,
) -> Program:
    """Curry the inner puzzle for a specific registry state.

    Currying order MUST match ``property_registry_inner.clsp``:

        SELF_MOD_HASH, GOV_PUBKEY, REGISTRY_VERSION
    """
    if len(gov_pubkey) != 48:
        raise ValueError(
            f"gov_pubkey must be 48 bytes (BLS G1), got {len(gov_pubkey)}"
        )
    if registry_version < 0:
        raise ValueError(
            f"registry_version must be ≥ 0, got {registry_version}"
        )
    return property_registry_inner_mod().curry(
        property_registry_inner_mod_hash(),
        gov_pubkey,
        registry_version,
    )


def make_inner_puzzle_hash(
    gov_pubkey: bytes,
    registry_version: int,
) -> bytes32:
    """Tree hash of the curried inner puzzle."""
    return bytes32(
        make_inner_puzzle(
            gov_pubkey=gov_pubkey,
            registry_version=registry_version,
        ).get_tree_hash()
    )


# ─────────────────────────────────────────────────────────────────────────
# State parsing.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PropertyRegistryState:
    """Decoded state of a property-registry singleton."""

    self_mod_hash: bytes32
    gov_pubkey: bytes
    registry_version: int


def parse_inner_puzzle(curried_inner_puzzle: Program) -> PropertyRegistryState:
    """Decompose a curried inner puzzle back into typed state."""
    uncurried = curried_inner_puzzle.uncurry()
    if uncurried is None:
        raise ValueError("puzzle is not curried; cannot parse state")
    mod, args = uncurried
    if bytes32(mod.get_tree_hash()) != property_registry_inner_mod_hash():
        raise ValueError(
            "puzzle reveal does not instantiate property_registry_inner.clsp; "
            f"mod_hash={mod.get_tree_hash().hex()} expected="
            f"{property_registry_inner_mod_hash().hex()}"
        )
    args_list = list(args.as_iter())
    if len(args_list) != 3:
        raise ValueError(
            f"property_registry_inner expects 3 curried args, got {len(args_list)}"
        )
    self_mod_hash = bytes32(args_list[0].as_atom())
    gov_pubkey = bytes(args_list[1].as_atom())
    registry_version = int(args_list[2].as_int())
    if len(gov_pubkey) != 48:
        raise ValueError(
            f"gov_pubkey must be 48 bytes (BLS G1), got {len(gov_pubkey)}"
        )
    return PropertyRegistryState(
        self_mod_hash=self_mod_hash,
        gov_pubkey=gov_pubkey,
        registry_version=registry_version,
    )


# ─────────────────────────────────────────────────────────────────────────
# Registration spend.
# ─────────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RegistrationSpendArtifacts:
    """Bundle of artifacts an operator needs to drive a registration spend."""

    inner_solution: Program
    new_inner_puzzle_hash: bytes32
    agg_sig_me_message: bytes32
    """What GOV_PUBKEY signs (the result of :func:`compute_signing_message`)."""
    announcement_message: bytes
    """Full announcement body — ``PROTOCOL_PREFIX (0x50) || property_id_canon``.

    Other coins ASSERT_PUZZLE_ANNOUNCEMENT this exact bytes value to
    confirm a property registration on-chain.
    """


def build_registration_spend(
    *,
    current: PropertyRegistryState,
    property_id_canon: bytes32,
    my_amount: int,
) -> RegistrationSpendArtifacts:
    """Construct the inner-puzzle solution + signing message.

    The puzzle on-chain enforces ``new_registry_version == REGISTRY_VERSION + 1``;
    we replicate that here so callers fail fast in Python.

    Args:
        current: pre-registration state (from :func:`parse_inner_puzzle`).
        property_id_canon: bytes32 produced by :func:`canonicalise_property_id`.
        my_amount: singleton coin amount (must be odd).

    Returns:
        :class:`RegistrationSpendArtifacts`.
    """
    if len(property_id_canon) != 32:
        raise ValueError(
            f"property_id_canon must be 32 bytes, got {len(property_id_canon)}"
        )
    if my_amount % 2 == 0:
        raise ValueError(
            f"singleton amount must be odd (got {my_amount})"
        )

    new_registry_version = current.registry_version + 1
    agg_sig_me_message = compute_signing_message(
        property_id_canon=property_id_canon,
        new_registry_version=new_registry_version,
    )
    new_inner_puzzle_hash = make_inner_puzzle_hash(
        gov_pubkey=current.gov_pubkey,
        registry_version=new_registry_version,
    )
    inner_solution = Program.to(
        [
            my_amount,
            property_id_canon,
            new_registry_version,
        ]
    )
    # PROTOCOL_PREFIX is 0x50 (matches utility_macros.clib).
    announcement_message = b"\x50" + bytes(property_id_canon)
    return RegistrationSpendArtifacts(
        inner_solution=inner_solution,
        new_inner_puzzle_hash=new_inner_puzzle_hash,
        agg_sig_me_message=agg_sig_me_message,
        announcement_message=announcement_message,
    )


__all__ = [
    "PropertyRegistryState",
    "RegistrationSpendArtifacts",
    "build_registration_spend",
    "canonicalise_property_id",
    "compute_signing_message",
    "make_inner_puzzle",
    "make_inner_puzzle_hash",
    "parse_inner_puzzle",
    "property_registry_inner_mod",
    "property_registry_inner_mod_hash",
]
