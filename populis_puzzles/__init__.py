"""Populis Protocol puzzle loader with integrity verification.

Compiles .clsp files on first access and caches them. Provides a SHA256
checksum over all compiled puzzle tree hashes so that downstream code can
detect accidental or malicious corruption of the deployed puzzles.

Usage:
    from populis_puzzles import load_puzzle, verify_puzzle_checksum

    pool_mod = load_puzzle("pool_singleton_inner.clsp")
    verify_puzzle_checksum()  # raises PuzzleIntegrityError on mismatch
"""
from __future__ import annotations

import hashlib
import logging
from typing import Dict, Optional

from chia.types.blockchain_format.program import Program
from chia.wallet.puzzles.load_clvm import load_clvm

logger = logging.getLogger(__name__)

# ── All contract filenames in canonical order (determines checksum) ──
PUZZLE_FILENAMES = (
    "singleton_launcher_with_did.clsp",
    "smart_deed_inner.clsp",
    "vault_singleton_inner.clsp",
    "p2_vault.clsp",
    "p2_pool.clsp",
    "pool_token_tail.clsp",
    "pool_singleton_inner.clsp",
    "governance_singleton_inner.clsp",
    "quorum_did_inner.clsp",
    "mint_offer_delegate.clsp",
    "purchase_payment.clsp",
    "p2_deed_settlement.clsp",
    "pgt_tail.clsp",
    "pgt_free_inner.clsp",
    "pgt_locked_inner.clsp",
    # A.3 — protocol_config singleton, replaces 3 off-chain env-var trust roots.
    "protocol_config_inner.clsp",
    # A.2 — admin_authority singleton, replaces POPULIS_ADMIN_PUBKEY_ALLOWLIST
    # + JWT secret with m-of-n quorum on-chain rotation.
    "admin_authority_inner.clsp",
    # A.4 — property_registry singleton; append-only on-chain log of
    # registered property ids, paired with the A.1 mint_proposal singleton.
    "property_registry_inner.clsp",
    # A.1 — mint_proposal singleton; per-proposal state machine
    # (DRAFT → APPROVED → CANCELLED) replacing MintProposalStore.
    "mint_proposal_inner.clsp",
)

# ── Frozen checksum — update after every intentional puzzle change ──
# Set to None to skip verification (development mode).
# Generate with: python -c "from populis_puzzles import compute_puzzles_checksum; print(compute_puzzles_checksum())"
# Refrozen after the POP-CANON-017 + POP-CANON-018 hardening landed:
#   - admin_authority_inner: added all-bls-g1-pubkeys + has-no-duplicates
#     guards against ALLOWLIST and new_allowlist.
#   - mint_proposal_inner: added is-size-bls-g1 guards on OWNER_PUBKEY
#     and GOV_PUBKEY.
#   - protocol_config_inner: added is-size-bls-g1 guard on GOV_PUBKEY.
#   - property_registry_inner: added is-size-bls-g1 guard on GOV_PUBKEY.
# All four A.x puzzles' mod hashes therefore changed; the new values
# are pinned in the corresponding driver caches and API singletons.py.
FROZEN_CHECKSUM: Optional[str] = (
    "c9b5741f1c729c0d1c08b51443c22fee907b27d466a83a773918bfbc253f14a8"
)

# ── Cache ──
_puzzle_cache: Dict[str, Program] = {}


class PuzzleIntegrityError(Exception):
    """Raised when compiled puzzle checksums do not match the frozen value."""
    pass


def load_puzzle(filename: str) -> Program:
    """Load and cache a compiled Chialisp puzzle by filename."""
    if filename not in _puzzle_cache:
        _puzzle_cache[filename] = load_clvm(
            filename,
            package_or_requirement="populis_puzzles",
            recompile=True,
        )
    return _puzzle_cache[filename]


def compute_puzzles_checksum() -> str:
    """Compute a SHA256 checksum over all puzzle tree hashes in canonical order.

    Returns the hex-encoded digest string.
    """
    h = hashlib.sha256()
    for filename in PUZZLE_FILENAMES:
        mod = load_puzzle(filename)
        h.update(bytes(mod.get_tree_hash()))
    return h.hexdigest()


def verify_puzzle_checksum() -> None:
    """Verify compiled puzzles against the frozen checksum.

    Raises PuzzleIntegrityError if the checksums do not match.
    Does nothing if FROZEN_CHECKSUM is None (development mode).
    """
    if FROZEN_CHECKSUM is None:
        logger.debug("Puzzle integrity check skipped (FROZEN_CHECKSUM is None)")
        return

    actual = compute_puzzles_checksum()
    if actual != FROZEN_CHECKSUM:
        raise PuzzleIntegrityError(
            f"Puzzle integrity check failed!\n"
            f"  Expected: {FROZEN_CHECKSUM}\n"
            f"  Actual:   {actual}\n"
            f"  This may indicate corrupted or tampered puzzle files."
        )
    logger.debug("Puzzle integrity check passed: %s", actual)
