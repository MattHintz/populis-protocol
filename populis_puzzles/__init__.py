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
# Refrozen after the A.1..A.4 on-chain-migration series landed; covers
# all of the canonical puzzle set including protocol_config_inner,
# admin_authority_inner, property_registry_inner, mint_proposal_inner.
FROZEN_CHECKSUM: Optional[str] = (
    "ade1495f4efb3871c783766ced7c011428f4009d2ef401ff0a9f525331ba6447"
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
