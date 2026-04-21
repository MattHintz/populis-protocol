# Populis Protocol

**A sketch architectural framework for tokenized real-world assets on Chia.**

Populis is an open-source protocol for issuing, pooling, and settling real-world asset (RWA) tokens entirely on-chain. No servers. No databases. No oracles. Just puzzles, singletons, and a full node.

> This is an early-stage architectural sketch — working code, passing tests, but not audited. Built in public to advance the conversation about what RWA infrastructure should look like on a UTXO chain.

---

## Why RWA Needs a New Stack

Existing tokenized real-world asset platforms share a common flaw: they inherit the trust assumptions of traditional finance and bolt them onto a blockchain. Centralized issuance servers, off-chain metadata, oracle-dependent pricing, custodial wallets, permissioned transfers.

The result is a system that is *on* a blockchain but not *of* a blockchain. Kill the server and the assets become unreachable. Revoke the API key and the tokens become worthless.

**Populis takes the opposite approach.** Every piece of state — asset metadata, pool balances, governance votes, settlement distributions — lives in the coin set. The protocol operates through puzzle evaluation alone. If every server in the world shuts down, a user with a full node can still locate, verify, and move their assets.

This is what RWA infrastructure looks like when you take the "decentralized" part seriously.

---

## Architecture at a Glance

```
                    ┌─────────────────────┐
                    │   Governance         │  Propose / vote / settle / freeze / mint
                    │   Singleton          │  Quorum-gated via DID
                    └────────┬────────────┘
                             │ CHIP-25 messages
                    ┌────────▼────────────┐
                    │   Pool              │  Central state machine
                    │   Singleton         │  Deposit / redeem / settlement / offers
                    └──┬──────────┬───────┘
                       │          │
              ┌────────▼──┐  ┌───▼──────────┐
              │ Smart Deed │  │ Pool Tokens  │
              │ (Gated NFT)│  │ (Free CATs)  │
              └────────────┘  └──────────────┘
```

### Core Contracts (12 Chialisp puzzles)

| Contract | Role |
|----------|------|
| `smart_deed_inner` | Gated RWA NFT — moves only through pool (deposit/redeem). All metadata curried on-chain. |
| `pool_singleton_inner` | Pool state machine — 5 spend cases. Manages TVL, deed count, token mint/melt, batch settlement, secondary offers. |
| `governance_singleton_inner` | On-chain governance — propose, settle, freeze, mint. Quorum-gated, no oracles. |
| `pool_token_tail` | Ungated CAT tail — freely tradable pool tokens. Mint/melt authorized by pool puzzle announcements. |
| `vault_singleton_inner` | Per-user vault singleton — holds deeds via escrow. |
| `p2_vault` / `p2_pool` | Escrow puzzles enforcing singleton-controlled custody. |
| `singleton_launcher_with_did` | DID-approved singleton launcher for deed minting. |
| `quorum_did_inner` | DID inner puzzle requiring governance message (quorum gate). |
| `mint_offer_delegate` | Eve deed inner — on-chain standing offer for primary purchase. |
| `purchase_payment` | Ephemeral payment enforcer — atomic purchase in a single block. |
| `p2_deed_settlement` | Settlement leaf puzzle — burn deed, receive XCH share (secure-the-bag pattern). |

### Key Design Decisions

- **Deeds are gated.** Smart Deeds cannot be freely transferred peer-to-peer. They move only through the pool (deposit/redeem) or via governance-approved settlement. This is intentional — RWA tokens need controlled transfer for regulatory compliance.
- **Tokens are free.** Pool tokens are standard Chia CATs. Trade them on any DEX, send them to any wallet. Liquidity lives in the token layer.
- **All metadata on-chain.** Par value, asset class, property ID, jurisdiction, royalty terms — all curried into the puzzle hash. No IPFS. No URLs. No off-chain lookups.
- **Batch settlement.** Governance approves a settlement, the pool creates a Merkle distribution tree (secure-the-bag pattern), and every deed holder receives their equal XCH share. One transaction settles an entire collection.
- **Zero server dependencies.** A Chia full node is the only infrastructure. No API servers, no databases, no webhooks.

---

## Project Structure

```
populis_protocol/
├── populis_puzzles/          # Core contract package
│   ├── *.clsp                # 12 Chialisp contracts
│   ├── *.clib                # 7 include libraries
│   ├── *.clsp.hex            # Pre-compiled (checksum-verified on import)
│   ├── settlement_splitxch.py # Distribution tree builder
│   └── __init__.py           # load_puzzle(), verify_puzzle_checksum()
├── tests/                    # 108 tests, ~1s execution
│   └── test_*.py             # Unit + integration + e2e simulation
└── pyproject.toml
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/MattHintz/populis-protocol.git
cd populis-protocol

# Setup
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests
pytest
```

**Requirements:** Python 3.10+, `chia-blockchain >= 2.3.0`

---

## Test Suite

108 tests covering every contract spend case, cross-contract message pairing, and a full 9-phase end-to-end lifecycle simulation:

1. Governance mint approval
2. DID-gated singleton launch
3. Primary purchase (atomic, single-block)
4. Vault deposit to pool
5. Token minting
6. Pool redeem
7. Secondary sale (on-chain offer)
8. Batch settlement (secure-the-bag)
9. Full round-trip lifecycle

All tests run via pure puzzle evaluation (`.run()` on curried programs). No SpendSim required for unit tests.

---

## The RWA Problem

Real-world assets are the largest addressable market for blockchain technology. Real estate alone is a $300+ trillion global asset class. But tokenized RWA today looks like this:

- **Centralized issuance** — A company mints tokens. If the company disappears, so do the tokens.
- **Off-chain metadata** — Token points to a URL. URL goes down, metadata is gone.
- **Oracle dependency** — Pricing requires an oracle feed. Oracle goes offline, settlement halts.
- **Permissioned custody** — Assets live in a custodial wallet. Custodian gets hacked, assets are compromised.
- **Regulatory theater** — Transfer restrictions bolted on at the application layer, trivially bypassable.

This architecture fails the most basic test of blockchain utility: **it doesn't survive the removal of trusted parties.**

## The Populis Thesis

RWA tokenization works when the protocol enforces the rules that matter — gated transfer, on-chain metadata, governance-approved settlement — at the puzzle level, not the application level.

On Chia's coin-set model, every constraint is part of the puzzle hash. You can't bypass transfer restrictions because they *are* the coin. You can't fake metadata because it's curried into the puzzle. You can't settle without governance because the pool puzzle requires a CHIP-25 message from the governance singleton.

**The enforcement layer is the consensus layer.** That's the point.

---

## What This Is (and Isn't)

**This is:**
- A working architectural sketch with 12 contracts and 108 passing tests
- An exploration of how RWA primitives compose on Chia's coin-set model
- Open-source infrastructure for the community to examine, critique, and build on
- A demonstration that fully on-chain RWA is possible without servers, oracles, or off-chain dependencies

**This is not:**
- Audited production code
- A finished product
- Financial advice or a token offering

---

## Roadmap

- [ ] Redemption pricing model (NAV-based vs fixed vs hybrid)
- [ ] Richer on-chain metadata schemas (yield, maturity, issuer, regulatory class)
- [ ] Governance-approved deed variants for different asset types
- [ ] Unwind-the-bag driver for post-settlement XCH distribution
- [ ] CAT-based purchase payments (replace XCH with stablecoins)
- [ ] Rate adjustment mechanism (governance-voted FP_SCALE changes)
- [ ] Secondary sale royalty enforcement (distinct deed spend case)
- [ ] Phase 2: direct wallet interaction (no vault requirement)

---

## Cross-Contract Communication

All inter-contract coordination uses **CHIP-25** (`SEND_MESSAGE 0x10` / `RECEIVE_MESSAGE 0x10`) for verified message passing, with `CREATE_PUZZLE_ANNOUNCEMENT` / `ASSERT_PUZZLE_ANNOUNCEMENT` for token authorization and deed release.

Every announcement is prefixed with `0x50` ("P") to namespace protocol messages from user-generated announcements. All contracts validate inputs with `is-uint64` and `is-size-b32` on every parameter.

Puzzle integrity is verified on import via SHA256 checksum of all compiled `.clsp.hex` files.

---

## Influences

- **[Chia Network](https://github.com/Chia-Network/chia-blockchain)** — Coin-set model, Chialisp, CATs, singletons, CHIP-25
- **[Solslot](https://github.com/solslot)** — Vault singletons, secure-the-bag settlement pattern, p2_nft_burn_or_delayed leaf puzzles

---

## License

Proprietary — All Rights Reserved.

Copyright (c) 2025-2026 Matthew S. Hintz. See [LICENSE](LICENSE) for the full
terms. No rights are granted to copy, modify, distribute, deploy, or
commercially use this Software without prior written permission from the
Author.

---

## Contributing

This repository is published for visibility only. Unsolicited pull requests
cannot be accepted under the current license terms. If you are interested in
collaborating or licensing the Software, please contact the Author.

```bash
# Run the full suite
pytest -v

# Check puzzle integrity
python -c "from populis_puzzles import verify_puzzle_checksum; verify_puzzle_checksum()"
```

---

*Built for a future where real-world assets don't need permission to exist on-chain.*
