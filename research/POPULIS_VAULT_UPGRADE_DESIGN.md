# Populis Vault Upgrade Design

Status: draft contract for implementation
Date: 2026-06-15

## Purpose

Populis vaults are permanent singletons. Their protocol parameters — the pool
reference, the zkPassport bridge policy hash, and the `vault_singleton_inner`
module itself — are curried at mint and are **immutable**. When the protocol
ships a new vault version (a new inner-puzzle module, or new canonical
parameters), existing vaults cannot change in place.

This document pins a **decentralized, backend-free** mechanism that lets the
admin (now) and an admin-authority/committee (later) publish a new canonical
vault version on chain, and lets any client:

1. Detect that a user's vault is outdated by reading the chain directly.
2. Offer the user a one-click upgrade that creates a new vault at the current
   version and migrates the old vault's contents into it.

An upgrade is offered **only when a new known vault version exists on chain.**

## Goals / Non-goals

Goals:

- **Decentralized.** Detection and upgrade read the chain directly
  (coinset.org). There is **no Populis backend dependency** in the detection or
  upgrade path.
- **On-chain version source of truth.** An upgrade is offered only when a new
  known vault version is advertised on chain.
- **Admin-published now, committee-governed later**, using the existing
  authority model (`protocol_config_inner.clsp` / `admin_authority_v2`).
- **One-click, client-side, non-custodial.** The user's wallet signs every
  spend; no backend holds keys or moves assets.

Non-goals:

- No automatic or forced upgrades. Users opt in.
- No retroactive in-place upgrade of already-deployed vaults — impossible,
  because curried params are immutable.
- No custodial migration.

## Motivating example

The zkPassport bridge-policy-hash bug (fixed in `populis_api` commit `a59bd02`)
minted vaults with a zero `ZKPASSPORT_BRIDGE_POLICY_HASH`, making them
permanently un-enrollable. Such vaults must be replaced by a new vault at the
correct parameters — exactly the upgrade flow this design enables.

## On-chain vault version registry (the version source)

A dedicated singleton `vault_version_registry_inner.clsp`, mirroring the proven
`protocol_config_inner.clsp` (A.3) state-machine pattern.

Curried immutable policy:

- `SELF_MOD_HASH` — for self-recurry on update.
- `GOV_PUBKEY` — BLS pubkey authorized to publish a new vault version. For now
  this is the admin's governance key; the design allows binding it to the
  `admin_authority_v2` quorum / committee later (same way `protocol_config`
  governance can be rotated to an authority).

Curried mutable state:

- `VAULT_INNER_MOD_HASH` — tree hash of the canonical current
  `vault_singleton_inner` module (the puzzle version).
- `CANONICAL_PARAMS_HASH` — `sha256tree` of the canonical curried vault params
  every new vault must use.
- `VAULT_VERSION` — uint64, **monotonically increasing**. Replay/downgrade
  guard, asserted strictly increasing on every update spend.

Canonical params hash (the immutable-at-mint params, excluding per-user
identity):

```text
CANONICAL_PARAMS_HASH = sha256tree(list
  POOL_SINGLETON_MOD_HASH
  POOL_LAUNCHER_ID
  POOL_SINGLETON_LAUNCHER_PUZZLE_HASH
  ZKPASSPORT_BRIDGE_POLICY_HASH)
```

Content hash and update spend (authorized exactly like `protocol_config`):

```text
content_hash(state) = sha256tree(list VAULT_INNER_MOD_HASH CANONICAL_PARAMS_HASH VAULT_VERSION)

On a valid publish-version spend:
  AGG_SIG_ME GOV_PUBKEY content_hash(new_state)
  CREATE_COIN new_inner_puzhash my_amount
  CREATE_PUZZLE_ANNOUNCEMENT (PROTOCOL_PREFIX || content_hash(new_state))
  assert (> new_VAULT_VERSION VAULT_VERSION)
```

Discovery: the registry singleton's launcher id is published in
`deployment_manifest.json` and the portal `environment.ts` as a public,
chain-anchored constant. Clients walk its lineage on coinset.org to read the
latest state — identical to how `protocol_config` is read today.

## Vault version identity & outdated detection (client-side, no backend)

A vault's **version identity** is the pair
`(vault_inner_mod_hash, canonical_params_hash)` it was minted with. The portal
already reconstructs a vault's curried params from chain (see
`zkpassport-vault-enrollment-spend.service.ts`).

A vault is **CURRENT** iff both hold:

- its `vault_inner_mod_hash` == `registry.VAULT_INNER_MOD_HASH`, and
- its `canonical_params_hash` == `registry.CANONICAL_PARAMS_HASH`.

Otherwise it is **OUTDATED**, and an upgrade to `registry.VAULT_VERSION` is
offered. Detection is pure: read the registry singleton + the user's live vault
coin from coinset.org, compute both hashes client-side, compare. **No backend.**

Existing vaults carry no explicit version number; comparison is by mod-hash +
params-hash, which works retroactively. Future vault modules MAY also curry an
explicit `VAULT_VERSION` for display.

## The upgrade transaction (create new + migrate contents)

Conceptually one user-signed operation:

1. **Launch a NEW vault singleton** at the canonical params (new launcher id),
   reusing the user's identity (owner pubkey, auth type, members root). The
   launcher spend is client-built (no backend) and funded by the user (or the
   faucet during alpha).
2. **Move the old vault's contents** to the new vault:
   - XCH and pool-share CATs (ungated, freely transferable) → sent to the new
     vault's `p2_vault` / owner address. Movable with existing puzzles.
   - Deeds held at `p2_vault` / deposited in the pool → require a new `migrate`
     spend case in `vault_singleton_inner.clsp` that authorizes sending the
     deed to the **new** vault's `p2_vault`. **This is a consensus change.**
3. The old vault is left empty (and, if a melt case is added later, may be
   melted to reclaim its mojo).

**Chicken-and-egg:** the `migrate` spend case can only be used by vaults that
were minted **with** it. Vaults minted before it (including the bridge-bug
vaults) can move only freely-transferable assets and must abandon the old
launcher. Therefore the `migrate` case must ship in the next vault module so
that all subsequent upgrades are seamless.

## Decentralization invariants

- **No Populis backend** participates in version detection or upgrade. The
  portal reads coinset.org directly and the wallet signs locally.
- The single trust root is the on-chain `vault_version_registry` singleton,
  authorized by `GOV_PUBKEY` (admin now → `admin_authority_v2` / committee
  later).
- An upgrade is offered **only** when the on-chain registry advertises a higher
  `VAULT_VERSION` (or a differing canonical identity) than the user's vault. No
  client-side or env-injected version can trigger an upgrade.
- Users opt in; nothing is forced or custodial.

## Phased brick plan

- **Brick 1 (this doc):** design contract + docs-contract test.
- **Brick 2 (protocol):** `vault_version_registry_inner.clsp` + driver + tests,
  mirroring `protocol_config_inner` (gov-authorized, monotonic version,
  content-hash, announcement).
- **Brick 3 (protocol, consensus-critical):** add a curried `VAULT_VERSION` and
  a `migrate` spend case to `vault_singleton_inner.clsp` (audited) that
  atomically sends the deed/position to a new vault launcher; recompile.
- **Brick 4 (api/protocol):** registry launch + admin publish-version helper;
  faucet mints new vaults at the canonical params/version.
- **Brick 5 (portal):** read the registry from chain (no backend), compute
  outdated detection, show an "Upgrade available" banner.
- **Brick 6 (portal):** one-click upgrade — build the new-vault launch +
  asset-migration spends client-side, wallet-signed.

## Open decisions

- Bind the registry `GOV_PUBKEY` to the `admin_authority_v2` quorum vs a
  standalone gov key (recommend: standalone now, committee-bound later).
- Whether to add a `melt`/reclaim case to empty old vaults.
- Faucet vs user funding for the new launcher coin during alpha.
