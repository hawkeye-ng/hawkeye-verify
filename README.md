# hawkeye-verify

Check Hawkeye's election-results ledger yourself, without trusting Hawkeye.

[Hawkeye](https://hawkeye.com.ng) collects polling-unit results from observers in Nigeria.
Every accepted report goes into a hash chain. The chain's head is signed and published to
[Sigstore Rekor](https://docs.sigstore.dev/logging/overview/), a public transparency log that
Hawkeye does not run. This tool checks that record end to end from the outside. It has no
dependencies and runs on Node 20 or later. The checks themselves use only WebCrypto, so they
also run in a browser.

```bash
git clone https://github.com/hawkeye-ng/hawkeye-verify && cd hawkeye-verify
node bin/hawkeye-verify.mjs
```

```
  ✔ The site shows the same figures it anchored
  ✔ Rekor holds this exact artifact, signed with the site's anchor key
  ✔ Logged when the site says
  ✔ The entry is inside Rekor's Merkle tree
  ✔ Rekor signed that tree
  ✔ Rekor signed the time it logged the entry
  ✔ Every race folds to the anchored root
  ✔ The ledger replays to the anchored head
  ✔ The practice chain replays to its anchored head

Result: VERIFIED (9 passed)
```

**Exit codes:**
- `0`: verified.
- `1`: a check failed.
- `2`: the run could not finish, for example because the network failed.

**Options:**
- `--anchor <id>` checks an older anchor.
- `--race <key>` also checks one race on its own.
- `--no-chain` skips replaying the ledger.
- `--rekor-key <pem>` pins Rekor's public key instead of fetching it.
- `--json` prints a machine-readable report.
- `--site <url>` points the tool at another deployment.

## What each check proves

| Check | What it rules out |
|---|---|
| The site shows the same figures it anchored | The site showing you numbers other than the ones it signed and logged |
| Rekor holds this exact artifact, signed with the site's anchor key | An anchor invented after the fact, or signed by someone else |
| Logged when the site says | Back-dating: Rekor sets the time, not Hawkeye |
| The entry is inside Rekor's Merkle tree | An entry Rekor shows but never put in its log |
| Rekor signed that tree, and the time it logged the entry | A forged Rekor response |
| Every race folds to the anchored root | A race's record changed after it was anchored |
| The ledger replays to the anchored head | Any report edited, removed or reordered since that anchor |

Rekor is append-only and public. So a Hawkeye database restored from an old backup, or
quietly edited, can no longer reproduce a head that was already logged. That mismatch is what
these checks look for.

## The formats

All hashes are SHA-256, written as lowercase hex.

- **Ledger entry:** `entry_hash = sha256(prev_hash + ledger_payload)`.
  - The chain starts from 64 zeros. The practice chain starts from 64 `p`s, so a rehearsal can never pass for the real ledger.
  - Entries are served in order by `GET /api/ledger/entries?sinceId=<id>&limit=1000`.
- **Race head:** fold that race's entry hashes in ledger order, from 64 zeros: `head = sha256(head + entry_hash)`.
- **Race leaf:** `sha256("race|v1|" + raceKey + "|" + head + "|" + entries)`.
  - Leaves are sorted by race key.
  - A node is `sha256(left + right)`. At an odd level, the last node pairs with itself.
  - With no races, the root is 64 zeros.
- **Anchor artifact:** one line, signed with ECDSA P-256 and logged as a Rekor `hashedrekord`.
  ```
  hawkeye-ledger-anchor|v1|election=…|day=…|head=…|entries=…|collationHead=…|collationEntries=…
  |racesRoot=…|races=…|docketHead=…|practiceHead=…|at=…
  ```
  Older anchors have fewer fields. `GET /api/anchors` lists every anchor with its artifact,
  its Rekor entry and the site's public key.
- **Rekor:**
  - The inclusion proof follows RFC 9162 §2.1.3.2.
  - The checkpoint is a signed note.
  - The signed entry timestamp covers canonical JSON of `body`, `integratedTime`, `logID` and `logIndex`.

## What this does not check

- **Who the observers are.** Each report is signed on the observer's own phone, but observer
  keys are not published, because that would make reports linkable to people. The chain
  proves reports were not changed after they were accepted. It does not prove who sent them.
- **The fraud checks.** How reports are screened is deliberately not public, so it cannot be
  tuned against. This tool checks the record, not the screening.
- **A reset ledger.** A new election cycle starts the ledger again from zero. An anchor from
  an earlier cycle still verifies in Rekor, but it cannot be replayed against today's ledger.
  The tool says so rather than passing it.
- **Rekor's key, by default.** The key is fetched from Rekor over HTTPS, and the tool checks
  that the log's ID matches it. To pin the key yourself, get it from Sigstore's trusted root
  and pass it with `--rekor-key`.

## As a library

```js
import { Site, verifyAnchor, verifyChain, verifyRaceProof } from './src/index.mjs';

const report = await verifyAnchor({ site: new Site('https://hawkeye.com.ng') });
console.log(report.ok, report.checks);
```

`npm test` runs the checks offline in two ways, and every check has a tampered control that must fail:
- against vectors produced by Hawkeye's own server code;
- against a real anchor and its Rekor entry.

## Licence and security

The code is MIT-licensed; see [LICENSE](LICENSE). The Hawkeye name and marks are not; see
[TRADEMARKS](https://github.com/HawkeyeNG/hawkeye/blob/main/TRADEMARKS.md).

Report vulnerabilities to **security@hawkeye.com.ng**.
