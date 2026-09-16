// The ledger is an append-only hash chain. Every accepted report's entry_hash commits to
// everything before it:
//
//   entry_hash = sha256(prev_hash + ledger_payload)     (hex strings, UTF-8, concatenated)
//
// starting from the all-zero genesis hash. Change, remove or reorder any entry and every
// hash after it stops matching.
import { sha256hex } from './crypto.mjs';

export const GENESIS = '0'.repeat(64);
/** The practice chain starts from a different genesis, so it can never pass for the real one. */
export const PRACTICE_GENESIS = 'p'.repeat(64);

export const entryHash = (prevHash, ledgerPayload) => sha256hex(prevHash + ledgerPayload);

/**
 * Checks a run of consecutive entries ({ id, prev_hash, ledger_payload, entry_hash }).
 * Pass `prev` (the head so far) and `count` to continue across pages. `onEntry(head, count)`
 * is called after each good entry, so a caller can note the head at a given length.
 */
export async function verifyChain(entries, { genesis = GENESIS, prev = genesis, count = 0, onEntry } = {}) {
  let head = prev;
  let n = count;
  for (const e of entries) {
    if (e.prev_hash !== head) {
      return { ok: false, brokenAtId: e.id, reason: 'prev_hash is not the previous entry_hash', entries: n, head };
    }
    if ((await entryHash(head, e.ledger_payload)) !== e.entry_hash) {
      return { ok: false, brokenAtId: e.id, reason: 'entry_hash is not sha256(prev_hash + ledger_payload)', entries: n, head };
    }
    head = e.entry_hash;
    n += 1;
    if (onEntry) onEntry(head, n);
  }
  return { ok: true, entries: n, head };
}
