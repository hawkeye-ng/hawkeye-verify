// Each anchor batches every race into one Merkle root, so a single Rekor entry fixes all
// of them while any one race can still be checked on its own.
//
//   race leaf  = sha256("race|v1|" + raceKey + "|" + raceHead + "|" + entries)
//   node       = sha256(left + right)                  (hex strings concatenated)
//   odd level  = the last node is paired with itself
//   no races   = a root of 64 zeros
//
// A race's head folds that race's entry hashes in ledger order, from the genesis hash:
// head = sha256(head + entry_hash).
import { sha256hex } from './crypto.mjs';

export const EMPTY_ROOT = '0'.repeat(64);

export const raceLeaf = ({ raceKey, head, entries }) => sha256hex(`race|v1|${raceKey}|${head}|${entries}`);

export async function merkleRoot(leaves) {
  if (!leaves.length) return EMPTY_ROOT;
  let level = leaves.slice();
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(await sha256hex(level[i] + (i + 1 < level.length ? level[i + 1] : level[i])));
    }
    level = next;
  }
  return level[0];
}

/** Folds an inclusion proof ([{ hash, side: 'left'|'right' }]) from a leaf up to a root. */
export async function foldProof(leaf, proof) {
  let h = leaf;
  for (const step of proof) {
    if (step.side === 'left') h = await sha256hex(step.hash + h);
    else if (step.side === 'right') h = await sha256hex(h + step.hash);
    else throw new Error(`proof step has no side: ${JSON.stringify(step)}`);
  }
  return h;
}

/**
 * One race, checked alone: the leaf must be what its key, head and count say, and the proof
 * must fold that leaf to the root. `d` is the shape GET /api/anchors/:id/races/:raceKey returns.
 */
export async function verifyRaceProof(d, expectedRoot = d.racesRoot) {
  const leaf = await raceLeaf(d);
  const leafOk = leaf === d.leaf;
  const root = await foldProof(leaf, d.proof);
  return { ok: leafOk && root === expectedRoot, leafOk, rootOk: root === expectedRoot, leaf, root };
}

/**
 * Every race in an anchor, rebuilt: `races` is [{ race_key, race_head, entries, leaf_index }]
 * as GET /api/anchors/:id/races returns them. The rebuilt root must equal the anchored root.
 */
export async function verifyAllRaces(races, expectedRoot) {
  const ordered = [...races].sort((a, b) => a.leaf_index - b.leaf_index);
  const outOfPlace = ordered.findIndex((r, i) => r.leaf_index !== i);
  const sorted = ordered.every((r, i) => i === 0 || ordered[i - 1].race_key < r.race_key);
  const leaves = await Promise.all(ordered.map((r) => raceLeaf({ raceKey: r.race_key, head: r.race_head, entries: r.entries })));
  const root = await merkleRoot(leaves);
  return { ok: root === expectedRoot && outOfPlace === -1 && sorted, root, races: ordered.length, contiguous: outOfPlace === -1, sorted };
}
