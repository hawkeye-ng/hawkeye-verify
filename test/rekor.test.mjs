// Rekor checks against a real entry: anchor #1395 from hawkeye.com.ng as logged in the public
// Sigstore Rekor log. Every check has a control that changes one thing and must fail.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  checkCheckpoint, checkHashedRekord, checkInclusion, checkSignedEntryTimestamp, logIdOf,
} from '../src/rekor.mjs';

const F = JSON.parse(fs.readFileSync(new URL('./fixtures/anchor-1395.json', import.meta.url), 'utf8'));
const entry = () => JSON.parse(JSON.stringify(F.rekorEntry));
const flipHex = (h, at = 10) => h.slice(0, at) + (h[at] === 'a' ? 'b' : 'a') + h.slice(at + 1);

test('the Rekor key is the key of the log that holds the entry', async () => {
  assert.equal(await logIdOf(F.rekorPublicKey), F.rekorEntry.logID);
});

test('hashedrekord: the artifact, the hash, the site key and the signature agree', async () => {
  const r = await checkHashedRekord(entry(), { artifact: F.anchor.artifact, publicKeyPem: F.sitePublicKey });
  assert.deepEqual(r.problems, []);
  assert.equal(r.ok, true);
});

test('hashedrekord controls: one changed character, or another key, fails', async () => {
  const edited = F.anchor.artifact.replace('entries=0', 'entries=1');
  assert.notEqual(edited, F.anchor.artifact);
  assert.equal((await checkHashedRekord(entry(), { artifact: edited, publicKeyPem: F.sitePublicKey })).ok, false);
  assert.equal((await checkHashedRekord(entry(), { artifact: F.anchor.artifact, publicKeyPem: F.rekorPublicKey })).ok, false);
});

test('inclusion proof folds to the tree root; a changed proof node does not', async () => {
  assert.equal((await checkInclusion(entry())).ok, true);
  const e = entry();
  e.verification.inclusionProof.hashes[3] = flipHex(e.verification.inclusionProof.hashes[3]);
  assert.equal((await checkInclusion(e)).ok, false);
  const moved = entry();
  moved.verification.inclusionProof.logIndex += 1;
  assert.equal((await checkInclusion(moved)).ok, false);
});

test('checkpoint is signed by Rekor and names the proof root; a changed root does not verify', async () => {
  const good = await checkCheckpoint(entry(), F.rekorPublicKey);
  assert.deepEqual(good.problems, []);
  const e = entry();
  e.verification.inclusionProof.rootHash = flipHex(e.verification.inclusionProof.rootHash);
  assert.equal((await checkCheckpoint(e, F.rekorPublicKey)).ok, false);
  const forged = entry();
  forged.verification.inclusionProof.checkpoint = forged.verification.inclusionProof.checkpoint.replace(/\n(\d+)\n/, (m, n) => `\n${Number(n) + 1}\n`);
  forged.verification.inclusionProof.treeSize += 1;
  assert.equal((await checkCheckpoint(forged, F.rekorPublicKey)).ok, false);
});

test('signed entry timestamp verifies; a back-dated time does not', async () => {
  const good = await checkSignedEntryTimestamp(entry(), F.rekorPublicKey);
  assert.deepEqual(good.problems, []);
  const e = entry();
  e.integratedTime -= 86400;
  assert.equal((await checkSignedEntryTimestamp(e, F.rekorPublicKey)).ok, false);
});
