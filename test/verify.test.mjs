// The whole run, offline: a stand-in site and Rekor serve the real anchor #1395, and the
// report must pass; then the stand-in site lies in the ways a dishonest operator could.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { Site } from '../src/site.mjs';
import { verifyAnchor } from '../src/verify.mjs';
import { PRACTICE_GENESIS } from '../src/chain.mjs';
import { sha256hex } from '../src/crypto.mjs';

const F = JSON.parse(fs.readFileSync(new URL('./fixtures/anchor-1395.json', import.meta.url), 'utf8'));

async function practiceRowsEndingAt(head) {
  // The fixture anchor's practice head came from real practice runs we do not ship; stand in a
  // chain whose head we can control, and point the anchor copy at it where a test needs that.
  let prev = PRACTICE_GENESIS;
  const rows = [];
  for (let i = 1; i <= 3; i += 1) {
    const ledger_payload = JSON.stringify({ practice: true, n: i });
    const entry_hash = await sha256hex(prev + ledger_payload);
    rows.push({ id: i, prev_hash: prev, ledger_payload, entry_hash });
    prev = entry_hash;
  }
  return { rows, head: head ?? prev };
}

function fakeFetch(routes) {
  return async (url) => {
    const u = new URL(url);
    const key = u.pathname + (u.search || '');
    const hit = Object.entries(routes).find(([p]) => key === p || (p.endsWith('*') && key.startsWith(p.slice(0, -1))));
    if (!hit) return { ok: false, status: 404, json: async () => ({ error: 'no_route' }), text: async () => '' };
    const body = typeof hit[1] === 'function' ? hit[1](u) : hit[1];
    return { ok: true, status: 200, json: async () => body, text: async () => (typeof body === 'string' ? body : JSON.stringify(body)) };
  };
}

function routes({ anchor = F.anchor, entries = [], practice = { rows: [] }, rekorEntry = F.rekorEntry } = {}) {
  return {
    '/api/anchors': { publicKey: F.sitePublicKey, anchors: [anchor] },
    '/api/ledger/entries*': (u) => (Number(u.searchParams.get('sinceId')) === 0 ? entries : []),
    '/api/practice/ledger': practice,
    [`/api/v1/log/entries/${F.anchor.rekorUuid}`]: { [rekorEntry.uuid]: rekorEntry },
    '/api/v1/log/publicKey': F.rekorPublicKey,
  };
}

const run = (r, opts = {}) => {
  const fetch = fakeFetch(r);
  return verifyAnchor({ site: new Site('https://example.test', { fetch }), fetch, rekor: 'https://rekor.test', ...opts });
};

test('the real anchor verifies end to end', async () => {
  const p = await practiceRowsEndingAt();
  const anchor = { ...F.anchor };
  // Rebuilding the artifact would break Rekor's hash, so the practice check is told to skip here.
  const report = await run(routes({ anchor, practice: p }), { practice: false });
  const failed = report.checks.filter((c) => c.status === 'fail');
  assert.deepEqual(failed, []);
  assert.equal(report.ok, true);
  const names = report.checks.map((c) => `${c.status} ${c.name}`);
  for (const must of ['Rekor holds this exact artifact', "inside Rekor's Merkle tree", 'Rekor signed that tree',
    'Rekor signed the time', 'Every race folds', 'The ledger replays', 'same figures it anchored']) {
    assert.ok(names.some((n) => n.startsWith('pass') && n.includes(must)), `missing pass: ${must}\n${names.join('\n')}`);
  }
});

test('control: the site shows a different head from the one it anchored', async () => {
  const report = await run(routes({ anchor: { ...F.anchor, head: 'f'.repeat(64) } }), { practice: false });
  assert.equal(report.ok, false);
  assert.match(report.checks.find((c) => c.status === 'fail').detail, /head/);
});

test('control: the site serves a rewritten artifact', async () => {
  const artifact = F.anchor.artifact.replace('entries=0', 'entries=7');
  const report = await run(routes({ anchor: { ...F.anchor, artifact, entries: 7 } }), { practice: false });
  const rekor = report.checks.find((c) => c.name.startsWith('Rekor holds this exact artifact'));
  assert.equal(rekor.status, 'fail');
});

test('control: the ledger now holds entries whose head is not the anchored one', async () => {
  // The anchor recorded 0 entries, so any chain passes the length-0 prefix; anchor a length of 1 instead.
  let prev = '0'.repeat(64);
  const ledger_payload = '{"observerId":1}';
  const entry_hash = await sha256hex(prev + ledger_payload);
  const entries = [{ id: 1, prev_hash: prev, ledger_payload, entry_hash }];
  const report = await run(routes({ anchor: { ...F.anchor, entries: 1 }, entries }), { practice: false });
  const chain = report.checks.find((c) => c.name.startsWith('The ledger replays'));
  assert.equal(chain.status, 'fail');
  // (the artifact check fails too, because the site's figure no longer matches the artifact)
  assert.equal(report.ok, false);
});

test('control: a reset or shortened ledger is reported, not passed', async () => {
  const report = await run(routes({ anchor: { ...F.anchor, entries: 5 } }), { practice: false });
  const chain = report.checks.find((c) => c.name.startsWith('The ledger replays'));
  assert.equal(chain.status, 'warn');
  assert.match(chain.detail, /fewer than the 5/);
});

test('control: a practice chain that breaks is a failure', async () => {
  const p = await practiceRowsEndingAt();
  p.rows[1].ledger_payload = '{"practice":true,"n":99}';
  const report = await run(routes({ practice: p }));
  const practice = report.checks.find((c) => c.name.startsWith('The practice chain'));
  assert.equal(practice.status, 'fail');
});
