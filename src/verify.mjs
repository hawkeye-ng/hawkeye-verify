// End to end: take one anchor the site published and check everything that can be checked
// without trusting the site. Each check reports pass, fail, warn or skip, with the reason.
import { crossCheckAnchor } from './artifact.mjs';
import { GENESIS, PRACTICE_GENESIS, verifyChain } from './chain.mjs';
import { EMPTY_ROOT, verifyAllRaces, verifyRaceProof } from './merkle.mjs';
import {
  checkCheckpoint, checkHashedRekord, checkInclusion, checkSignedEntryTimestamp,
  fetchRekorEntry, fetchRekorPublicKey, logIdOf, NetworkError, REKOR,
} from './rekor.mjs';

const pass = (name, detail) => ({ name, status: 'pass', detail });
const fail = (name, detail) => ({ name, status: 'fail', detail });
const warn = (name, detail) => ({ name, status: 'warn', detail });
const skip = (name, detail) => ({ name, status: 'skip', detail });
const short = (h) => (h ? `${String(h).slice(0, 12)}…` : String(h));

/**
 * @param {object} o
 * @param {import('./site.mjs').Site} o.site
 * @param {number} [o.anchorId]   default: the newest anchor that reached Rekor
 * @param {string} [o.raceKey]    also check this one race's proof on its own
 * @param {boolean} [o.chain]     replay the ledger against the anchored head (default true)
 * @param {string} [o.rekorPublicKeyPem]  pin Rekor's key instead of fetching it
 */
export async function verifyAnchor({
  site, anchorId, raceKey, chain = true, practice = true,
  rekor = REKOR, rekorPublicKeyPem, fetch: fetchImpl = globalThis.fetch, onCheck = () => {},
}) {
  const checks = [];
  const add = (c) => { checks.push(c); onCheck(c); return c; };

  const { publicKey, anchors } = await site.anchors();
  const anchor = anchorId == null
    ? anchors.find((a) => a.rekorUuid && a.artifact)
    : anchors.find((a) => String(a.id) === String(anchorId));
  if (!anchor) {
    throw new Error(anchorId == null ? 'the site has published no anchor that reached Rekor' : `the site has no anchor #${anchorId}`);
  }
  const summary = {
    id: anchor.id, day: anchor.day, at: anchor.at, entries: anchor.entries, racesCount: anchor.racesCount,
    rekorLogIndex: anchor.rekorLogIndex, rekorUrl: anchor.rekorUrl, rekorSearchUrl: anchor.rekorSearchUrl,
  };

  // 1. The site's figures are the anchored figures.
  if (!anchor.artifact) {
    add(fail('The site shows the anchored artifact', 'this anchor has no artifact, so it was never logged in Rekor'));
    return finish(summary, checks);
  }
  let artifactFields = {};
  try {
    const x = crossCheckAnchor(anchor);
    artifactFields = x.fields;
    summary.election = x.fields.election;
    add(x.ok
      ? pass('The site shows the same figures it anchored', `${x.compared.length} fields match the signed artifact`)
      : fail('The site shows the same figures it anchored',
        x.mismatches.map((m) => `${m.field}: site ${short(m.site)}, anchored ${short(m.anchored)}`).join('; ')));
  } catch (e) {
    add(fail('The site shows the same figures it anchored', e.message));
  }

  // 2–5. Rekor.
  if (!anchor.rekorUuid) {
    add(fail('Rekor holds the anchor', 'the site lists no Rekor entry for this anchor'));
  } else {
    let entry;
    let rekorKey = rekorPublicKeyPem;
    try {
      entry = await fetchRekorEntry(anchor.rekorUuid, { fetch: fetchImpl, rekor });
      rekorKey = rekorKey || await fetchRekorPublicKey({ fetch: fetchImpl, rekor });
    } catch (e) {
      if (e instanceof NetworkError) throw e;
      add(fail('Rekor holds the anchor', e.message));
    }
    if (entry) {
      const h = await checkHashedRekord(entry, { artifact: anchor.artifact, publicKeyPem: publicKey });
      add(h.ok
        ? pass('Rekor holds this exact artifact, signed with the site\'s anchor key', `sha256 ${short(h.hash)} · log index ${entry.logIndex}`)
        : fail('Rekor holds this exact artifact, signed with the site\'s anchor key', h.problems.join('; ')));

      if (anchor.rekorTime != null && Number(anchor.rekorTime) !== Number(entry.integratedTime)) {
        add(fail('Logged when the site says', `Rekor logged it at ${entry.integratedTime}, the site says ${anchor.rekorTime}`));
      } else {
        const lag = Math.round(entry.integratedTime - Date.parse(anchor.at) / 1000);
        const when = new Date(entry.integratedTime * 1000).toISOString();
        add(Math.abs(lag) <= 3600
          ? pass('Logged when the site says', `Rekor time ${when}, ${lag}s after the anchor was made`)
          : warn('Logged when the site says', `Rekor time ${when} is ${lag}s from the anchor's own time`));
      }

      const inc = await checkInclusion(entry);
      add(inc.ok
        ? pass('The entry is inside Rekor\'s Merkle tree', `tree of ${Number(inc.treeSize).toLocaleString('en')} entries`)
        : fail('The entry is inside Rekor\'s Merkle tree', inc.problems.join('; ')));

      const cp = await checkCheckpoint(entry, rekorKey);
      add(cp.ok
        ? pass('Rekor signed that tree', `checkpoint from ${cp.origin.split(' ')[0]}, log ${short(await logIdOf(rekorKey))}`)
        : fail('Rekor signed that tree', cp.problems.join('; ')));

      const set = await checkSignedEntryTimestamp(entry, rekorKey);
      add(set.ok
        ? pass('Rekor signed the time it logged the entry', 'signed entry timestamp verifies')
        : fail('Rekor signed the time it logged the entry', set.problems.join('; ')));
    }
  }

  // 6. Races.
  if (!anchor.racesRoot) {
    add(skip('Every race folds to the anchored root', 'this anchor predates per-race batching'));
  } else if (Number(anchor.racesCount) === 0) {
    add(anchor.racesRoot === EMPTY_ROOT
      ? pass('Every race folds to the anchored root', 'no races were recorded in this cycle, and the root is empty as it should be')
      : fail('Every race folds to the anchored root', 'no races are listed, but the root is not the empty root'));
  } else {
    const { races } = await site.races(anchor.id);
    const all = await verifyAllRaces(races, anchor.racesRoot);
    const countOk = races.length === Number(anchor.racesCount);
    add(all.ok && countOk
      ? pass('Every race folds to the anchored root', `${races.length} races rebuilt to ${short(all.root)}`)
      : fail('Every race folds to the anchored root', [
        !countOk && `${races.length} races listed, ${anchor.racesCount} anchored`,
        !all.contiguous && 'leaf positions have gaps',
        !all.sorted && 'races are not in key order',
        all.root !== anchor.racesRoot && `rebuilt root ${short(all.root)} is not the anchored ${short(anchor.racesRoot)}`,
      ].filter(Boolean).join('; ')));
  }
  if (raceKey) {
    try {
      const d = await site.race(anchor.id, raceKey);
      const r = await verifyRaceProof(d, artifactFields.racesRoot || anchor.racesRoot);
      add(r.ok
        ? pass(`Race "${raceKey}" checks on its own`, `${d.entries} report(s); its proof folds to the anchored root`)
        : fail(`Race "${raceKey}" checks on its own`, !r.leafOk ? 'its leaf is not what its head and count say' : 'its proof does not fold to the anchored root'));
    } catch (e) {
      if (e instanceof NetworkError && e.status !== 404) throw e;
      add(fail(`Race "${raceKey}" checks on its own`, e.status === 404 ? 'the site has no such race under this anchor' : e.message));
    }
  }

  // 7. The ledger itself.
  if (!chain) {
    add(skip('The ledger replays to the anchored head', 'not requested'));
  } else {
    const target = Number(anchor.entries);
    let headAtTarget = target === 0 ? GENESIS : null;
    let result = { ok: true, entries: 0, head: GENESIS };
    for await (const page of site.ledgerEntries()) {
      result = await verifyChain(page, {
        prev: result.head, count: result.entries,
        onEntry: (head, n) => { if (n === target) headAtTarget = head; },
      });
      if (!result.ok) break;
    }
    if (!result.ok) {
      add(fail('The ledger replays to the anchored head', `the chain breaks at entry ${result.brokenAtId}: ${result.reason}`));
    } else if (headAtTarget === null) {
      add(warn('The ledger replays to the anchored head',
        `the site now holds ${result.entries} entries, fewer than the ${target} this anchor recorded. Either the ledger was reset for a new election cycle or entries were removed; Rekor still holds the anchored head ${short(anchor.head)}.`));
    } else if (headAtTarget !== anchor.head) {
      add(fail('The ledger replays to the anchored head', `after ${target} entries the chain head is ${short(headAtTarget)}, but ${short(anchor.head)} was anchored`));
    } else {
      add(pass('The ledger replays to the anchored head',
        `${result.entries} entries replayed from genesis; the head after ${target} is the anchored one`));
    }
  }

  // 8. The practice chain (rehearsals, kept apart from the ledger).
  if (practice && artifactFields.practiceHead) {
    try {
      const p = await site.practiceLedger();
      const heads = new Set([PRACTICE_GENESIS]);
      const r = await verifyChain(p.rows || [], { genesis: PRACTICE_GENESIS, onEntry: (head) => heads.add(head) });
      if (!r.ok) {
        add(fail('The practice chain replays to its anchored head', `it breaks at practice entry ${r.brokenAtId}: ${r.reason}`));
      } else if (heads.has(artifactFields.practiceHead)) {
        add(pass('The practice chain replays to its anchored head', `${r.entries} practice entries; the anchored head is on the chain`));
      } else {
        add(warn('The practice chain replays to its anchored head',
          `the anchored practice head ${short(artifactFields.practiceHead)} is not on today's practice chain (${r.entries} entries). Practice runs are cleared periodically.`));
      }
    } catch (e) {
      if (e instanceof NetworkError && e.status !== 404) throw e;
      add(skip('The practice chain replays to its anchored head', 'the site does not publish a practice ledger'));
    }
  }

  return finish(summary, checks);
}

function finish(anchor, checks) {
  const count = (s) => checks.filter((c) => c.status === s).length;
  return { ok: count('fail') === 0, anchor, checks, passed: count('pass'), failed: count('fail'), warned: count('warn'), skipped: count('skip') };
}
