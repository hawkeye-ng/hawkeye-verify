#!/usr/bin/env node
// hawkeye-verify: check a Hawkeye site's published ledger without trusting the site.
// Exit codes: 0 verified · 1 a check failed · 2 could not finish (network or bad input).
import { Site, DEFAULT_SITE } from '../src/site.mjs';
import { verifyAnchor } from '../src/verify.mjs';
import { NetworkError } from '../src/rekor.mjs';
import fs from 'node:fs';

const VERSION = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version;

const HELP = `hawkeye-verify ${VERSION}: independently verify a Hawkeye election-results ledger

Usage: hawkeye-verify [options]

  --site <url>         the Hawkeye site to check (default ${DEFAULT_SITE})
  --anchor <id>        the anchor to check (default: the newest one logged in Rekor)
  --race <key>         also check one race's Merkle proof on its own, e.g. "PRES"
  --no-chain           skip replaying the ledger from genesis
  --no-practice        skip the practice chain
  --rekor-key <file>   pin Rekor's public key (PEM) instead of fetching it from Rekor
  --json               print the full report as JSON
  -h, --help           show this help
  -v, --version        show the version

Checks: the site shows what it anchored; Rekor holds that exact artifact, signed with the
site's key, inside its Merkle tree, under a checkpoint and timestamp Rekor signed; every race
rebuilds to the anchored root; and the ledger replays from genesis to the anchored head.`;

function parseArgs(argv) {
  const o = { site: DEFAULT_SITE, chain: true, practice: true, json: false };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const value = () => {
      const v = argv[++i];
      if (v === undefined || v.startsWith('--')) throw new Error(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case '--site': o.site = value(); break;
      case '--anchor': o.anchorId = value(); break;
      case '--race': o.raceKey = value(); break;
      case '--rekor-key': o.rekorPublicKeyPem = fs.readFileSync(value(), 'utf8'); break;
      case '--no-chain': o.chain = false; break;
      case '--no-practice': o.practice = false; break;
      case '--json': o.json = true; break;
      case '-h': case '--help': o.help = true; break;
      case '-v': case '--version': o.version = true; break;
      default: throw new Error(`unknown option ${a} (try --help)`);
    }
  }
  return o;
}

const MARK = { pass: '✔', fail: '✘', warn: '!', skip: '–' };

async function main() {
  let o;
  try {
    o = parseArgs(process.argv.slice(2));
  } catch (e) {
    console.error(e.message);
    return 2;
  }
  if (o.help) { console.log(HELP); return 0; }
  if (o.version) { console.log(VERSION); return 0; }

  const site = new Site(o.site, { userAgent: `hawkeye-verify/${VERSION} (+https://github.com/hawkeye-ng/hawkeye-verify)` });
  if (!o.json) console.log(`Hawkeye ledger verification · ${site.base}\n`);
  try {
    const report = await verifyAnchor({
      site, anchorId: o.anchorId, raceKey: o.raceKey, chain: o.chain, practice: o.practice,
      rekorPublicKeyPem: o.rekorPublicKeyPem,
      onCheck: o.json ? undefined : (c) => {
        console.log(`  ${MARK[c.status]} ${c.name}`);
        if (c.detail) console.log(`      ${c.detail}`);
      },
    });
    if (o.json) {
      console.log(JSON.stringify(report, null, 2));
    } else {
      const a = report.anchor;
      console.log(`\nAnchor #${a.id} · ${a.at} · ${a.election || 'unlabelled'} · Rekor log index ${a.rekorLogIndex ?? '—'}`);
      if (a.rekorSearchUrl) console.log(`See it in Rekor: ${a.rekorSearchUrl}`);
      const tally = [`${report.passed} passed`, report.failed && `${report.failed} failed`,
        report.warned && `${report.warned} to note`, report.skipped && `${report.skipped} skipped`].filter(Boolean).join(', ');
      console.log(`Result: ${report.ok ? 'VERIFIED' : 'NOT VERIFIED'} (${tally})`);
    }
    return report.ok ? 0 : 1;
  } catch (e) {
    const where = e instanceof NetworkError ? 'Could not finish' : 'Stopped';
    if (o.json) console.log(JSON.stringify({ ok: null, error: e.message }));
    else console.error(`\n${where}: ${e.message}`);
    return 2;
  }
}

process.exitCode = await main();
