// A small client for the public verification endpoints a Hawkeye site serves. Nothing here
// is trusted: every figure it returns is re-checked by the functions in the other modules.
import { NetworkError } from './rekor.mjs';

export const DEFAULT_SITE = 'https://hawkeye.com.ng';
const PAGE = 1000; // the server's maximum page size for /api/ledger/entries

export class Site {
  constructor(base = DEFAULT_SITE, { fetch: fetchImpl = globalThis.fetch, userAgent } = {}) {
    // Trailing slashes stripped by a scan, not a regex: /\/+$/ backtracks
    // quadratically on a string of many slashes, and `base` is whatever URL
    // the caller was given rather than one they necessarily chose.
    const raw = String(base);
    let end = raw.length;
    while (end > 0 && raw.charCodeAt(end - 1) === 47 /* '/' */) end -= 1;
    this.base = raw.slice(0, end);
    this.fetch = fetchImpl;
    // Browsers ignore a user-agent header; Node sends it. Some hosts refuse anonymous clients.
    this.headers = { accept: 'application/json', ...(userAgent ? { 'user-agent': userAgent } : {}) };
  }

  async json(path) {
    let res;
    try {
      res = await this.fetch(this.base + path, { headers: this.headers });
    } catch (e) {
      throw new NetworkError(`could not reach ${new URL(this.base).host}: ${e.cause?.code || e.message}`);
    }
    if (!res.ok) {
      const err = new NetworkError(`${new URL(this.base).host} answered HTTP ${res.status} for ${path}`);
      err.status = res.status;
      throw err;
    }
    return res.json();
  }

  /** { publicKey, anchors: [...] }, newest first. */
  anchors() { return this.json('/api/anchors'); }

  races(anchorId) { return this.json(`/api/anchors/${encodeURIComponent(anchorId)}/races`); }

  race(anchorId, raceKey) {
    return this.json(`/api/anchors/${encodeURIComponent(anchorId)}/races/${encodeURIComponent(raceKey)}`);
  }

  ledgerVerify() { return this.json('/api/ledger/verify'); }

  practiceLedger() { return this.json('/api/practice/ledger'); }

  /** Every ledger entry, oldest first, one page at a time. */
  async* ledgerEntries() {
    let sinceId = 0;
    for (;;) {
      const rows = await this.json(`/api/ledger/entries?sinceId=${sinceId}&limit=${PAGE}`);
      if (!Array.isArray(rows) || rows.length === 0) return;
      yield rows;
      sinceId = rows[rows.length - 1].id;
      if (rows.length < PAGE) return;
    }
  }
}
