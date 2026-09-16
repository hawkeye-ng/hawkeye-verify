// Checks against Sigstore Rekor, the public transparency log the anchors are published to.
// Rekor is run by the Sigstore project, not by Hawkeye: an entry logged there cannot be
// edited, back-dated or removed by us, which is what makes a rolled-back database visible.
import {
  concat, equalBytes, fromBase64, fromHex, hex, pemToDer, sha256, sha256hex, toText, verifyEcdsaP256,
} from './crypto.mjs';

export const REKOR = 'https://rekor.sigstore.dev';

export class NetworkError extends Error {}

async function getJson(url, fetchImpl) {
  let res;
  try {
    res = await fetchImpl(url, { headers: { accept: 'application/json' } });
  } catch (e) {
    throw new NetworkError(`could not reach ${new URL(url).host}: ${e.cause?.code || e.message}`);
  }
  if (!res.ok) throw new NetworkError(`${new URL(url).host} answered HTTP ${res.status} for ${new URL(url).pathname}`);
  return res.json();
}

export async function fetchRekorEntry(uuid, { fetch: fetchImpl = globalThis.fetch, rekor = REKOR } = {}) {
  const body = await getJson(`${rekor}/api/v1/log/entries/${encodeURIComponent(uuid)}`, fetchImpl);
  const key = Object.keys(body)[0];
  if (!key) throw new Error(`Rekor returned no entry for ${uuid}`);
  return { uuid: key, ...body[key] };
}

export async function fetchRekorPublicKey({ fetch: fetchImpl = globalThis.fetch, rekor = REKOR } = {}) {
  let res;
  try {
    res = await fetchImpl(`${rekor}/api/v1/log/publicKey`);
  } catch (e) {
    throw new NetworkError(`could not reach ${new URL(rekor).host}: ${e.cause?.code || e.message}`);
  }
  if (!res.ok) throw new NetworkError(`Rekor answered HTTP ${res.status} for its public key`);
  return res.text();
}

export function decodeEntryBody(entry) {
  return JSON.parse(toText(fromBase64(entry.body)));
}

/** A log ID is the SHA-256 of the log's DER public key. */
export async function logIdOf(publicKeyPem) {
  return sha256hex(pemToDer(publicKeyPem));
}

/**
 * The logged record is a hashedrekord over sha256(artifact), signed with the key the site
 * publishes, and the signature verifies over the artifact itself.
 */
export async function checkHashedRekord(entry, { artifact, publicKeyPem }) {
  const problems = [];
  let body;
  try {
    body = decodeEntryBody(entry);
  } catch (e) {
    return { ok: false, problems: [`entry body is not readable: ${e.message}`] };
  }
  if (body.kind !== 'hashedrekord') problems.push(`the entry is a ${body.kind}, not a hashedrekord`);
  const hash = body.spec?.data?.hash;
  const expected = await sha256hex(artifact);
  if (hash?.algorithm !== 'sha256' || hash?.value !== expected) {
    problems.push(`Rekor holds hash ${hash?.value?.slice(0, 16)}…, but sha256(artifact) is ${expected.slice(0, 16)}…`);
  }
  let loggedKey = '';
  try {
    loggedKey = toText(fromBase64(body.spec?.signature?.publicKey?.content || ''));
    if (!equalBytes(pemToDer(loggedKey), pemToDer(publicKeyPem))) {
      problems.push('the entry was signed with a different key from the one the site publishes');
    }
  } catch (e) {
    problems.push(`the logged public key is not readable: ${e.message}`);
  }
  let signed = false;
  try {
    signed = await verifyEcdsaP256({
      publicKeyPem: loggedKey || publicKeyPem,
      signatureDer: fromBase64(body.spec?.signature?.content || ''),
      data: artifact,
    });
  } catch (e) {
    problems.push(`the signature could not be checked: ${e.message}`);
  }
  if (!signed) problems.push('the signature does not verify over the artifact');
  return { ok: problems.length === 0, problems, hash: expected };
}

/**
 * RFC 6962 / RFC 9162 §2.1.3.2 inclusion proof: the entry is a leaf of the log's Merkle tree
 * whose root is `rootHash`. Leaf hash = sha256(0x00 || entry body); node = sha256(0x01 || l || r).
 */
export async function checkInclusion(entry) {
  const p = entry.verification?.inclusionProof;
  if (!p) return { ok: false, problems: ['Rekor returned no inclusion proof'] };
  let fn = BigInt(p.logIndex);
  let sn = BigInt(p.treeSize) - 1n;
  if (fn > sn) return { ok: false, problems: ['the proof index is outside the tree'] };
  let r = await sha256(concat(new Uint8Array([0]), fromBase64(entry.body)));
  for (const step of p.hashes) {
    if (sn === 0n) return { ok: false, problems: ['the proof is longer than the tree is deep'] };
    const node = fromHex(step);
    if ((fn & 1n) === 1n || fn === sn) {
      r = await sha256(concat(new Uint8Array([1]), node, r));
      if ((fn & 1n) === 0n) {
        while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
      }
    } else {
      r = await sha256(concat(new Uint8Array([1]), r, node));
    }
    fn >>= 1n;
    sn >>= 1n;
  }
  const ok = sn === 0n && hex(r) === p.rootHash;
  return { ok, problems: ok ? [] : ['the inclusion proof does not fold to the tree root'], rootHash: p.rootHash, treeSize: p.treeSize };
}

/**
 * The checkpoint is Rekor's signed statement of that tree's size and root (a signed note:
 * the text, a blank line, then "— <origin> base64(keyHint(4) || DER signature)").
 */
export async function checkCheckpoint(entry, rekorPublicKeyPem) {
  const p = entry.verification?.inclusionProof;
  const text = p?.checkpoint;
  if (!text) return { ok: false, problems: ['Rekor returned no checkpoint'] };
  const problems = [];
  const split = text.indexOf('\n\n');
  if (split < 0) return { ok: false, problems: ['the checkpoint has no signature block'] };
  const note = text.slice(0, split + 1);
  const [origin, size, rootB64] = note.split('\n');
  if (size !== String(p.treeSize)) problems.push(`the checkpoint is for tree size ${size}, the proof for ${p.treeSize}`);
  if (hex(fromBase64(rootB64 || '')) !== p.rootHash) problems.push('the checkpoint root is not the proof root');
  const keyId = fromHex(await logIdOf(rekorPublicKeyPem));
  const host = origin.split(' ')[0];
  let verified = false;
  for (const line of text.slice(split + 2).split('\n').filter(Boolean)) {
    const m = /^— (\S+) (\S+)$/.exec(line);
    if (!m || m[1] !== host) continue;
    const raw = fromBase64(m[2]);
    if (!equalBytes(raw.slice(0, 4), keyId.slice(0, 4))) continue;
    try {
      verified = await verifyEcdsaP256({ publicKeyPem: rekorPublicKeyPem, signatureDer: raw.slice(4), data: note });
    } catch (e) {
      problems.push(`the checkpoint signature could not be checked: ${e.message}`);
    }
    if (verified) break;
  }
  if (!verified) problems.push("no checkpoint signature verifies with Rekor's public key");
  return { ok: problems.length === 0, problems, origin };
}

/**
 * The signed entry timestamp (SET) is Rekor's signature over the entry body, its log
 * position and the time it was logged — proof of WHEN, from the log itself.
 */
export async function checkSignedEntryTimestamp(entry, rekorPublicKeyPem) {
  const set = entry.verification?.signedEntryTimestamp;
  if (!set) return { ok: false, problems: ['Rekor returned no signed entry timestamp'] };
  const problems = [];
  const logId = await logIdOf(rekorPublicKeyPem);
  if (entry.logID !== logId) problems.push(`the entry names log ${entry.logID?.slice(0, 12)}…, but the key given is for log ${logId.slice(0, 12)}…`);
  // Canonical JSON: keys in code-point order, no whitespace.
  const payload = `{"body":${JSON.stringify(entry.body)},"integratedTime":${entry.integratedTime},`
    + `"logID":${JSON.stringify(entry.logID)},"logIndex":${entry.logIndex}}`;
  let ok = false;
  try {
    ok = await verifyEcdsaP256({ publicKeyPem: rekorPublicKeyPem, signatureDer: fromBase64(set), data: payload });
  } catch (e) {
    problems.push(`the timestamp signature could not be checked: ${e.message}`);
  }
  if (!ok) problems.push('the signed entry timestamp does not verify');
  return { ok: problems.length === 0, problems, integratedTime: entry.integratedTime };
}
