// Hashing, encoding and ECDSA verification on WebCrypto alone, so the same code runs in
// Node 20+, in a browser and in anything else with a standard `crypto.subtle`. No
// dependencies: a verifier that pulls in a package tree asks you to trust that tree too.

const subtle = globalThis.crypto?.subtle;
if (!subtle) throw new Error('hawkeye-verify needs WebCrypto: Node 20 or later, or a modern browser');

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** A string becomes its UTF-8 bytes; bytes pass through. */
export const toBytes = (value) => (typeof value === 'string' ? encoder.encode(value) : value);
export const toText = (bytes) => decoder.decode(bytes);

export const hex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');

export function fromHex(text) {
  if (typeof text !== 'string' || text.length % 2 !== 0 || /[^0-9a-f]/i.test(text)) {
    throw new Error(`not a hex string: ${String(text).slice(0, 20)}`);
  }
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function fromBase64(text) {
  const binary = atob(String(text).replace(/\s+/g, ''));
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

export const equalBytes = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);

export async function sha256(data) {
  return new Uint8Array(await subtle.digest('SHA-256', toBytes(data)));
}

export async function sha256hex(data) {
  return hex(await sha256(data));
}

/** The DER bytes inside a PEM block (the header, footer and line breaks removed). */
export function pemToDer(pem) {
  const body = String(pem).replace(/-----(BEGIN|END) [A-Z ]+-----/g, '').replace(/\s+/g, '');
  if (!body) throw new Error('empty PEM');
  return fromBase64(body);
}

/**
 * ECDSA signatures from Node, OpenSSL and Go are DER: SEQUENCE { INTEGER r, INTEGER s }.
 * WebCrypto only accepts the fixed-width form, r || s, 32 bytes each for P-256.
 */
export function derToRaw(der, size = 32) {
  let i = 0;
  const byte = () => {
    if (i >= der.length) throw new Error('signature DER is truncated');
    return der[i++];
  };
  const length = () => {
    let n = byte();
    if (n & 0x80) {
      const count = n & 0x7f;
      n = 0;
      for (let k = 0; k < count; k += 1) n = (n << 8) | byte();
    }
    return n;
  };
  if (byte() !== 0x30) throw new Error('signature is not a DER sequence');
  length();
  const integer = () => {
    if (byte() !== 0x02) throw new Error('signature DER is missing an integer');
    const n = length();
    let value = der.slice(i, i + n);
    i += n;
    if (value.length !== n) throw new Error('signature DER is truncated');
    while (value.length > size && value[0] === 0) value = value.slice(1);
    if (value.length > size) throw new Error('signature integer is too long for P-256');
    const padded = new Uint8Array(size);
    padded.set(value, size - value.length);
    return padded;
  };
  return concat(integer(), integer());
}

/** Verifies a DER ECDSA P-256 / SHA-256 signature over `data` with an SPKI PEM public key. */
export async function verifyEcdsaP256({ publicKeyPem, signatureDer, data }) {
  const key = await subtle.importKey('spki', pemToDer(publicKeyPem), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, derToRaw(signatureDer), toBytes(data));
}
