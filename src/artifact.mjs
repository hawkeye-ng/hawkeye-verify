// The anchor artifact is the one line the site signs and logs in Sigstore Rekor:
//
//   hawkeye-ledger-anchor|v1|election=<label>|day=<YYYY-MM-DD>|head=<hex>|entries=<n>
//     |collationHead=<hex>|collationEntries=<n>|racesRoot=<hex>|races=<n>
//     |docketHead=<hex>|practiceHead=<hex>|at=<ISO time>
//
// (one line, no spaces; older anchors carry fewer fields). Rekor stores sha256 of this
// exact string, so it can be rebuilt and re-hashed by anyone.

export const ARTIFACT_PREFIX = 'hawkeye-ledger-anchor|v1|';

export function parseArtifact(artifact) {
  if (typeof artifact !== 'string' || !artifact.startsWith(ARTIFACT_PREFIX)) {
    throw new Error('not a v1 Hawkeye anchor artifact');
  }
  const fields = {};
  for (const part of artifact.slice(ARTIFACT_PREFIX.length).split('|')) {
    const eq = part.indexOf('=');
    if (eq < 1) throw new Error(`artifact field without a name: "${part.slice(0, 40)}"`);
    fields[part.slice(0, eq)] = part.slice(eq + 1);
  }
  return fields;
}

// The site's anchor row and the field in the signed artifact that must say the same thing.
const PAIRS = [
  ['day', 'day'], ['at', 'at'],
  ['head', 'head'], ['entries', 'entries'],
  ['collationHead', 'collationHead'], ['collationEntries', 'collationEntries'],
  ['racesRoot', 'racesRoot'], ['racesCount', 'races'],
  ['practiceHead', 'practiceHead'],
];

/**
 * The artifact is what Rekor holds; the row is what the site shows. Any field that differs
 * means the site is showing something other than what was anchored.
 */
export function crossCheckAnchor(anchor) {
  const fields = parseArtifact(anchor.artifact);
  const compared = [];
  const mismatches = [];
  for (const [rowKey, artifactKey] of PAIRS) {
    if (!(artifactKey in fields) || anchor[rowKey] === null || anchor[rowKey] === undefined) continue;
    compared.push(rowKey);
    if (String(anchor[rowKey]) !== fields[artifactKey]) {
      mismatches.push({ field: rowKey, site: String(anchor[rowKey]), anchored: fields[artifactKey] });
    }
  }
  return { ok: mismatches.length === 0, fields, compared, mismatches };
}
