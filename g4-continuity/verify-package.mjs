import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
const root = path.resolve(import.meta.dirname, '..');
const m = JSON.parse(fs.readFileSync(new URL('package-manifest.json', import.meta.url)));
assert.equal(m.schemaVersion, 'g4.public-continuity-release.v1');
assert.equal(m.financialAcceptance, false);
assert.equal(m.frozenSourceManifestSha256, '8a615beac35c8c3f565cc2dc7d1d647a6cc1ec275939c492d210334bc7ec9098');
const names = new Set();
for (const f of m.files) {
  assert((f.path.startsWith('g4-continuity/') || f.path === '.github/workflows/g4-public-continuity-20261123.yml') && /^[a-zA-Z0-9_./-]+$/.test(f.path) && !f.path.split('/').some(x => !x || x === '.' || x === '..'));
  assert(!names.has(f.path)); names.add(f.path);
  const file = path.join(root, f.path);
  const stat = fs.lstatSync(file);
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && fs.realpathSync(file) === file && stat.size === f.bytes);
  assert.equal(createHash('sha256').update(fs.readFileSync(file)).digest('hex'), f.sha256);
}
const index = JSON.parse(fs.readFileSync(new URL('series.json', import.meta.url)));
assert.equal(index.id, 'g4-public-continuity-20261123-v1'); assert.equal(index.workflowPath, '.github/workflows/g4-public-continuity-20261123.yml');
assert.deepEqual(index.sessions.map(s => s.date), ["2026-11-23","2026-11-24","2026-11-25"]);
assert(names.has(index.workflowPath) && names.has('g4-continuity/log-envelopes.mjs') && names.has('g4-continuity/verify-ready-publication.mjs') && names.has('g4-continuity/series.json') && names.has('g4-continuity/verify-package.mjs'));
for (const s of index.sessions) assert(m.files.some(f => f.path === 'g4-continuity/' + s.planFile && f.sha256 === s.planSha256));
console.log(JSON.stringify({ status:'CONTINUITY_RELEASE_VERIFIED', files:names.size, sessions:index.sessions.length, financialAcceptance:false }));
