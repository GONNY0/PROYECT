import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
const { PILOT_PLAN_FILE: planFile, PILOT_PLAN_SHA256: planSha, GITHUB_RUN_ID: runId, GITHUB_RUN_ATTEMPT: attempt } = process.env;
assert.match(planFile, /^plans\/(20261123|20261124|20261125)\.json$/);
assert.match(runId, /^[1-9][0-9]{0,17}$/);
assert.equal(attempt, '1');
const date = planFile.slice('plans/'.length, -'.json'.length);
const sha = b => createHash('sha256').update(b).digest('hex');
assert.equal(sha(fs.readFileSync(planFile)), planSha);
const files = { plan:planFile, ready:'out/READY.json', control:'out/SUMMARY.json',
  'window-01':'out/captures/01/result.json', 'window-02':'out/captures/02/result.json', 'window-03':'out/captures/03/result.json' };
for (const [label,file] of Object.entries(files)) {
  const stat = fs.lstatSync(file, {throwIfNoEntry:false});
  if (!stat) continue;
  assert(stat.isFile() && !stat.isSymbolicLink() && stat.nlink === 1 && stat.size <= 262144);
  console.log(['G4_CONTINUITY_SHA256', date, runId, attempt, label, sha(fs.readFileSync(file))].join(' '));
}
