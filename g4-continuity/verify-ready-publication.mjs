import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
function verifyPublicReadyMetadata({ artifact, id, digest, plan, ready, runId, commitSha, checkedAtMs }) {
  assert.match(id, /^[1-9][0-9]{0,17}$/);
  assert.match(digest, /^[a-f0-9]{64}$/);
  assert.match(runId, /^[1-9][0-9]{0,17}$/);
  assert.match(commitSha, /^[a-f0-9]{40}$/);
  assert(Number.isSafeInteger(artifact.id) && String(artifact.id) === id, 'READY_ARTIFACT_ID');
  assert(Number.isSafeInteger(artifact.workflow_run?.id) && String(artifact.workflow_run.id) === runId &&
    artifact.workflow_run.head_sha === commitSha, 'READY_ARTIFACT_RUN');
  assert(artifact.name === 'g4-continuity-ready-' + runId + '-1' && artifact.expired === false &&
    artifact.digest === 'sha256:' + digest && Number.isSafeInteger(artifact.size_in_bytes) && artifact.size_in_bytes > 0, 'READY_ARTIFACT_DIGEST_OR_NAME');
  assert(ready.kind === 'NATIVE_PUBLIC' && ready.runIdentity.provider === 'GITHUB_ACTIONS' &&
    ready.runIdentity.eventName === 'schedule' && ready.runIdentity.runAttempt === '1' &&
    ready.runIdentity.runId === runId && ready.runIdentity.commitSha === commitSha &&
    ready.runIdentity.repository === plan.schedule.repository && ready.scheduleId === plan.schedule.id, 'READY_SESSION');
  assert.match(artifact.created_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  const createdAtMs = Date.parse(artifact.created_at);
  assert(Number.isSafeInteger(createdAtMs) && Number.isSafeInteger(checkedAtMs) && Number.isSafeInteger(ready.readyAtMs) &&
    ready.readyAtMs >= plan.startup.notBeforeMs && createdAtMs <= checkedAtMs &&
    createdAtMs + 1000 > ready.readyAtMs && createdAtMs + 1000 <= plan.startup.latestReadyAtMs &&
    checkedAtMs >= ready.readyAtMs && checkedAtMs < plan.startup.latestReadyAtMs, 'READY_PUBLICATION_DEADLINE');
  return { artifactId: id, apiDigest: artifact.digest, runId, commitSha, createdAtMs, checkedAtMs, latestReadyAtMs: plan.startup.latestReadyAtMs };
}
const { G4_ARTIFACT_ID: id, G4_ARTIFACT_DIGEST: digest, GITHUB_REPOSITORY: repo, GITHUB_RUN_ID: runId, GITHUB_SHA: commitSha } = process.env;
assert.equal(repo, 'GONNY0/PROYECT');
assert.match(id, /^[1-9][0-9]{0,17}$/);
const bytes = fs.readFileSync(process.env.PILOT_PLAN_FILE);
assert.equal(createHash('sha256').update(bytes).digest('hex'), process.env.PILOT_PLAN_SHA256);
const plan = JSON.parse(bytes);
const readyBytes = fs.readFileSync('out/READY.json');
assert.equal(createHash('sha256').update(readyBytes).digest('hex'), process.env.PILOT_READY_SHA256);
const ready = JSON.parse(readyBytes);
assert.equal(ready.planSha256, process.env.PILOT_PLAN_SHA256);
assert(Date.now() < plan.startup.latestReadyAtMs, 'READY_PUBLICATION_DEADLINE');
const response = await fetch('https://api.github.com/repos/' + repo + '/actions/artifacts/' + id, {
  headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'g4-public-continuity', 'X-GitHub-Api-Version': '2022-11-28' },
  redirect: 'error', signal: AbortSignal.timeout(10000)
});
assert(response.ok, 'PUBLIC_READY_HTTP_' + response.status);
const artifact = await response.json();
console.log(JSON.stringify(verifyPublicReadyMetadata({ artifact, id, digest, plan, ready, runId, commitSha, checkedAtMs: Date.now() })));
