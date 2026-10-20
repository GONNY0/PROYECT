/** One public acquisition and an offline replay. No account or ledger access. */
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {capturePublicBundle, replayPublicBundle} from './public-capture-bundle.mjs';

const artifacts=path.resolve(import.meta.dirname,'../artifacts');
await fs.mkdir(artifacts); // Never replace a previous run.
const bundle=path.join(artifacts,'bundle');
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const save=async(name,value)=>fs.writeFile(path.join(artifacts,name),JSON.stringify(value,null,2)+'\n',{flag:'wx'});
let phase='CAPTURE';
try {
 const capture=await capturePublicBundle({directory:bundle});
 await save('capture-result.json',capture);
 assert.equal(capture.status,'COMPLETE','PUBLIC_CAPTURE_INCOMPLETE');
 assert.equal(capture.nativeCapture,true,'NATIVE_CAPTURE_REQUIRED');
 const manifestSha256=sha(await fs.readFile(path.join(bundle,'manifest.json')));
 assert.equal(manifestSha256,capture.manifestSha256,'MANIFEST_RECEIPT_MISMATCH');
 phase='OFFLINE_REPLAY';
 const replay=await replayPublicBundle({directory:bundle,expectedManifestSha256:manifestSha256});
 await save(`${process.platform}-replay-result.json`,replay);
 assert.equal(replay.status,'VERIFIED_NATIVE_PUBLIC_CAPTURE','REPLAY_NOT_VERIFIED');
 assert.equal(replay.verified,true,'REPLAY_NOT_VERIFIED');
 const result={schemaVersion:'g4.public-host-check.v1',status:'PUBLIC_CAPTURE_AND_REPLAY_VERIFIED',
  completedAtUtc:new Date().toISOString(),nodeVersion:process.version,platform:process.platform,
  architecture:process.arch,manifestSha256,scope:'PUBLIC_DATA_ONLY_NO_ACCOUNT_ORDERS_OR_FINANCIAL_ACCEPTANCE',
  githubRunId:process.env.GITHUB_RUN_ID??null,githubRunAttempt:process.env.GITHUB_RUN_ATTEMPT??null,
  githubCommit:process.env.GITHUB_SHA??null};
 await save('result.json',result);
 console.log(JSON.stringify(result));
} catch(error) {
 // Errors may contain local paths or external bodies. Detailed acquisition
 // evidence lives in the bounded bundle; the public failure marker is closed.
 const failure={schemaVersion:'g4.public-host-check.v1',status:'FAILED',phase,
  completedAtUtc:new Date().toISOString(),platform:process.platform,
  code:typeof error?.code==='string'&&/^[A-Z][A-Z0-9_]{0,79}$/.test(error.code)?error.code:'PUBLIC_CAPTURE_OR_REPLAY_FAILED'};
 await save('failure.json',failure);
 console.log(JSON.stringify(failure));
 process.exitCode=1;
}
