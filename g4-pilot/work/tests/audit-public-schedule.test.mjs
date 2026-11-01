import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,readdirSync,cpSync,linkSync,symlinkSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {auditPublicSchedule} from '../audit-public-schedule.mjs';
import {publicScheduleSourceBinding,publicSchedulePlanSha256,selectPublicWindow} from '../public-capture-schedule.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const policy={publicDataOnly:true,accountCredentialsUsed:false,ordersSent:0,forwardExperimentRegistered:false,
 forwardV1V2Observation:false,economicAcceptance:false,liveEnabled:false,providerAttestation:false,missedWindowsBackfilled:false};
function plan(){
 return {schemaVersion:'g4.public-capture-schedule.v1',id:'audit-fixture',repository:'fixture/public',enabled:true,
  registeredAtMs:0,expiresAtMs:90000,allowedEvents:['schedule','workflow_dispatch','push'],
  windows:[{id:'one',openMs:10000,closeMs:20000},{id:'two',openMs:30000,closeMs:40000},
   {id:'three',openMs:60000,closeMs:70000},{id:'four',openMs:80000,closeMs:90000}],
  sourceBinding:publicScheduleSourceBinding()};
}
function identity(extra={}){return {provider:'GITHUB_ACTIONS',repository:'fixture/public',commitSha:'a'.repeat(40),runId:'101',runAttempt:'1',eventName:'schedule',...extra};}
function write(directory,file,value,canon=false){writeFileSync(join(directory,file),(canon?canonical(value):JSON.stringify(value,null,2))+'\n');}
function envelope(p,{id=identity(),status='ON_TIME_CAPTURED',startedAtMs=11000,acquisitionStartedAtMs=12000,completedAtMs=13000,kind='NATIVE_PUBLIC',reason=null}={}){
 const parent=mkdtempSync(join(tmpdir(),'g4-schedule-audit-')),directory=join(parent,'run');mkdirSync(directory);
 const selection=selectPublicWindow(p,startedAtMs),complete=status==='ON_TIME_CAPTURED'||(status==='LATE'&&reason==='WINDOW_CLOSED_DURING_ACQUISITION');
 let bundle=null;
 if(complete){
  mkdirSync(join(directory,'bundle'));
  const manifest={captureKind:kind,startedAtMs:acquisitionStartedAtMs+1,completedAtMs:completedAtMs-1};
  write(directory,'bundle/manifest.json',manifest);
  bundle={directory:'bundle',manifestSha256:sha(readFileSync(join(directory,'bundle/manifest.json'))),status:kind==='NATIVE_PUBLIC'?'COMPLETE':'FIXTURE_COMPLETE',verified:true};
 }
 const result={schemaVersion:'g4.public-schedule-run.v1',scheduleId:p.id,planSha256:publicSchedulePlanSha256(p),runIdentity:id,
  runKey:`${id.repository}:${id.runId}:${id.runAttempt}`,kind,fixtureLabel:kind==='INJECTED_FIXTURE'?'explicit-fixture':null,
  startedAtMs,acquisitionStartedAtMs,completedAtMs,window:selection.window,status,
  scheduledAcceptanceEligible:kind==='NATIVE_PUBLIC'&&id.eventName==='schedule'&&status==='ON_TIME_CAPTURED',
  bundle,reason,policy};
 write(directory,'plan.json',p,true);
 write(directory,'start.json',{...result,status:selection.status==='READY'?'PREPARED':selection.status,
  acquisitionStartedAtMs:null,completedAtMs:null,bundle:null,reason:null,scheduledAcceptanceEligible:false});
 write(directory,'result.json',result);
 return {parent,directory,result,binding:{directory,expectedResultSha256:sha(readFileSync(join(directory,'result.json'))),github:id}};
}
function revise(f,change){Object.assign(f.result,change);write(f.directory,'result.json',f.result);f.binding.expectedResultSha256=sha(readFileSync(join(f.directory,'result.json')));}
function failed(p,extra={}){
 return envelope(p,{status:'FAILED',acquisitionStartedAtMs:12000,completedAtMs:13000,reason:'PUBLIC_SCHEDULE_CAPTURE_FAILED',...extra});
}
function injectedReplay(){
 return {label:'explicit-audit-fixture',replayBundle:async({directory,expectedManifestSha256})=>{
  const m=JSON.parse(readFileSync(join(directory,'manifest.json'))),native=m.captureKind==='NATIVE_PUBLIC';
  return {verified:true,nativeCapture:native,status:native?'VERIFIED_NATIVE_PUBLIC_CAPTURE':'VERIFIED_INJECTED_FIXTURE',
   manifestSha256:expectedManifestSha256,providerRequestsMade:false,originalPathsRead:false,sqliteOpened:false};
 }};
}
function audit(p,entries,extra={}){return auditPublicSchedule({plan:p,runDirectories:entries,asOfMs:95000,testFixture:injectedReplay(),...extra});}

test('empty imported collection separates closed, current and future windows without inventing observations',async()=>{
 const p=plan(),r=await auditPublicSchedule({plan:p,runDirectories:[],asOfMs:65000});
 assert.equal(r.status,'VERIFIED_IMPORTED_COLLECTION');
 assert.deepEqual(r.windows.map(w=>w.status),['MISSING_EVIDENCE','MISSING_EVIDENCE','PENDING','FUTURE']);
 assert.equal(r.counts.missingEvidenceWindows,2);assert.equal(Object.hasOwn(r.counts,'missedWindows'),false);
 assert.equal(r.counts.scheduledCoverageAccepted,0);assert.equal(r.policy.completeGitHubRunInventoryClaimed,false);
 assert.equal(r.coverageAcceptanceBlocked,true);assert.equal(r.coverageAcceptanceBlockedReason,'INCOMPLETE_EXTERNAL_RUN_INVENTORY');
 assert.equal(r.scheduledAcceptanceEligible,false);assert.equal(r.counts.importedCollectionEligibleSlots,0);
 assert.equal(r.policy.firstImportedScheduledAttemptClaimed,true);
 assert.equal(r.policy.forwardV1V2Observation,false);assert.equal(r.policy.economicAcceptance,false);
});

test('injected verification can test a candidate but can never establish native coverage',async()=>{
 const p=plan(),f=envelope(p),r=await audit(p,[f.binding]);
 assert.equal(r.status,'FIXTURE_NOT_OPERATIONAL');assert.equal(r.kind,'INJECTED_FIXTURE');
 assert.equal(r.simulatedEligibleSlots,1);assert.equal(r.counts.scheduledCoverageAccepted,0);
 assert.equal(r.counts.importedCollectionEligibleSlots,0);
 assert.equal(r.windows[0].scheduledAcceptanceEligible,false);assert.equal(r.coverageAcceptanceBlocked,true);
 await assert.rejects(auditPublicSchedule({plan:p,runDirectories:[],asOfMs:95000,testFixture:{replayBundle:async()=>({})}}),/FIELDS/);
 await assert.rejects(auditPublicSchedule({plan:p,runDirectories:[],asOfMs:95000,replayBundle:async()=>({})}),/FIELDS/);
});

test('identity and fixture labels require strings instead of coercible numbers or arrays',async()=>{
 const p=plan(),number=failed(p,{id:identity({runId:101})}),array=failed(p,{id:identity({commitSha:['a'.repeat(40)]})});
 const f=envelope(p,{kind:'INJECTED_FIXTURE'});revise(f,{fixtureLabel:['coerced-label']});
 const r=await audit(p,[number.binding,array.binding,f.binding]);
 assert.equal(r.counts.invalidInputs,3);
 assert.deepEqual(r.violations.map(v=>v.reason),['PUBLIC_SCHEDULE_AUDIT_RUN_IDENTITY','PUBLIC_SCHEDULE_AUDIT_RUN_IDENTITY','PUBLIC_SCHEDULE_AUDIT_CAPTURE_KIND']);
 await assert.rejects(audit(p,[],{testFixture:{label:['coerced-label'],replayBundle:async()=>({})}}),/EXPLICIT_TEST_FIXTURE/);
});

test('scheduled outside, expired and paused attempts are explicit without inventing missed acquisition',async()=>{
 const p=plan(),outside=envelope(p,{status:'OUTSIDE',startedAtMs:25000,acquisitionStartedAtMs:null,completedAtMs:25000}),
  expired=envelope(p,{id:identity({runId:'102'}),status:'EXPIRED',startedAtMs:90000,acquisitionStartedAtMs:null,completedAtMs:90000});
 const r=await audit(p,[outside.binding,expired.binding]);
 assert.equal(r.counts.outsideScheduledRuns,1);assert.equal(r.counts.expiredScheduledRuns,1);
 assert.equal(r.counts.missingEvidenceWindows,4);assert.equal(r.counts.scheduledCoverageAccepted,0);
 const pausedPlan={...p,enabled:false},paused=envelope(pausedPlan,{status:'PAUSED',startedAtMs:11000,acquisitionStartedAtMs:null,completedAtMs:11000});
 const pausedAudit=await audit(pausedPlan,[paused.binding]);assert.equal(pausedAudit.counts.pausedScheduledRuns,1);
 assert.equal(pausedAudit.counts.scheduledCoverageAccepted,0);
});

test('first scheduled failure is retained even when a later attempt succeeds',async()=>{
 const p=plan(),first=failed(p,{id:identity({runId:'7'}),startedAtMs:11000}),
  later=envelope(p,{id:identity({runId:'8'}),startedAtMs:14000,acquisitionStartedAtMs:15000,completedAtMs:16000});
 const r=await audit(p,[later.binding,first.binding]);
 assert.equal(r.windows[0].selectedRunKey,first.result.runKey);assert.equal(r.windows[0].status,'FAILED');
 assert.equal(r.counts.failedWindows,1);assert.equal(r.counts.laterAttemptsNotSelected,1);assert.equal(r.simulatedEligibleSlots,0);
});

test('omitting an earlier failed attempt cannot turn an imported candidate into accepted coverage',async()=>{
 const p=plan(),first=failed(p,{id:identity({runId:'7'}),startedAtMs:11000}),
  later=envelope(p,{id:identity({runId:'8'}),startedAtMs:14000,acquisitionStartedAtMs:15000,completedAtMs:16000});
 const full=await audit(p,[first.binding,later.binding]),subset=await audit(p,[later.binding]);
 assert.equal(full.simulatedEligibleSlots,0);assert.equal(subset.simulatedEligibleSlots,1);
 for(const r of [full,subset]){
  assert.equal(r.counts.scheduledCoverageAccepted,0);assert.equal(r.counts.importedCollectionEligibleSlots,0);
  assert.equal(r.scheduledAcceptanceEligible,false);assert.ok(r.windows.every(w=>w.scheduledAcceptanceEligible===false));
  assert.equal(r.coverageAcceptanceBlocked,true);assert.equal(r.coverageAcceptanceBlockedReason,'INCOMPLETE_EXTERNAL_RUN_INVENTORY');
  assert.equal(r.policy.completeGitHubRunInventoryClaimed,false);assert.equal(r.policy.firstImportedScheduledAttemptClaimed,true);
 }
 const nativeFailure=await auditPublicSchedule({plan:p,runDirectories:[first.binding],asOfMs:95000});
 assert.equal(nativeFailure.status,'VERIFIED_IMPORTED_COLLECTION');
 assert.equal(nativeFailure.coverageAcceptanceBlocked,true);assert.equal(nativeFailure.scheduledAcceptanceEligible,false);
 assert.equal(nativeFailure.coverageAcceptanceBlockedReason,'INCOMPLETE_EXTERNAL_RUN_INVENTORY');
 assert.equal(nativeFailure.counts.scheduledCoverageAccepted,0);
 await assert.rejects(auditPublicSchedule({plan:p,runDirectories:[first.binding],asOfMs:95000,completeGitHubRunInventoryClaimed:true}),/FIELDS/);
});

test('selection orders start time before acquisition time and uses exact numeric run IDs for ties',async()=>{
 const p=plan(),early=envelope(p,{id:identity({runId:'9007199254740993'}),startedAtMs:11000,acquisitionStartedAtMs:15000,completedAtMs:16000}),
  later=envelope(p,{id:identity({runId:'9007199254740992'}),startedAtMs:12000,acquisitionStartedAtMs:13000,completedAtMs:14000});
 const r=await audit(p,[later.binding,early.binding]);assert.equal(r.windows[0].selectedRunKey,early.result.runKey);
 const a=failed(p,{id:identity({runId:'9007199254740993'})}),b=failed(p,{id:identity({runId:'9007199254740992'})});
 const tie=await audit(p,[a.binding,b.binding]);assert.equal(tie.windows[0].selectedRunKey,b.result.runKey);
 const c=failed(p,{id:identity({runId:'99',runAttempt:'2'})}),d=failed(p,{id:identity({runId:'99',runAttempt:'1'})});
 const attempt=await audit(p,[c.binding,d.binding]);assert.equal(attempt.windows[0].selectedRunKey,d.result.runKey);
});

test('byte-identical copies are deduplicated and can share an independently acquired binding',async()=>{
 const p=plan(),f=envelope(p),copy=join(f.parent,'copy');cpSync(f.directory,copy,{recursive:true});
 const r=await audit(p,[f.directory,{...f.binding,directory:copy}]);
 assert.equal(r.counts.identicalCopies,1);assert.equal(r.counts.laterAttemptsNotSelected,0);
 assert.equal(r.counts.unboundRuns,0);assert.equal(r.simulatedEligibleSlots,1);
 assert.equal(r.runs[1].duplicateOf,0);
});

test('same run key with different valid bytes is a blocking conflict',async()=>{
 const p=plan(),a=failed(p),b=failed(p,{reason:'PUBLIC_SCHEDULE_CLOCK_REGRESSION'});
 const r=await audit(p,[a.binding,b.binding]);
 assert.equal(r.status,'CONFLICT');assert.equal(r.counts.conflicts,1);
 assert.equal(r.counts.scheduledCoverageAccepted,0);assert.equal(r.coverageAcceptanceBlocked,true);
});

test('bare directories remain consistency-only and block coverage promotion',async()=>{
 const p=plan(),f=failed(p),r=await auditPublicSchedule({plan:p,runDirectories:[f.directory],asOfMs:95000});
 assert.equal(r.status,'CONSISTENCY_ONLY');assert.equal(r.counts.unboundRuns,1);
 assert.equal(r.coverageAcceptanceBlocked,true);assert.equal(r.counts.scheduledCoverageAccepted,0);
});

test('external result hashes and GitHub identities are mandatory matching evidence',async()=>{
 const p=plan(),a=failed(p),b=failed(p,{id:identity({runId:'102'})});
 const r=await audit(p,[{...a.binding,expectedResultSha256:'0'.repeat(64)},
  {...b.binding,github:{...b.binding.github,commitSha:'b'.repeat(40)}}]);
 assert.equal(r.status,'INVALID');assert.equal(r.counts.invalidInputs,2);
 assert.deepEqual(r.violations.map(v=>v.reason),['PUBLIC_SCHEDULE_AUDIT_RESULT_HASH','PUBLIC_SCHEDULE_AUDIT_EXTERNAL_IDENTITY_MISMATCH']);
});

test('plan, start, eligibility and capture times cannot be silently changed',async()=>{
 const p=plan(),a=failed(p);writeFileSync(join(a.directory,'plan.json'),JSON.stringify(p));
 const b=failed(p,{id:identity({runId:'102'})}),start=JSON.parse(readFileSync(join(b.directory,'start.json')));start.runKey='other';write(b.directory,'start.json',start);
 const c=envelope(p,{id:identity({runId:'103'})});revise(c,{scheduledAcceptanceEligible:false});
 const d=envelope(p,{id:identity({runId:'104'})});revise(d,{completedAtMs:20000});
 const r=await audit(p,[a.binding,b.binding,c.binding,d.binding]);
 assert.equal(r.counts.invalidInputs,4);assert.equal(r.counts.scheduledCoverageAccepted,0);
 assert.deepEqual(r.violations.map(v=>v.reason),['PUBLIC_SCHEDULE_AUDIT_PLAN_HASH','PUBLIC_SCHEDULE_AUDIT_START_RESULT_MISMATCH',
  'PUBLIC_SCHEDULE_AUDIT_ELIGIBILITY_MISMATCH','PUBLIC_SCHEDULE_AUDIT_ON_TIME_CONTRACT']);
});

test('replay contract and manifest timing are independently checked',async()=>{
 const p=plan(),a=envelope(p),b=envelope(p,{id:identity({runId:'102'})});
 const m=JSON.parse(readFileSync(join(a.directory,'bundle/manifest.json')));m.startedAtMs=11000;write(a.directory,'bundle/manifest.json',m);
 revise(a,{bundle:{...a.result.bundle,manifestSha256:sha(readFileSync(join(a.directory,'bundle/manifest.json')))}});
 const fake=injectedReplay(),bad={...fake,replayBundle:async args=>({...await fake.replayBundle(args),providerRequestsMade:true})};
 const r=await audit(p,[a.binding,b.binding],{testFixture:bad});
 assert.deepEqual(r.violations.map(v=>v.reason),['PUBLIC_SCHEDULE_AUDIT_BUNDLE_TIME','PUBLIC_SCHEDULE_AUDIT_REPLAY_CONTRACT']);
});

test('real verifier rejects a forged native envelope without network calls',async()=>{
 const p=plan(),f=envelope(p),saved=globalThis.fetch;let calls=0;
 globalThis.fetch=()=>{calls++;throw Error('NO_NETWORK_ALLOWED');};
 try{
  const r=await auditPublicSchedule({plan:p,runDirectories:[f.binding],asOfMs:95000});
  assert.equal(r.status,'INVALID');assert.equal(calls,0);assert.equal(r.counts.scheduledCoverageAccepted,0);
 }finally{globalThis.fetch=saved;}
});

test('push, manual runs and fixture captures never become accepted scheduled coverage',async()=>{
 const p=plan(),push=envelope(p,{id:identity({runId:'2',eventName:'push'})}),
  dispatch=envelope(p,{id:identity({runId:'3',eventName:'workflow_dispatch'})}),
  fixture=envelope(p,{id:identity({runId:'4'}),kind:'INJECTED_FIXTURE'});
 const r=await audit(p,[push.binding,dispatch.binding,fixture.binding]);
 assert.equal(r.counts.diagnosticRuns,2);assert.equal(r.counts.fixtureWindows,1);assert.equal(r.simulatedEligibleSlots,0);
});

test('late-before and late-during captures are retained without promotion',async()=>{
 const p=plan(),before=envelope(p,{status:'LATE',acquisitionStartedAtMs:20000,completedAtMs:20000,reason:'WINDOW_CLOSED_BEFORE_ACQUISITION'}),
  during=envelope(p,{id:identity({runId:'102'}),status:'LATE',startedAtMs:31000,acquisitionStartedAtMs:32000,completedAtMs:40001,reason:'WINDOW_CLOSED_DURING_ACQUISITION'});
 const r=await audit(p,[before.binding,during.binding]);
 assert.equal(r.counts.lateWindows,2);assert.equal(r.counts.invalidInputs,0);assert.equal(r.simulatedEligibleSlots,0);
});

test('unexpected files, hardlinks and directory links are refused',async()=>{
 const p=plan(),a=failed(p),b=failed(p,{id:identity({runId:'102'})}),c=failed(p,{id:identity({runId:'103'})});
 write(a.directory,'orphan.json',{unexpected:true});linkSync(join(b.directory,'result.json'),join(b.parent,'alias.json'));
 const alias=join(c.parent,'alias');symlinkSync(c.directory,alias,process.platform==='win32'?'junction':'dir');
 const r=await audit(p,[a.binding,b.binding,{...c.binding,directory:alias}]);
 assert.equal(r.counts.invalidInputs,3);assert.equal(r.counts.scheduledCoverageAccepted,0);
});

test('audit is read-only, rejects stale source bindings, and guards snapshot mutation during replay',async()=>{
 const p=plan(),f=envelope(p),before=readdirSync(f.directory).map(n=>n),resultBytes=readFileSync(join(f.directory,'result.json'));
 await audit(p,[f.binding]);assert.deepEqual(readdirSync(f.directory),before);assert.deepEqual(readFileSync(join(f.directory,'result.json')),resultBytes);
 const stale=structuredClone(p);stale.sourceBinding[0].sha256='0'.repeat(64);
 await assert.rejects(audit(stale,[]),/IMPLEMENTATION_MISMATCH/);
 const replay=injectedReplay(),mutating={...replay,replayBundle:async args=>{
  const answer=await replay.replayBundle(args);writeFileSync(join(f.directory,'result.json'),Buffer.concat([resultBytes,Buffer.from(' ')]));return answer;
 }};
 const r=await audit(p,[f.binding],{testFixture:mutating});assert.equal(r.status,'INVALID');assert.match(r.violations[0].reason,/RESOURCE_CHANGED/);
});
