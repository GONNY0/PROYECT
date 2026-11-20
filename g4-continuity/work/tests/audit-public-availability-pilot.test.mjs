import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,mkdirSync,readFileSync,writeFileSync,linkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import {auditPublicAvailabilityPilot} from '../audit-public-availability-pilot.mjs';
import {publicAvailabilityPilotSourceBinding,publicAvailabilityPilotRuntime} from '../public-availability-pilot.mjs';
import {publicSchedulePlanSha256} from '../public-capture-schedule.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const canonical=x=>Array.isArray(x)?'['+x.map(canonical).join(',')+']':x&&typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}':JSON.stringify(x);
const save=(file,value)=>{const b=Buffer.from(JSON.stringify(value,null,2)+'\n');writeFileSync(file,b);return sha(b);};
const time=1793012400000,DAY=86400000;
const pilotPolicy={publicDataOnly:true,credentialsUsed:false,ordersSent:0,originalCalendarAcceptance:false,
 scheduledAcceptanceEligible:false,forwardV1V2Observation:false,paperObservation:false,economicAcceptance:false,
 financialAcceptance:false,externalReadinessVerified:false,providerAttestation:false};
const legacyPolicy={publicDataOnly:true,accountCredentialsUsed:false,ordersSent:0,forwardExperimentRegistered:false,
 forwardV1V2Observation:false,economicAcceptance:false,liveEnabled:false,providerAttestation:false,missedWindowsBackfilled:false};

/** Synthetic files, API records and replay are labelled by the consumer's explicit
 * fixture hook. No native collection or provider response is claimed by these tests.
 */
function fixture({complete=true,scheduled=false}={}){
 const directory=mkdtempSync(join(tmpdir(),'g4-pilot-audit-')),binding=publicAvailabilityPilotSourceBinding(),runtime=publicAvailabilityPilotRuntime();
 const schedule={schemaVersion:'g4.public-capture-schedule.v1',id:'fixture-pilot-three-windows',repository:'fixture/repository',enabled:true,
  registeredAtMs:time,expiresAtMs:time+10000,windows:[1,2,3].map((n,i)=>({id:'w'+n,openMs:time+2000+i*3000,closeMs:time+4000+i*3000})),
  allowedEvents:['schedule','push','workflow_dispatch'],sourceBinding:binding.sourceBinding};
 const plan={schemaVersion:'g4.public-availability-pilot.v1',schedule,limits:{maxRuntimeMs:12000,pollMs:100,maxClockSkewMs:100,maxObservationGapMs:1000},runtime,
  wrapperSource:binding.wrapperSource,auditSourceBinding:binding.auditSourceBinding};
 if(scheduled){
  plan.schemaVersion='g4.public-availability-pilot.v2';schedule.registeredAtMs=time-DAY;schedule.allowedEvents=['schedule'];
  for(const w of schedule.windows){w.openMs+=180000;w.closeMs+=180000;}schedule.expiresAtMs+=180000;
  plan.startup={notBeforeMs:time-19800000,latestReadyAtMs:schedule.windows[0].openMs-120000};plan.limits.maxRuntimeMs=21000000;
 }
 const expectedPlanSha256=save(join(directory,'pilot-plan.json'),plan),nativePlanFileSha256=save(join(directory,'native-plan.json'),schedule);
 const runIdentity={provider:'GITHUB_ACTIONS',repository:schedule.repository,commitSha:'a'.repeat(40),runId:'1100',runAttempt:'1',eventName:'workflow_dispatch'};
 if(scheduled)runIdentity.eventName='schedule';
 const ready={schemaVersion:'g4.public-availability-pilot-ready.v1',kind:'NATIVE_PUBLIC',fixtureLabel:null,planSha256:expectedPlanSha256,
  scheduleId:schedule.id,schedulePlanSha256:publicSchedulePlanSha256(schedule),nativePlanFileSha256,wrapperSource:plan.wrapperSource,runtime,
  runIdentity,readyAtMs:time+100,readyMonotonicMs:500,firstOpenMs:time+2000,deadlineMs:time+12000,policy:pilotPolicy};
 if(scheduled){ready.schemaVersion='g4.public-availability-pilot-ready.v2';ready.firstOpenMs=schedule.windows[0].openMs;ready.deadlineMs=plan.startup.notBeforeMs+plan.limits.maxRuntimeMs;}
 const expectedReadySha256=save(join(directory,'READY.json'),ready);
 const summary={schemaVersion:'g4.public-availability-pilot-result.v1',kind:ready.kind,fixtureLabel:null,planSha256:expectedPlanSha256,
  schedulePlanSha256:ready.schedulePlanSha256,readySha256:expectedReadySha256,runIdentity,readyAtMs:ready.readyAtMs,
  startedAtMs:time+1100,completedAtMs:time+9200,status:'CAPTURED_PENDING_EXTERNAL_REVIEW',reason:null,policy:pilotPolicy,
  windows:[],clock:{samples:100,maxObservedGapMs:100,maxObservedSkewMs:0}};
 if(scheduled){summary.schemaVersion='g4.public-availability-pilot-result.v2';summary.completedAtMs+=180000;}
 const replays=new Map();
 if(complete){
  mkdirSync(join(directory,'captures'));
  for(const [index,window] of schedule.windows.entries()){
   const relative='captures/'+String(index+1).padStart(2,'0'),dir=join(directory,relative);mkdirSync(dir);mkdirSync(join(dir,'bundle'));
   writeFileSync(join(dir,'plan.json'),canonical(schedule)+'\n');
   const manifest={captureKind:'NATIVE_PUBLIC',startedAtMs:window.openMs+200,completedAtMs:window.openMs+800};
   const manifestSha256=save(join(dir,'bundle','manifest.json'),manifest);
   const result={schemaVersion:'g4.public-schedule-run.v1',scheduleId:schedule.id,planSha256:ready.schedulePlanSha256,runIdentity,
    runKey:`${runIdentity.repository}:${runIdentity.runId}:1`,kind:'NATIVE_PUBLIC',fixtureLabel:null,startedAtMs:window.openMs+100,
    acquisitionStartedAtMs:window.openMs+150,completedAtMs:window.openMs+900,window,status:'ON_TIME_CAPTURED',scheduledAcceptanceEligible:scheduled,
    bundle:{directory:'bundle',manifestSha256,status:'COMPLETE',verified:true},reason:null,policy:legacyPolicy};
   save(join(dir,'start.json'),{...result,acquisitionStartedAtMs:null,completedAtMs:null,bundle:null,reason:null,status:'PREPARED',scheduledAcceptanceEligible:false});
   const resultSha256=save(join(dir,'result.json'),result);
   const entry={windowId:window.id,directory:relative,status:'CAPTURED',reason:null,startedAtMs:window.openMs+50,completedAtMs:window.openMs+1000,
    resultSha256,child:{code:0,signal:null,terminated:false,terminationRequested:false,closeObserved:true},availabilityPilotCandidateEligible:true};
   summary.windows.push(entry);save(join(directory,window.id+'-child.json'),{...entry.child,stdout:JSON.stringify({resultSha256}),stderr:'',error:false});
   const receipt=window.openMs+700;
   replays.set(join(dir,'bundle'),{verified:true,nativeCapture:true,status:'VERIFIED_NATIVE_PUBLIC_CAPTURE',manifestSha256,producer:runtime,
    providerRequestsMade:false,originalPathsRead:false,sqliteOpened:false,verification:{sourceChecks:{externalNetworkCallsDuringReplay:0},
     history:{asOfMs:window.openMs+200,lastClosedBarMs:Math.floor((window.openMs+200)/DAY)*DAY-DAY,bars:64},
     quote:{receivedAtMs:receipt,quote:{symbol:'BTC/USD',currency:'USD',baseCurrency:'BTC',source:'ALPACA_CRYPTO_US',timestampMs:receipt-1,timestampNs:String(BigInt(receipt-1)*1000000n)}}}});
  }
  const {windows,clock,...start}=summary;save(join(directory,'RUN-START.json'),{...start,completedAtMs:null,status:'RUNNING',reason:null});
 }
 const expectedSummarySha256=complete?save(join(directory,'SUMMARY.json'),summary):null;
 // These are synthetic bytes and a synthetic import receipt, exercised only
 // under testFixture. Native audit still replays the real capture contract.
 const archiveFile=directory+'-ready.zip',archiveBytes=Buffer.from('PK\x03\x04synthetic-test-archive');writeFileSync(archiveFile,archiveBytes);
 const apiDigestSha256=sha(archiveBytes),extractionReceiptFile=directory+'-ready-import.json';
 const receipt={schemaVersion:'g4.public-availability-ready-import.v1',archiveSha256:apiDigestSha256,archiveBytes:archiveBytes.length,
  entries:['READY.json','pilot-plan.json','native-plan.json'].map(path=>{const b=readFileSync(join(directory,path));return {path,bytes:b.length,sha256:sha(b)};}),
  inspectorSha256:plan.auditSourceBinding.find(x=>x.path==='inspect-public-pilot-ready-archive.ps1').sha256,readOnly:true};
 const expectedExtractionReceiptSha256=save(extractionReceiptFile,receipt);
 const github={runIdentity,readyArtifactCreatedAtMs:time+500,readyArtifactTimestampPrecisionMs:1000,readySha256:expectedReadySha256,
  summarySha256:expectedSummarySha256,windowResults:summary.windows.map(w=>({windowId:w.windowId,resultSha256:w.resultSha256})),
  readyArtifact:{archiveFile,apiDigestSha256,extractionReceiptFile,expectedExtractionReceiptSha256}};
 if(scheduled)github.runCreatedAtMs=time-1000;
 const options={directory,expectedPlanSha256,expectedReadySha256,expectedSummarySha256,github,asOfMs:time+13000+(scheduled?180000:0),
  testFixture:{label:'synthetic-pilot-audit',replayBundle:async({directory})=>structuredClone(replays.get(directory))}};
 return {directory,plan,ready,summary,github,options,replays,receipt,
  resaveSummary(){options.expectedSummarySha256=save(join(directory,'SUMMARY.json'),summary);github.summarySha256=options.expectedSummarySha256;},
  resaveReady(){options.expectedReadySha256=save(join(directory,'READY.json'),ready);github.readySha256=options.expectedReadySha256;}};
}

test('three windows sharing one actual run key are verified individually and never promoted from fixture',async()=>{
 const f=fixture(),r=await auditPublicAvailabilityPilot(f.options);
 assert.equal(r.status,'FIXTURE_NOT_OPERATIONAL');assert.equal(r.counts.structurallyVerified,3);assert.equal(r.counts.invalid,0);
 assert.equal(r.counts.availabilityAccepted,0);assert.equal(r.counts.dataQualityAccepted,0);assert.equal(r.finitePilotRecurrenceAccepted,false);
 assert.ok(r.windows.every(w=>w.externallyBound&&w.quality.qualityCriteriaPassed));assert.equal(r.scheduledCalendarCoverageAccepted,false);
 assert.equal(r.forwardV1V2Observation,false);assert.equal(r.paperObservation,false);assert.equal(r.financialAcceptance,false);
});

test('V2 audit binds scheduled identities and readiness while keeping synthetic evidence and original calendar unaccepted',async()=>{
 const f=fixture({scheduled:true}),r=await auditPublicAvailabilityPilot(f.options);
 assert.equal(r.schemaVersion,'g4.public-availability-pilot-audit.v2');assert.equal(r.counts.structurallyVerified,3);assert.equal(r.counts.invalid,0,JSON.stringify(r));
 assert.ok(r.externallyBound);assert.ok(r.windows.every(w=>w.externallyBound&&w.quality.qualityCriteriaPassed));
 assert.equal(r.scheduledStartup.accepted,false);assert.equal(r.dailyAutonomousStartupProven,false);assert.equal(r.financialAcceptance,false);
 assert.equal(r.scheduledCalendarCoverageAccepted,false);assert.equal(r.scheduledStartup.readyLeadMs,180500);
});

test('V2 audit requires external run creation, rejects manual substitution and fails late readiness publication',async()=>{
 for(const mutate of [f=>delete f.github.runCreatedAtMs,f=>f.github.runCreatedAtMs=f.plan.startup.notBeforeMs-1,
  f=>f.github.runCreatedAtMs=f.ready.readyAtMs+1,f=>f.github.runIdentity={...f.github.runIdentity,eventName:'push'}]){
  const f=fixture({scheduled:true});mutate(f);await assert.rejects(auditPublicAvailabilityPilot(f.options),/PUBLIC_PILOT_AUDIT_(FIELDS|EXTERNAL_SCHEDULED_START_TIME|RUN_IDENTITY)/);
 }
 const f=fixture({scheduled:true});f.github.readyArtifactCreatedAtMs=f.plan.startup.latestReadyAtMs;
 const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.externallyBound,false);assert.equal(r.scheduledStartup.accepted,false);
 assert.equal(r.counts.availabilityAccepted,0);assert.equal(r.externalBindingReason,'READY_NOT_EXTERNALLY_PROVEN_BEFORE_OPEN');
});

test('prepared artifacts without a result remain incomplete and preserve the denominator of three',async()=>{
 const f=fixture({complete:false});delete f.options.testFixture;
 const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.status,'INCOMPLETE');assert.equal(r.counts.missing,3);assert.equal(r.counts.windows,3);
 assert.equal(r.finitePilotRecurrenceAccepted,false);assert.equal(r.counts.availabilityAccepted,0);
});

test('absent external records allow inspection but cannot establish externally bound windows',async()=>{
 const f=fixture();f.options.github=null;const r=await auditPublicAvailabilityPilot(f.options);
 assert.equal(r.externallyBound,false);assert.equal(r.externalBindingReason,'EXTERNAL_GITHUB_BINDINGS_MISSING');assert.ok(r.windows.every(w=>!w.externallyBound));
});

test('READY creation time uses the entire provider second and never accepts an overlapping interval',async()=>{
 for(const [created,bound] of [[time+1000,true],[time+1001,false],[time+2000,false]]){
  const f=fixture();f.github.readyArtifactCreatedAtMs=created;const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.externallyBound,bound);
 }
 const f=fixture();f.github.readyArtifactTimestampPrecisionMs=1;await assert.rejects(auditPublicAvailabilityPilot(f.options),/EXTERNAL_READY_TIME/);
});

test('external readiness before local READY is not a valid corroboration',async()=>{
 const f=fixture();f.github.readyArtifactCreatedAtMs=time-1000;const r=await auditPublicAvailabilityPilot(f.options);
 assert.equal(r.externallyBound,false);assert.equal(r.externalBindingReason,'EXTERNAL_READY_PRECEDES_LOCAL_READY');
});

test('source, plan, READY and SUMMARY byte substitutions are rejected',async()=>{
 for(const field of ['expectedPlanSha256','expectedReadySha256','expectedSummarySha256']){const f=fixture();f.options[field]='0'.repeat(64);await assert.rejects(auditPublicAvailabilityPilot(f.options),/HASH/);}
 const f=fixture();f.plan.auditSourceBinding[0].sha256='0'.repeat(64);f.options.expectedPlanSha256=save(join(f.directory,'pilot-plan.json'),f.plan);
 await assert.rejects(auditPublicAvailabilityPilot(f.options),/IMPLEMENTATION_MISMATCH/);
});

test('external run, attempt and duplicate window identities cannot be transplanted',async()=>{
 for(const edit of [g=>g.runIdentity={...g.runIdentity,runId:'1101'},g=>g.runIdentity={...g.runIdentity,runAttempt:'2'},
  g=>g.runIdentity={...g.runIdentity,eventName:'schedule'},g=>g.windowResults.push({...g.windowResults[0]})]){
  const f=fixture();edit(f.github);await assert.rejects(auditPublicAvailabilityPilot(f.options),/EXTERNAL_|RUN_IDENTITY/);
 }
 const f=fixture();f.summary.windows[1]={...f.summary.windows[0]};f.resaveSummary();await assert.rejects(auditPublicAvailabilityPilot(f.options),/WINDOW_DUPLICATE/);
});

test('one externally supplied result hash mismatch invalidates the complete collection',async()=>{
 const f=fixture();f.github.windowResults[1].resultSha256='0'.repeat(64);const r=await auditPublicAvailabilityPilot(f.options);
 assert.equal(r.status,'INVALID');assert.equal(r.counts.invalid,1);assert.equal(r.windows[1].reason,'PUBLIC_PILOT_AUDIT_EXTERNAL_WINDOW_HASH');
 assert.equal(r.counts.availabilityAccepted,0);
});

test('missing expected window remains visible and an externally known omitted result is a violation',async()=>{
 const f=fixture();f.summary.windows.pop();f.resaveSummary();const r=await auditPublicAvailabilityPilot(f.options);
 assert.equal(r.status,'INVALID');assert.equal(r.counts.missing,1);assert.ok(r.violations.some(v=>v.reason==='EXTERNAL_RESULT_NOT_IN_SUMMARY'));
});

test('failed window with preserved partial bytes does not become a capture',async()=>{
 const f=fixture();const entry=f.summary.windows[1];entry.status='FAILED';entry.reason='PUBLIC_PILOT_WINDOW_CLOSED_DURING_CAPTURE';entry.resultSha256=null;entry.availabilityPilotCandidateEligible=false;
 f.github.windowResults=f.github.windowResults.filter(w=>w.windowId!==entry.windowId);f.summary.status='FAILED';f.resaveSummary();
 const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.windows[1].status,'FAILED');assert.equal(r.windows[1].structuralReplayVerified,false);assert.equal(r.counts.captured,2);
 assert.equal(r.finitePilotRecurrenceAccepted,false);
});

test('capture closing at the boundary and child without acknowledged closure fail',async()=>{
 for(const edit of [f=>f.summary.windows[0].completedAtMs=f.plan.schedule.windows[0].closeMs,f=>f.summary.windows[0].child.closeObserved=false]){
  const f=fixture();edit(f);f.resaveSummary();const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.status,'INVALID');assert.equal(r.windows[0].status,'INVALID');
 }
});

test('runtime or child stdout substitutions cannot be accepted as the same capture',async()=>{
 const f=fixture();f.replays.get(join(f.directory,'captures/01/bundle')).producer={...f.plan.runtime,nodeSha256:'0'.repeat(64)};
 const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.windows[0].reason,'PUBLIC_PILOT_AUDIT_CAPTURE_RUNTIME');
 const g=fixture(),file=join(g.directory,'w1-child.json'),child=JSON.parse(readFileSync(file));child.stdout=JSON.stringify({resultSha256:'0'.repeat(64)});save(file,child);
 const q=await auditPublicAvailabilityPilot(g.options);assert.equal(q.windows[0].reason,'PUBLIC_PILOT_AUDIT_CHILD_RESULT_BINDING');
});

test('quality remains separate: future quotes, stale age intervals and missing last close are rejected',async()=>{
 for(const edit of [v=>{v.quote.quote.timestampMs=v.quote.receivedAtMs+1;v.quote.quote.timestampNs=String(BigInt(v.quote.quote.timestampMs)*1000000n);},
  v=>{v.quote.quote.timestampMs=v.quote.receivedAtMs-10000;v.quote.quote.timestampNs=String(BigInt(v.quote.quote.timestampMs)*1000000n);},
  v=>{v.history.lastClosedBarMs-=DAY;}]){
  const f=fixture();edit(f.replays.get(join(f.directory,'captures/01/bundle')).verification);
  const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.counts.structurallyVerified,3);assert.equal(r.windows[0].quality.qualityCriteriaPassed,false);
  assert.equal(r.windows[1].quality.qualityCriteriaPassed,true);assert.equal(r.counts.dataQualityAccepted,0);
 }
});

test('falsely labelled native fixture bytes fail real replay without invoking the network',async()=>{
 const f=fixture();delete f.options.testFixture;const original=globalThis.fetch;let network=0;globalThis.fetch=()=>{network++;throw Error('network forbidden');};
 try{const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.status,'INVALID');assert.equal(r.counts.structurallyVerified,0);assert.equal(network,0);}
 finally{globalThis.fetch=original;}
});

test('read-only audit leaves input bytes unchanged and refuses hard-linked evidence',async()=>{
 const f=fixture(),before=readFileSync(join(f.directory,'SUMMARY.json'));await auditPublicAvailabilityPilot(f.options);assert.deepEqual(readFileSync(join(f.directory,'SUMMARY.json')),before);
 const g=fixture();linkSync(join(g.directory,'READY.json'),join(g.directory,'ready-alias.json'));
 await assert.rejects(auditPublicAvailabilityPilot(g.options),/LINK_OR_NONREGULAR_RESOURCE|UNEXPECTED_FILE/);
});

test('global run start, deadline and clock failures invalidate acceptance independently of coherent hashes',async()=>{
 for(const [edit,reason] of [
  [s=>s.startedAtMs=time+2020,'RUN_NOT_PREARMED'],[s=>s.completedAtMs=time+12500,'RUN_EXCEEDED_DEADLINE'],
  [s=>s.clock.maxObservedGapMs=1001,'RUN_CLOCK_NOT_VALID'],[s=>s.clock.maxObservedSkewMs=101,'RUN_CLOCK_NOT_VALID']]){
  const f=fixture();edit(f.summary);f.resaveSummary();const {windows,clock,...base}=f.summary;
  save(join(f.directory,'RUN-START.json'),{...base,completedAtMs:null,status:'RUNNING',reason:null});
  const r=await auditPublicAvailabilityPilot(f.options);assert.equal(r.runControlValid,false);assert.ok(r.runControlReasons.includes(reason));
  assert.equal(r.counts.availabilityAccepted,0);assert.equal(r.counts.dataQualityAccepted,0);assert.equal(r.finitePilotRecurrenceAccepted,false);
 }
});

test('fourth capture and unrelated child-control files cannot hide outside the denominator',async()=>{
 const f=fixture();mkdirSync(join(f.directory,'captures','04'));await assert.rejects(auditPublicAvailabilityPilot(f.options),/UNEXPECTED_CAPTURE_DIRECTORY/);
 const g=fixture();save(join(g.directory,'unknown-child.json'),{});await assert.rejects(auditPublicAvailabilityPilot(g.options),/UNEXPECTED_CONTROL_FILE/);
});

test('archive bytes and all three extracted READY control files must match independently bound receipts',async()=>{
 const f=fixture();writeFileSync(f.github.readyArtifact.archiveFile,'changed archive');await assert.rejects(auditPublicAvailabilityPilot(f.options),/READY_ARCHIVE_HASH/);
 const g=fixture();g.receipt.entries[1].sha256='0'.repeat(64);g.github.readyArtifact.expectedExtractionReceiptSha256=save(g.github.readyArtifact.extractionReceiptFile,g.receipt);
 await assert.rejects(auditPublicAvailabilityPilot(g.options),/READY_EXTRACTION_ENTRY/);
 const h=fixture();h.github.readyArtifact=null;const r=await auditPublicAvailabilityPilot(h.options);assert.equal(r.externallyBound,false);
 assert.equal(r.externalBindingReason,'READY_ARCHIVE_BINDING_MISSING');assert.ok(r.windows.every(w=>!w.externallyBound));
});
