/** Read-only audit of explicitly imported scheduled public acquisitions.
 * External GitHub identity/result bindings must be acquired independently.
 * An imported subset cannot establish first-attempt coverage for the full schedule.
 */
import {createHash} from 'node:crypto';
import {readFileSync,lstatSync,realpathSync,readdirSync} from 'node:fs';
import {resolve,dirname,join,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {validatePublicSchedule,selectPublicWindow,publicSchedulePlanSha256,publicScheduleSourceBinding} from './public-capture-schedule.mjs';
import {replayPublicBundle} from './public-capture-bundle.mjs';

const SHA=/^[a-f0-9]{64}$/,ID=/^[a-z0-9][a-z0-9_.-]{0,79}$/;
const POLICY={publicDataOnly:true,accountCredentialsUsed:false,ordersSent:0,forwardExperimentRegistered:false,
 forwardV1V2Observation:false,economicAcceptance:false,liveEnabled:false,providerAttestation:false,missedWindowsBackfilled:false};
const FIELDS=['schemaVersion','scheduleId','planSha256','runIdentity','runKey','kind','fixtureLabel','startedAtMs',
 'acquisitionStartedAtMs','completedAtMs','window','status','scheduledAcceptanceEligible','bundle','reason','policy'];
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const sha=b=>createHash('sha256').update(b).digest('hex');
const integer=n=>Number.isSafeInteger(n)&&n>=0;
function require(ok,code){if(!ok)throw Error('PUBLIC_SCHEDULE_AUDIT_'+code);}
function keys(value,expected){require(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===expected.slice().sort().join(','),'FIELDS');}
function pathKey(p){return process.platform==='win32'?p.toLowerCase():p;}
function regular(file,directory=false){
 const s=lstatSync(file);
 require(!s.isSymbolicLink()&&(directory?s.isDirectory():s.isFile())&&(directory||s.nlink===1)
  &&pathKey(realpathSync(file))===pathKey(file),'LINK_OR_NONREGULAR_RESOURCE');return s;
}
function localRoot(directory){
 require(typeof directory==='string'&&isAbsolute(directory)&&!directory.includes('\0')&&!directory.startsWith('\\\\')&&!directory.startsWith('//'),'LOCAL_DIRECTORY_REQUIRED');
 const root=resolve(directory);let p=root;
 for(;;){regular(p,true);if(dirname(p)===p)break;p=dirname(p);}return root;
}
function bounded(file,max=262144){require(regular(file).size<=max,'RESOURCE_SIZE');return readFileSync(file);}
function json(file){return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bounded(file)));}
function inventory(root){
 const files=[];let count=0,total=0;
 function visit(prefix,depth){
  require(depth<=6,'INVENTORY_DEPTH');
  for(const name of readdirSync(join(root,prefix))){
   require(++count<=64&&/^[A-Za-z0-9_.-]+$/.test(name)&&name!=='.'&&name!=='..'&&!/[. ]$/.test(name),'INVENTORY_ENTRY');
   const p=prefix?prefix+'/'+name:name,full=join(root,p),s=lstatSync(full);regular(full,s.isDirectory());
   if(s.isDirectory()){
    require(p==='bundle'||p==='bundle/history'||p==='bundle/quotes'||/^bundle\/quotes\/[A-Za-z0-9_.-]+$/.test(p),'UNEXPECTED_DIRECTORY');
    visit(p,depth+1);
   }else{
    require(['start.json','plan.json','result.json'].includes(p)
     ||/^bundle\/(?:START|FAILED|quote|manifest)\.json$/.test(p)
     ||/^bundle\/history\/(?:START|asset-pairs\.raw|bars\.normalized|ohlc\.raw|receipt)\.json$/.test(p)
     ||/^bundle\/quotes\/[A-Za-z0-9_.-]+\/(?:metadata\.json|response\.body)$/.test(p),'UNEXPECTED_FILE');
    require(s.size<=2097152,'RESOURCE_SIZE');total+=s.size;require(total<=13369344,'TOTAL_SIZE');
    const b=readFileSync(full);files.push({path:p,bytes:b.length,sha256:sha(b)});
   }
  }
 }
 visit('',0);files.sort((a,b)=>a.path.localeCompare(b.path));
 require(['start.json','plan.json','result.json'].every(p=>files.some(f=>f.path===p)),'MISSING_ENVELOPE');
 return {files,sha256:sha(canonical(files)),bytes:total};
}
function identity(value,plan){
 keys(value,['provider','repository','commitSha','runId','runAttempt','eventName']);
 require(value.provider==='GITHUB_ACTIONS'&&value.repository===plan.repository&&typeof value.commitSha==='string'&&/^[a-f0-9]{40}$/.test(value.commitSha)
  &&typeof value.runId==='string'&&/^[1-9][0-9]{0,19}$/.test(value.runId)&&typeof value.runAttempt==='string'&&/^[1-9][0-9]{0,8}$/.test(value.runAttempt)
  &&plan.allowedEvents.includes(value.eventName),'RUN_IDENTITY');
 return `${value.repository}:${value.runId}:${value.runAttempt}`;
}
function checkEnvelope(result,start,plan,planSha256,asOfMs){
 keys(result,FIELDS);keys(start,FIELDS);
 require(result.schemaVersion==='g4.public-schedule-run.v1'&&result.scheduleId===plan.id&&result.planSha256===planSha256,'RESULT_PLAN');
 require(identity(result.runIdentity,plan)===result.runKey,'RUN_KEY');
 require(['NATIVE_PUBLIC','INJECTED_FIXTURE'].includes(result.kind)
  &&(result.kind==='NATIVE_PUBLIC'?result.fixtureLabel===null:typeof result.fixtureLabel==='string'&&ID.test(result.fixtureLabel)),'CAPTURE_KIND');
 require(canonical(result.policy)===canonical(POLICY),'POLICY');
 require(integer(result.startedAtMs)&&result.startedAtMs<=asOfMs
  &&(result.completedAtMs===null||(integer(result.completedAtMs)&&result.completedAtMs>=result.startedAtMs&&result.completedAtMs<=asOfMs))
  &&(result.acquisitionStartedAtMs===null||(integer(result.acquisitionStartedAtMs)&&result.acquisitionStartedAtMs>=result.startedAtMs&&result.acquisitionStartedAtMs<=asOfMs)),'RUN_TIME');
 const selection=selectPublicWindow(plan,result.startedAtMs);
 require(canonical(result.window)===canonical(selection.window),'WINDOW');
 const expectedStart={...result,acquisitionStartedAtMs:null,completedAtMs:null,bundle:null,reason:null,
  status:selection.status==='READY'?'PREPARED':selection.status,scheduledAcceptanceEligible:false};
 require(canonical(start)===canonical(expectedStart),'START_RESULT_MISMATCH');
 let complete=false;
 if(result.bundle!==null){
  keys(result.bundle,['directory','manifestSha256','status','verified']);
  require(result.bundle.directory==='bundle'&&typeof result.bundle.status==='string'&&typeof result.bundle.verified==='boolean'
   &&(result.bundle.manifestSha256===null||typeof result.bundle.manifestSha256==='string'&&SHA.test(result.bundle.manifestSha256)),'BUNDLE_CONTRACT');
  complete=['COMPLETE','FIXTURE_COMPLETE'].includes(result.bundle.status);
  if(complete)require(result.bundle.status===(result.kind==='NATIVE_PUBLIC'?'COMPLETE':'FIXTURE_COMPLETE')
   &&result.bundle.verified&&SHA.test(result.bundle.manifestSha256),'COMPLETE_BUNDLE_CONTRACT');
 }
 if(selection.status!=='READY'){
  require(result.status===selection.status&&result.completedAtMs===result.startedAtMs&&result.acquisitionStartedAtMs===null
   &&result.bundle===null&&result.reason===null,'NO_ACQUISITION_CONTRACT');
 }else{
  require(['ON_TIME_CAPTURED','LATE','FAILED'].includes(result.status),'READY_RESULT');
  if(result.status==='FAILED'){
   require(typeof result.reason==='string'&&/^PUBLIC_(SCHEDULE|CAPTURE)_[A-Z_]+$/.test(result.reason),'FAILURE_REASON');
  }else{
   require(integer(result.acquisitionStartedAtMs)&&integer(result.completedAtMs)&&result.completedAtMs>=result.acquisitionStartedAtMs,'ACQUISITION_TIME');
   if(result.status==='ON_TIME_CAPTURED'){
    require(complete&&result.acquisitionStartedAtMs<result.window.closeMs&&result.completedAtMs<result.window.closeMs&&result.reason===null,'ON_TIME_CONTRACT');
   }else if(result.bundle===null){
    require(result.acquisitionStartedAtMs>=result.window.closeMs&&result.completedAtMs===result.acquisitionStartedAtMs
     &&result.reason==='WINDOW_CLOSED_BEFORE_ACQUISITION','LATE_BEFORE_CONTRACT');
   }else{
    require(complete&&result.acquisitionStartedAtMs<result.window.closeMs&&result.completedAtMs>=result.window.closeMs
     &&result.reason==='WINDOW_CLOSED_DURING_ACQUISITION','LATE_CAPTURE_CONTRACT');
   }
  }
 }
 const eligible=result.kind==='NATIVE_PUBLIC'&&result.runIdentity.eventName==='schedule'&&result.status==='ON_TIME_CAPTURED';
 require(result.scheduledAcceptanceEligible===eligible,'ELIGIBILITY_MISMATCH');
 return {complete,eligible};
}
function safeError(error){return /^PUBLIC_(SCHEDULE_AUDIT|SCHEDULE|CAPTURE)_[A-Z_]+$/.test(error?.message??'')?error.message:'PUBLIC_SCHEDULE_AUDIT_INVALID_OR_UNAVAILABLE_RESOURCE';}
function order(a,b){
 if(a.result.startedAtMs!==b.result.startedAtMs)return a.result.startedAtMs-b.result.startedAtMs;
 const x=BigInt(a.result.runIdentity.runId),y=BigInt(b.result.runIdentity.runId);
 if(x!==y)return x<y?-1:1;
 return Number(a.result.runIdentity.runAttempt)-Number(b.result.runIdentity.runAttempt);
}

/** Bindings are supplied by the caller's independently acquired GitHub metadata.
 * Only candidates within the imported subset are reported, never accepted coverage.
 * Bare directory strings are inspectable, but cannot establish native candidates.
 * An injected verifier always marks the whole report as a fixture.
 */
export async function auditPublicSchedule(options={}){
 keys(options,options.testFixture===undefined?['plan','runDirectories','asOfMs']:['plan','runDirectories','asOfMs','testFixture']);
 const {plan,runDirectories,asOfMs,testFixture}=options,fixture=testFixture!==undefined;
 validatePublicSchedule(plan);require(integer(asOfMs),'AS_OF');
 const sourceSort=v=>v.slice().sort((a,b)=>a.path.localeCompare(b.path));
 require(canonical(sourceSort(plan.sourceBinding))===canonical(sourceSort(publicScheduleSourceBinding())),'IMPLEMENTATION_MISMATCH');
 require(Array.isArray(runDirectories)&&runDirectories.length<=256,'RUN_DIRECTORY_LIST');
 if(fixture){keys(testFixture,['label','replayBundle']);require(typeof testFixture.label==='string'&&ID.test(testFixture.label)&&typeof testFixture.replayBundle==='function','EXPLICIT_TEST_FIXTURE');}
 const replay=fixture?testFixture.replayBundle:replayPublicBundle,planSha256=publicSchedulePlanSha256(plan);
 const runs=[],violations=[],conflicts=[],groups=new Map();
 for(let index=0;index<runDirectories.length;index++){
  const input=runDirectories[index];
  try{
   const bound=typeof input!=='string';
   if(bound){keys(input,['directory','expectedResultSha256','github']);require(typeof input.expectedResultSha256==='string'&&SHA.test(input.expectedResultSha256),'EXPECTED_RESULT_HASH');identity(input.github,plan);}
   const root=localRoot(bound?input.directory:input),before=inventory(root),bytes=bounded(join(root,'result.json')),resultSha256=sha(bytes);
   if(bound)require(resultSha256===input.expectedResultSha256,'RESULT_HASH');
   const result=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)),start=json(join(root,'start.json'));
   require(sha(bounded(join(root,'plan.json')))===planSha256&&canonical(json(join(root,'plan.json')))===canonical(plan),'PLAN_HASH');
   const verified=checkEnvelope(result,start,plan,planSha256,asOfMs);
   if(bound)require(canonical(input.github)===canonical(result.runIdentity),'EXTERNAL_IDENTITY_MISMATCH');
   const hasBundle=before.files.some(f=>f.path.startsWith('bundle/'));
   require(result.bundle===null?(result.status==='FAILED'||!hasBundle):hasBundle,'BUNDLE_PRESENCE');
   let replayStatus=null;
   if(verified.complete){
    const manifestBytes=bounded(join(root,'bundle/manifest.json')),m=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(manifestBytes));
    require(sha(manifestBytes)===result.bundle.manifestSha256,'BUNDLE_MANIFEST_HASH');
    require(m.captureKind===result.kind&&integer(m.startedAtMs)&&integer(m.completedAtMs)&&m.completedAtMs>=m.startedAtMs
     &&integer(result.acquisitionStartedAtMs)&&m.startedAtMs>=result.acquisitionStartedAtMs
     &&m.completedAtMs<=(result.completedAtMs??asOfMs),'BUNDLE_TIME');
    const replayed=await replay({directory:join(root,'bundle'),expectedManifestSha256:result.bundle.manifestSha256});
    require(replayed?.verified===true&&replayed.nativeCapture===(result.kind==='NATIVE_PUBLIC')
     &&replayed.status===(result.kind==='NATIVE_PUBLIC'?'VERIFIED_NATIVE_PUBLIC_CAPTURE':'VERIFIED_INJECTED_FIXTURE')
     &&replayed.manifestSha256===result.bundle.manifestSha256&&replayed.providerRequestsMade===false
     &&replayed.originalPathsRead===false&&replayed.sqliteOpened===false,'REPLAY_CONTRACT');
    replayStatus=replayed.status;
   }
   require(inventory(root).sha256===before.sha256,'RESOURCE_CHANGED');
   const record={inputIndex:index,result,resultSha256,externallyBound:bound,replayStatus,inventorySha256:before.sha256,duplicateOf:null};
   const previous=groups.get(result.runKey);
   if(previous){
    if(previous.resultSha256!==resultSha256||previous.inventorySha256!==before.sha256){
     conflicts.push({runKey:result.runKey,inputIndices:[previous.inputIndex,index],reason:'SAME_RUN_KEY_DIFFERENT_BYTES'});
    }else{
     record.duplicateOf=previous.inputIndex;
     if(bound)previous.externallyBound=true;
    }
   }else{groups.set(result.runKey,record);}
   runs.push(record);
  }catch(error){violations.push({inputIndex:index,reason:safeError(error)});}
 }
 const unique=[...groups.values()].sort(order),duplicates=[];
 const windows=plan.windows.map(window=>{
  const candidates=unique.filter(r=>r.result.window?.id===window.id&&r.result.runIdentity.eventName==='schedule');
  if(!candidates.length)return {...window,status:asOfMs<window.openMs?'FUTURE':asOfMs<window.closeMs?'PENDING':'MISSING_EVIDENCE',
   selectedRunKey:null,eligibleCandidate:false,externallyBound:false,reason:'NO_MATCHING_IMPORTED_SCHEDULED_ATTEMPT'};
  const selected=candidates[0];
  for(const r of candidates.slice(1))duplicates.push({runKey:r.result.runKey,selectedRunKey:selected.result.runKey,windowId:window.id,reason:'LATER_ATTEMPT_NOT_SELECTED'});
  return {...window,status:selected.result.kind==='INJECTED_FIXTURE'?'FIXTURE':selected.result.status,
   selectedRunKey:selected.result.runKey,selectedInputIndex:selected.inputIndex,
   eligibleCandidate:selected.result.scheduledAcceptanceEligible&&selected.externallyBound,
   externallyBound:selected.externallyBound};
 });
 const unboundRuns=unique.filter(r=>!r.externallyBound).length;
 const blocked=violations.length>0||conflicts.length>0,candidatesBlocked=blocked||fixture||unboundRuns>0;
 const candidateSlots=windows.filter(w=>w.eligibleCandidate).length;
 // The supplied subset may omit an earlier failed attempt, even with valid bindings.
 // Coverage stays closed until a separate complete external inventory is established.
 for(const w of windows)w.scheduledAcceptanceEligible=false;
 const counts={totalWindows:windows.length,closedWindows:plan.windows.filter(w=>w.closeMs<=asOfMs).length,
  futureWindows:windows.filter(w=>w.status==='FUTURE').length,pendingWindows:windows.filter(w=>w.status==='PENDING').length,
  missingEvidenceWindows:windows.filter(w=>w.status==='MISSING_EVIDENCE').length,lateWindows:windows.filter(w=>w.status==='LATE').length,
  failedWindows:windows.filter(w=>w.status==='FAILED').length,fixtureWindows:windows.filter(w=>w.status==='FIXTURE').length,
  scheduledCoverageAccepted:0,importedCollectionEligibleSlots:candidatesBlocked?0:candidateSlots,
  identicalCopies:runs.filter(r=>r.duplicateOf!==null).length,
  laterAttemptsNotSelected:duplicates.length,diagnosticRuns:unique.filter(r=>r.result.runIdentity.eventName!=='schedule').length,
  outsideScheduledRuns:unique.filter(r=>r.result.runIdentity.eventName==='schedule'&&r.result.status==='OUTSIDE').length,
  expiredScheduledRuns:unique.filter(r=>r.result.runIdentity.eventName==='schedule'&&r.result.status==='EXPIRED').length,
  pausedScheduledRuns:unique.filter(r=>r.result.runIdentity.eventName==='schedule'&&r.result.status==='PAUSED').length,
  unboundRuns,invalidInputs:violations.length,conflicts:conflicts.length};
 return {schemaVersion:'g4.public-schedule-audit.v1',status:blocked?(conflicts.length?'CONFLICT':'INVALID'):fixture?'FIXTURE_NOT_OPERATIONAL':counts.unboundRuns?'CONSISTENCY_ONLY':'VERIFIED_IMPORTED_COLLECTION',
  kind:fixture?'INJECTED_FIXTURE':'OFFLINE_EVIDENCE_AUDIT',fixtureLabel:fixture?testFixture.label:null,scheduleId:plan.id,planSha256,asOfMs,
  coverageAcceptanceBlocked:true,coverageAcceptanceBlockedReason:'INCOMPLETE_EXTERNAL_RUN_INVENTORY',
  scheduledAcceptanceEligible:false,counts,windows,duplicates,conflicts,violations,
  ...(fixture?{simulatedEligibleSlots:candidateSlots}:{}),
  runs:runs.map(r=>({inputIndex:r.inputIndex,runKey:r.result.runKey,status:r.result.status,eventName:r.result.runIdentity.eventName,
   resultSha256:r.resultSha256,inventorySha256:r.inventorySha256,externallyBound:r.externallyBound,duplicateOf:r.duplicateOf,replayStatus:r.replayStatus})),
  policy:{...POLICY,readOnly:true,networkRequestsMade:false,sqliteOpened:false,completeGitHubRunInventoryClaimed:false,
   firstImportedScheduledAttemptClaimed:true},
  limitations:['Audits only the supplied imported collection; missing GitHub artifacts remain unproven, not successful.',
   'External bindings are caller-supplied evidence, not cryptographic GitHub or provider attestations.',
   'Only the first imported scheduled attempt is selected; an earlier unimported attempt may exist.',
   'Candidates from the imported collection never establish accepted operational coverage.',
   'Public-data collection is not a strategy observation or financial acceptance.']};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  require(process.argv.length===3,'INPUT_FILE_REQUIRED');
  const request=json(resolve(process.argv[2])),result=await auditPublicSchedule(request);
  console.log(JSON.stringify(result,null,2));
  if(['INVALID','CONFLICT'].includes(result.status))process.exitCode=1;
 }catch(error){console.error(JSON.stringify({status:'INVALID',reason:safeError(error)}));process.exitCode=1;}
}
