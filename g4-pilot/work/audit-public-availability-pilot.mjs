/** Offline audit of one finite, prearmed public-data pilot.
 * Caller-supplied GitHub bindings are independently obtained evidence, not signatures.
 * The legacy auditor is used one directory at a time, never as this pilot's aggregator.
 */
import {createHash} from 'node:crypto';
import {readFileSync,lstatSync,realpathSync,readdirSync,existsSync} from 'node:fs';
import {resolve,dirname,join,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {validatePublicAvailabilityPilotPlan,publicAvailabilityPilotSourceBinding} from './public-availability-pilot.mjs';
import {publicSchedulePlanSha256} from './public-capture-schedule.mjs';
import {auditPublicSchedule} from './audit-public-schedule.mjs';
import {replayPublicBundle} from './public-capture-bundle.mjs';
import {measurePublicCaptureQuality} from './public-capture-quality.mjs';

const SHA=/^[a-f0-9]{64}$/,ID=/^[a-z0-9][a-z0-9_.-]{0,79}$/;
const QUALITY=Object.freeze({quote:Object.freeze({maxAgeAtReceiptMs:10000,comparison:'RECEIPT_MILLISECOND_INTERVAL_UPPER_BOUND'}),history:Object.freeze({intervalMs:86400000})});
const PILOT_POLICY={publicDataOnly:true,credentialsUsed:false,ordersSent:0,originalCalendarAcceptance:false,
 scheduledAcceptanceEligible:false,forwardV1V2Observation:false,paperObservation:false,economicAcceptance:false,
 financialAcceptance:false,externalReadinessVerified:false,providerAttestation:false};
const canonical=x=>Array.isArray(x)?'['+x.map(canonical).join(',')+']':x&&typeof x==='object'?'{'+Object.keys(x).sort().map(k=>JSON.stringify(k)+':'+canonical(x[k])).join(',')+'}':JSON.stringify(x);
const sha=x=>createHash('sha256').update(x).digest('hex');
const integer=x=>Number.isSafeInteger(x)&&x>=0;
const equal=(a,b)=>canonical(a)===canonical(b);
function require(ok,code){if(!ok)throw Error('PUBLIC_PILOT_AUDIT_'+code);}
function keys(value,expected){require(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===expected.slice().sort().join(','),'FIELDS');}
function regular(file,directory=false){const s=lstatSync(file),actual=realpathSync(file),same=process.platform==='win32'?actual.toLowerCase()===file.toLowerCase():actual===file;
 require(!s.isSymbolicLink()&&(directory?s.isDirectory():s.isFile())&&(directory||s.nlink===1)&&same,'LINK_OR_NONREGULAR_RESOURCE');return s;}
function localRoot(directory){require(typeof directory==='string'&&isAbsolute(directory)&&!directory.includes('\0')&&!directory.startsWith('\\\\')&&!directory.startsWith('//'),'LOCAL_DIRECTORY_REQUIRED');
 const root=resolve(directory);for(let p=root;;p=dirname(p)){regular(p,true);if(p===dirname(p))break;}return root;}
function bytes(file,max=262144){require(regular(file).size<=max,'RESOURCE_SIZE');return readFileSync(file);}
function parse(b){return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}
function json(file){return parse(bytes(file));}
function inventory(root){const files=[],directories=[];let count=0,total=0;
 function walk(prefix,depth){require(depth<=8,'INVENTORY_DEPTH');for(const name of readdirSync(join(root,prefix))){
  require(++count<=256&&/^[A-Za-z0-9_.-]+$/.test(name)&&name!=='.'&&name!=='..'&&!/[. ]$/.test(name),'INVENTORY_ENTRY');
  const path=prefix?prefix+'/'+name:name,full=join(root,path),s=lstatSync(full);regular(full,s.isDirectory());
  if(s.isDirectory()){require(path==='captures'||path.startsWith('captures/'),'UNEXPECTED_DIRECTORY');directories.push(path);walk(path,depth+1);}
  else{require(prefix!==''||['pilot-plan.json','native-plan.json','READY.json','RUN-START.json','SUMMARY.json','FAILED.json'].includes(name)||/^[a-z0-9][a-z0-9_.-]*-child\.json$/.test(name)||/^0[123]-termination-request\.json$/.test(name),'UNEXPECTED_FILE');
   require(s.size<=2097152,'RESOURCE_SIZE');total+=s.size;require(total<=45000000,'TOTAL_SIZE');const b=readFileSync(full);files.push({path,bytes:b.length,sha256:sha(b)});}
 }}walk('',0);files.sort((a,b)=>a.path.localeCompare(b.path));directories.sort();return {files,directories,sha256:sha(canonical({files,directories})),bytes:total};}
function checkInventory(found,plan){
 const controls=new Set(['pilot-plan.json','native-plan.json','READY.json','RUN-START.json','SUMMARY.json','FAILED.json',
  ...plan.schedule.windows.map(w=>w.id+'-child.json'),'01-termination-request.json','02-termination-request.json','03-termination-request.json']);
 for(const file of found.files){const p=file.path;if(!p.includes('/')){require(controls.has(p),'UNEXPECTED_CONTROL_FILE');continue;}
  require(/^captures\/0[123]\/(?:plan|start|result)\.json$/.test(p)
   ||/^captures\/0[123]\/bundle\/(?:START|FAILED|quote|manifest)\.json$/.test(p)
   ||/^captures\/0[123]\/bundle\/history\/(?:START|asset-pairs\.raw|bars\.normalized|ohlc\.raw|receipt)\.json$/.test(p)
   ||/^captures\/0[123]\/bundle\/quotes\/[A-Za-z0-9_.-]{1,100}\/(?:metadata\.json|response\.body)$/.test(p),'UNEXPECTED_CAPTURE_FILE');}
 for(const p of found.directories)require(p==='captures'||/^captures\/0[123](?:\/bundle(?:\/(?:history|quotes(?:\/[A-Za-z0-9_.-]{1,100})?))?)?$/.test(p),'UNEXPECTED_CAPTURE_DIRECTORY');
}
function identity(value,repository){keys(value,['provider','repository','commitSha','runId','runAttempt','eventName']);
 require(value.provider==='GITHUB_ACTIONS'&&value.repository===repository&&/^[a-f0-9]{40}$/.test(value.commitSha??'')
  &&typeof value.runId==='string'&&/^[1-9][0-9]{0,19}$/.test(value.runId)&&value.runAttempt==='1'
  &&['push','workflow_dispatch'].includes(value.eventName),'RUN_IDENTITY');}
function sources(plan){const current=publicAvailabilityPilotSourceBinding();
 const sorted=x=>x.slice().sort((a,b)=>a.path.localeCompare(b.path));
 require(equal(plan.wrapperSource,current.wrapperSource)&&equal(sorted(plan.schedule.sourceBinding),sorted(current.sourceBinding))
  &&equal(sorted(plan.auditSourceBinding),sorted(current.auditSourceBinding)),'IMPLEMENTATION_MISMATCH');}
function safeError(e){return /^PUBLIC_[A-Z_]+$/.test(e?.message??'')?e.message:'PUBLIC_PILOT_AUDIT_INVALID_OR_UNAVAILABLE_RESOURCE';}
function checkKind(value){require(['NATIVE_PUBLIC','INJECTED_FIXTURE'].includes(value.kind)
 &&(value.kind==='NATIVE_PUBLIC'?value.fixtureLabel===null:typeof value.fixtureLabel==='string'&&ID.test(value.fixtureLabel)),'KIND');}
function checkReady(ready,plan,expectedPlanSha256,asOfMs){
 require(ready.schemaVersion==='g4.public-availability-pilot-ready.v1','READY_SCHEMA');checkKind(ready);identity(ready.runIdentity,plan.schedule.repository);
 require(ready.planSha256===expectedPlanSha256&&ready.scheduleId===plan.schedule.id
  &&ready.schedulePlanSha256===publicSchedulePlanSha256(plan.schedule)&&equal(ready.wrapperSource,plan.wrapperSource)
  &&equal(ready.runtime,plan.runtime),'READY_BINDING');
 require(integer(ready.readyAtMs)&&ready.readyAtMs>=plan.schedule.registeredAtMs&&ready.readyAtMs<plan.schedule.windows[0].openMs
  &&ready.readyAtMs<=asOfMs&&ready.firstOpenMs===plan.schedule.windows[0].openMs
  &&ready.deadlineMs===plan.schedule.registeredAtMs+plan.limits.maxRuntimeMs
  &&Number.isFinite(ready.readyMonotonicMs)&&ready.readyMonotonicMs>=0,'READY_TIME');
 require(equal(ready.policy,PILOT_POLICY),'READY_POLICY');
}
function externalBinding(github,ready,plan,asOfMs,readyHash,summaryHash,root){
 if(github===null)return {bound:false,reason:'EXTERNAL_GITHUB_BINDINGS_MISSING',windowHashes:new Map()};
 keys(github,['runIdentity','readyArtifactCreatedAtMs','readyArtifactTimestampPrecisionMs','readySha256','summarySha256','windowResults','readyArtifact']);
 identity(github.runIdentity,plan.schedule.repository);require(equal(github.runIdentity,ready.runIdentity),'EXTERNAL_IDENTITY_MISMATCH');
 require(github.readySha256===readyHash&&SHA.test(github.readySha256),'EXTERNAL_READY_HASH');
 require(github.summarySha256===summaryHash&&(summaryHash===null||SHA.test(summaryHash)),'EXTERNAL_SUMMARY_HASH');
 require(integer(github.readyArtifactCreatedAtMs)&&github.readyArtifactCreatedAtMs<=asOfMs
  &&github.readyArtifactTimestampPrecisionMs===1000,'EXTERNAL_READY_TIME');
 require(Array.isArray(github.windowResults)&&github.windowResults.length<=3,'EXTERNAL_WINDOW_LIST');
 const map=new Map();for(const entry of github.windowResults){keys(entry,['windowId','resultSha256']);
  require(plan.schedule.windows.some(w=>w.id===entry.windowId)&&SHA.test(entry.resultSha256??'')&&!map.has(entry.windowId),'EXTERNAL_WINDOW_DUPLICATE_OR_UNKNOWN');map.set(entry.windowId,entry.resultSha256);}
 const upper=github.readyArtifactCreatedAtMs+1000;
 require(Number.isSafeInteger(upper),'EXTERNAL_READY_TIME');
 let archiveBound=false;
 if(github.readyArtifact!==null){const a=github.readyArtifact;keys(a,['archiveFile','apiDigestSha256','extractionReceiptFile','expectedExtractionReceiptSha256']);
  require(SHA.test(a.apiDigestSha256??'')&&SHA.test(a.expectedExtractionReceiptSha256??''),'READY_ARCHIVE_BINDING');
  require(typeof a.archiveFile==='string'&&isAbsolute(a.archiveFile)&&typeof a.extractionReceiptFile==='string'&&isAbsolute(a.extractionReceiptFile),'READY_ARCHIVE_PATH');
  localRoot(dirname(resolve(a.archiveFile)));localRoot(dirname(resolve(a.extractionReceiptFile)));
  const archiveBytes=bytes(resolve(a.archiveFile),1048576),receiptBytes=bytes(resolve(a.extractionReceiptFile));
  require(sha(archiveBytes)===a.apiDigestSha256&&sha(receiptBytes)===a.expectedExtractionReceiptSha256,'READY_ARCHIVE_HASH');
  const receipt=parse(receiptBytes);keys(receipt,['schemaVersion','archiveSha256','archiveBytes','entries','inspectorSha256','readOnly']);
  require(receipt.schemaVersion==='g4.public-availability-ready-import.v1'&&receipt.archiveSha256===a.apiDigestSha256
   &&receipt.archiveBytes===archiveBytes.length&&receipt.readOnly===true
   &&receipt.inspectorSha256===plan.auditSourceBinding.find(x=>x.path==='inspect-public-pilot-ready-archive.ps1')?.sha256
   &&Array.isArray(receipt.entries)&&receipt.entries.length===3,'READY_EXTRACTION_RECEIPT');
  const names=new Set();for(const entry of receipt.entries){keys(entry,['path','bytes','sha256']);
   require(['READY.json','pilot-plan.json','native-plan.json'].includes(entry.path)&&!names.has(entry.path),'READY_EXTRACTION_ENTRY');names.add(entry.path);
   const body=bytes(join(root,entry.path));require(entry.sha256===sha(body)&&entry.bytes===body.length,'READY_EXTRACTION_ENTRY');}
  archiveBound=true;
 }
 const beforeOpen=upper<=ready.firstOpenMs,afterLocalReady=upper>ready.readyAtMs;
 return {bound:beforeOpen&&afterLocalReady&&archiveBound,reason:!beforeOpen?'READY_NOT_EXTERNALLY_PROVEN_BEFORE_OPEN':!afterLocalReady?'EXTERNAL_READY_PRECEDES_LOCAL_READY':!archiveBound?'READY_ARCHIVE_BINDING_MISSING':null,
  readyTimeUpperBoundExclusiveMs:upper,windowHashes:map};
}

/** All paths refer to imported local bytes. No external API or market request is made.
 * Expected hashes and GitHub fields must come from independent logs/API receipts.
 * Missing external fields yield consistency-only results, never accepted recurrence.
 */
export async function auditPublicAvailabilityPilot(options={}){
 keys(options,options.testFixture===undefined?['directory','expectedPlanSha256','expectedReadySha256','expectedSummarySha256','github','asOfMs']
  :['directory','expectedPlanSha256','expectedReadySha256','expectedSummarySha256','github','asOfMs','testFixture']);
 const {expectedPlanSha256,expectedReadySha256,expectedSummarySha256,github,asOfMs,testFixture}=options,fixture=testFixture!==undefined;
 require(SHA.test(expectedPlanSha256??'')&&SHA.test(expectedReadySha256??'')&&(expectedSummarySha256===null||SHA.test(expectedSummarySha256??''))&&integer(asOfMs),'INPUT_BINDINGS');
 if(fixture){keys(testFixture,['label','replayBundle']);require(typeof testFixture.label==='string'&&ID.test(testFixture.label)&&typeof testFixture.replayBundle==='function','EXPLICIT_TEST_FIXTURE');}
 const replay=fixture?testFixture.replayBundle:replayPublicBundle,root=localRoot(options.directory),before=inventory(root);
 const planBytes=bytes(join(root,'pilot-plan.json'));require(sha(planBytes)===expectedPlanSha256,'PLAN_HASH');
 const plan=parse(planBytes);validatePublicAvailabilityPilotPlan(plan);sources(plan);checkInventory(before,plan);
 const readyBytes=bytes(join(root,'READY.json'));require(sha(readyBytes)===expectedReadySha256,'READY_HASH');const ready=parse(readyBytes);checkReady(ready,plan,expectedPlanSha256,asOfMs);
 const nativeBytes=bytes(join(root,'native-plan.json'));require(sha(nativeBytes)===ready.nativePlanFileSha256&&equal(parse(nativeBytes),plan.schedule),'NATIVE_PLAN_HASH');
 const summaryExists=existsSync(join(root,'SUMMARY.json'));let summary=null,summaryHash=null;
 const violations=[];
 if(summaryExists){const b=bytes(join(root,'SUMMARY.json'));summaryHash=sha(b);if(expectedSummarySha256!==null)require(summaryHash===expectedSummarySha256,'SUMMARY_HASH');summary=parse(b);
  require(summary.schemaVersion==='g4.public-availability-pilot-result.v1','SUMMARY_SCHEMA');checkKind(summary);
  require(summary.kind===ready.kind&&summary.fixtureLabel===ready.fixtureLabel&&summary.planSha256===expectedPlanSha256
   &&summary.schedulePlanSha256===ready.schedulePlanSha256&&summary.readySha256===expectedReadySha256
   &&equal(summary.runIdentity,ready.runIdentity)&&summary.readyAtMs===ready.readyAtMs&&equal(summary.policy,ready.policy),'SUMMARY_BINDING');
  require(integer(summary.startedAtMs)&&summary.startedAtMs>=ready.readyAtMs&&integer(summary.completedAtMs)
   &&summary.completedAtMs>=summary.startedAtMs&&summary.completedAtMs<=asOfMs,'SUMMARY_TIME');
  require(Array.isArray(summary.windows)&&summary.windows.length<=3,'SUMMARY_WINDOWS');
  const {windows:summaryWindows,clock,...startBase}=summary;
  require(equal(json(join(root,'RUN-START.json')),{...startBase,completedAtMs:null,status:'RUNNING',reason:null}),'RUN_START_BINDING');
  require(clock&&integer(clock.samples)&&integer(clock.maxObservedGapMs)&&integer(clock.maxObservedSkewMs),'CLOCK_STATS');
 }else require(expectedSummarySha256===null,'SUMMARY_MISSING');
 const ext=externalBinding(github,ready,plan,asOfMs,expectedReadySha256,summaryHash,root);
 const runControlReasons=[];
 if(!summary)runControlReasons.push('SUMMARY_MISSING');
 else{
  if(summary.startedAtMs>=ready.firstOpenMs)runControlReasons.push('RUN_NOT_PREARMED');
  if(summary.completedAtMs>ready.deadlineMs)runControlReasons.push('RUN_EXCEEDED_DEADLINE');
  if(summary.clock.samples===0||summary.clock.maxObservedGapMs>plan.limits.maxObservationGapMs||summary.clock.maxObservedSkewMs>plan.limits.maxClockSkewMs
   ||/^PUBLIC_PILOT_(?:CLOCK_|OBSERVATION_GAP|DEADLINE)/.test(summary.reason??''))runControlReasons.push('RUN_CLOCK_NOT_VALID');
 }
 const runControlValid=runControlReasons.length===0;
 const entries=new Map();for(const entry of summary?.windows??[]){require(entry&&plan.schedule.windows.some(w=>w.id===entry.windowId)
  &&!entries.has(entry.windowId),'WINDOW_DUPLICATE_OR_UNKNOWN');entries.set(entry.windowId,entry);}
 const windows=[];
 for(const [windowIndex,window] of plan.schedule.windows.entries()){const entry=entries.get(window.id),record={...window,status:asOfMs<window.openMs?'FUTURE':asOfMs<window.closeMs?'PENDING':'MISSING_EVIDENCE',
  reason:null,resultSha256:null,structuralReplayVerified:false,nativeCapture:false,externallyBound:false,availabilityAccepted:false,dataQualityAccepted:false,quality:null};
  windows.push(record);if(!entry)continue;
  try{
   require(entry.directory==='captures/'+String(windowIndex+1).padStart(2,'0'),'WINDOW_DIRECTORY');
   require(['CAPTURED','NOT_ATTEMPTED','MISSED','FAILED'].includes(entry.status)&&(entry.reason===null||typeof entry.reason==='string'),'WINDOW_STATUS');
   record.status=entry.status;record.reason=entry.reason;
   if(entry.resultSha256===null){require(entry.status!=='CAPTURED','CAPTURED_WITHOUT_RESULT');continue;}
   require(SHA.test(entry.resultSha256??''),'WINDOW_RESULT_HASH');
   const directory=join(root,entry.directory),body=bytes(join(directory,'result.json'));require(sha(body)===entry.resultSha256,'WINDOW_RESULT_HASH');
   const result=parse(body);record.resultSha256=entry.resultSha256;
   require(equal(result.runIdentity,ready.runIdentity)&&result.kind===ready.kind,'WINDOW_IDENTITY');
   require(result.window?.id===window.id&&equal(result.window,window),'WINDOW_MISMATCH');
   if(ext.windowHashes.has(window.id))require(ext.windowHashes.get(window.id)===entry.resultSha256,'EXTERNAL_WINDOW_HASH');
   record.externallyBound=ext.bound&&ext.windowHashes.get(window.id)===entry.resultSha256&&expectedSummarySha256!==null;
   const perWindow=await auditPublicSchedule({plan:plan.schedule,runDirectories:[{directory,expectedResultSha256:entry.resultSha256,github:ready.runIdentity}],asOfMs,
    ...(fixture?{testFixture}:{} )});
   require(perWindow.violations.length===0&&perWindow.conflicts.length===0&&perWindow.runs.length===1,'LEGACY_ENVELOPE_OR_REPLAY');
   if(entry.status!=='CAPTURED'){require(entry.availabilityPilotCandidateEligible===false,'FAILED_WINDOW_CANDIDATE');continue;}
   require(result.status==='ON_TIME_CAPTURED'&&result.scheduledAcceptanceEligible===false,'CAPTURE_STATUS');
   require(integer(entry.startedAtMs)&&integer(entry.completedAtMs)&&entry.startedAtMs>=window.openMs
    &&entry.startedAtMs<=result.startedAtMs&&entry.completedAtMs>=result.completedAtMs&&entry.completedAtMs<window.closeMs
    &&entry.startedAtMs>=summary.startedAtMs&&entry.completedAtMs<=summary.completedAtMs,'WINDOW_TIME');
   require(entry.child?.code===0&&entry.child.signal===null&&entry.child.terminated===false&&entry.child.terminationRequested===false&&entry.child.closeObserved===true,'CHILD_TERMINATION');
   const childRecord=json(join(root,window.id+'-child.json'));keys(childRecord,['code','signal','terminated','terminationRequested','closeObserved','stdout','stderr','error']);
   require(equal(entry.child,{code:childRecord.code,signal:childRecord.signal,terminated:childRecord.terminated,terminationRequested:childRecord.terminationRequested,closeObserved:childRecord.closeObserved})
    &&childRecord.error===false&&typeof childRecord.stdout==='string'&&typeof childRecord.stderr==='string'
    &&parse(Buffer.from(childRecord.stdout.trim())).resultSha256===entry.resultSha256,'CHILD_RESULT_BINDING');
   const bundle=await replay({directory:join(directory,'bundle'),expectedManifestSha256:result.bundle.manifestSha256});
   require(bundle.verified===true&&bundle.providerRequestsMade===false&&bundle.originalPathsRead===false&&bundle.sqliteOpened===false
    &&bundle.verification.sourceChecks.externalNetworkCallsDuringReplay===0&&bundle.manifestSha256===result.bundle.manifestSha256,'QUALITY_REPLAY');
   require(equal(bundle.producer,plan.runtime),'CAPTURE_RUNTIME');
   const native=bundle.nativeCapture===true&&bundle.status==='VERIFIED_NATIVE_PUBLIC_CAPTURE'&&result.kind==='NATIVE_PUBLIC';
   require(entry.availabilityPilotCandidateEligible===native,'CANDIDATE_ELIGIBILITY');
   const quality=measurePublicCaptureQuality({...bundle.verification,policy:QUALITY});
   record.structuralReplayVerified=true;record.nativeCapture=native;record.quality=quality;
   record.availabilityAccepted=!fixture&&native&&record.externallyBound&&runControlValid;
   record.dataQualityAccepted=record.availabilityAccepted&&quality.qualityCriteriaPassed;
  }catch(error){record.status='INVALID';record.reason=safeError(error);record.availabilityAccepted=false;record.dataQualityAccepted=false;violations.push({windowId:window.id,reason:record.reason});}
 }
 for(const id of ext.windowHashes.keys())if(!entries.has(id))violations.push({windowId:id,reason:'EXTERNAL_RESULT_NOT_IN_SUMMARY'});
 require(inventory(root).sha256===before.sha256,'RESOURCE_CHANGED');sources(plan);
 const failed=violations.length>0;if(failed)for(const w of windows){w.availabilityAccepted=false;w.dataQualityAccepted=false;}
 const counts={windows:3,closed:windows.filter(w=>w.closeMs<=asOfMs).length,captured:windows.filter(w=>w.status==='CAPTURED').length,
  structurallyVerified:windows.filter(w=>w.structuralReplayVerified).length,availabilityAccepted:windows.filter(w=>w.availabilityAccepted).length,
  dataQualityAccepted:windows.filter(w=>w.dataQualityAccepted).length,missing:windows.filter(w=>w.status==='MISSING_EVIDENCE').length,
  failed:windows.filter(w=>w.status==='FAILED').length,missed:windows.filter(w=>w.status==='MISSED').length,notAttempted:windows.filter(w=>w.status==='NOT_ATTEMPTED').length,
  invalid:violations.length,scheduledCalendarCoverageAccepted:0,financialObservations:0};
 const allThreeAccepted=counts.availabilityAccepted===3&&runControlValid&&summary.status==='CAPTURED_PENDING_EXTERNAL_REVIEW'&&summary.reason===null;
 return {schemaVersion:'g4.public-availability-pilot-audit.v1',status:failed?'INVALID':fixture?'FIXTURE_NOT_OPERATIONAL':!summary?'INCOMPLETE'
  :!ext.bound?'CONSISTENCY_ONLY':allThreeAccepted?'VERIFIED_FINITE_PILOT_RECURRENCE':'PILOT_NOT_ACCEPTED',
  kind:fixture?'INJECTED_FIXTURE':'OFFLINE_EVIDENCE_AUDIT',fixtureLabel:fixture?testFixture.label:null,planSha256:expectedPlanSha256,
  schedulePlanSha256:ready.schedulePlanSha256,readySha256:expectedReadySha256,summarySha256:summaryHash,asOfMs,
  sourceBindingsVerified:true,inventorySha256:before.sha256,externallyBound:ext.bound,externalBindingReason:ext.reason,
  readyExternalTimeUpperBoundExclusiveMs:ext.readyTimeUpperBoundExclusiveMs??null,runControlValid,runControlReasons,counts,windows,violations,
  finitePilotRecurrenceAccepted:allThreeAccepted&&!fixture&&!failed,dailyAutonomousStartupProven:false,
  availability24x7Proven:false,scheduledCalendarCoverageAccepted:false,forwardV1V2Observation:false,paperObservation:false,
  financialAcceptance:false,liveEnabled:false,providerRequestsMade:false,sqliteOpened:false,
  limitations:['Acceptance is limited to three windows in one already-started run; it does not prove daily startup or continuous availability.',
   'External GitHub identities and hashes are caller-supplied independent evidence, not cryptographic attestations.',
   'GitHub artifact creation is evaluated at its one-second timestamp upper bound; local clocks are not independently attested UTC.',
   'Freshness at collection does not establish freshness at a later decision; different data venues are not execution-equivalent.',
   'No original schedule coverage, V1/V2/PAPER observation, execution permission or financial outcome is established.']};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{require(process.argv.length===3,'INPUT_FILE_REQUIRED');const inputPath=resolve(process.argv[2]);localRoot(dirname(inputPath));
  const result=await auditPublicAvailabilityPilot(json(inputPath));console.log(JSON.stringify(result,null,2));if(result.status==='INVALID')process.exitCode=1;
 }catch(error){console.error(JSON.stringify({status:'INVALID',reason:safeError(error)}));process.exitCode=1;}
}
