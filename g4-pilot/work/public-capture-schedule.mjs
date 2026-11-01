/** Bounded public acquisition schedule. No ledger, strategy, account or orders.
 * Event identity and clocks are local evidence, not a GitHub/provider signature.
 */
import {createHash} from 'node:crypto';
import {readFileSync,writeFileSync,openSync,closeSync,fsyncSync,lstatSync,realpathSync,mkdirSync,existsSync} from 'node:fs';
import {resolve,dirname,join,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';
import {capturePublicBundle,PUBLIC_CAPTURE_SOURCES} from './public-capture-bundle.mjs';

const SOURCE_PATHS=Object.freeze(['public-capture-schedule.mjs',...PUBLIC_CAPTURE_SOURCES]);
const EVENTS=['schedule','workflow_dispatch','push'],HASH=/^[a-f0-9]{64}$/,ID=/^[a-z0-9][a-z0-9_.-]{0,79}$/;
const POLICY=Object.freeze({publicDataOnly:true,accountCredentialsUsed:false,ordersSent:0,
 forwardExperimentRegistered:false,forwardV1V2Observation:false,economicAcceptance:false,
 liveEnabled:false,providerAttestation:false,missedWindowsBackfilled:false});
const sha=b=>createHash('sha256').update(b).digest('hex');
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const integer=n=>Number.isSafeInteger(n)&&n>=0;
function require(ok,code){if(!ok)throw Error('PUBLIC_SCHEDULE_'+code);}
function keys(value,expected){require(value&&typeof value==='object'&&!Array.isArray(value)&&Object.keys(value).sort().join(',')===expected.slice().sort().join(','),'FIELDS');}
function repository(value){return typeof value==='string'&&/^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$/.test(value);}

/** Pure validation; no clock, filesystem, or network access. */
export function validatePublicSchedule(plan){
 keys(plan,['schemaVersion','id','repository','enabled','registeredAtMs','expiresAtMs','windows','allowedEvents','sourceBinding']);
 require(plan.schemaVersion==='g4.public-capture-schedule.v1'&&typeof plan.id==='string'&&ID.test(plan.id)&&repository(plan.repository),'PLAN_IDENTITY');
 require(typeof plan.enabled==='boolean'&&integer(plan.registeredAtMs)&&integer(plan.expiresAtMs),'PLAN_CONTROL');
 require(Array.isArray(plan.allowedEvents)&&plan.allowedEvents.includes('schedule')&&new Set(plan.allowedEvents).size===plan.allowedEvents.length
  &&plan.allowedEvents.every(e=>EVENTS.includes(e)),'EVENTS');
 require(Array.isArray(plan.windows)&&plan.windows.length>=1&&plan.windows.length<=32,'WINDOW_COUNT');
 const seen=new Set();let last=plan.registeredAtMs;
 for(const window of plan.windows){
  keys(window,['id','openMs','closeMs']);
  require(typeof window.id==='string'&&ID.test(window.id)&&!seen.has(window.id)&&integer(window.openMs)&&integer(window.closeMs)
   &&window.openMs>=last&&window.openMs<window.closeMs&&window.closeMs-window.openMs<=3600000,'WINDOW_CONTRACT');
  seen.add(window.id);last=window.closeMs;
 }
 require(plan.registeredAtMs<plan.windows[0].openMs&&plan.expiresAtMs===last
  &&last-plan.registeredAtMs<=45*86400000,'FINITE_HORIZON');
 require(Array.isArray(plan.sourceBinding)&&plan.sourceBinding.length===SOURCE_PATHS.length,'SOURCE_BINDING');
 const sourceSet=new Set();
 for(const source of plan.sourceBinding){
  keys(source,['path','sha256','bytes']);
  require(SOURCE_PATHS.includes(source.path)&&!sourceSet.has(source.path)&&HASH.test(source.sha256??'')
   &&Number.isSafeInteger(source.bytes)&&source.bytes>0&&source.bytes<=1048576,'SOURCE_BINDING');
  sourceSet.add(source.path);
 }
 return {valid:true,scheduleId:plan.id,windowCount:plan.windows.length,expiresAtMs:plan.expiresAtMs};
}
export function publicSchedulePlanSha256(plan){validatePublicSchedule(plan);return sha(canonical(plan)+'\n');}
export function publicScheduleSourceBinding(){
 return SOURCE_PATHS.map(path=>{
  const file=fileURLToPath(new URL(path,import.meta.url)),s=lstatSync(file);
  require(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=1048576,'SOURCE_RESOURCE');
  const bytes=readFileSync(file);return {path,sha256:sha(bytes),bytes:bytes.length};
 });
}
function verifySources(plan){
 const sort=a=>a.slice().sort((x,y)=>x.path.localeCompare(y.path));
 require(canonical(sort(plan.sourceBinding))===canonical(sort(publicScheduleSourceBinding())),'IMPLEMENTATION_MISMATCH');
}

/** Half-open windows, with no acquisition for a closed or future window. */
export function selectPublicWindow(plan,nowMs){
 validatePublicSchedule(plan);require(integer(nowMs),'CLOCK');
 if(!plan.enabled)return {status:'PAUSED',window:null,evaluatedAtMs:nowMs};
 if(nowMs>=plan.expiresAtMs)return {status:'EXPIRED',window:null,evaluatedAtMs:nowMs};
 const window=plan.windows.find(w=>nowMs>=w.openMs&&nowMs<w.closeMs);
 return {status:window?'READY':'OUTSIDE',window:window?{...window}:null,evaluatedAtMs:nowMs};
}
function validateIdentity(identity,plan){
 keys(identity,['provider','repository','commitSha','runId','runAttempt','eventName']);
 require(identity.provider==='GITHUB_ACTIONS'&&identity.repository===plan.repository
  &&typeof identity.commitSha==='string'&&/^[a-f0-9]{40}$/.test(identity.commitSha)
  &&typeof identity.runId==='string'&&/^[1-9][0-9]{0,19}$/.test(identity.runId)
  &&typeof identity.runAttempt==='string'&&/^[1-9][0-9]{0,8}$/.test(identity.runAttempt)&&plan.allowedEvents.includes(identity.eventName),'RUN_IDENTITY');
}
function safeDirectory(directory){
 require(typeof directory==='string'&&isAbsolute(directory)&&!directory.includes('\0')&&!directory.startsWith('\\\\')&&!directory.startsWith('//'),'DIRECTORY');
 const root=resolve(directory);let parent=dirname(root);
 for(;;){
  const s=lstatSync(parent),real=realpathSync(parent),same=process.platform==='win32'?real.toLowerCase()===parent.toLowerCase():real===parent;
  require(s.isDirectory()&&!s.isSymbolicLink()&&same,'DIRECTORY_LINK');
  if(dirname(parent)===parent)break;parent=dirname(parent);
 }
 require(!existsSync(root),'NEW_DIRECTORY_REQUIRED');return root;
}
function syncDirectory(directory){
 let fd;try{fd=openSync(directory,'r');fsyncSync(fd);}
 catch(e){if(!['EPERM','EACCES','EINVAL','EISDIR','ENOTSUP','EBADF'].includes(e.code))throw e;}
 finally{if(fd!==undefined)closeSync(fd);}
}
function writeNew(file,value,{canonicalJson=false}={}){
 const bytes=Buffer.from((canonicalJson?canonical(value):JSON.stringify(value,null,2))+'\n');
 require(bytes.length<=262144,'RECEIPT_SIZE');
 const fd=openSync(file,'wx',0o600);try{writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}
 syncDirectory(dirname(file));return sha(bytes);
}
function safeReason(error){return /^PUBLIC_(SCHEDULE|CAPTURE)_[A-Z_]+$/.test(error?.message??'')?error.message:'PUBLIC_SCHEDULE_ACQUISITION_OR_VALIDATION_FAILED';}

/** Each caller supplies a new artifact directory. Cross-run duplicate detection
 * belongs to the aggregator; this function never overwrites or selects a winner.
 */
export async function runPublicSchedule(options={}){
 keys(options,options.testFixture===undefined?['plan','directory','runIdentity']:['plan','directory','runIdentity','testFixture']);
 const {directory,testFixture}=options,plan=structuredClone(options.plan),identity=structuredClone(options.runIdentity),fixture=testFixture!==undefined;
 validatePublicSchedule(plan);validateIdentity(identity,plan);verifySources(plan);
 if(fixture){
  keys(testFixture,['label','capture','clock']);
  require(typeof testFixture.label==='string'&&ID.test(testFixture.label)&&typeof testFixture.capture==='function'&&typeof testFixture.clock==='function','EXPLICIT_TEST_FIXTURE');
 }
 const clock=fixture?testFixture.clock:Date.now,startedAtMs=clock(),selection=selectPublicWindow(plan,startedAtMs),root=safeDirectory(directory);
 mkdirSync(root,{mode:0o700});syncDirectory(dirname(root));
 const planSha256=writeNew(join(root,'plan.json'),plan,{canonicalJson:true});
 const base={schemaVersion:'g4.public-schedule-run.v1',scheduleId:plan.id,planSha256,runIdentity:identity,
  runKey:`${identity.repository}:${identity.runId}:${identity.runAttempt}`,kind:fixture?'INJECTED_FIXTURE':'NATIVE_PUBLIC',
  fixtureLabel:fixture?testFixture.label:null,startedAtMs,acquisitionStartedAtMs:null,completedAtMs:null,
  window:selection.window,status:selection.status,scheduledAcceptanceEligible:false,bundle:null,reason:null,policy:POLICY};
 writeNew(join(root,'start.json'),{...base,status:selection.status==='READY'?'PREPARED':selection.status});
 let result={...base},capture;
 try{
  if(selection.status!=='READY'){
   result.completedAtMs=startedAtMs;
  }else{
   const acquisitionStartedAtMs=clock();
   require(integer(acquisitionStartedAtMs)&&acquisitionStartedAtMs>=startedAtMs,'CLOCK_REGRESSION');
   result.acquisitionStartedAtMs=acquisitionStartedAtMs;
   const current=selectPublicWindow(plan,acquisitionStartedAtMs);
   if(current.status!=='READY'||current.window.id!==selection.window.id){
    result={...result,status:'LATE',completedAtMs:acquisitionStartedAtMs,reason:'WINDOW_CLOSED_BEFORE_ACQUISITION'};
   }else{
    capture=fixture?await testFixture.capture({directory:join(root,'bundle')}):await capturePublicBundle({directory:join(root,'bundle')});
    result.bundle={directory:'bundle',manifestSha256:capture?.manifestSha256??null,status:capture?.status??'UNAVAILABLE',verified:capture?.verified===true};
    require(capture?.status===(fixture?'FIXTURE_COMPLETE':'COMPLETE')&&capture.nativeCapture===!fixture&&capture.verified===true
     &&HASH.test(capture.manifestSha256??''),'CAPTURE_FAILED');
    let manifest;
    if(!fixture){
     const file=join(root,'bundle/manifest.json'),s=lstatSync(file);require(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=262144,'MANIFEST_RESOURCE');
     const bytes=readFileSync(file);require(sha(bytes)===capture.manifestSha256,'MANIFEST_HASH');
     manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    }
    verifySources(plan);
    const completedAtMs=clock();require(integer(completedAtMs)&&completedAtMs>=acquisitionStartedAtMs,'CLOCK_REGRESSION');
    result.completedAtMs=completedAtMs;
    if(manifest)require(manifest.captureKind==='NATIVE_PUBLIC'&&manifest.startedAtMs>=acquisitionStartedAtMs
     &&manifest.completedAtMs<=completedAtMs&&manifest.completedAtMs>=manifest.startedAtMs,'CAPTURE_TIMING');
    result.status=completedAtMs<selection.window.closeMs?'ON_TIME_CAPTURED':'LATE';
    result.reason=result.status==='LATE'?'WINDOW_CLOSED_DURING_ACQUISITION':null;
    result.scheduledAcceptanceEligible=!fixture&&identity.eventName==='schedule'&&result.status==='ON_TIME_CAPTURED';
   }
  }
 }catch(error){
  result={...result,status:'FAILED',scheduledAcceptanceEligible:false,reason:safeReason(error)};
  let end;try{end=clock();}catch{}result.completedAtMs=integer(end)&&end>=startedAtMs?end:null;
 }
 const resultSha256=writeNew(join(root,'result.json'),result);
 return {...result,resultSha256};
}

if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const args={};for(let i=2;i<process.argv.length;i+=2){const name={'--plan':'plan','--directory':'directory'}[process.argv[i]];
   require(name&&typeof process.argv[i+1]==='string'&&!Object.hasOwn(args,name),'ARGUMENTS');args[name]=process.argv[i+1];}
  require(Object.keys(args).length===2,'ARGUMENTS');
  const planFile=resolve(args.plan),s=lstatSync(planFile);require(s.isFile()&&!s.isSymbolicLink()&&s.nlink===1&&s.size<=262144,'PLAN_RESOURCE');
  const plan=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(readFileSync(planFile)));
  const result=await runPublicSchedule({plan,directory:resolve(args.directory),runIdentity:{provider:'GITHUB_ACTIONS',
   repository:process.env.GITHUB_REPOSITORY,commitSha:process.env.GITHUB_SHA,runId:process.env.GITHUB_RUN_ID,
   runAttempt:process.env.GITHUB_RUN_ATTEMPT,eventName:process.env.GITHUB_EVENT_NAME}});
  console.log(JSON.stringify({status:result.status,scheduleId:result.scheduleId,windowId:result.window?.id??null,
   scheduledAcceptanceEligible:result.scheduledAcceptanceEligible,kind:result.kind,planSha256:result.planSha256,resultSha256:result.resultSha256}));
  if(['FAILED','LATE'].includes(result.status))process.exitCode=1;
 }catch(error){console.error(JSON.stringify({status:'FAILED',reason:safeReason(error)}));process.exitCode=1;}
}
