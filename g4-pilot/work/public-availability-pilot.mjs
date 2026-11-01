/** Finite, diagnostic public pilot. No orders, accounts, credentials or cron.
 * prepare --plan ABS --plan-sha256 SHA256 --directory NEW_ABS
 * run     --plan ABS --plan-sha256 SHA256 --directory SAME_ABS --ready-sha256 SHA256
 * Upload READY.json externally between these commands, before the first opening.
 * The caller must subsequently verify that artifact's GitHub identity/time/digest.
 * This producer never claims external readiness or original-calendar acceptance.
 * One-shot exclusion is local to the prepared directory. The external consumer
 * must reject duplicate (plan,window,run,attempt) keys across imported artifacts.
 * Plan: {schemaVersion,schedule,limits,runtime,wrapperSource,auditSourceBinding}.
 * schedule is the unchanged native schedule contract, with exactly 3 absolute
 * windows; limits are maxRuntimeMs,pollMs,maxClockSkewMs,maxObservationGapMs.
 * Capture envelopes remain unchanged in captures/01/, 02/, 03/; control files
 * stay outside those directories. A killed child can leave no result.json:
 * its original partial bytes and the supervisor's failed window remain evidence.
 */
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {validatePublicSchedule,publicSchedulePlanSha256,publicScheduleSourceBinding} from './public-capture-schedule.mjs';

const HASH=/^[a-f0-9]{64}$/,ID=/^[a-z0-9][a-z0-9_.-]{0,79}$/;
const AUDIT=['audit-public-availability-pilot.mjs','audit-public-schedule.mjs','public-capture-quality.mjs','inspect-public-pilot-ready-archive.ps1'];
const TERMINATION_GRACE_MS=1000;
const POLICY=Object.freeze({publicDataOnly:true,credentialsUsed:false,ordersSent:0,originalCalendarAcceptance:false,
 scheduledAcceptanceEligible:false,forwardV1V2Observation:false,paperObservation:false,economicAcceptance:false,
 financialAcceptance:false,externalReadinessVerified:false,providerAttestation:false});
const sha=b=>createHash('sha256').update(b).digest('hex');
const canonical=v=>Array.isArray(v)?'['+v.map(canonical).join(',')+']':v&&typeof v==='object'?'{'+Object.keys(v).sort().map(k=>JSON.stringify(k)+':'+canonical(v[k])).join(',')+'}':JSON.stringify(v);
const integer=n=>Number.isSafeInteger(n)&&n>=0;
function check(ok,code){if(!ok)throw Error('PUBLIC_PILOT_'+code);}
function fields(v,names){check(v&&typeof v==='object'&&!Array.isArray(v)&&Object.keys(v).sort().join(',')===names.slice().sort().join(','),'FIELDS');}
function local(p){check(typeof p==='string'&&path.isAbsolute(p)&&!p.includes('\0')&&!p.startsWith('\\\\')&&!p.startsWith('//'),'ABSOLUTE_LOCAL_PATH');return path.resolve(p);}
function regular(p,directory=false){const s=fs.lstatSync(p),real=fs.realpathSync(p);check(!s.isSymbolicLink()&&(directory?s.isDirectory():s.isFile()&&s.nlink===1)&&(process.platform==='win32'?real.toLowerCase()===p.toLowerCase():real===p),'REGULAR_RESOURCE');return s;}
function parents(p){let current=local(p);for(;;){regular(current,true);if(path.dirname(current)===current)break;current=path.dirname(current);}}
function bytes(p,max=262144){const s=regular(p);check(s.size<=max,'RESOURCE_SIZE');return fs.readFileSync(p);}
function decode(b){return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(b));}
function pinned(p,expected){check(HASH.test(expected??''),'EXTERNAL_HASH_REQUIRED');const b=bytes(p);check(sha(b)===expected,'RESOURCE_HASH');return b;}
function syncDir(p){let fd;try{fd=fs.openSync(p,'r');fs.fsyncSync(fd);}catch(e){if(!['EPERM','EACCES','EINVAL','EISDIR','ENOTSUP','EBADF'].includes(e.code))throw e;}finally{if(fd!==undefined)fs.closeSync(fd);}}
function writeBytes(p,b){check(b.length<=262144,'RECEIPT_SIZE');const fd=fs.openSync(p,'wx',0o600);try{fs.writeFileSync(fd,b);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}syncDir(path.dirname(p));return sha(b);}
const write=(p,v)=>writeBytes(p,Buffer.from(JSON.stringify(v,null,2)+'\n'));
function source(p){const b=bytes(fileURLToPath(new URL(p,import.meta.url)),1048576);return {path:p,sha256:sha(b),bytes:b.length};}
function sourceContract(v,p){fields(v,['path','sha256','bytes']);check(v.path===p&&HASH.test(v.sha256??'')&&Number.isSafeInteger(v.bytes)&&v.bytes>0&&v.bytes<=1048576,'SOURCE_CONTRACT');}
export function publicAvailabilityPilotRuntime(){return {nodeVersion:process.version,nodeSha256:sha(fs.readFileSync(process.execPath)),platform:process.platform,architecture:process.arch};}
export function publicAvailabilityPilotSourceBinding(){return {wrapperSource:source('public-availability-pilot.mjs'),sourceBinding:publicScheduleSourceBinding(),auditSourceBinding:AUDIT.map(source)};}

/** Pure plan validation. Hash the original plan bytes separately, before dispatch. */
export function validatePublicAvailabilityPilotPlan(plan){
 fields(plan,['schemaVersion','schedule','limits','runtime','wrapperSource','auditSourceBinding']);
 check(plan.schemaVersion==='g4.public-availability-pilot.v1','PLAN_SCHEMA');validatePublicSchedule(plan.schedule);
 check(plan.schedule.enabled===true&&plan.schedule.windows.length===3,'THREE_ENABLED_WINDOWS_REQUIRED');
 check(plan.schedule.allowedEvents.includes('push')||plan.schedule.allowedEvents.includes('workflow_dispatch'),'PILOT_EVENT_REQUIRED');
 fields(plan.limits,['maxRuntimeMs','pollMs','maxClockSkewMs','maxObservationGapMs']);const l=plan.limits;
 check(Number.isSafeInteger(l.maxRuntimeMs)&&l.maxRuntimeMs>0&&l.maxRuntimeMs<=1800000
  &&Number.isSafeInteger(l.pollMs)&&l.pollMs>=1&&l.pollMs<=1000
  &&Number.isSafeInteger(l.maxClockSkewMs)&&l.maxClockSkewMs>=0&&l.maxClockSkewMs<=1000
  &&Number.isSafeInteger(l.maxObservationGapMs)&&l.maxObservationGapMs>=2*l.pollMs&&l.maxObservationGapMs<=5000,'WAIT_LIMITS');
 check(integer(plan.schedule.registeredAtMs+l.maxRuntimeMs)&&plan.schedule.expiresAtMs-plan.schedule.registeredAtMs+TERMINATION_GRACE_MS<=l.maxRuntimeMs,'FINITE_HORIZON');
 fields(plan.runtime,['nodeVersion','nodeSha256','platform','architecture']);
 check(plan.runtime.nodeVersion==='v24.19.0'&&HASH.test(plan.runtime.nodeSha256??'')&&['win32','linux','darwin','freebsd','openbsd','aix','sunos'].includes(plan.runtime.platform)&&/^[a-z0-9_]{2,16}$/.test(plan.runtime.architecture??''),'RUNTIME_CONTRACT');
 sourceContract(plan.wrapperSource,'public-availability-pilot.mjs');check(Array.isArray(plan.auditSourceBinding)&&plan.auditSourceBinding.length===AUDIT.length,'AUDIT_BINDING');
 for(const p of AUDIT){const matches=plan.auditSourceBinding.filter(v=>v.path===p);check(matches.length===1,'AUDIT_BINDING');sourceContract(matches[0],p);}
 return {valid:true,pilotId:plan.schedule.id,windowCount:3,deadlineMs:plan.schedule.registeredAtMs+l.maxRuntimeMs};
}
function verifyImplementation(plan){
 const current=publicAvailabilityPilotSourceBinding(),sort=a=>a.slice().sort((a,b)=>a.path.localeCompare(b.path));
 check(canonical(plan.wrapperSource)===canonical(current.wrapperSource)&&canonical(sort(plan.schedule.sourceBinding))===canonical(sort(current.sourceBinding))&&canonical(sort(plan.auditSourceBinding))===canonical(sort(current.auditSourceBinding)),'SOURCE_MISMATCH');
 check(canonical(plan.runtime)===canonical(publicAvailabilityPilotRuntime()),'RUNTIME_MISMATCH');
}
function identity(plan,testFixture){
 const e=process.env,id=testFixture?structuredClone(testFixture.runIdentity):{provider:'GITHUB_ACTIONS',repository:e.GITHUB_REPOSITORY,commitSha:e.GITHUB_SHA,runId:e.GITHUB_RUN_ID,runAttempt:e.GITHUB_RUN_ATTEMPT,eventName:e.GITHUB_EVENT_NAME};
 fields(id,['provider','repository','commitSha','runId','runAttempt','eventName']);
 check(id.provider==='GITHUB_ACTIONS'&&id.repository===plan.schedule.repository&&/^[a-f0-9]{40}$/.test(id.commitSha??'')&&/^[1-9][0-9]{0,19}$/.test(id.runId??'')&&id.runAttempt==='1'&&['push','workflow_dispatch'].includes(id.eventName)&&plan.schedule.allowedEvents.includes(id.eventName),'IDENTITY_FIRST_MANUAL_OR_PUSH_ONLY');return id;
}
function fixtureOf(value){
 if(value===undefined)return null;
 check(value&&Object.keys(value).every(k=>['label','clock','runIdentity','launch'].includes(k))&&typeof value.label==='string'&&ID.test(value.label),'EXPLICIT_FIXTURE');
 fields(value.clock,['wall','monotonic','sleep']);check(Object.values(value.clock).every(x=>typeof x==='function')&&(value.launch===undefined||typeof value.launch==='function'),'EXPLICIT_FIXTURE');return value;
}
const nativeClock={wall:()=>Date.now(),monotonic:()=>Number(process.hrtime.bigint()/1000000n),sleep:ms=>new Promise(resolve=>setTimeout(resolve,ms))};
function load(options,run=false){
 fields(options,[...['planFile','expectedPlanSha256','directory'],...(run?['expectedReadySha256']:[]),...(options.testFixture===undefined?[]:['testFixture'])]);
 const planFile=local(options.planFile),directory=local(options.directory);parents(path.dirname(planFile));parents(path.dirname(directory));
 const raw=pinned(planFile,options.expectedPlanSha256),plan=decode(raw);validatePublicAvailabilityPilotPlan(plan);verifyImplementation(plan);
 const testFixture=fixtureOf(options.testFixture),runIdentity=identity(plan,testFixture),clock=testFixture?.clock??nativeClock;
 return {plan,raw,directory,testFixture,runIdentity,clock,kind:testFixture?'INJECTED_FIXTURE':'NATIVE_PUBLIC',fixtureLabel:testFixture?.label??null};
}
function reason(error){return /^PUBLIC_PILOT_[A-Z_]+$/.test(error?.message??'')?error.message:'PUBLIC_PILOT_UNAVAILABLE_OR_INVALID_RESOURCE';}

export function preparePublicAvailabilityPilot(options){
 const c=load(options);check(!fs.existsSync(c.directory),'NEW_DIRECTORY_REQUIRED');fs.mkdirSync(c.directory,{mode:0o700});syncDir(path.dirname(c.directory));
 try{
  writeBytes(path.join(c.directory,'pilot-plan.json'),c.raw);
  const nativePlanFileSha256=write(path.join(c.directory,'native-plan.json'),c.plan.schedule);
  const readyAtMs=c.clock.wall(),readyMonotonicMs=c.clock.monotonic(),firstOpenMs=c.plan.schedule.windows[0].openMs;
  check(integer(readyAtMs)&&integer(readyMonotonicMs)&&readyAtMs>=c.plan.schedule.registeredAtMs&&readyAtMs<firstOpenMs,'READY_BEFORE_FIRST_OPEN_REQUIRED');
  const ready={schemaVersion:'g4.public-availability-pilot-ready.v1',kind:c.kind,fixtureLabel:c.fixtureLabel,planSha256:options.expectedPlanSha256,
   scheduleId:c.plan.schedule.id,schedulePlanSha256:publicSchedulePlanSha256(c.plan.schedule),nativePlanFileSha256,
   wrapperSource:c.plan.wrapperSource,runtime:c.plan.runtime,runIdentity:c.runIdentity,readyAtMs,readyMonotonicMs,firstOpenMs,
   deadlineMs:c.plan.schedule.registeredAtMs+c.plan.limits.maxRuntimeMs,policy:POLICY};
  const readySha256=write(path.join(c.directory,'READY.json'),ready);return {status:'READY_REQUIRES_EXTERNAL_PUBLICATION',readySha256,ready};
 }catch(error){write(path.join(c.directory,'FAILED.json'),{schemaVersion:'g4.public-availability-pilot-prepare-failure.v1',reason:reason(error),policy:POLICY});throw error;}
}

function childEnvironment(id){
 const env={PATH:path.dirname(process.execPath),GITHUB_REPOSITORY:id.repository,GITHUB_SHA:id.commitSha,GITHUB_RUN_ID:id.runId,GITHUB_RUN_ATTEMPT:id.runAttempt,GITHUB_EVENT_NAME:id.eventName,G4_ENABLE_PAPER_ORDERS:'0'};
 for(const k of ['SystemRoot','WINDIR'])if(process.env[k])env[k]=process.env[k];return env;
}
function launchNative({directory,planFile,runIdentity}){
 let stdout='',stderr='',overflow=false;
 const child=spawn(process.execPath,[fileURLToPath(new URL('./public-capture-schedule.mjs',import.meta.url)),'--plan',planFile,'--directory',directory],{windowsHide:true,env:childEnvironment(runIdentity),stdio:['ignore','pipe','pipe']});
 const collect=which=>chunk=>{if(which==='out')stdout+=chunk.toString('utf8');else stderr+=chunk.toString('utf8');if(Buffer.byteLength(stdout)+Buffer.byteLength(stderr)>131072){overflow=true;child.kill('SIGKILL');}};
 child.stdout.on('data',collect('out'));child.stderr.on('data',collect('err'));
 const completion=new Promise(resolve=>{let error=false;child.once('error',()=>{error=true;});child.once('close',(code,signal)=>resolve({code,signal,closeObserved:true,stdout:stdout.slice(0,65536),stderr:stderr.slice(0,65536),error:error||overflow}));});
 return {completion,terminate:()=>child.kill('SIGKILL'),releaseUnconfirmed:()=>{child.stdout.destroy();child.stderr.destroy();child.unref();}};
}
async function boundedClose(completion){
 // A rejected/malformed completion cannot acknowledge process close. Keep the
 // real-time grace bounded even when there is no usable completion contract.
 const acknowledged=new Promise(resolve=>{if(completion instanceof Promise)Promise.prototype.then.call(completion,value=>{if(value?.closeObserved===true)resolve({value});},()=>{});});
 let timer;try{return await Promise.race([acknowledged,new Promise(resolve=>{timer=setTimeout(()=>resolve({unconfirmed:true}),TERMINATION_GRACE_MS);})]);}
 finally{clearTimeout(timer);}
}
function monitorClock(clock,plan,started){
 let previous=started;const stats={samples:0,maxObservedGapMs:0,maxObservedSkewMs:0};
 return {stats,sample(){const v={wall:clock.wall(),mono:clock.monotonic()};check(integer(v.wall)&&integer(v.mono),'CLOCK_INVALID');
  check(v.wall>=previous.wall&&v.mono>=previous.mono,'CLOCK_REGRESSION');
  const gap=v.mono-previous.mono,skew=Math.abs((v.wall-started.wall)-(v.mono-started.mono));
  stats.samples++;stats.maxObservedGapMs=Math.max(stats.maxObservedGapMs,gap);stats.maxObservedSkewMs=Math.max(stats.maxObservedSkewMs,skew);
  check(gap<=plan.limits.maxObservationGapMs,'OBSERVATION_GAP');check(skew<=plan.limits.maxClockSkewMs,'CLOCK_SKEW');
  check(v.wall<plan.schedule.registeredAtMs+plan.limits.maxRuntimeMs&&v.mono-started.mono<plan.limits.maxRuntimeMs,'DEADLINE');previous=v;return v;
 }};
}

/** One-shot supervisor. Termination is acknowledged only after child close.
 * It never advances to another window while a capture child remains alive.
 * OS timer latency can exceed a deadline; such runs fail, never gain acceptance.
 */
export async function runPublicAvailabilityPilot(options){
 const c=load(options,true);parents(c.directory);
 const ready=decode(pinned(path.join(c.directory,'READY.json'),options.expectedReadySha256));
 check(ready.schemaVersion==='g4.public-availability-pilot-ready.v1'&&ready.kind===c.kind&&ready.fixtureLabel===c.fixtureLabel
  &&ready.planSha256===options.expectedPlanSha256&&ready.schedulePlanSha256===publicSchedulePlanSha256(c.plan.schedule)
  &&ready.scheduleId===c.plan.schedule.id&&canonical(ready.runIdentity)===canonical(c.runIdentity)
  &&canonical(ready.wrapperSource)===canonical(c.plan.wrapperSource)&&canonical(ready.runtime)===canonical(c.plan.runtime)
  &&canonical(ready.policy)===canonical(POLICY),'READY_BINDING');
 pinned(path.join(c.directory,'pilot-plan.json'),options.expectedPlanSha256);
 const nativePlan=decode(pinned(path.join(c.directory,'native-plan.json'),ready.nativePlanFileSha256));check(canonical(nativePlan)===canonical(c.plan.schedule),'NATIVE_PLAN_BINDING');
 const first=c.plan.schedule.windows[0],deadlineMs=c.plan.schedule.registeredAtMs+c.plan.limits.maxRuntimeMs;
 check(integer(ready.readyAtMs)&&ready.readyAtMs>=c.plan.schedule.registeredAtMs&&ready.readyAtMs<first.openMs&&ready.firstOpenMs===first.openMs&&ready.deadlineMs===deadlineMs,'READY_TIMING');
 check(!fs.existsSync(path.join(c.directory,'RUN-START.json'))&&!fs.existsSync(path.join(c.directory,'SUMMARY.json'))&&!fs.existsSync(path.join(c.directory,'captures')),'DUPLICATE_RUN');
 const started={wall:c.clock.wall(),mono:c.clock.monotonic()};
 const base={schemaVersion:'g4.public-availability-pilot-result.v1',kind:c.kind,fixtureLabel:c.fixtureLabel,planSha256:options.expectedPlanSha256,schedulePlanSha256:ready.schedulePlanSha256,
  readySha256:options.expectedReadySha256,runIdentity:c.runIdentity,readyAtMs:ready.readyAtMs,startedAtMs:started.wall,completedAtMs:null,status:'RUNNING',reason:null,policy:POLICY};
 write(path.join(c.directory,'RUN-START.json'),base);
 const windows=c.plan.schedule.windows.map((w,i)=>({windowId:w.id,directory:'captures/'+String(i+1).padStart(2,'0'),status:'NOT_ATTEMPTED',reason:null,startedAtMs:null,completedAtMs:null,resultSha256:null,child:null,availabilityPilotCandidateEligible:false}));
 const guard=monitorClock(c.clock,c.plan,started);let failure=null;
 try{
  check(integer(started.wall)&&integer(started.mono)&&started.wall>=ready.readyAtMs&&started.wall<first.openMs,'RUN_BEFORE_FIRST_OPEN_REQUIRED');
  check(c.testFixture===null||typeof c.testFixture.launch==='function','FIXTURE_LAUNCH_REQUIRED');
  fs.mkdirSync(path.join(c.directory,'captures'),{mode:0o700});
  for(let i=0;i<3;i++){
   const w=c.plan.schedule.windows[i],r=windows[i];let now=guard.sample();
   while(now.wall<w.openMs){await c.clock.sleep(Math.min(c.plan.limits.pollMs,w.openMs-now.wall));now=guard.sample();}
   if(now.wall>=w.closeMs){r.status='MISSED';r.reason='PUBLIC_PILOT_WINDOW_CLOSED';r.completedAtMs=now.wall;continue;}
   verifyImplementation(c.plan);pinned(path.join(c.directory,'READY.json'),options.expectedReadySha256);pinned(path.join(c.directory,'pilot-plan.json'),options.expectedPlanSha256);pinned(path.join(c.directory,'native-plan.json'),ready.nativePlanFileSha256);
   now=guard.sample();if(now.wall>=w.closeMs){r.status='MISSED';r.reason='PUBLIC_PILOT_WINDOW_CLOSED';r.completedAtMs=now.wall;continue;}
   r.startedAtMs=now.wall;
   const captureDirectory=path.join(c.directory,r.directory),launch=c.testFixture?.launch??launchNative;
   const child=launch({directory:captureDirectory,planFile:path.join(c.directory,'native-plan.json'),runIdentity:c.runIdentity,window:w});
    let done=false,outcome,childFailure=false,termination=false,completion,stopReason=null,fatalReason=null;
    const secondaryErrors=[];
    const secondary=(stage,code,error)=>secondaryErrors.push({stage,reason:'PUBLIC_PILOT_'+code,cause:reason(error),code:/^[A-Z0-9_]+$/.test(error?.code??'')?error.code:null});
   try{
     completion=child?.completion;
     if(completion instanceof Promise)Promise.prototype.then.call(completion,v=>{outcome=v;done=true;},()=>{childFailure=true;done=true;});
     check(child&&completion instanceof Promise&&typeof child.terminate==='function','CAPTURE_CHILD_CONTRACT');
     try{
      while(!done){now=guard.sample();if(now.wall>=w.closeMs){stopReason='PUBLIC_PILOT_WINDOW_CLOSED_DURING_CAPTURE';break;}
       await Promise.race([completion.catch(()=>{}),c.clock.sleep(Math.min(c.plan.limits.pollMs,w.closeMs-now.wall))]);}
      now=guard.sample();if(now.wall>=w.closeMs)stopReason='PUBLIC_PILOT_WINDOW_CLOSED_DURING_CAPTURE';
     }catch(error){stopReason=reason(error);}
     check(!done||(!childFailure&&outcome?.closeObserved===true),'CHILD_CLOSE_REQUIRED');
    }catch(error){fatalReason=reason(error);stopReason??=fatalReason;}
    finally{
     // Once launch returns, every exit without an observed close attempts kill
     // and waits for ACK. A failed receipt or kill must never skip this cleanup.
     if(outcome?.closeObserved!==true){
      termination=true;
      try{write(path.join(c.directory,String(i+1).padStart(2,'0')+'-termination-request.json'),{windowId:w.id,reason:stopReason,requestedAtMs:c.clock.wall(),graceMs:TERMINATION_GRACE_MS,closeObserved:false,policy:POLICY});}
      catch(error){secondary('terminationReceipt','TERMINATION_RECEIPT_FAILED',error);}
      try{check(typeof child?.terminate==='function','CAPTURE_CHILD_CONTRACT');child.terminate();}
      catch(error){secondary('terminate','TERMINATE_REQUEST_FAILED',error);}
      const closing=await boundedClose(completion);
      if(closing.value)outcome=closing.value;
      else{
       fatalReason='PUBLIC_PILOT_TERMINATION_UNCONFIRMED';
       try{child?.releaseUnconfirmed?.();}catch(error){secondary('releaseUnconfirmed','CHILD_RELEASE_FAILED',error);}
      }
    }
   }
    const closeObserved=outcome?.closeObserved===true;
    r.child={code:closeObserved?outcome.code??null:null,signal:closeObserved?outcome.signal??null:null,terminated:termination&&closeObserved,terminationRequested:termination,closeObserved};
    try{r.completedAtMs=c.clock.wall();}catch(error){secondary('completionClock','CLOCK_READ_FAILED',error);}
    try{write(path.join(c.directory,w.id+'-child.json'),{...r.child,stdout:closeObserved?outcome.stdout??'':'',stderr:closeObserved?outcome.stderr??'':'',error:!closeObserved||outcome.error===true});}
    catch(error){secondary('childReceipt','CHILD_RECEIPT_FAILED',error);}
    if(stopReason||secondaryErrors.length)r.failureDetails={primaryReason:stopReason??secondaryErrors[0].reason,secondaryErrors};
    if(fatalReason||secondaryErrors.length)throw Error(fatalReason??secondaryErrors[0].reason);
   const resultFile=path.join(captureDirectory,'result.json');let result=null;
   if(fs.existsSync(resultFile)){const raw=bytes(resultFile);r.resultSha256=sha(raw);result=decode(raw);}
   if(stopReason){r.status='FAILED';r.reason=stopReason;if(stopReason!=='PUBLIC_PILOT_WINDOW_CLOSED_DURING_CAPTURE')throw Error(stopReason);continue;}
   check(outcome.code===0&&outcome.signal===null&&outcome.error!==true&&result,'CAPTURE_PROCESS_FAILED');
   const reported=decode(Buffer.from(outcome.stdout.trim()));check(reported.resultSha256===r.resultSha256,'RESULT_HASH');
   check(result.kind===c.kind&&result.fixtureLabel===c.fixtureLabel&&result.planSha256===ready.schedulePlanSha256&&canonical(result.runIdentity)===canonical(c.runIdentity)
    &&result.window?.id===w.id&&result.scheduledAcceptanceEligible===false,'RESULT_BINDING');
   check(result.status==='ON_TIME_CAPTURED'&&integer(result.acquisitionStartedAtMs)&&result.startedAtMs>=r.startedAtMs&&result.acquisitionStartedAtMs>=w.openMs&&result.completedAtMs>=result.acquisitionStartedAtMs&&result.completedAtMs<=r.completedAtMs&&r.completedAtMs<w.closeMs,'CAPTURE_TIMING');
   verifyImplementation(c.plan);guard.sample();r.status='CAPTURED';r.availabilityPilotCandidateEligible=c.kind==='NATIVE_PUBLIC';
  }
 }catch(error){failure=reason(error);const active=windows.find(r=>r.startedAtMs!==null&&r.status==='NOT_ATTEMPTED');if(active){active.status='FAILED';active.reason=failure;}}
 let completedAtMs;try{completedAtMs=c.clock.wall();}catch{};
 const result={...base,completedAtMs:integer(completedAtMs)?completedAtMs:null,status:!failure&&windows.every(w=>w.status==='CAPTURED')?(c.testFixture?'FIXTURE_COMPLETE':'CAPTURED_PENDING_EXTERNAL_REVIEW'):'FAILED',reason:failure,windows,clock:guard.stats};
 const resultSha256=write(path.join(c.directory,'SUMMARY.json'),result);return {...result,resultSha256};
}

if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const [command,...rest]=process.argv.slice(2),options={},map={'--plan':'planFile','--plan-sha256':'expectedPlanSha256','--directory':'directory','--ready-sha256':'expectedReadySha256'};
  check(['prepare','run'].includes(command)&&rest.length%2===0,'ARGUMENTS');
  for(let i=0;i<rest.length;i+=2){const k=map[rest[i]];check(k&&typeof rest[i+1]==='string'&&!Object.hasOwn(options,k),'ARGUMENTS');options[k]=rest[i+1];}
  const result=command==='prepare'?preparePublicAvailabilityPilot(options):await runPublicAvailabilityPilot(options);
  console.log(JSON.stringify({status:result.status,readySha256:result.readySha256??null,resultSha256:result.resultSha256??null,
   ...(command==='run'?{windowResults:result.windows.map(w=>({windowId:w.windowId,resultSha256:w.resultSha256}))}:{})}));if(result.status==='FAILED')process.exitCode=1;
 }catch(error){console.error(JSON.stringify({status:'FAILED',reason:reason(error)}));process.exitCode=1;}
}
