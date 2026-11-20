import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {tmpdir} from 'node:os';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import * as pilot from '../public-availability-pilot.mjs';
import {runPublicSchedule} from '../public-capture-schedule.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const json=p=>JSON.parse(fs.readFileSync(p,'utf8'));
const identity={provider:'GITHUB_ACTIONS',repository:'fixture/pilot',commitSha:'a'.repeat(40),runId:'1234',runAttempt:'1',eventName:'workflow_dispatch'};
function fixture({api=pilot,sleepEdit,launchEdit,scheduled=false}={}){
 const parent=fs.mkdtempSync(path.join(tmpdir(),'g4-public-pilot-fixture-')),directory=path.join(parent,'control'),planFile=path.join(parent,'plan.json');
 const binding=api.publicAvailabilityPilotSourceBinding(),state={wall:1100,mono:100,waits:0,calls:[],terminateCalls:0,alive:0,closed:0};
 const plan={schemaVersion:'g4.public-availability-pilot.v1',schedule:{schemaVersion:'g4.public-capture-schedule.v1',id:'explicit-fixture-three-window-pilot',repository:'fixture/pilot',enabled:true,registeredAtMs:1000,expiresAtMs:7000,
  windows:[{id:'first',openMs:2000,closeMs:3000},{id:'second',openMs:4000,closeMs:5000},{id:'third',openMs:6000,closeMs:7000}],allowedEvents:['schedule','workflow_dispatch','push'],sourceBinding:binding.sourceBinding},
  limits:{maxRuntimeMs:7000,pollMs:100,maxClockSkewMs:20,maxObservationGapMs:500},runtime:api.publicAvailabilityPilotRuntime(),wrapperSource:binding.wrapperSource,auditSourceBinding:binding.auditSourceBinding};
 if(scheduled){
  plan.schemaVersion='g4.public-availability-pilot.v2';
  const start=86401000;
  for(const [i,w] of plan.schedule.windows.entries()){w.openMs=start+19800000+i*240000;w.closeMs=w.openMs+90000;}
  plan.schedule.expiresAtMs=plan.schedule.windows[2].closeMs;plan.schedule.allowedEvents=['schedule'];
  plan.startup={notBeforeMs:start,latestReadyAtMs:plan.schedule.windows[0].openMs-120000};
  plan.limits={maxRuntimeMs:21000000,pollMs:1000,maxClockSkewMs:1000,maxObservationGapMs:5000};
  state.wall=start+100;
 }
 const clock={wall:()=>state.wall,monotonic:()=>state.mono,sleep:async ms=>{state.waits++;if(sleepEdit)await sleepEdit(state,ms);else{state.wall+=ms;state.mono+=ms;}await new Promise(resolve=>setImmediate(resolve));}};
 const testFixture={label:'explicit-three-window-fixture',clock,runIdentity:structuredClone(identity),launch:args=>{
  state.calls.push({windowId:args.window.id,atMs:state.wall,directory:args.directory});
  if(launchEdit)return launchEdit(args,state,clock);
  const completion=runPublicSchedule({plan:json(args.planFile),directory:args.directory,runIdentity:args.runIdentity,testFixture:{label:testFixture.label,clock:clock.wall,capture:async({directory:bundle})=>{
   fs.mkdirSync(bundle);fs.writeFileSync(path.join(bundle,'explicit-fixture.txt'),'Not native or financial evidence');
   return {status:'FIXTURE_COMPLETE',nativeCapture:false,verified:true,manifestSha256:'b'.repeat(64)};
  }}}).then(r=>({code:0,signal:null,closeObserved:true,stdout:JSON.stringify({resultSha256:r.resultSha256}),stderr:'',error:false}));
  return {completion,terminate:()=>{state.terminateCalls++;throw Error('unexpected termination of completed fixture');}};
 }};
 if(scheduled)testFixture.runIdentity.eventName='schedule';
 const f={api,parent,directory,planFile,plan,state,testFixture,options:null,ready:null};
 f.save=()=>{const b=Buffer.from(JSON.stringify(plan,null,2)+'\n');fs.writeFileSync(planFile,b);f.options={planFile,directory,expectedPlanSha256:sha(b),testFixture};};
 f.prepare=()=>{f.ready=api.preparePublicAvailabilityPilot(f.options);return f.ready;};
 f.run=()=>api.runPublicAvailabilityPilot({...f.options,expectedReadySha256:f.ready.readySha256});f.save();return f;
}

test('three absolute windows run only after opening, with separate unchanged envelopes and no promoted fixture',async()=>{
 const f=fixture();f.prepare();const readyBefore=fs.readFileSync(path.join(f.directory,'READY.json'));
 assert.equal(f.state.calls.length,0);assert.equal(f.ready.ready.readyAtMs,1100);
 const r=await f.run();assert.equal(r.status,'FIXTURE_COMPLETE',JSON.stringify(r));assert.equal(f.state.calls.length,3);
 assert.deepEqual(f.state.calls.map(v=>v.atMs),[2000,4000,6000]);assert.ok(f.state.waits>0);
 assert.deepEqual(r.windows.map(v=>v.directory),['captures/01','captures/02','captures/03']);
 for(const w of r.windows){assert.equal(w.status,'CAPTURED');assert.equal(w.availabilityPilotCandidateEligible,false);assert.equal(w.child.closeObserved,true);
  const e=json(path.join(f.directory,w.directory,'result.json'));assert.equal(e.kind,'INJECTED_FIXTURE');assert.equal(e.runIdentity.eventName,'workflow_dispatch');assert.equal(e.scheduledAcceptanceEligible,false);
  assert.equal(sha(fs.readFileSync(path.join(f.directory,w.directory,'result.json'))),w.resultSha256);
 }
 assert.deepEqual(fs.readFileSync(path.join(f.directory,'READY.json')),readyBefore);assert.equal(r.policy.originalCalendarAcceptance,false);assert.equal(r.policy.financialAcceptance,false);
});

test('V2 scheduled start waits five and a half hours on the fixture clock without moving preregistered windows',async()=>{
 const f=fixture({scheduled:true}),original=structuredClone(f.plan);f.prepare();const r=await f.run();
 assert.equal(r.status,'FIXTURE_COMPLETE',JSON.stringify(r));assert.equal(r.schemaVersion,'g4.public-availability-pilot-result.v2');
 assert.deepEqual(f.state.calls.map(x=>x.atMs),original.schedule.windows.map(x=>x.openMs));
 assert.ok(f.state.waits>19000);assert.equal(f.ready.ready.deadlineMs,f.plan.startup.notBeforeMs+21000000);
 assert.deepEqual(json(path.join(f.directory,'pilot-plan.json')),original);
 assert.ok(r.windows.every(w=>!w.availabilityPilotCandidateEligible));assert.equal(r.policy.financialAcceptance,false);
});

test('V2 rejects early/late startup, manual substitutions, retries and unbounded leases without acquisition',()=>{
 for(const mutate of [f=>f.state.wall=f.plan.startup.notBeforeMs-1,f=>f.state.wall=f.plan.startup.latestReadyAtMs+1,
  f=>f.testFixture.runIdentity.eventName='push',f=>f.testFixture.runIdentity.eventName='workflow_dispatch',f=>f.testFixture.runIdentity.runAttempt='2']){
  const f=fixture({scheduled:true});mutate(f);assert.throws(()=>f.prepare(),/PUBLIC_PILOT_(READY_BEFORE_FIRST_OPEN_REQUIRED|IDENTITY_FIRST_SCHEDULE_ONLY)/);assert.equal(f.state.calls.length,0);
 }
 const original=fixture({scheduled:true}).plan;
 for(const mutate of [p=>p.startup.notBeforeMs=p.schedule.registeredAtMs-1,p=>p.startup.latestReadyAtMs=p.schedule.windows[0].openMs-119999,
  p=>p.limits.maxRuntimeMs=21000001,p=>p.limits.maxRuntimeMs=1000,p=>p.schedule.allowedEvents.push('push'),p=>p.startup.extra=true]){
  const p=structuredClone(original);mutate(p);assert.throws(()=>pilot.validatePublicAvailabilityPilotPlan(p),/PUBLIC_PILOT_/);
 }
});

test('V2 delayed but on-time startup retains its fixed expiry and duplicate runs cannot add observations',async()=>{
 const f=fixture({scheduled:true});f.state.wall=f.plan.startup.latestReadyAtMs-10000;f.prepare();const r=await f.run();
 assert.equal(r.status,'FIXTURE_COMPLETE');assert.equal(f.state.calls.length,3);assert.equal(f.ready.ready.deadlineMs,f.plan.startup.notBeforeMs+21000000);
 await assert.rejects(f.run(),/DUPLICATE_RUN/);assert.equal(f.state.calls.length,3);
});

test('V2 waiting cannot silently recover from a suspended process or clock jump',async()=>{
 for(const edit of [(s,ms)=>{s.wall+=ms+6000;s.mono+=ms+6000;},(s,ms)=>{s.wall+=ms+2000;s.mono+=ms;}]){
  const f=fixture({scheduled:true,sleepEdit:edit});f.prepare();const r=await f.run();
  assert.equal(r.status,'FAILED');assert.match(r.reason,/OBSERVATION_GAP|CLOCK_SKEW/);assert.equal(f.state.calls.length,0);
 }
});

test('V2 a capture completing at a short window boundary remains a recorded failure',async()=>{
 const f=fixture({scheduled:true});for(const w of f.plan.schedule.windows)w.closeMs=w.openMs+1000;
 f.plan.schedule.expiresAtMs=f.plan.schedule.windows[2].closeMs;f.save();f.prepare();const r=await f.run();
 assert.equal(r.status,'FAILED');assert.ok(r.windows.every(w=>w.reason==='PUBLIC_PILOT_WINDOW_CLOSED_DURING_CAPTURE'));
 assert.ok(r.windows.every(w=>!w.availabilityPilotCandidateEligible));
});

test('plan rejects fewer or overlapping windows, relative waits, excessive horizon, bad source and runtime contracts',()=>{
 const original=fixture().plan;
 for(const mutate of [p=>p.schedule.windows.pop(),p=>p.schedule.windows[1].openMs=2900,p=>p.schedule.windows[0].openMs=0,
  p=>p.limits.maxRuntimeMs=1800001,p=>p.limits.maxRuntimeMs=5999,p=>p.runtime.nodeVersion='v22.0.0',p=>p.wrapperSource.path='../other.mjs',
  p=>p.auditSourceBinding[1]=p.auditSourceBinding[0],p=>p.limits.pollMs=1001,p=>p.limits.maxObservationGapMs=100,p=>p.limits.maxClockSkewMs=1001]){
  const plan=structuredClone(original);mutate(plan);assert.throws(()=>pilot.validatePublicAvailabilityPilotPlan(plan),/PUBLIC_(PILOT|SCHEDULE)_/);
 }
});

test('late prepare preserves failure and late run never captures or moves registered windows',async()=>{
 const f=fixture();f.state.wall=2000;assert.throws(()=>f.prepare(),/READY_BEFORE_FIRST_OPEN/);assert.equal(json(path.join(f.directory,'FAILED.json')).reason,'PUBLIC_PILOT_READY_BEFORE_FIRST_OPEN_REQUIRED');assert.equal(f.state.calls.length,0);
 const g=fixture();g.prepare();g.state.wall=2000;const r=await g.run();assert.equal(r.status,'FAILED');assert.equal(r.reason,'PUBLIC_PILOT_RUN_BEFORE_FIRST_OPEN_REQUIRED');assert.equal(g.state.calls.length,0);assert.ok(r.windows.every(w=>w.status==='NOT_ATTEMPTED'));
 assert.deepEqual(json(path.join(g.directory,'pilot-plan.json')).schedule.windows,g.plan.schedule.windows);
});

test('schedule events, retries, wrong run identity and implicit fixtures cannot acquire',async()=>{
 for(const change of [id=>id.eventName='schedule',id=>id.runAttempt='2']){const f=fixture();change(f.testFixture.runIdentity);assert.throws(()=>f.prepare(),/IDENTITY_FIRST_MANUAL_OR_PUSH_ONLY/);assert.equal(f.state.calls.length,0);}
 const f=fixture();f.prepare();f.testFixture.runIdentity.runId='4321';await assert.rejects(f.run(),/READY_BINDING/);assert.equal(f.state.calls.length,0);
 const g=fixture();g.testFixture.label='';assert.throws(()=>g.prepare(),/EXPLICIT_FIXTURE/);
});

test('duplicate prepare/run preserves previous READY, captures and summary without a fourth acquisition',async()=>{
 const f=fixture();f.prepare();assert.throws(()=>f.prepare(),/NEW_DIRECTORY_REQUIRED/);await f.run();
 const before=fs.readFileSync(path.join(f.directory,'SUMMARY.json'));await assert.rejects(f.run(),/DUPLICATE_RUN/);assert.equal(f.state.calls.length,3);assert.deepEqual(fs.readFileSync(path.join(f.directory,'SUMMARY.json')),before);
});

test('wall/monotonic regression, stopped wall and observation gap fail before capture',async()=>{
 for(const [expected,edit] of [
  ['CLOCK_REGRESSION',(s,ms)=>{s.wall--;s.mono+=ms;}],['CLOCK_REGRESSION',(s,ms)=>{s.wall+=ms;s.mono--;}],
  ['CLOCK_SKEW',(s,ms)=>{s.mono+=ms;}],['OBSERVATION_GAP',(s)=>{s.wall+=1000;s.mono+=1000;}]
 ]){const f=fixture({sleepEdit:edit});f.prepare();const r=await f.run();assert.equal(r.status,'FAILED');assert.match(r.reason,new RegExp(expected));assert.equal(f.state.calls.length,0);}
});

test('late, hanging child is terminated and close observed before the next window; partial bytes survive',async()=>{
 const f=fixture({launchEdit:(args,state)=>{
  fs.mkdirSync(args.directory);fs.writeFileSync(path.join(args.directory,'partial.body'),'original partial fixture bytes');state.alive++;
  let done;const completion=new Promise(resolve=>{done=resolve;});
  return {completion,terminate(){state.terminateCalls++;setImmediate(()=>{state.alive--;state.closed++;done({code:null,signal:'SIGKILL',closeObserved:true,stdout:'',stderr:''});});}};
 }});f.prepare();const r=await f.run();assert.equal(r.status,'FAILED');assert.equal(f.state.alive,0);assert.equal(f.state.calls.length,3);assert.equal(f.state.closed,3);
 for(const w of r.windows){assert.equal(w.status,'FAILED');assert.equal(w.child.terminated,true);assert.equal(w.child.closeObserved,true);assert.equal(w.resultSha256,null);assert.equal(w.availabilityPilotCandidateEligible,false);assert.equal(fs.readFileSync(path.join(f.directory,w.directory,'partial.body'),'utf8'),'original partial fixture bytes');}
});

test('real fixture subprocess is killed and awaited after clock fault, preserving its actual partial file',async()=>{
 let childReady=Promise.resolve(),hasChild=false;
 const f=fixture({sleepEdit:async(s,ms)=>{if(hasChild){await childReady;s.wall+=ms;s.mono+=ms+1000;}else{s.wall+=ms;s.mono+=ms;}},launchEdit:(args,state)=>{
  fs.mkdirSync(args.directory);const partial=path.join(args.directory,'partial.body');
  const child=spawn(process.execPath,['-e',"require('node:fs').writeFileSync(process.argv[1],'actual child partial');process.stdout.write('READY');setInterval(()=>{},1000);",partial],{windowsHide:true,env:{PATH:path.dirname(process.execPath)},stdio:['ignore','pipe','pipe']});
  state.alive++;hasChild=true;childReady=new Promise(resolve=>child.stdout.once('data',resolve));
  const completion=new Promise(resolve=>child.once('close',(code,signal)=>{state.alive--;state.closed++;resolve({code,signal,closeObserved:true,stdout:'',stderr:''});}));
  return {completion,terminate:()=>{state.terminateCalls++;return child.kill('SIGKILL');}};
 }});f.prepare();const r=await f.run();assert.equal(r.status,'FAILED');assert.match(r.reason,/OBSERVATION_GAP|CLOCK_SKEW/);assert.equal(f.state.calls.length,1);assert.equal(f.state.alive,0);assert.equal(f.state.closed,1);assert.equal(r.windows[0].child.closeObserved,true);
 assert.equal(fs.readFileSync(path.join(f.directory,'captures/01/partial.body'),'utf8'),'actual child partial');
});

test('missing close acknowledgement produces bounded unconfirmed termination and no next capture',async()=>{
 const f=fixture({launchEdit:(args,state)=>{fs.mkdirSync(args.directory);fs.writeFileSync(path.join(args.directory,'partial.body'),'unconfirmed child partial');
  return {completion:new Promise(()=>{}),terminate:()=>{state.terminateCalls++;return false;}};
 }});f.prepare();const started=performance.now(),r=await f.run();
 assert.equal(r.status,'FAILED');assert.equal(r.reason,'PUBLIC_PILOT_TERMINATION_UNCONFIRMED');assert.ok(performance.now()-started<10000);
 assert.equal(f.state.calls.length,1);assert.equal(f.state.terminateCalls,1);assert.equal(r.windows[0].child.closeObserved,false);assert.equal(r.windows[0].child.terminated,false);
 assert.equal(r.windows[0].child.terminationRequested,true);assert.ok(r.windows.slice(1).every(w=>w.status==='NOT_ATTEMPTED'));
 assert.equal(json(path.join(f.directory,'01-termination-request.json')).closeObserved,false);assert.equal(fs.readFileSync(path.join(f.directory,'captures/01/partial.body'),'utf8'),'unconfirmed child partial');
});

test('occupied termination receipt still kills and awaits a real fixture child, preserving primary and secondary failures',async()=>{
 let childReady=Promise.resolve(),hasChild=false;
 const f=fixture({sleepEdit:async(s,ms)=>{if(hasChild){await childReady;s.wall+=ms;s.mono+=ms+1000;}else{s.wall+=ms;s.mono+=ms;}},launchEdit:(args,state)=>{
  fs.mkdirSync(args.directory);const partial=path.join(args.directory,'partial.body');
  const child=spawn(process.execPath,['-e',"require('node:fs').writeFileSync(process.argv[1],'receipt collision child partial');process.stdout.write('READY');setInterval(()=>{},1000);",partial],{windowsHide:true,env:{PATH:path.dirname(process.execPath)},stdio:['ignore','pipe','pipe']});
  state.alive++;hasChild=true;childReady=new Promise(resolve=>child.stdout.once('data',resolve));
  const completion=new Promise(resolve=>child.once('close',(code,signal)=>{state.alive--;state.closed++;resolve({code,signal,closeObserved:true,stdout:'',stderr:''});}));
  return {completion,terminate:()=>{state.terminateCalls++;return child.kill('SIGKILL');}};
 }});f.prepare();const receipt=path.join(f.directory,'01-termination-request.json'),original='preexisting receipt, must remain unchanged';fs.writeFileSync(receipt,original);
 const r=await f.run();assert.equal(r.status,'FAILED');assert.equal(r.reason,'PUBLIC_PILOT_TERMINATION_RECEIPT_FAILED');
 assert.equal(f.state.calls.length,1);assert.equal(f.state.terminateCalls,1);assert.equal(f.state.alive,0);assert.equal(f.state.closed,1);
 const w=r.windows[0];assert.equal(w.child.closeObserved,true);assert.equal(w.child.terminated,true);assert.match(w.failureDetails.primaryReason,/OBSERVATION_GAP|CLOCK_SKEW/);
 assert.deepEqual(w.failureDetails.secondaryErrors.map(e=>[e.stage,e.code]),[['terminationReceipt','EEXIST']]);assert.ok(r.windows.slice(1).every(w=>w.status==='NOT_ATTEMPTED'));
 assert.equal(fs.readFileSync(receipt,'utf8'),original);assert.equal(fs.readFileSync(path.join(f.directory,'captures/01/partial.body'),'utf8'),'receipt collision child partial');
 assert.equal(json(path.join(f.directory,'first-child.json')).closeObserved,true);
});

test('throwing terminate still waits for ACK and reports uncertainty despite release and child-receipt failures',async()=>{
 let releaseCalls=0;
 const f=fixture({launchEdit:(args,state)=>{fs.mkdirSync(args.directory);fs.writeFileSync(path.join(args.directory,'partial.body'),'uncertain original partial');
  return {completion:new Promise(()=>{}),terminate:()=>{state.terminateCalls++;throw Object.assign(Error('fixture kill failed'),{code:'EKILL'});},releaseUnconfirmed:()=>{releaseCalls++;throw Error('fixture release failed');}};
 }});f.prepare();const childReceipt=path.join(f.directory,'first-child.json');fs.writeFileSync(childReceipt,'occupied child receipt');
 const started=performance.now(),r=await f.run(),elapsed=performance.now()-started;
 assert.ok(elapsed>=900&&elapsed<10000,String(elapsed));assert.equal(r.status,'FAILED');assert.equal(r.reason,'PUBLIC_PILOT_TERMINATION_UNCONFIRMED');
 assert.equal(f.state.calls.length,1);assert.equal(f.state.terminateCalls,1);assert.equal(releaseCalls,1);
 const w=r.windows[0];assert.deepEqual(w.child,{code:null,signal:null,terminated:false,terminationRequested:true,closeObserved:false});
 assert.equal(w.failureDetails.primaryReason,'PUBLIC_PILOT_WINDOW_CLOSED_DURING_CAPTURE');
 assert.deepEqual(w.failureDetails.secondaryErrors.map(e=>[e.stage,e.code]),[['terminate','EKILL'],['releaseUnconfirmed',null],['childReceipt','EEXIST']]);
 assert.ok(r.windows.slice(1).every(w=>w.status==='NOT_ATTEMPTED'));assert.equal(json(path.join(f.directory,'SUMMARY.json')).reason,'PUBLIC_PILOT_TERMINATION_UNCONFIRMED');
 assert.equal(fs.readFileSync(childReceipt,'utf8'),'occupied child receipt');assert.equal(fs.readFileSync(path.join(f.directory,'captures/01/partial.body'),'utf8'),'uncertain original partial');
});

test('a throwing terminate with subsequent close ACK preserves the terminate failure and stops later windows',async()=>{
 const f=fixture({launchEdit:(args,state)=>{let resolve;const completion=new Promise(done=>{resolve=done;});
  return {completion,terminate:()=>{state.terminateCalls++;setImmediate(()=>resolve({code:null,signal:'SIGKILL',closeObserved:true,stdout:'',stderr:''}));throw Error('fixture terminate threw after kill');}};
 }});f.prepare();const r=await f.run();assert.equal(r.status,'FAILED');assert.equal(r.reason,'PUBLIC_PILOT_TERMINATE_REQUEST_FAILED');
 assert.equal(f.state.calls.length,1);assert.equal(f.state.terminateCalls,1);assert.equal(r.windows[0].child.closeObserved,true);
 assert.equal(r.windows[0].failureDetails.primaryReason,'PUBLIC_PILOT_WINDOW_CLOSED_DURING_CAPTURE');assert.equal(r.windows[0].failureDetails.secondaryErrors[0].stage,'terminate');
 assert.ok(r.windows.slice(1).every(w=>w.status==='NOT_ATTEMPTED'));
});

test('malformed launch contracts and rejected completion still attempt cleanup and cannot claim close',async()=>{
 for(const mode of ['missing-completion','missing-terminate','rejected-completion','false-close']){
  let releaseCalls=0;
  const f=fixture({launchEdit:(args,state)=>{
   const child={terminate:()=>{state.terminateCalls++;},releaseUnconfirmed:()=>{releaseCalls++;}};
   if(mode!=='missing-completion')child.completion=mode==='rejected-completion'?Promise.reject(Error('fixture completion rejected')):mode==='false-close'?Promise.resolve({closeObserved:false}):new Promise(()=>{});
   if(mode==='missing-terminate')delete child.terminate;return child;
  }});f.prepare();const r=await f.run();assert.equal(r.reason,'PUBLIC_PILOT_TERMINATION_UNCONFIRMED',mode);assert.equal(f.state.calls.length,1);assert.equal(releaseCalls,1);
  assert.equal(f.state.terminateCalls,mode==='missing-terminate'?0:1);assert.equal(r.windows[0].child.closeObserved,false);assert.equal(r.windows[0].child.terminated,false);
  assert.equal(r.windows[0].failureDetails.primaryReason,mode.startsWith('missing-')?'PUBLIC_PILOT_CAPTURE_CHILD_CONTRACT':'PUBLIC_PILOT_CHILD_CLOSE_REQUIRED');
  assert.ok(r.windows.slice(1).every(w=>w.status==='NOT_ATTEMPTED'));
 }
});

test('changed plan, READY, native plan and external expected hashes reject before acquisition',async()=>{
 for(const name of ['pilot-plan.json','READY.json','native-plan.json']){
  const f=fixture();f.prepare();fs.appendFileSync(path.join(f.directory,name),'\n');await assert.rejects(f.run(),/RESOURCE_HASH/);assert.equal(f.state.calls.length,0);
 }
 const f=fixture();f.prepare();fs.appendFileSync(f.planFile,'\n');await assert.rejects(f.run(),/RESOURCE_HASH/);
 const g=fixture();g.prepare();g.ready.readySha256='0'.repeat(64);await assert.rejects(g.run(),/RESOURCE_HASH/);
});

test('copied isolated wrapper mutation after READY is detected without touching working sources',async()=>{
 const owner=fs.mkdtempSync(path.join(tmpdir(),'g4-pilot-owned-source-copy-')),binding=pilot.publicAvailabilityPilotSourceBinding();
 for(const f of [binding.wrapperSource,...binding.sourceBinding,...binding.auditSourceBinding]){
  const destination=path.join(owner,f.path);fs.mkdirSync(path.dirname(destination),{recursive:true});fs.copyFileSync(path.resolve(import.meta.dirname,'..',f.path),destination);
 }
 const api=await import(pathToFileURL(path.join(owner,'public-availability-pilot.mjs')).href),f=fixture({api});f.prepare();
 fs.appendFileSync(path.join(owner,'public-availability-pilot.mjs'),'\n// owned tamper probe\n');await assert.rejects(f.run(),/SOURCE_MISMATCH/);assert.equal(f.state.calls.length,0);
});

test('a fixture attempting native promotion or altered envelope hash is rejected',async()=>{
 for(const mode of ['promotion','hash']){
  const f=fixture({launchEdit:(args)=>{const completion=runPublicSchedule({plan:json(args.planFile),directory:args.directory,runIdentity:args.runIdentity,testFixture:{label:'explicit-three-window-fixture',clock:()=>2000,capture:async()=>({status:'FIXTURE_COMPLETE',nativeCapture:false,verified:true,manifestSha256:'c'.repeat(64)})}}).then(r=>{
   let resultSha256=r.resultSha256;if(mode==='promotion'){const file=path.join(args.directory,'result.json'),v=json(file);v.kind='NATIVE_PUBLIC';v.fixtureLabel=null;const b=Buffer.from(JSON.stringify(v));fs.writeFileSync(file,b);resultSha256=sha(b);}else resultSha256='0'.repeat(64);
   return {code:0,signal:null,closeObserved:true,stdout:JSON.stringify({resultSha256}),stderr:''};});return {completion,terminate(){throw Error('unexpected termination');}};}});
  f.prepare();const r=await f.run();assert.equal(r.status,'FAILED');assert.match(r.reason,mode==='promotion'?/RESULT_BINDING/:/RESULT_HASH/);assert.ok(r.windows.every(w=>!w.availabilityPilotCandidateEligible));
 }
});
