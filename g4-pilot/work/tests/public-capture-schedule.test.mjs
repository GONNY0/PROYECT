import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,existsSync,writeFileSync,mkdirSync,symlinkSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import {validatePublicSchedule,selectPublicWindow,publicSchedulePlanSha256,publicScheduleSourceBinding,runPublicSchedule} from '../public-capture-schedule.mjs';

const SHA='a'.repeat(64),MODULE=resolve(import.meta.dirname,'../public-capture-schedule.mjs');
function plan(){return {schemaVersion:'g4.public-capture-schedule.v1',id:'public-operational-fixture',repository:'fixture/repository',enabled:true,
 registeredAtMs:1000,expiresAtMs:5000,windows:[{id:'one',openMs:2000,closeMs:3000},{id:'two',openMs:4000,closeMs:5000}],
 allowedEvents:['schedule','workflow_dispatch','push'],sourceBinding:publicScheduleSourceBinding()};}
const identity=(eventName='schedule',runId='100',runAttempt='1')=>({provider:'GITHUB_ACTIONS',repository:'fixture/repository',commitSha:'a'.repeat(40),runId,runAttempt,eventName});
function fixture({times=[2100,2200,2300],eventName='schedule',capture,runId='100',runAttempt='1'}={}){
 const parent=mkdtempSync(join(tmpdir(),'g4-public-schedule-'));let calls=0,index=0;
 const testFixture={label:'bounded-schedule-fixture',clock:()=>times[Math.min(index++,times.length-1)],
 capture:async args=>{calls++;return capture?capture(args):{status:'FIXTURE_COMPLETE',nativeCapture:false,verified:true,manifestSha256:SHA};}};
 return {options:{plan:plan(),directory:join(parent,'run'),runIdentity:identity(eventName,runId,runAttempt),testFixture},parent,calls:()=>calls};
}

test('pure selection uses half-open windows, finite expiry and explicit pause',()=>{
 const p=plan();assert.deepEqual(validatePublicSchedule(p),{valid:true,scheduleId:p.id,windowCount:2,expiresAtMs:5000});
 for(const [time,status,id] of [[1999,'OUTSIDE',null],[2000,'READY','one'],[2999,'READY','one'],[3000,'OUTSIDE',null],[3999,'OUTSIDE',null],[4000,'READY','two'],[5000,'EXPIRED',null],[9999,'EXPIRED',null]]){
  const result=selectPublicWindow(p,time);assert.equal(result.status,status);assert.equal(result.window?.id??null,id);
 }
 p.enabled=false;assert.equal(selectPublicWindow(p,2100).status,'PAUSED');assert.equal(selectPublicWindow(p,9999).status,'PAUSED');
});

test('invalid, overlapping, unsorted, excessive and unbounded plans are rejected',()=>{
 const edits=[
  p=>p.windows[1].openMs=2999,p=>p.windows.reverse(),p=>p.windows[1].id='one',
  p=>p.windows[0].openMs=p.registeredAtMs,p=>p.expiresAtMs=6000,p=>p.windows[0].closeMs=2000,
  p=>p.enabled='yes',p=>p.id=123,p=>p.windows[0].id=123,p=>p.allowedEvents.push('pull_request'),p=>p.allowedEvents.push('schedule'),
  p=>p.sourceBinding[0].path='../outside',p=>p.sourceBinding[0].sha256='wrong',
  p=>p.sourceBinding[1]={...p.sourceBinding[0]},p=>p.extra='unexpected',
  p=>{p.windows=Array.from({length:33},(_,i)=>({id:'w'+i,openMs:2000+i*1000,closeMs:2500+i*1000}));p.expiresAtMs=p.windows.at(-1).closeMs;},
  p=>{p.windows=[{id:'far',openMs:46*86400000,closeMs:46*86400000+1000}];p.expiresAtMs=p.windows[0].closeMs;}
 ];
 for(const edit of edits){const p=plan();edit(p);assert.throws(()=>validatePublicSchedule(p),/PUBLIC_SCHEDULE_/);}
 for(const time of [-1,NaN,Infinity,1.1])assert.throws(()=>selectPublicWindow(plan(),time),/CLOCK/);
});

test('plan hash is stable across key ordering and the saved snapshot binds its exact bytes',async()=>{
 const f=fixture(),original=publicSchedulePlanSha256(f.options.plan),reordered=Object.fromEntries(Object.entries(f.options.plan).reverse());
 assert.equal(publicSchedulePlanSha256(reordered),original);
 const r=await runPublicSchedule(f.options),saved=readFileSync(join(f.options.directory,'plan.json'));
 assert.equal(createHash('sha256').update(saved).digest('hex'),original);assert.equal(r.planSha256,original);
});

test('outside, paused and expired runs persist receipts with no acquisition',async()=>{
 for(const [time,enabled,status] of [[1999,true,'OUTSIDE'],[3000,true,'OUTSIDE'],[2100,false,'PAUSED'],[5000,true,'EXPIRED']]){
  const f=fixture({times:[time]});f.options.plan.enabled=enabled;
  const result=await runPublicSchedule(f.options);assert.equal(result.status,status);assert.equal(f.calls(),0);
  assert.equal(result.scheduledAcceptanceEligible,false);assert.equal(result.bundle,null);
  assert.equal(existsSync(join(f.options.directory,'result.json')),true);assert.equal(existsSync(join(f.options.directory,'bundle')),false);
 }
});

test('fixture capture can never acquire native status or scheduled acceptance',async()=>{
 const f=fixture(),r=await runPublicSchedule(f.options);assert.equal(r.status,'ON_TIME_CAPTURED');assert.equal(f.calls(),1);
 assert.equal(r.kind,'INJECTED_FIXTURE');assert.equal(r.fixtureLabel,'bounded-schedule-fixture');assert.equal(r.scheduledAcceptanceEligible,false);
 const g=fixture({capture:async()=>({status:'COMPLETE',nativeCapture:true,verified:true,manifestSha256:SHA})});
 const forged=await runPublicSchedule(g.options);assert.equal(forged.status,'FAILED');assert.equal(forged.scheduledAcceptanceEligible,false);
});

test('closing boundary before acquisition prevents network and preserves lateness',async()=>{
 const f=fixture({times:[2999,3000]});const r=await runPublicSchedule(f.options);
 assert.equal(r.status,'LATE');assert.equal(r.reason,'WINDOW_CLOSED_BEFORE_ACQUISITION');assert.equal(f.calls(),0);assert.equal(r.bundle,null);
});

test('capture ending exactly at close or crossing into another window is never accepted',async()=>{
 for(const end of [3000,3001,4100]){
  const f=fixture({times:[2100,2200,end]}),r=await runPublicSchedule(f.options);
  assert.equal(r.status,'LATE');assert.equal(r.reason,'WINDOW_CLOSED_DURING_ACQUISITION');assert.equal(f.calls(),1);
  assert.equal(r.window.id,'one');assert.equal(r.scheduledAcceptanceEligible,false);assert.equal(r.bundle.manifestSha256,SHA);
 }
});

test('clock regression fails before network or after capture with evidence retained',async()=>{
 for(const [times,calls] of [[[2100,2099,2200],0],[[2100,2200,2199,2250],1]]){
  const f=fixture({times}),r=await runPublicSchedule(f.options);assert.equal(r.status,'FAILED');assert.match(r.reason,/CLOCK_REGRESSION/);
  assert.equal(f.calls(),calls);assert.equal(r.scheduledAcceptanceEligible,false);
 }
});

test('acquisition throws or partial result remains FAILED with a bounded nonprivate reason',async()=>{
 for(const capture of [async()=>{throw Error('sensitive local failure details');},async()=>({status:'FAILED_PARTIAL',verified:false,nativeCapture:false,manifestSha256:null})]){
  const f=fixture({capture}),r=await runPublicSchedule(f.options);
  assert.equal(r.status,'FAILED');assert.equal(f.calls(),1);assert.equal(r.scheduledAcceptanceEligible,false);
  assert.equal(JSON.stringify(r).includes('sensitive local'),false);
  const saved=readFileSync(join(f.options.directory,'result.json'),'utf8');assert.equal(saved.includes(f.parent),false);
 }
});

test('event, repository, source binding and incomplete injection fail before directory or network',async()=>{
 const edits=[
  o=>o.runIdentity.repository='other/repository',o=>o.runIdentity.eventName='pull_request',
  o=>o.runIdentity.runId='0',o=>o.runIdentity.runId=100,o=>o.runIdentity.runAttempt='0',o=>o.runIdentity.runAttempt=1,o=>o.runIdentity.commitSha='a'.repeat(39),
  o=>o.plan.sourceBinding[0].sha256='b'.repeat(64),o=>delete o.testFixture.label,o=>o.fetchImpl=()=>{},
 ];
 for(const edit of edits){const f=fixture();edit(f.options);await assert.rejects(runPublicSchedule(f.options),/PUBLIC_SCHEDULE_/);
  assert.equal(f.calls(),0);assert.equal(existsSync(f.options.directory),false);}
});

test('manual and push diagnostics remain distinguishable from the schedule event',async()=>{
 for(const event of ['push','workflow_dispatch']){
  const f=fixture({eventName:event}),r=await runPublicSchedule(f.options);
  assert.equal(r.status,'ON_TIME_CAPTURED');assert.equal(r.runIdentity.eventName,event);assert.equal(r.scheduledAcceptanceEligible,false);
 }
});

test('each attempt is preserved and existing directories cannot be overwritten',async()=>{
 const first=fixture(),r1=await runPublicSchedule(first.options),saved=readFileSync(join(first.options.directory,'result.json'));
 await assert.rejects(runPublicSchedule(first.options),/NEW_DIRECTORY_REQUIRED/);assert.deepEqual(readFileSync(join(first.options.directory,'result.json')),saved);
 const second=fixture({runAttempt:'2'}),r2=await runPublicSchedule(second.options);
 assert.notEqual(r1.runKey,r2.runKey);assert.equal(r1.window.id,r2.window.id);assert.equal(first.calls(),1);assert.equal(second.calls(),1);
});

test('symlink parents are refused before acquisition',async()=>{
 const f=fixture(),outside=join(f.parent,'outside'),linked=join(f.parent,'linked');mkdirSync(outside);
 symlinkSync(outside,linked,process.platform==='win32'?'junction':'dir');f.options.directory=join(linked,'run');
 await assert.rejects(runPublicSchedule(f.options),/DIRECTORY_LINK/);assert.equal(f.calls(),0);assert.equal(existsSync(join(outside,'run')),false);
});

test('native CLI outside schedule persists a nonpromoted receipt without account settings',()=>{
 const f=fixture(),p=plan(),now=Date.now();p.registeredAtMs=now;p.windows=[{id:'future',openMs:now+60000,closeMs:now+120000}];p.expiresAtMs=now+120000;
 const planFile=join(f.parent,'plan.json');writeFileSync(planFile,JSON.stringify(p));
 const child=spawnSync(process.execPath,[MODULE,'--plan',planFile,'--directory',f.options.directory],{encoding:'utf8',timeout:30000,windowsHide:true,
  env:{...process.env,GITHUB_REPOSITORY:p.repository,GITHUB_SHA:'a'.repeat(40),GITHUB_RUN_ID:'100',GITHUB_RUN_ATTEMPT:'1',GITHUB_EVENT_NAME:'push'}});
 assert.equal(child.status,0,child.stderr);const small=JSON.parse(child.stdout),saved=JSON.parse(readFileSync(join(f.options.directory,'result.json')));
 assert.equal(small.status,'OUTSIDE');assert.equal(saved.kind,'NATIVE_PUBLIC');assert.equal(saved.scheduledAcceptanceEligible,false);
 assert.equal(existsSync(join(f.options.directory,'bundle')),false);assert.ok(child.stdout.length<1000);
});
