import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync,writeFileSync,mkdtempSync} from 'node:fs';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {capturePublicBundle} from '../public-capture-bundle.mjs';
import {evaluatePublicCaptureQuality,validatePublicCaptureQualityPolicy,measurePublicCaptureQuality} from '../public-capture-quality.mjs';

const sha=x=>createHash('sha256').update(x).digest('hex'),DAY=86400000;
const policyBytes=readFileSync(new URL('../config/public-capture-quality-20261020.json',import.meta.url));
const expectedPolicySha256=sha(policyBytes),policy=validatePublicCaptureQualityPolicy({policyBytes,expectedPolicySha256});
const NOW=Date.parse('2026-10-21T00:13:00Z');
function measured({ageNs=1000000000n,lastOpen=Date.parse('2026-10-20T00:00:00Z'),asOfMs=NOW,bars=720}={}){
 const receivedAtMs=asOfMs+2000,ns=BigInt(receivedAtMs)*1000000n-ageNs;
 return {history:{asOfMs,lastClosedBarMs:lastOpen,bars},quote:{receivedAtMs,
  quote:{timestampNs:String(ns),timestampMs:Number(ns/1000000n),symbol:'BTC/USD',currency:'USD',baseCurrency:'BTC',source:'ALPACA_CRYPTO_US'}},policy};
}
async function fixture({staleQuote=false,staleHistory=false}={}){
 const parent=mkdtempSync(join(tmpdir(),'g4-quality-')),directory=join(parent,'capture');
 const today=Math.floor(Date.now()/DAY)*DAY-(staleHistory?DAY:0);
 const rows=Array.from({length:65},(_,i)=>[(today+(i-64)*DAY)/1000,'100','102','99','101','100','12',10]);
 const history={error:[],result:{XXBTZUSD:rows,last:rows.at(-1)[0]}};
 const metadata={error:[],result:{XXBTZUSD:{altname:'XBTUSD',base:'XXBT',quote:'ZUSD',pair_decimals:2,lot_decimals:8,cost_decimals:6,tick_size:'0.01',ordermin:'0.00001',costmin:'0.01',status:'online'}}};
 const capture=await capturePublicBundle({directory,testFixture:{label:'quality-fixture',
  historyFetch:async url=>new Response(JSON.stringify(url.includes('/OHLC')?history:metadata)),
  quoteFetch:async()=>new Response(JSON.stringify({quotes:{'BTC/USD':{bp:'100',ap:'101',bs:'12',as:'10',t:new Date(Date.now()-(staleQuote?20000:1000)).toISOString()}}}))}});
 assert.equal(capture.status,'FIXTURE_COMPLETE');return {directory,expectedManifestSha256:capture.manifestSha256,policyBytes,expectedPolicySha256};
}

test('policy binds exact bytes and the frozen plan, not equivalent JSON formatting',()=>{
 assert.equal(policy.quote.maxAgeAtReceiptMs,10000);assert.ok(policy.registeredAtMs<policy.firstWindowOpenMs);
 assert.throws(()=>validatePublicCaptureQualityPolicy({policyBytes:Buffer.concat([policyBytes,Buffer.from(' ')]),expectedPolicySha256}),/POLICY_HASH/);
 assert.throws(()=>validatePublicCaptureQualityPolicy({policyBytes,expectedPolicySha256:'0'.repeat(64)}),/POLICY_HASH/);
});
test('policy cannot loosen quote age, allow future timestamps, or silently rebind the schedule',()=>{
 for(const mutate of [p=>p.quote.maxAgeAtReceiptMs=60000,p=>p.quote.futureToleranceNs='1',p=>p.planSha256='a'.repeat(64),p=>p.history.contiguousBarsRequired=false,p=>p.registeredAtMs=p.firstWindowOpenMs,p=>p.extra=true]){
  const p=JSON.parse(policyBytes);mutate(p);const body=Buffer.from(JSON.stringify(p));
  assert.throws(()=>validatePublicCaptureQualityPolicy({policyBytes:body,expectedPolicySha256:sha(body)}),/PUBLIC_QUALITY_/);
 }
});
test('pure arithmetic distinguishes daily OPEN from CLOSE and never accepts native quality',()=>{
 const r=measurePublicCaptureQuality(measured());assert.equal(r.qualityCriteriaPassed,true);
 assert.equal(r.history.lastClosedBarOpenMs,Date.parse('2026-10-20T00:00:00Z'));
 assert.equal(r.history.lastClosedBarCloseMs,Date.parse('2026-10-21T00:00:00Z'));
 assert.equal(r.history.expectedLastClosedBarCloseMs,r.history.lastClosedBarCloseMs);
 assert.equal(r.history.lagClosedDays,0);assert.equal(r.dataQualityAccepted,false);assert.equal(r.structuralReplayVerified,false);
});
test('upper age bound exactly 10 seconds passes and one nanosecond above fails',()=>{
 const equal=measurePublicCaptureQuality(measured({ageNs:9999000000n}));
 assert.equal(equal.qualityCriteriaPassed,true);
 assert.equal(equal.quote.ageAtReceiptLowerBoundNs,'9999000000');
 assert.equal(equal.quote.ageAtReceiptUpperBoundExclusiveNs,'10000000000');
 assert.equal(measurePublicCaptureQuality(measured({ageNs:9998999999n})).qualityCriteriaPassed,true);
 const r=measurePublicCaptureQuality(measured({ageNs:9999000001n}));
 assert.deepEqual(r.reasons,['QUOTE_STALE_AT_RECEIPT']);
 assert.equal(r.quote.ageAtReceiptUpperBoundExclusiveNs,'10000000001');
});
test('a 10-second lower age bound is rejected because receipt precision can exceed the limit',()=>{
 const r=measurePublicCaptureQuality(measured({ageNs:10000000000n}));
 assert.equal(r.qualityCriteriaPassed,false);assert.deepEqual(r.reasons,['QUOTE_STALE_AT_RECEIPT']);
 assert.equal(r.quote.ageAtReceiptLowerBoundNs,'10000000000');
 assert.equal(r.quote.ageAtReceiptUpperBoundExclusiveNs,'10001000000');
 assert.equal(Object.hasOwn(r.quote,'ageAtReceiptNs'),false);
});
test('future quote one nanosecond inside the same millisecond is rejected conservatively',()=>{
 const r=measurePublicCaptureQuality(measured({ageNs:-1n}));assert.deepEqual(r.reasons,['QUOTE_FUTURE_AT_RECEIPT']);
 assert.equal(r.quote.ageAtReceiptMs,0);assert.equal(r.quote.ageAtReceiptLowerBoundNs,'-1');
 assert.equal(r.quote.ageAtReceiptUpperBoundExclusiveNs,'999999');
 assert.equal(measurePublicCaptureQuality(measured({ageNs:0n})).quote.freshAtReceipt,true);
});
test('latest closed UTC day must be present; old contiguous history cannot pass',()=>{
 const r=measurePublicCaptureQuality(measured({lastOpen:Date.parse('2026-10-19T00:00:00Z')}));
 assert.deepEqual(r.reasons,['LATEST_CLOSED_UTC_DAY_MISSING']);assert.equal(r.history.lagClosedDays,1);
});
test('open daily row cannot masquerade as most recent closed row',()=>{
 const r=measurePublicCaptureQuality(measured({lastOpen:Date.parse('2026-10-21T00:00:00Z')}));
 assert.deepEqual(r.reasons,['FUTURE_OR_UNCLOSED_DAILY_BAR']);
});
test('midnight and DST dates are governed by UTC daily boundaries',()=>{
 for(const iso of ['2026-10-25T00:00:00Z','2026-10-25T01:30:00Z','2026-10-26T00:00:00Z']){
  const asOfMs=Date.parse(iso),close=Math.floor(asOfMs/DAY)*DAY;
  const r=measurePublicCaptureQuality(measured({asOfMs,lastOpen:close-DAY}));
  assert.equal(r.qualityCriteriaPassed,true);assert.equal(r.history.lastClosedBarCloseMs,close);
 }
});
test('invalid timestamp precision, receipt before capture and wrong currency fail closed',()=>{
 for(const mutate of [p=>p.quote.quote.timestampNs='1',p=>p.quote.receivedAtMs=p.history.asOfMs-1,p=>p.quote.quote.currency='EUR',p=>p.history.lastClosedBarMs++,p=>p.history.bars=721]){
  const f=measured();mutate(f);assert.throws(()=>measurePublicCaptureQuality(f),/PUBLIC_QUALITY_/);
 }
});
test('fresh fully replayed fixture remains diagnostic with no external network access',async()=>{
 const f=await fixture(),old=globalThis.fetch;let calls=0;globalThis.fetch=()=>{calls++;throw Error('NETWORK_FORBIDDEN');};
 try{
  const r=await evaluatePublicCaptureQuality(f);assert.equal(r.status,'FIXTURE_QUALITY_DIAGNOSTIC');
  assert.equal(r.qualityCriteriaPassed,true);assert.equal(r.dataQualityAccepted,false);assert.equal(r.nativeCapture,false);
  assert.equal(r.structuralReplayVerified,true);assert.equal(r.providerRequestsMade,false);assert.equal(r.usableAtDecisionTime,false);
  assert.equal(calls,0);
 }finally{globalThis.fetch=old;}
});
test('the new gate rejects stale quote and stale daily history that frozen replay permits',async()=>{
 const q=await evaluatePublicCaptureQuality(await fixture({staleQuote:true}));assert.equal(q.status,'DATA_QUALITY_REJECTED');assert.ok(q.reasons.includes('QUOTE_STALE_AT_RECEIPT'));
 const h=await evaluatePublicCaptureQuality(await fixture({staleHistory:true}));assert.equal(h.status,'DATA_QUALITY_REJECTED');assert.ok(h.reasons.includes('LATEST_CLOSED_UTC_DAY_MISSING'));
});
test('raw-byte tampering cannot reach the quality arithmetic',async()=>{
 const f=await fixture(),raw=join(f.directory,'history/ohlc.raw.json');writeFileSync(raw,Buffer.concat([readFileSync(raw),Buffer.from(' ')]));
 await assert.rejects(evaluatePublicCaptureQuality(f),/RESOURCE_HASH/);
});
