import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtempSync,readFileSync,writeFileSync,renameSync,mkdirSync,linkSync,symlinkSync,unlinkSync,existsSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {capturePublicBundle,replayPublicBundle,PUBLIC_CAPTURE_SOURCES} from '../public-capture-bundle.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex'),MODULE=resolve(import.meta.dirname,'../public-capture-bundle.mjs');
function fixture({historyFailure=false,quoteFailure=false,crossed=false}={}){
 const parent=mkdtempSync(join(tmpdir(),'g4-public-bundle-')),directory=join(parent,'capture'),calls=[];
 const today=Math.floor(Date.now()/86400000)*86400000;
 const rows=Array.from({length:65},(_,i)=>[(today+(i-64)*86400000)/1000,'100','102','99','101','100','12',10]);
 const history={error:[],result:{XXBTZUSD:rows,last:rows.at(-1)[0]}};
 const metadata={error:[],result:{XXBTZUSD:{altname:'XBTUSD',base:'XXBT',quote:'ZUSD',pair_decimals:2,lot_decimals:8,cost_decimals:6,tick_size:'0.01',ordermin:'0.00001',costmin:'0.01',status:'online'}}};
 const testFixture={label:'isolated-public-fixture',historyFetch:async(url,options)=>{
  calls.push({url,options});assert.equal(options.method,'GET');assert.equal(options.body,undefined);assert.equal(options.headers['APCA-API-KEY-ID'],undefined);
  if(historyFailure)throw Error('SYNTHETIC_NETWORK_FAILURE');
  return new Response(JSON.stringify(url.includes('/OHLC')?history:metadata));
 },quoteFetch:async(url,options)=>{
  calls.push({url,options});assert.equal(options.method,'GET');assert.equal(options.body,undefined);assert.equal(options.headers['APCA-API-KEY-ID'],undefined);
  if(quoteFailure)return new Response('{"message":"fixture unavailable"}',{status:503});
  return new Response(JSON.stringify({quotes:{'BTC/USD':{bp:crossed?'102':'100',ap:'101',bs:'12.12345678',as:'10.5',t:new Date().toISOString()}}}));
 }};
 return {parent,directory,calls,testFixture};
}
async function captureFixture(f){return capturePublicBundle({directory:f.directory,testFixture:f.testFixture});}
async function sealed(){const f=fixture();f.result=await captureFixture(f);assert.equal(f.result.status,'FIXTURE_COMPLETE',JSON.stringify(f.result));return f;}
function manifest(f){return JSON.parse(readFileSync(join(f.directory,'manifest.json')));}
function rewrite(f,m){const bytes=Buffer.from(JSON.stringify(m,null,2)+'\n');writeFileSync(join(f.directory,'manifest.json'),bytes);return sha(bytes);}
async function replay(f,hash=f.result.manifestSha256){return replayPublicBundle({directory:f.directory,expectedManifestSha256:hash});}

test('three public GET fixtures remain labelled and relocate without original files or network',async()=>{
 const f=await sealed();assert.equal(f.calls.length,3);assert.equal(f.result.nativeCapture,false);assert.equal(f.result.verified,true);
 const original=f.directory,m=manifest(f),all=JSON.stringify(m)+readFileSync(join(f.directory,'quote.json'),'utf8');
 assert.equal(all.includes(f.parent),false);assert.equal(all.includes('metadataPath'),false);assert.equal(all.includes('rawPath'),false);
 assert.equal(m.resources.length,9);assert.equal(m.resources.some(r=>r.path.includes(':')||r.path.includes('\\')),false);
 const moved=join(f.parent,'relocated');renameSync(f.directory,moved);f.directory=moved;assert.equal(existsSync(original),false);
 const oldFetch=globalThis.fetch;let externalCalls=0;globalThis.fetch=()=>{externalCalls++;throw Error('REPLAY_NETWORK_FORBIDDEN');};
 try{
  const r=await replay(f);assert.equal(r.status,'VERIFIED_INJECTED_FIXTURE');assert.equal(r.nativeCapture,false);
  assert.equal(r.originalPathsRead,false);assert.equal(r.sqliteOpened,false);assert.equal(r.verification.history.bars,64);
  assert.deepEqual(r.verification,f.result.verification);assert.equal(externalCalls,0);
 }finally{globalThis.fetch=oldFetch;}
});

test('failures retain original receipts and never create a complete manifest',async()=>{
 for(const options of [{historyFailure:true},{quoteFailure:true},{crossed:true}]){
  const f=fixture(options),r=await captureFixture(f);assert.equal(r.status,'FAILED_PARTIAL');assert.equal(r.verified,false);
  assert.equal(r.nativeCapture,false);assert.equal(existsSync(join(f.directory,'FAILED.json')),true);
  const failureBytes=readFileSync(join(f.directory,'FAILED.json'),'utf8'),failure=JSON.parse(failureBytes);
  assert.equal(Object.hasOwn(failure,'directory'),false);assert.equal(Object.hasOwn(failure,'manifestPath'),false);assert.equal(failureBytes.includes(f.parent),false);
  assert.equal(existsSync(join(f.directory,'manifest.json')),false);assert.equal(existsSync(join(f.directory,'history/receipt.json')),true);
  assert.equal(f.calls.length,options.historyFailure?1:3);
  await assert.rejects(captureFixture(f),/NEW_DESTINATION_REQUIRED/);
 }
});

test('native acquisition outage is FAILED_PARTIAL and cannot be labelled COMPLETE',async()=>{
 const f=fixture(),saved=globalThis.fetch;let count=0;globalThis.fetch=async()=>{count++;throw Error('NATIVE_UNAVAILABLE');};
 try{const r=await capturePublicBundle({directory:f.directory});assert.equal(r.captureKind,'NATIVE_PUBLIC');assert.equal(r.status,'FAILED_PARTIAL');assert.equal(r.nativeCapture,false);assert.equal(count,1);}
 finally{globalThis.fetch=saved;}
});

test('injection requires explicit labelled fixture and matching non-native receipts',async()=>{
 const f=fixture();await assert.rejects(capturePublicBundle({directory:f.directory,fetchImpl:f.testFixture.historyFetch}),/CAPTURE_OPTIONS/);
 await assert.rejects(capturePublicBundle({directory:f.directory,testFixture:{historyFetch:f.testFixture.historyFetch,quoteFetch:f.testFixture.quoteFetch}}),/TEST_FIXTURE_REQUIRED/);
 const ok=await sealed(),m=manifest(ok);m.captureKind='NATIVE_PUBLIC';m.fixtureLabel=null;
 await assert.rejects(replay(ok,rewrite(ok,m)),/START_CONTRACT/);
 const original=globalThis.fetch,g=fixture();
 globalThis.fetch=g.testFixture.historyFetch;
 try{const r=await capturePublicBundle({directory:g.directory,testFixture:{...g.testFixture,historyFetch:globalThis.fetch}});assert.equal(r.status,'FAILED_PARTIAL');assert.equal(r.reason,'PUBLIC_CAPTURE_HISTORY_SOURCE');}
 finally{globalThis.fetch=original;}
});

test('external hash, byte hashes and complete closed inventory are mandatory',async()=>{
 const f=await sealed();await assert.rejects(replayPublicBundle({directory:f.directory}),/EXTERNAL_MANIFEST_HASH_REQUIRED/);
 await assert.rejects(replay(f,'0'.repeat(64)),/MANIFEST_HASH/);
 const raw=join(f.directory,'history/ohlc.raw.json'),before=readFileSync(raw);writeFileSync(raw,Buffer.concat([before,Buffer.from(' ')]));
 await assert.rejects(replay(f),/RESOURCE_HASH/);writeFileSync(raw,before);
 writeFileSync(join(f.directory,'orphan.json'),'{}');await assert.rejects(replay(f),/UNEXPECTED_INVENTORY/);unlinkSync(join(f.directory,'orphan.json'));
 mkdirSync(join(f.directory,'orphan-directory'));await assert.rejects(replay(f),/UNEXPECTED_DIRECTORIES/);
});

test('untrusted manifests reject traversal, absolute aliases and duplicate resources',async()=>{
 for(const path of ['../outside','/etc/passwd',['C:','private','file'].join('/'),'history\\receipt.json','history/../receipt.json']){
  const f=await sealed(),m=manifest(f);m.resources[0].path=path;
  await assert.rejects(replay(f,rewrite(f,m)),/RELATIVE_PATH_REQUIRED/);
 }
 const f=await sealed(),m=manifest(f);m.resources[1]={...m.resources[0]};await assert.rejects(replay(f,rewrite(f,m)),/RESOURCE_CONTRACT/);
});

test('hardlinks and symlink directories are refused before legacy readers run',async()=>{
 const f=await sealed(),raw=join(f.directory,'history/ohlc.raw.json');linkSync(raw,join(f.parent,'alias.json'));
 await assert.rejects(replay(f),/LINK_OR_NONREGULAR_RESOURCE/);
 const g=await sealed(),history=join(g.directory,'history'),moved=join(g.parent,'outside-history');renameSync(history,moved);
 symlinkSync(moved,history,process.platform==='win32'?'junction':'dir');
 await assert.rejects(replay(g),/LINK_OR_NONREGULAR_RESOURCE/);
 const parent=fixture();symlinkSync(g.directory,parent.directory,process.platform==='win32'?'junction':'dir');
 await assert.rejects(capturePublicBundle({directory:join(parent.directory,'new'),testFixture:parent.testFixture}),/LINK_OR_NONREGULAR_RESOURCE/);
});

test('normalization is independently rerun even when attacker updates file and manifest hashes',async()=>{
 const f=await sealed(),path=join(f.directory,'quote.json'),record=JSON.parse(readFileSync(path));record.packet.quote.bidPriceUnits18='1';
 writeFileSync(path,JSON.stringify(record));const m=manifest(f),r=m.resources.find(r=>r.path==='quote.json');r.sha256=sha(readFileSync(path));r.bytes=readFileSync(path).length;
 await assert.rejects(replay(f,rewrite(f,m)),/QUOTE_NORMALIZATION/);
 const g=await sealed(),p=join(g.directory,'history/bars.normalized.json'),dataset=JSON.parse(readFileSync(p));dataset.bars[0].closeMicros='1';writeFileSync(p,JSON.stringify(dataset));
 const n=manifest(g),resource=n.resources.find(r=>r.path==='history/bars.normalized.json');resource.sha256=sha(readFileSync(p));resource.bytes=readFileSync(p).length;
 await assert.rejects(replay(g,rewrite(g,n)),/Normalized hash mismatch/);
});

test('the fixed executable closure imports no database, execution adapter or secret loader',()=>{
 assert.equal(PUBLIC_CAPTURE_SOURCES.length,7);
 for(const path of PUBLIC_CAPTURE_SOURCES){
  const source=readFileSync(new URL('../'+path,import.meta.url),'utf8');
  assert.equal(/from\s+['"][^'"]*(?:store|ledger|cli|alpaca-paper|coordinator|secret-loader)[^'"]*['"]/.test(source),false,path);
  assert.equal(/from\s+['"]node:sqlite['"]/.test(source),false,path);
 }
});

test('replay CLI writes full result outside bundle and compact stdout, preserving original bytes',async()=>{
 const f=await sealed(),output=join(f.parent,'result.json'),mBefore=readFileSync(join(f.directory,'manifest.json'));
 const args=[MODULE,'replay','--directory',f.directory,'--manifest-sha256',f.result.manifestSha256,'--result',output];
 const child=spawnSync(process.execPath,args,{encoding:'utf8',timeout:30000,windowsHide:true});
 assert.equal(child.status,0,child.stderr);const small=JSON.parse(child.stdout),full=JSON.parse(readFileSync(output));
 assert.equal(small.status,'VERIFIED_INJECTED_FIXTURE');assert.equal(small.resultSha256,sha(readFileSync(output)));assert.equal(full.verified,true);
 assert.ok(child.stdout.length<1500);assert.deepEqual(readFileSync(join(f.directory,'manifest.json')),mBefore);
 const second=spawnSync(process.execPath,args,{encoding:'utf8',timeout:30000,windowsHide:true});assert.equal(second.status,1);assert.match(second.stderr,/NEW_EXTERNAL_RESULT_REQUIRED/);
});
