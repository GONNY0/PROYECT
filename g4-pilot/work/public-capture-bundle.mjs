/** Public, one-shot market-data capture. No ledger, registration, credentials or orders.
 * Hashes bind local bytes; they are not provider signatures or host attestation.
 * This independent acquisition is never a forward V1/V2 observation.
 */
import {createHash} from 'node:crypto';
import {mkdirSync,readFileSync,writeFileSync,openSync,closeSync,fsyncSync,lstatSync,realpathSync,readdirSync,existsSync} from 'node:fs';
import {resolve,dirname,join,relative,isAbsolute,sep,win32} from 'node:path';
import {fileURLToPath} from 'node:url';
import {fetchHistory,loadHistory} from './engine-node/data-history.mjs';
import {AlpacaCryptoDataAdapter,ALPACA_CRYPTO_QUOTE_URL} from './engine-node/brokers/alpaca-data.mjs';
import {replayAlpacaCapture} from './engine-node/brokers/alpaca-capture.mjs';

export const PUBLIC_CAPTURE_SOURCES=Object.freeze([
 'public-capture-bundle.mjs','engine-node/data-history.mjs','engine-node/paper-precision.mjs',
 'engine-node/brokers/alpaca-data.mjs','engine-node/brokers/alpaca-transport.mjs',
 'engine-node/brokers/alpaca-capture.mjs','engine-node/brokers/alpaca-error.mjs',
]);
const SCHEMA='g4.public-capture-bundle.v1',SHA=/^[a-f0-9]{64}$/,MAX_FILE=2097152,MAX_TOTAL=12582912;
const HISTORY=['START.json','asset-pairs.raw.json','bars.normalized.json','ohlc.raw.json','receipt.json'];
const POLICY=Object.freeze({publicDataOnly:true,credentialsUsed:false,orderSubmitted:false,liveEnabled:false,
 realCapitalAuthorized:false,forwardExperimentRegistered:false,forwardV1V2Observation:false,economicGatePassed:false,
 realProfitRecognizedMicros:'0',providerAttestation:false,hostileHostIsolation:false});
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical(value[k])).join(',')+'}':JSON.stringify(value);
function fail(ok,reason){if(!ok)throw Error('PUBLIC_CAPTURE_'+reason);}
function exact(value){return Number.isSafeInteger(value)&&value>=0;}
function key(path){const p=resolve(path);return process.platform==='win32'?p.toLowerCase():p;}
function inside(root,path){const r=relative(root,path);return r!==''&&r!=='..'&&!r.startsWith('..'+sep)&&!isAbsolute(r);}
function local(value){fail(typeof value==='string'&&value.length>0&&isAbsolute(value)&&!value.includes('\0')&&!value.startsWith('\\\\')&&!value.startsWith('//'),'LOCAL_ABSOLUTE_PATH_REQUIRED');return resolve(value);}
function regular(path,directory=false){
 const stat=lstatSync(path);
 fail(!stat.isSymbolicLink()&&(directory?stat.isDirectory():stat.isFile())&&(directory||stat.nlink===1),'LINK_OR_NONREGULAR_RESOURCE');
 fail(key(realpathSync(path))===key(path),'LINK_OR_NONREGULAR_RESOURCE');return stat;
}
function ancestors(path){
 let current=local(path);const paths=[current];
 while(dirname(current)!==current){current=dirname(current);paths.push(current);}
 for(const entry of paths.reverse())regular(entry,true);
}
function relpath(value){
 fail(typeof value==='string'&&value.length<=240&&/^[A-Za-z0-9_./-]+$/.test(value)&&!isAbsolute(value)&&!win32.isAbsolute(value)
  &&value.split('/').every(p=>p&&p!=='.'&&p!=='..'&&!/[. ]$/.test(p)),'RELATIVE_PATH_REQUIRED');return value;
}
function bounded(path,max=MAX_FILE){fail(regular(path).size<=max,'RESOURCE_TOO_LARGE');return readFileSync(path);}
function json(path,max=MAX_FILE){return JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bounded(path,max)));}
function syncDir(path){let fd;try{fd=openSync(path,'r');fsyncSync(fd);}catch(error){if(!['EPERM','EACCES','EINVAL','EISDIR','ENOTSUP','EBADF'].includes(error.code))throw error;}finally{if(fd!==undefined)closeSync(fd);}}
function writeNew(path,value){
 const bytes=Buffer.from(JSON.stringify(value,null,2)+'\n');fail(bytes.length<=MAX_FILE,'JSON_TOO_LARGE');
 const fd=openSync(path,'wx',0o600);try{writeFileSync(fd,bytes);fsyncSync(fd);}finally{closeSync(fd);}syncDir(dirname(path));return digest(bytes);
}
function inventory(root){
 const files=[],directories=[];let entries=0;
 function visit(prefix,depth){fail(depth<=5,'INVENTORY_DEPTH');
  for(const name of readdirSync(join(root,prefix))){
   fail(++entries<=48,'INVENTORY_BOUND');const path=prefix?prefix+'/'+name:name;relpath(path);
   const full=join(root,path),stat=lstatSync(full);regular(full,stat.isDirectory());
   if(stat.isDirectory()){directories.push(path);visit(path,depth+1);}else{fail(stat.size<=MAX_FILE,'RESOURCE_TOO_LARGE');files.push(path);}
  }
 }
 visit('',0);return {files:files.sort(),directories:directories.sort()};
}
function sources(){return PUBLIC_CAPTURE_SOURCES.map(path=>{const body=readFileSync(new URL(path,import.meta.url));return {path,sha256:digest(body),bytes:body.length};});}
function runtime(){return {nodeVersion:process.version,nodeSha256:digest(readFileSync(process.execPath)),platform:process.platform,architecture:process.arch};}
function runtimeContract(value){
 fail(value&&/^v(2[4-9]|[3-9]\d)\.\d+\.\d+$/.test(value.nodeVersion??'')&&SHA.test(value.nodeSha256??'')
  &&['win32','linux','darwin','freebsd','openbsd','aix','sunos'].includes(value.platform)&&/^[a-z0-9_]{2,16}$/.test(value.architecture??''),'RUNTIME_CONTRACT');
 fail(Object.keys(value).sort().join(',')==='architecture,nodeSha256,nodeVersion,platform','RUNTIME_FIELDS');
}
function checkManifest(manifest){
 fail(manifest?.schemaVersion===SCHEMA&&manifest.status==='SEALED_FOR_REPLAY'&&manifest.symbol==='BTC-USD','MANIFEST_CONTRACT');
 fail(['NATIVE_PUBLIC','INJECTED_FIXTURE'].includes(manifest.captureKind),'CAPTURE_KIND');
 fail(canonical(manifest.policy)===canonical(POLICY),'POLICY_CONTRACT');
 fail(exact(manifest.startedAtMs)&&exact(manifest.completedAtMs)&&manifest.completedAtMs>=manifest.startedAtMs,'CAPTURE_TIMING');
 fail(manifest.captureKind==='NATIVE_PUBLIC'?manifest.fixtureLabel===null:typeof manifest.fixtureLabel==='string'&&/^[A-Za-z0-9_.-]{1,80}$/.test(manifest.fixtureLabel),'FIXTURE_LABEL');
 fail(manifest.historyDirectory==='history'&&/^quotes\/[A-Za-z0-9_.-]{1,100}$/.test(manifest.quoteDirectory??''),'CAPTURE_DIRECTORIES');
 runtimeContract(manifest.producer);fail(canonical(manifest.sources)===canonical(sources()),'IMPLEMENTATION_MISMATCH');
 fail(Array.isArray(manifest.resources)&&manifest.resources.length===9,'RESOURCE_SET');
 const expected=['START.json','quote.json',...HISTORY.map(n=>'history/'+n),manifest.quoteDirectory+'/metadata.json',manifest.quoteDirectory+'/response.body'].sort();
 const seen=new Set();let total=0;
 for(const resource of manifest.resources){
  relpath(resource.path);fail(!seen.has(resource.path.toLowerCase())&&SHA.test(resource.sha256??'')&&exact(resource.bytes)&&resource.bytes<=MAX_FILE,'RESOURCE_CONTRACT');
  seen.add(resource.path.toLowerCase());total+=resource.bytes;
 }
 fail(total<=MAX_TOTAL&&canonical(manifest.resources.map(r=>r.path).sort())===canonical(expected),'RESOURCE_SET');
 return expected;
}
function checkResources(root,manifest,hasManifest){
 const expected=checkManifest(manifest),found=inventory(root);
 fail(canonical(found.files)===canonical([...expected,...(hasManifest?['manifest.json']:[])].sort()),'UNEXPECTED_INVENTORY');
 fail(canonical(found.directories)===canonical(['history','quotes',manifest.quoteDirectory].sort()),'UNEXPECTED_DIRECTORIES');
 for(const resource of manifest.resources){const bytes=bounded(join(root,resource.path));fail(bytes.length===resource.bytes&&digest(bytes)===resource.sha256,'RESOURCE_HASH');}
}
async function verifyContent(root,manifest,{hasManifest=true}={}){
 checkResources(root,manifest,hasManifest);
 const start=json(join(root,'START.json'),65536),record=json(join(root,'quote.json'),65536);
 fail(start.schemaVersion==='g4.public-capture-start.v1'&&start.startedAtMs===manifest.startedAtMs&&start.captureKind===manifest.captureKind
  &&start.fixtureLabel===manifest.fixtureLabel&&canonical(start.producer)===canonical(manifest.producer)&&canonical(start.policy)===canonical(POLICY),'START_CONTRACT');
 const loaded=await loadHistory(join(root,'history'));
 fail(loaded.dataset.symbol==='BTC-USD'&&loaded.receipt.symbol==='BTC-USD','USD_HISTORY_REQUIRED');
 const native=manifest.captureKind==='NATIVE_PUBLIC',historyKind=native?'PUBLIC_HTTPS_CAPTURE':'UNVERIFIED_TRANSPORT',quoteKind=native?'ALPACA_CRYPTO_DATA_API':'INJECTED_TRANSPORT';
 fail(loaded.dataset.provenance.kind===historyKind&&loaded.receipt.provenanceKind===historyKind,'HISTORY_SOURCE');
 fail(loaded.receipt.asOfMs===manifest.startedAtMs&&exact(loaded.receipt.completedAtMs)&&loaded.receipt.completedAtMs>=manifest.startedAtMs&&loaded.receipt.completedAtMs<=manifest.completedAtMs,'HISTORY_TIMING');
 fail(loaded.receipt.requests.every(r=>exact(r.requestedAtMs)&&exact(r.receivedAtMs)&&r.requestedAtMs>=manifest.startedAtMs&&r.receivedAtMs>=r.requestedAtMs&&r.receivedAtMs<=loaded.receipt.completedAtMs),'REQUEST_TIMING');
 const resource=manifest.resources.find(r=>r.path===manifest.quoteDirectory+'/metadata.json');
 const capture=await replayAlpacaCapture(join(root,manifest.quoteDirectory),{expectedMetadataSha256:resource.sha256});
 fail(capture.status==='REPLAYED'&&capture.replayVerified===true&&capture.scope==='DATA'&&capture.metadata.httpStatus===200&&capture.captureSource===quoteKind,'QUOTE_CAPTURE');
 const m=capture.metadata,p=record.packet;
 fail(record.schemaVersion==='g4.public-quote-record.v1'&&record.captureDirectory===manifest.quoteDirectory&&record.metadataSha256===resource.sha256,'QUOTE_RECORD');
 fail(m.requestedAtMs>=loaded.receipt.completedAtMs&&m.receivedAtMs<=manifest.completedAtMs,'QUOTE_TIMING');
 fail(p?.status==='QUOTE'&&p.provider==='ALPACA'&&p.source==='ALPACA_CRYPTO_US'&&p.mode==='PAPER_DATA'&&p.tradingPermission===false
  &&p.realEconomicProfitMicros==='0'&&p.provenanceKind===quoteKind&&p.observedAtMs===m.receivedAtMs,'QUOTE_PACKET');
 fail(p.evidence?.source===quoteKind&&p.evidence.endpoint===ALPACA_CRYPTO_QUOTE_URL&&p.evidence.authentication==='PUBLIC_NO_CREDENTIALS'
  &&p.evidence.requestedAtMs===m.requestedAtMs&&p.evidence.receivedAtMs===m.receivedAtMs&&p.evidence.httpStatus===200
  &&p.evidence.rawSha256===capture.rawSha256&&p.evidence.rawBytes===m.rawBytes&&!Object.hasOwn(p.evidence,'evidenceCapture'),'QUOTE_EVIDENCE');
 const bytes=bounded(join(root,manifest.quoteDirectory,'response.body'));let normalizationCalls=0;
 const replayAdapter=new AlpacaCryptoDataAdapter({fetchImpl:async(url,options)=>{
  fail(url===ALPACA_CRYPTO_QUOTE_URL&&options.method==='GET'&&!options.body,'REPLAY_REQUEST_CONTRACT');normalizationCalls++;
  return new Response(bytes,{status:200,headers:{'content-type':'application/json'}});
 }});
 const normalized=await replayAdapter.getQuote();
 fail(normalizationCalls===1&&normalized.status==='QUOTE'&&canonical(normalized.quote)===canonical(p.quote)
  &&normalized.schemaVersion===p.schemaVersion&&canonical(normalized.settlementContract)===canonical(p.settlementContract),'QUOTE_NORMALIZATION');
 checkResources(root,manifest,hasManifest);
 return {history:{bars:loaded.dataset.bars.length,datasetSha256:digest(canonical(loaded.dataset)),receiptSha256:manifest.resources.find(r=>r.path==='history/receipt.json').sha256,
  lastClosedBarMs:loaded.dataset.bars.at(-1).timeMs,asOfMs:loaded.dataset.asOfMs},
  quote:{quote:p.quote,quoteSha256:digest(canonical(p.quote)),metadataSha256:resource.sha256,rawSha256:capture.rawSha256,receivedAtMs:m.receivedAtMs,
   ageAtReceiptMs:m.receivedAtMs-p.quote.timestampMs,freshnessAcceptanceClaimed:false},
  sourceChecks:{historyKind,quoteKind,normalizationCalls,externalNetworkCallsDuringReplay:0,originalPathsRead:false,closedInventory:true}};
}

/** Only an explicit labelled testFixture permits transport/clock injection. */
export async function capturePublicBundle(options={}){
 fail(options&&Object.keys(options).every(k=>['directory','testFixture'].includes(k)),'CAPTURE_OPTIONS');
 const {directory,testFixture}=options,root=local(directory),fixture=testFixture!==undefined;
 if(fixture)fail(testFixture&&/^[A-Za-z0-9_.-]{1,80}$/.test(testFixture.label??'')
  &&typeof testFixture.historyFetch==='function'&&typeof testFixture.quoteFetch==='function'
  &&(testFixture.clock===undefined||typeof testFixture.clock==='function')
  &&Object.keys(testFixture).every(k=>['label','historyFetch','quoteFetch','clock'].includes(k)),'TEST_FIXTURE_REQUIRED');
 ancestors(dirname(root));fail(!existsSync(root),'NEW_DESTINATION_REQUIRED');mkdirSync(root,{mode:0o700});syncDir(dirname(root));
 const clock=fixture?(testFixture.clock??Date.now):Date.now,captureKind=fixture?'INJECTED_FIXTURE':'NATIVE_PUBLIC';
 let stage='START',startedAtMs;
 try{
  startedAtMs=clock();fail(exact(startedAtMs),'CLOCK_INVALID');
  const producer=runtime();runtimeContract(producer);
  writeNew(join(root,'START.json'),{schemaVersion:'g4.public-capture-start.v1',startedAtMs,captureKind,fixtureLabel:fixture?testFixture.label:null,producer,policy:POLICY});
  stage='HISTORY';
  await fetchHistory({directory:join(root,'history'),symbol:'BTC-USD',nowMs:startedAtMs,...(fixture?{fetchImpl:testFixture.historyFetch}:{})});
  stage='QUOTE';
  const packet=await new AlpacaCryptoDataAdapter({evidenceDirectory:join(root,'quotes'),...(fixture?{fetchImpl:testFixture.quoteFetch}:{})}).getQuote();
  fail(packet.status==='QUOTE'&&packet.evidence?.evidenceCapture?.status==='CAPTURED','QUOTE_ACQUISITION_FAILED');
  const capture=packet.evidence.evidenceCapture;
  fail(inside(root,resolve(capture.directory)),'CAPTURE_OUTSIDE_BUNDLE');
  const quoteDirectory=relative(root,capture.directory).split(sep).join('/');relpath(quoteDirectory);
  // Path-bearing producer return values are deliberately discarded.
  const {evidenceCapture,...evidence}=packet.evidence;
  writeNew(join(root,'quote.json'),{schemaVersion:'g4.public-quote-record.v1',captureDirectory:quoteDirectory,metadataSha256:capture.metadataSha256,packet:{...packet,evidence}});
  stage='SEAL';
  const completedAtMs=clock(),files=inventory(root).files;
  const manifest={schemaVersion:SCHEMA,status:'SEALED_FOR_REPLAY',symbol:'BTC-USD',captureKind,fixtureLabel:fixture?testFixture.label:null,
   startedAtMs,completedAtMs,producer,sources:sources(),historyDirectory:'history',quoteDirectory,policy:POLICY,
   resources:files.map(path=>{const body=bounded(join(root,path));return {path,sha256:digest(body),bytes:body.length};}),
   limitations:['Independent public capture, not a strategy decision, forward interval, order, fill or economic result.',
    'Local clocks and hashes are not independent time or provider attestations.',
    'Different Kraken and Alpaca venues; no cross-venue execution equivalence.',
    'Static link/inventory validation does not isolate a hostile concurrently modifying host.']};
  const verification=await verifyContent(root,manifest,{hasManifest:false});
  const manifestSha256=writeNew(join(root,'manifest.json'),manifest);
  return {schemaVersion:'g4.public-capture-result.v1',status:fixture?'FIXTURE_COMPLETE':'COMPLETE',verified:true,nativeCapture:!fixture,
   directory:root,manifestPath:join(root,'manifest.json'),manifestSha256,captureKind,producer,verification,policy:POLICY,
   providerRequestsExpected:3,forwardObservation:false};
 }catch(error){
  const reason=/^PUBLIC_CAPTURE_[A-Z_]+$/.test(error?.message??'')?error.message:'PUBLIC_CAPTURE_ACQUISITION_OR_VALIDATION_FAILED';
  const result={schemaVersion:'g4.public-capture-result.v1',status:'FAILED_PARTIAL',verified:false,nativeCapture:false,
   directory:root,captureKind,stage,reason,startedAtMs:exact(startedAtMs)?startedAtMs:null,manifestSha256:null,policy:POLICY,
   preservedPartialFiles:true,forwardObservation:false};
  const {directory:privateLocalDirectory,...portableFailure}=result;
  writeNew(join(root,'FAILED.json'),portableFailure);return result;
 }
}

/** Replays only the imported directory and this verifier's own six dependencies.
 * The adapter's explicit in-memory transport reproduces normalization without
 * accessing the network, original host, credentials, or operational databases.
 */
export async function replayPublicBundle({directory,expectedManifestSha256}={}){
 const root=local(directory);ancestors(root);fail(SHA.test(expectedManifestSha256??''),'EXTERNAL_MANIFEST_HASH_REQUIRED');
 const raw=bounded(join(root,'manifest.json'),262144);fail(digest(raw)===expectedManifestSha256,'MANIFEST_HASH');
 const manifest=JSON.parse(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(raw));
 const verification=await verifyContent(root,manifest);
 fail(digest(bounded(join(root,'manifest.json'),262144))===expectedManifestSha256,'MANIFEST_CHANGED');
 return {schemaVersion:'g4.public-capture-replay.v1',status:manifest.captureKind==='NATIVE_PUBLIC'?'VERIFIED_NATIVE_PUBLIC_CAPTURE':'VERIFIED_INJECTED_FIXTURE',
  verified:true,nativeCapture:manifest.captureKind==='NATIVE_PUBLIC',manifestSha256:expectedManifestSha256,captureKind:manifest.captureKind,
  producer:manifest.producer,verifier:runtime(),verification,policy:POLICY,providerRequestsMade:false,originalPathsRead:false,
  sqliteOpened:false,forwardObservation:false};
}

function argumentsOf(args){
 const out={};for(let i=0;i<args.length;i+=2){const field={'--directory':'directory','--manifest-sha256':'expectedManifestSha256','--result':'result'}[args[i]];
  fail(field&&typeof args[i+1]==='string'&&!args[i+1].startsWith('--')&&!Object.hasOwn(out,field),'ARGUMENTS');out[field]=args[i+1];}return out;
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{
  const [command,...rest]=process.argv.slice(2),args=argumentsOf(rest);
  fail(['capture','replay'].includes(command),'COMMAND_CAPTURE_OR_REPLAY_REQUIRED');
  const root=local(args.directory),resultPath=local(args.result);ancestors(dirname(resultPath));
  fail(key(resultPath)!==key(root)&&!inside(root,resultPath)&&!existsSync(resultPath),'NEW_EXTERNAL_RESULT_REQUIRED');
  fail(command==='replay'||args.expectedManifestSha256===undefined,'CAPTURE_ARGUMENTS');
  const result=command==='capture'?await capturePublicBundle({directory:root}):await replayPublicBundle({directory:root,expectedManifestSha256:args.expectedManifestSha256});
  const resultSha256=writeNew(resultPath,result);
  console.log(JSON.stringify({status:result.status,verified:result.verified,nativeCapture:result.nativeCapture,manifestSha256:result.manifestSha256,resultPath,resultSha256}));
  if(!result.verified)process.exitCode=1;
 }catch(error){console.error(JSON.stringify({status:'FAILED',verified:false,reason:/^PUBLIC_CAPTURE_[A-Z_]+$/.test(error?.message??'')?error.message:'PUBLIC_CAPTURE_INVALID_OR_UNAVAILABLE_RESOURCE'}));process.exitCode=1;}
}
