import {createHash,randomUUID} from 'node:crypto';
import {mkdir,open,readFile,stat} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {hasAlpacaSecretEcho,validateAlpacaErrorDiagnostic} from './alpaca-error.mjs';

const HOSTS={PAPER:'https://paper-api.alpaca.markets',DATA:'https://data.alpaca.markets'},MAX_BYTES=2*1024*1024;
const INTEGRITY={PAPER:'LOCAL_PRIVATE_BYTES_NOT_PROVIDER_ATTESTATION',DATA:'LOCAL_PUBLIC_BYTES_NOT_PROVIDER_ATTESTATION'};
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function validateMetadata(meta){
 const host=HOSTS[meta.scope],nativeSource=meta.scope==='PAPER'?'ALPACA_PAPER_API':'ALPACA_CRYPTO_DATA_API';
 if(!['g4.alpaca-http-capture.v1','g4.alpaca-http-capture.v2'].includes(meta.schemaVersion)||!host||meta.mode!==(meta.scope==='PAPER'?'PAPER':'PAPER_DATA')||meta.host!==host||![nativeSource,'INJECTED_TRANSPORT'].includes(meta.source)
  ||!['GET','POST','DELETE'].includes(meta.method)||typeof meta.path!=='string'||meta.path.length>2048
  ||(meta.scope==='PAPER'?!meta.path.startsWith('/v2/'):(meta.method!=='GET'||meta.path!=='/v1beta3/crypto/us/latest/quotes?symbols=BTC%2FUSD'))
  ||/[\r\n\0]/.test(meta.path)||meta.path.includes('://')||new URL(meta.path,host).origin!==host
  ||!Number.isInteger(meta.httpStatus)||meta.httpStatus<100||meta.httpStatus>599
  ||!Number.isSafeInteger(meta.requestedAtMs)||!Number.isSafeInteger(meta.receivedAtMs)||meta.requestedAtMs<0||meta.receivedAtMs<meta.requestedAtMs
  ||meta.integrityScope!==INTEGRITY[meta.scope])throw Error('INVALID_CAPTURE_METADATA');
 if(meta.schemaVersion==='g4.alpaca-http-capture.v2')validateAlpacaErrorDiagnostic(meta.errorDiagnostic,meta.httpStatus);
 else if(Object.hasOwn(meta,'errorDiagnostic'))throw Error('INVALID_CAPTURE_METADATA');
}
async function writeExclusive(file,bytes){
 const handle=await open(file,'wx');try{await handle.writeFile(bytes);await handle.sync();}finally{await handle.close();}
}
async function syncDirectory(directory){
 let handle;try{handle=await open(directory,'r');await handle.sync();return true;}
 catch(error){if(!['EPERM','EACCES','EINVAL','EISDIR','ENOTSUP'].includes(error.code))throw error;return false;}
 finally{await handle?.close();}
}
/** Preserve response bytes locally only. Request headers/body and credentials are never serialized. */
export async function captureAlpacaResponse({directory,scope='PAPER',method,path,httpStatus,requestedAtMs,receivedAtMs,source,raw=null,credentials=[],errorDiagnostic}){
 if(directory===undefined)return {status:'NOT_REQUESTED'};
 let captureDirectory;
 try{
  if(typeof directory!=='string'||!directory.trim()||directory.includes('\0'))throw Error('INVALID_CAPTURE_DIRECTORY');
  const successful=httpStatus>=200&&httpStatus<300;
  if(successful&&(!(raw instanceof Uint8Array)||raw.byteLength>MAX_BYTES))throw Error('INVALID_CAPTURE_BODY');
  if(!successful&&raw!==null)throw Error('ERROR_BODY_CAPTURE_FORBIDDEN');
  const bytes=successful?Buffer.from(raw):null;
  const sanitizedDiagnostic=errorDiagnostic===undefined?undefined:validateAlpacaErrorDiagnostic(errorDiagnostic,httpStatus);
  const metadata={schemaVersion:sanitizedDiagnostic?'g4.alpaca-http-capture.v2':'g4.alpaca-http-capture.v1',scope,mode:scope==='PAPER'?'PAPER':'PAPER_DATA',host:HOSTS[scope],method,path,httpStatus,requestedAtMs,receivedAtMs,source,
   responseBodyAvailable:successful,rawFile:successful?'response.body':null,rawBytes:bytes?.length??0,rawSha256:bytes?sha(bytes):null,
   errorBodyPolicy:sanitizedDiagnostic?'NON_2XX_SANITIZED_DIAGNOSTIC_ONLY_NO_BODY_PRESERVED':'NON_2XX_BODY_NOT_READ_OR_PRESERVED',integrityScope:INTEGRITY[scope],
   ...(sanitizedDiagnostic?{errorDiagnostic:sanitizedDiagnostic}:{}),
   validationScope:source==='INJECTED_TRANSPORT'?'INJECTED_FIXTURE_NOT_EXTERNAL_SANDBOX_VALIDATION':'NATIVE_HTTPS_RECEIPT_NOT_SANDBOX_ACCEPTANCE',
   durability:'FILE_FSYNC_EXCLUSIVE_CREATE_DIRECTORY_SYNC_WHERE_SUPPORTED_NOT_POWER_LOSS_CERTIFIED'};
  validateMetadata(metadata);
  const metadataBytes=Buffer.from(JSON.stringify(metadata,null,2)+'\n');
  if(hasAlpacaSecretEcho(metadataBytes,credentials)||(bytes&&hasAlpacaSecretEcho(bytes,credentials)))return {status:'BLOCKED_SECRET_ECHO'};
  await mkdir(resolve(directory),{recursive:true});
  captureDirectory=join(resolve(directory),`${new Date(receivedAtMs).toISOString().replaceAll(':','-')}-${randomUUID()}`);
  await mkdir(captureDirectory); // Exclusive UUID reservation; existing evidence is never overwritten.
  if(bytes)await writeExclusive(join(captureDirectory,'response.body'),bytes);
  await writeExclusive(join(captureDirectory,'metadata.json'),metadataBytes);
  const directorySynced=await syncDirectory(captureDirectory);await syncDirectory(resolve(directory));
  return {status:successful?'CAPTURED':'METADATA_ONLY',directory:captureDirectory,metadataPath:join(captureDirectory,'metadata.json'),
   rawPath:successful?join(captureDirectory,'response.body'):null,metadataSha256:sha(metadataBytes),rawSha256:metadata.rawSha256,
   rawBytes:metadata.rawBytes,responseBodyAvailable:successful,directorySynced,integrityScope:INTEGRITY[scope]};
 }catch{return {status:'CAPTURE_FAILED',reason:'EVIDENCE_PUBLICATION_FAILED',...(captureDirectory?{directory:captureDirectory}:{})};}
}

/** Replay exact bytes, without network. An external expected hash binds the manifest to its saved audit receipt. */
export async function replayAlpacaCapture(directory,{expectedMetadataSha256}={}){
 if(typeof directory!=='string'||!directory.trim())throw Error('INVALID_CAPTURE_DIRECTORY');
 const root=resolve(directory),metadataPath=join(root,'metadata.json');
 if((await stat(metadataPath)).size>32768)throw Error('CAPTURE_METADATA_TOO_LARGE');
 const metadataBytes=await readFile(metadataPath),metadataSha256=sha(metadataBytes);
 if(expectedMetadataSha256!==undefined&&(!/^[a-f0-9]{64}$/.test(expectedMetadataSha256)||expectedMetadataSha256!==metadataSha256))throw Error('CAPTURE_METADATA_HASH_MISMATCH');
 const metadata=JSON.parse(metadataBytes.toString('utf8'));validateMetadata(metadata);
 if(metadata.httpStatus<200||metadata.httpStatus>299){
  if(metadata.responseBodyAvailable!==false||metadata.rawFile!==null||metadata.rawSha256!==null||metadata.rawBytes!==0)throw Error('CAPTURE_ERROR_BODY_CONTRACT');
  return {metadata,metadataSha256,data:null,captureSource:metadata.source,requestPath:metadata.path,scope:metadata.scope,errorDiagnostic:metadata.errorDiagnostic??null,replayVerified:false,status:'METADATA_ONLY',responseBodyAvailable:false,integrityScope:metadata.integrityScope};
 }
 if(metadata.responseBodyAvailable!==true||metadata.rawFile!=='response.body'||!Number.isSafeInteger(metadata.rawBytes)||metadata.rawBytes<0||metadata.rawBytes>MAX_BYTES||typeof metadata.rawSha256!=='string'||!/^[a-f0-9]{64}$/.test(metadata.rawSha256))throw Error('CAPTURE_BODY_CONTRACT');
 const rawPath=join(root,'response.body');if((await stat(rawPath)).size>MAX_BYTES)throw Error('CAPTURE_BODY_TOO_LARGE');
 const bytes=await readFile(rawPath);if(bytes.length!==metadata.rawBytes||sha(bytes)!==metadata.rawSha256)throw Error('CAPTURE_BODY_HASH_MISMATCH');
 // Deferred import avoids moving the production parser or introducing a second interpretation of numeric tokens.
 const {parseAlpacaJson}=await import('./alpaca-transport.mjs');
 const data=metadata.httpStatus===204?(bytes.length===0?null:(()=>{throw Error('CAPTURE_204_BODY_NOT_EMPTY');})()):parseAlpacaJson(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes));
 return {metadata,metadataSha256,data,captureSource:metadata.source,requestPath:metadata.path,scope:metadata.scope,rawSha256:metadata.rawSha256,replayVerified:true,status:'REPLAYED',responseBodyAvailable:true,integrityScope:metadata.integrityScope};
}
