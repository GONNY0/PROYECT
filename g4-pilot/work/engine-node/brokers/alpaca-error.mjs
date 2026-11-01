import {createHash} from 'node:crypto';

export const ALPACA_MAX_ERROR_BYTES=16*1024;
export const ALPACA_ERROR_DOCUMENTATION='https://alpaca.markets/learn/how-to-fix-common-trading-api-errors-at-alpaca';
const STATUSES=new Set(['PARSED','INVALID_JSON','INVALID_UTF8','OVERSIZED','READ_FAILED','SECRET_ECHO','EMPTY']);
const CAUSES=new Set(['UNKNOWN','INSUFFICIENT_BUYING_POWER','INSUFFICIENT_QUANTITY','AUTHENTICATION_REJECTED','PERMISSION_DENIED']);
const KEYS=['schemaVersion','bodyStatus','httpStatus','rawSha256','observedBytes','hashScope','providerCode','cause','requestId'];
const REQUEST_ID=/^(?:[a-f0-9]{32}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/i;
const CODE=/^[1-9]\d{2,8}$/;
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');

/** No provider message is returned. Patterns select a closed label; HTTP/code alone never select a cause. */
function causeFor(message){
 if(typeof message!=='string'||message.length>2048)return 'UNKNOWN';
 const text=message.trim().toLowerCase();
 if(/^insufficient (?:non-marginable )?buying power(?:$|[ (:])/.test(text))return 'INSUFFICIENT_BUYING_POWER';
 if(/^insufficient qty available for order(?:$|[ (:])/.test(text))return 'INSUFFICIENT_QUANTITY';
 if(text==='unauthorized')return 'AUTHENTICATION_REJECTED';
 if(/^insufficient permissions?$/.test(text))return 'PERMISSION_DENIED';
 return 'UNKNOWN';
}
function validCredentials(credentials){return credentials.filter(value=>typeof value==='string'&&value.length>0);}
function literalEcho(value,credentials){return credentials.some(secret=>value.includes(secret));}

/** Conservatively scan raw and JSON-escaped text, even when a body is truncated or has duplicate keys. */
export function hasAlpacaSecretEcho(bytes,credentials=[]){
 const values=validCredentials(credentials);if(!values.length)return false;
 const raw=Buffer.from(bytes);if(values.some(secret=>raw.includes(Buffer.from(secret))))return true;
 // This single-pass escape projection is only a taint check, never a JSON interpretation.
 // It also catches an escaped secret before an unterminated quote; escaped backslashes are not decoded twice.
 const escapes={'"':'"','\\':'\\','/':'/','b':'\b','f':'\f','n':'\n','r':'\r','t':'\t'};
 const projected=raw.toString('utf8').replace(/\\(?:u([0-9a-fA-F]{4})|(["\\/bfnrt]))/g,(_match,unicode,short)=>unicode?String.fromCharCode(parseInt(unicode,16)):escapes[short]);
 return literalEcho(projected,values);
}

/** Strict metadata boundary: callers cannot smuggle message/body/extra text into persisted diagnostics. */
export function validateAlpacaErrorDiagnostic(value,httpStatus){
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).length!==KEYS.length||Object.keys(value).some(key=>!KEYS.includes(key))
  ||value.schemaVersion!=='g4.alpaca-error-diagnostic.v1'||!STATUSES.has(value.bodyStatus)||value.httpStatus!==httpStatus
  ||!Number.isInteger(httpStatus)||httpStatus<400||httpStatus>599||!Number.isSafeInteger(value.observedBytes)||value.observedBytes<0||value.observedBytes>ALPACA_MAX_ERROR_BYTES
  ||!['COMPLETE_BODY','OBSERVED_PREFIX','NONE'].includes(value.hashScope)||!CAUSES.has(value.cause)
  ||(value.providerCode!==null&&(typeof value.providerCode!=='string'||!CODE.test(value.providerCode)))
  ||(value.requestId!==null&&(typeof value.requestId!=='string'||!REQUEST_ID.test(value.requestId)))
  ||(value.rawSha256!==null&&(typeof value.rawSha256!=='string'||!/^[a-f0-9]{64}$/.test(value.rawSha256))))throw Error('INVALID_ALPACA_ERROR_DIAGNOSTIC');
 if(value.hashScope==='NONE'?(value.rawSha256!==null||value.observedBytes!==0):value.rawSha256===null)throw Error('INVALID_ALPACA_ERROR_HASH_SCOPE');
 if(value.bodyStatus==='OVERSIZED'&&(value.hashScope!=='OBSERVED_PREFIX'||value.observedBytes!==ALPACA_MAX_ERROR_BYTES))throw Error('INVALID_ALPACA_ERROR_HASH_SCOPE');
 if(value.bodyStatus==='READ_FAILED'&&value.hashScope==='COMPLETE_BODY')throw Error('INVALID_ALPACA_ERROR_HASH_SCOPE');
 if(['PARSED','INVALID_JSON','INVALID_UTF8','EMPTY','SECRET_ECHO'].includes(value.bodyStatus)&&value.hashScope!=='COMPLETE_BODY')throw Error('INVALID_ALPACA_ERROR_HASH_SCOPE');
 if(value.bodyStatus==='EMPTY'&&(value.observedBytes!==0||value.rawSha256!==digest(Buffer.alloc(0))))throw Error('INVALID_ALPACA_ERROR_HASH_SCOPE');
 if(['PARSED','INVALID_JSON','INVALID_UTF8'].includes(value.bodyStatus)&&value.observedBytes===0)throw Error('INVALID_ALPACA_ERROR_HASH_SCOPE');
 if(value.bodyStatus!=='PARSED'&&(value.providerCode!==null||value.cause!=='UNKNOWN'))throw Error('INVALID_ALPACA_ERROR_DERIVATION');
 if(value.bodyStatus==='SECRET_ECHO'&&value.requestId!==null)throw Error('INVALID_ALPACA_ERROR_DERIVATION');
 return Object.fromEntries(KEYS.map(key=>[key,value[key]]));
}

/** Reads at most a small error prefix in memory. It never returns raw bytes, message, or arbitrary fields. */
export async function readAlpacaErrorDiagnostic(response,{credentials=[],timeoutMs=2000}={}){
 if(!Number.isSafeInteger(timeoutMs)||timeoutMs<1||timeoutMs>10000)throw Error('INVALID_ALPACA_ERROR_TIMEOUT');
 const httpStatus=response.status,values=validCredentials(credentials),chunks=[];let size=0,bodyStatus='READ_FAILED',reader;
 const header=response.headers?.get?.('x-request-id'),requestHeader=typeof header==='string'&&REQUEST_ID.test(header)?header.toLowerCase():null;
 const headerEcho=(typeof header==='string'&&literalEcho(header,values))||(requestHeader!==null&&literalEcho(requestHeader,values));
 const deadline=Date.now()+timeoutMs;
 try{
  if(response.body===null)bodyStatus='COMPLETE';
  else{
   if(!response.body?.getReader)throw Error('ERROR_BODY_STREAM_REQUIRED');reader=response.body.getReader();
   for(;;){
   let timer;
   try{
    const remaining=deadline-Date.now();if(remaining<=0)throw Error('ERROR_BODY_TIMEOUT');
    const pending=reader.read(),timeout=new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('ERROR_BODY_TIMEOUT')),remaining);});
    const {done,value}=await Promise.race([pending,timeout]);
    if(done){bodyStatus='COMPLETE';break;}
    if(!(value instanceof Uint8Array))throw Error('INVALID_ERROR_BODY_CHUNK');
    const take=Math.min(value.byteLength,ALPACA_MAX_ERROR_BYTES-size);if(take){chunks.push(Buffer.from(value.subarray(0,take)));size+=take;}
    if(take<value.byteLength){bodyStatus='OVERSIZED';break;}
   }finally{if(timer!==undefined)clearTimeout(timer);}
   }
  }
 }catch{bodyStatus='READ_FAILED';}
 finally{
  if(reader){if(bodyStatus!=='COMPLETE'){try{void reader.cancel().catch(()=>{});}catch{}}
   try{reader.releaseLock();}catch{}}
 }
 const bytes=Buffer.concat(chunks,size),complete=bodyStatus==='COMPLETE';
 const result={schemaVersion:'g4.alpaca-error-diagnostic.v1',bodyStatus:complete?(size?'INVALID_JSON':'EMPTY'):bodyStatus,httpStatus,
  rawSha256:complete||size?digest(bytes):null,observedBytes:size,hashScope:complete?'COMPLETE_BODY':size?'OBSERVED_PREFIX':'NONE',providerCode:null,cause:'UNKNOWN',requestId:headerEcho?null:requestHeader};
 // Incomplete bodies never yield provider fields, including a superficially valid JSON prefix.
 if(!complete)return validateAlpacaErrorDiagnostic(result,httpStatus);
 if(headerEcho||hasAlpacaSecretEcho(bytes,values)){result.bodyStatus='SECRET_ECHO';result.requestId=null;return validateAlpacaErrorDiagnostic(result,httpStatus);}
 if(!size)return validateAlpacaErrorDiagnostic(result,httpStatus);
 let text;try{text=new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(bytes);}catch{result.bodyStatus='INVALID_UTF8';return validateAlpacaErrorDiagnostic(result,httpStatus);}
 let parsed,echo=false;
 try{parsed=JSON.parse(text,(key,value,context)=>{
  if(literalEcho(key,values)||(typeof value==='string'&&literalEcho(value,values)))echo=true;
  return key==='code'&&typeof value==='number'?context.source:value;
 });}catch{return validateAlpacaErrorDiagnostic(result,httpStatus);}
 if(echo){result.bodyStatus='SECRET_ECHO';result.requestId=null;return validateAlpacaErrorDiagnostic(result,httpStatus);}
 if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))return validateAlpacaErrorDiagnostic(result,httpStatus);
 result.bodyStatus='PARSED';result.providerCode=typeof parsed.code==='string'&&CODE.test(parsed.code)?parsed.code:null;result.cause=causeFor(parsed.message);
 return validateAlpacaErrorDiagnostic(result,httpStatus);
}
