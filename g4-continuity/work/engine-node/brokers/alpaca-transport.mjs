import { createHash } from 'node:crypto';
import {captureAlpacaResponse} from './alpaca-capture.mjs';
import {readAlpacaErrorDiagnostic} from './alpaca-error.mjs';

export const ALPACA_MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
const HOSTS = Object.freeze({ PAPER: 'https://paper-api.alpaca.markets', DATA: 'https://data.alpaca.markets' });
const digest = bytes => createHash('sha256').update(bytes).digest('hex');

function expandNumericToken(token) {
  if (!/[eE]/.test(token)) return token;
  const match = /^(-?)(\d+)(?:\.(\d+))?[eE]([+-]?\d+)$/.exec(token);
  if (!match || token.length > 256 || match[4].length > 4) throw new Error('UNSUPPORTED_NUMERIC_TOKEN');
  const exponent = Number(match[4]); // A bounded small integer exponent, never a financial value.
  if (Math.abs(exponent) > 128) throw new Error('UNSUPPORTED_NUMERIC_TOKEN');
  const digits = match[2] + (match[3] ?? ''), point = match[2].length + exponent;
  const decimal = point <= 0 ? `0.${'0'.repeat(-point)}${digits}`
    : point >= digits.length ? digits + '0'.repeat(point - digits.length) : `${digits.slice(0, point)}.${digits.slice(point)}`;
  return match[1] + decimal;
}

/** Preserve JSON numeric tokens before Number rounding. Node 24 supplies the source context. */
export function parseAlpacaJson(raw) {
  return JSON.parse(raw, (_key, value, context) => {
    if (typeof value !== 'number') return value;
    if (typeof context?.source !== 'string') throw new Error('LOSSLESS_JSON_CONTEXT_REQUIRED');
    return expandNumericToken(context.source);
  });
}

async function boundedBody(response) {
  if (!response.body?.getReader) throw new Error('STREAMING_RESPONSE_REQUIRED');
  const reader = response.body.getReader(), chunks = []; let size = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read(); if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error('INVALID_RESPONSE_CHUNK');
      size += value.byteLength;
      if (size > ALPACA_MAX_RESPONSE_BYTES) { await reader.cancel().catch(() => {}); throw new Error('RESPONSE_TOO_LARGE'); }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  const raw = Buffer.concat(chunks, size);
  return { raw, rawSha256: digest(raw), rawBytes: size };
}

/** Only the two fixed Alpaca scopes exist. Caller adapters expose no host or method override. */
export class AlpacaTransport {
  #key; #secret; #fetch; #scope; #host; #evidenceDirectory;
  constructor(scope, { key, secret, fetchImpl, evidenceDirectory } = {}) {
    if (!Object.hasOwn(HOSTS, scope)) throw new Error('INVALID_ALPACA_SCOPE');
    this.#scope = scope; this.#host = HOSTS[scope];
    if(evidenceDirectory!==undefined&&(typeof evidenceDirectory!=='string'||!evidenceDirectory.trim()||evidenceDirectory.includes('\0')))throw Error('INVALID_EVIDENCE_DIRECTORY');
    this.#evidenceDirectory=evidenceDirectory;
    // Crypto US market data is public. DATA neither reads environment keys nor sends API credentials.
    this.#key = scope === 'PAPER' ? key ?? process.env.APCA_API_KEY_ID : undefined;
    this.#secret = scope === 'PAPER' ? secret ?? process.env.APCA_API_SECRET_KEY : undefined;
    this.#fetch = fetchImpl ?? globalThis.fetch;
    if (typeof this.#fetch !== 'function') throw new Error('FETCH_REQUIRED');
    for (const credential of [this.#key, this.#secret]) if (credential !== undefined
      && (typeof credential !== 'string' || /[\r\n]/.test(credential))) throw new Error('INVALID_CREDENTIAL_FORMAT');
  }
  get host() { return this.#host; }
  get source() { return this.#scope === 'PAPER' && (!this.#key?.trim() || !this.#secret?.trim()) ? 'LOCAL_CONFIGURATION'
    : this.#fetch === globalThis.fetch ? (this.#scope === 'PAPER' ? 'ALPACA_PAPER_API' : 'ALPACA_CRYPTO_DATA_API') : 'INJECTED_TRANSPORT'; }
  redact(value) {
    if (typeof value !== 'string') return value;
    let safe = value;
    for (const credential of [this.#key, this.#secret]) if (credential) safe = safe.split(credential).join('[REDACTED]');
    return safe;
  }
  async request(path, { method = 'GET', body } = {}) {
    if (this.#scope === 'PAPER' && (!this.#key?.trim() || !this.#secret?.trim())) return { ok: false, status: 'BLOCKED_CREDENTIALS' };
    if ((this.#scope === 'DATA' && (method !== 'GET' || path !== '/v1beta3/crypto/us/latest/quotes?symbols=BTC%2FUSD'))
      || (this.#scope === 'PAPER' && (!path.startsWith('/v2/') || !['GET', 'POST', 'DELETE'].includes(method)))
      || path.includes('://')) return { ok: false, status: 'BLOCKED_ENDPOINT' };
    const url = new URL(path, this.#host);
    if (url.origin !== this.#host) return { ok: false, status: 'BLOCKED_ENDPOINT' };
    const requestedAtMs = Date.now(); let response;
    try {
      response = await this.#fetch(url.href, { method, redirect: 'manual', signal: AbortSignal.timeout(10000),
        headers: { ...(this.#scope === 'PAPER' ? { 'APCA-API-KEY-ID': this.#key, 'APCA-API-SECRET-KEY': this.#secret } : {}), accept: 'application/json',
          ...(body ? { 'content-type': 'application/json' } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}) });
    } catch { return { ok: false, status: 'UNAVAILABLE', reason: 'TRANSPORT_FAILURE', requestedAtMs, receivedAtMs: Date.now() }; }
    const httpStatus = response?.status;
    if (!Number.isInteger(httpStatus) || httpStatus < 100 || httpStatus > 599) return { ok: false, status: 'INVALID_RESPONSE' };
    if(httpStatus<200){await response.body?.cancel?.().catch(()=>{});return {ok:false,status:'INVALID_RESPONSE',httpStatus,requestedAtMs,receivedAtMs:Date.now()};}
    let unexpectedOrigin;
    try { unexpectedOrigin = Boolean(response.url && new URL(response.url).origin !== this.#host); }
    catch { return { ok: false, status: 'INVALID_RESPONSE', httpStatus }; }
    if (response.redirected || (httpStatus >= 300 && httpStatus < 400) || unexpectedOrigin) {
      await response.body?.cancel?.().catch(() => {});
      const receivedAtMs=Date.now(),evidenceCapture=await this.#capture({method,path,httpStatus,requestedAtMs,receivedAtMs});
      return { ok: false, status: 'BLOCKED_REDIRECT', httpStatus,requestedAtMs,receivedAtMs,evidenceCapture };
    }
    if (httpStatus < 200 || httpStatus > 299) {
      const errorDiagnostic=await readAlpacaErrorDiagnostic(response,{credentials:[this.#key,this.#secret]});
      const receivedAtMs=Date.now(),evidenceCapture=await this.#capture({method,path,httpStatus,requestedAtMs,receivedAtMs,errorDiagnostic});
      if(['CAPTURE_FAILED','BLOCKED_SECRET_ECHO'].includes(evidenceCapture.status))return {ok:false,status:evidenceCapture.status,httpStatus,requestedAtMs,receivedAtMs,evidenceCapture,errorDiagnostic};
      const incomplete=['OVERSIZED','READ_FAILED'].includes(errorDiagnostic.bodyStatus);
      return { ok: false, status: incomplete?'UNKNOWN':httpStatus === 404 ? 'NOT_FOUND' : [401, 403].includes(httpStatus)
        ? 'BLOCKED_AUTH_OR_PERMISSION' : httpStatus === 429 ? 'RATE_LIMITED' : httpStatus >= 500 ? 'UNAVAILABLE' : 'REJECTED', httpStatus,requestedAtMs,receivedAtMs,evidenceCapture,errorDiagnostic };
    }
    const headers = {};
    for (const name of ['date', 'age', 'cache-control', 'last-modified', 'etag', 'x-ratelimit-remaining', 'x-ratelimit-reset']) {
      const value = response.headers?.get?.(name); if (typeof value === 'string') headers[name] = this.redact(value.slice(0, 4096));
    }
    let parsed;
    try {
      parsed=httpStatus===204?{raw:Buffer.alloc(0),rawSha256:digest(Buffer.alloc(0)),rawBytes:0}:await boundedBody(response);
    } catch { return { ok: false, status: 'INVALID_RESPONSE', reason: 'INVALID_OR_OVERSIZED_JSON', httpStatus,requestedAtMs,receivedAtMs:Date.now() }; }
    const receivedAtMs=Date.now(),evidenceCapture=await this.#capture({method,path,httpStatus,requestedAtMs,receivedAtMs,raw:parsed.raw});
    const metadata={rawSha256:parsed.rawSha256,rawBytes:parsed.rawBytes,httpStatus,requestedAtMs,receivedAtMs,headers,evidenceCapture};
    if(['CAPTURE_FAILED','BLOCKED_SECRET_ECHO'].includes(evidenceCapture.status))return {ok:false,status:evidenceCapture.status,...metadata};
    try{return {ok:true,data:httpStatus===204?null:parseAlpacaJson(new TextDecoder('utf-8',{fatal:true,ignoreBOM:true}).decode(parsed.raw)),...metadata};}
    catch{return {ok:false,status:'INVALID_RESPONSE',reason:'INVALID_JSON',...metadata};}
  }
  async #capture({method,path,httpStatus,requestedAtMs,receivedAtMs,raw=null,errorDiagnostic}){
    if(this.#evidenceDirectory===undefined)return {status:'NOT_REQUESTED'};
    return captureAlpacaResponse({directory:this.#evidenceDirectory,scope:this.#scope,method,path,httpStatus,requestedAtMs,receivedAtMs,source:this.source,raw,credentials:[this.#key,this.#secret],errorDiagnostic});
  }
}
