/** Independent, offline quality gate layered over the frozen public bundle replay.
 * Freshness is measured at receipt, never at a later decision or review time.
 */
import {createHash} from 'node:crypto';
import {replayPublicBundle} from './public-capture-bundle.mjs';

const DAY=86400000,NS_PER_MS=1000000n,SHA=/^[a-f0-9]{64}$/;
const PLAN='fdf372b84e545255a933c09dbf97ca72f9f6f2dff2970dc12b9c8b8b7a4d4c15';
const FIRST=1792541400000;
const require=(ok,reason)=>{if(!ok)throw Error('PUBLIC_QUALITY_'+reason);};
const integer=x=>Number.isSafeInteger(x)&&x>=0;
const sha=x=>createHash('sha256').update(x).digest('hex');
function keys(value,expected){
 require(value&&typeof value==='object'&&!Array.isArray(value),'OBJECT');
 require(Object.keys(value).sort().join(',')===expected.slice().sort().join(','),'FIELDS');
}

/** The expected SHA256 binds the exact UTF-8 bytes, including whitespace/newlines.
 * This revision deliberately cannot weaken its declared limits through configuration.
 */
export function validatePublicCaptureQualityPolicy({policyBytes,expectedPolicySha256}){
 require(policyBytes instanceof Uint8Array&&policyBytes.byteLength>0&&policyBytes.byteLength<=8192,'POLICY_BYTES');
 const bytes=Buffer.from(policyBytes);
 require(SHA.test(expectedPolicySha256??'')&&sha(bytes)===expectedPolicySha256,'POLICY_HASH');
 const policy=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
 keys(policy,['schemaVersion','id','registeredAtMs','planSha256','firstWindowOpenMs','scope','quote','history']);
 require(policy.schemaVersion==='g4.public-capture-quality-policy.v1'
  &&policy.id==='g4-public-capture-quality-20261020-v1'
  &&policy.planSha256===PLAN&&policy.firstWindowOpenMs===FIRST,'POLICY_BINDING');
 require(integer(policy.registeredAtMs)&&policy.registeredAtMs>=1792454400000
  &&policy.registeredAtMs<policy.firstWindowOpenMs,'POLICY_REGISTRATION');
 require(policy.scope==='AT_CAPTURE_ONLY_NOT_TRADE_AUTHORIZATION','POLICY_SCOPE');
 keys(policy.quote,['provider','source','symbol','currency','maxAgeAtReceiptMs','futureToleranceNs','comparison']);
 require(policy.quote.provider==='ALPACA'&&policy.quote.source==='ALPACA_CRYPTO_US'
  &&policy.quote.symbol==='BTC/USD'&&policy.quote.currency==='USD'
  &&policy.quote.maxAgeAtReceiptMs===10000&&policy.quote.futureToleranceNs==='0'
  &&policy.quote.comparison==='RECEIPT_MILLISECOND_INTERVAL_UPPER_BOUND','QUOTE_POLICY');
 keys(policy.history,['provider','symbol','intervalMs','mostRecentClosedDayRequired','contiguousBarsRequired','openBarExcluded']);
 require(policy.history.provider==='KRAKEN'&&policy.history.symbol==='BTC-USD'
  &&policy.history.intervalMs===DAY&&policy.history.mostRecentClosedDayRequired===true
  &&policy.history.contiguousBarsRequired===true&&policy.history.openBarExcluded===true,'HISTORY_POLICY');
 Object.freeze(policy.quote);Object.freeze(policy.history);return Object.freeze(policy);
}

/** Pure arithmetic only: no upstream replay/integrity or native acceptance claimed.
 * history.lastClosedBarMs in the frozen replay is the OPEN of the last closed bar.
 */
export function measurePublicCaptureQuality({history,quote,policy}){
 require(policy?.quote?.maxAgeAtReceiptMs===10000&&policy?.history?.intervalMs===DAY,'MEASUREMENT_POLICY');
 require(history&&integer(history.asOfMs)&&integer(history.lastClosedBarMs)
  &&history.lastClosedBarMs%DAY===0&&history.asOfMs>=DAY
  &&Number.isSafeInteger(history.bars)&&history.bars>=1&&history.bars<=720,'HISTORY_MEASUREMENT');
 require(quote&&integer(quote.receivedAtMs)&&quote.quote,'QUOTE_MEASUREMENT');
 const q=quote.quote;
 require(q.symbol==='BTC/USD'&&q.currency==='USD'&&q.baseCurrency==='BTC'&&q.source==='ALPACA_CRYPTO_US','QUOTE_SOURCE');
 require(integer(q.timestampMs)&&typeof q.timestampNs==='string'&&/^(0|[1-9][0-9]{0,29})$/.test(q.timestampNs)
  &&BigInt(q.timestampNs)/NS_PER_MS===BigInt(q.timestampMs),'QUOTE_TIMESTAMP_PRECISION');
 require(quote.receivedAtMs>=history.asOfMs,'QUOTE_RECEIVED_BEFORE_CAPTURE');
 const reasons=[],lastClosedBarOpenMs=history.lastClosedBarMs,lastClosedBarCloseMs=lastClosedBarOpenMs+DAY;
 require(Number.isSafeInteger(lastClosedBarCloseMs),'HISTORY_TIMESTAMP_OVERFLOW');
 const expectedLastClosedBarCloseMs=Math.floor(history.asOfMs/DAY)*DAY;
 if(lastClosedBarCloseMs<expectedLastClosedBarCloseMs)reasons.push('LATEST_CLOSED_UTC_DAY_MISSING');
 if(lastClosedBarCloseMs>expectedLastClosedBarCloseMs)reasons.push('FUTURE_OR_UNCLOSED_DAILY_BAR');
 // Date.now() quantizes receipt time to a millisecond. The unrounded receipt
 // instant lies in [receivedAtMs, receivedAtMs + 1 ms), so its age is an
 // interval rather than the exact difference from the interval's lower bound.
 const ageAtReceiptLowerBoundNs=BigInt(quote.receivedAtMs)*NS_PER_MS-BigInt(q.timestampNs);
 const ageAtReceiptUpperBoundExclusiveNs=(BigInt(quote.receivedAtMs)+1n)*NS_PER_MS-BigInt(q.timestampNs);
 const ageLimitNs=BigInt(policy.quote.maxAgeAtReceiptMs)*NS_PER_MS;
 if(ageAtReceiptLowerBoundNs<0n)reasons.push('QUOTE_FUTURE_AT_RECEIPT');
 if(ageAtReceiptUpperBoundExclusiveNs>ageLimitNs)reasons.push('QUOTE_STALE_AT_RECEIPT');
 return {schemaVersion:'g4.public-capture-quality-measurement.v1',qualityCriteriaPassed:reasons.length===0,reasons,
  history:{bars:history.bars,captureStartedAtMs:history.asOfMs,lastClosedBarOpenMs,lastClosedBarCloseMs,
   expectedLastClosedBarCloseMs,expectedLastClosedBarOpenMs:expectedLastClosedBarCloseMs-DAY,
   lagClosedDays:(expectedLastClosedBarCloseMs-lastClosedBarCloseMs)/DAY,
   closeToCaptureMs:history.asOfMs-lastClosedBarCloseMs,
   latestClosedDayPresent:lastClosedBarCloseMs===expectedLastClosedBarCloseMs},
  quote:{timestampMs:q.timestampMs,timestampNs:q.timestampNs,receivedAtMs:quote.receivedAtMs,
   ageAtReceiptMs:quote.receivedAtMs-q.timestampMs,
   ageAtReceiptLowerBoundNs:String(ageAtReceiptLowerBoundNs),
   ageAtReceiptUpperBoundExclusiveNs:String(ageAtReceiptUpperBoundExclusiveNs),
   ageAtReceiptMsSemantics:'DIFFERENCE_OF_MILLISECOND_TIMESTAMPS_NOT_EXACT_SUBMILLISECOND_AGE',
   maxAgeAtReceiptMs:policy.quote.maxAgeAtReceiptMs,
   freshAtReceipt:ageAtReceiptLowerBoundNs>=0n&&ageAtReceiptUpperBoundExclusiveNs<=ageLimitNs,
   comparison:policy.quote.comparison},
  dataQualityAccepted:false,structuralReplayVerified:false,usableAtDecisionTime:false,financialAcceptance:false};
}

export async function evaluatePublicCaptureQuality(options={}){
 keys(options,['directory','expectedManifestSha256','policyBytes','expectedPolicySha256']);
 const {directory,expectedManifestSha256,policyBytes,expectedPolicySha256}=options;
 const policy=validatePublicCaptureQualityPolicy({policyBytes,expectedPolicySha256});
 // The frozen verifier binds all raw bytes and re-runs both normalizers. It also
 // verifies all daily bars are contiguous, closed and in BTC/USD exact units.
 const replay=await replayPublicBundle({directory,expectedManifestSha256});
 require(replay.verified===true&&replay.providerRequestsMade===false
  &&replay.verification.sourceChecks.externalNetworkCallsDuringReplay===0,'REPLAY_REQUIRED');
 const measurement=measurePublicCaptureQuality({...replay.verification,policy});
 const nativeCapture=replay.nativeCapture===true&&replay.status==='VERIFIED_NATIVE_PUBLIC_CAPTURE';
 const policyRegisteredBeforeCapture=policy.registeredAtMs<=measurement.history.captureStartedAtMs;
 const dataQualityAccepted=nativeCapture&&policyRegisteredBeforeCapture&&measurement.qualityCriteriaPassed;
 return {...measurement,schemaVersion:'g4.public-capture-quality-result.v1',
  status:dataQualityAccepted?'VERIFIED_NATIVE_DATA_QUALITY_AT_CAPTURE'
   :!measurement.qualityCriteriaPassed?'DATA_QUALITY_REJECTED'
   :!nativeCapture?'FIXTURE_QUALITY_DIAGNOSTIC':'RETROSPECTIVE_QUALITY_DIAGNOSTIC',
  verified:true,nativeCapture,dataQualityAccepted,structuralReplayVerified:true,policyRegisteredBeforeCapture,
  policySha256:expectedPolicySha256,policyId:policy.id,policyRegisteredAtMs:policy.registeredAtMs,
  planSha256:policy.planSha256,manifestSha256:expectedManifestSha256,
  sources:{history:'KRAKEN_BTC_USD_DAILY',quote:'ALPACA_CRYPTO_US_BTC_USD'},
  units:{quotePrices:'USD_1E18',quoteQuantities:'BTC_1E18',historyPrices:'USD_1E6',historyVolumes:'BTC_1E8'},
  providerRequestsMade:false,sqliteOpened:false,forwardObservation:false,providerAttestation:false,
  limitations:['Quality at capture is not freshness at a later review or decision.',
   'Receipt clocks are millisecond-resolution host clocks, not independently attested UTC.',
   'Quote age is a half-open interval: its lower bound must be nonnegative and its exclusive upper bound at most 10 seconds.',
   'Different Kraken and Alpaca venues; prices are not asserted to be execution-equivalent.',
   'A prospective policy cannot retroactively accept a capture taken before registration.',
   'No trading authorization, risk acceptance, financial outcome or schedule coverage is inferred.']};
}
