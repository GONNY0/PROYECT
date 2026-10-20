import { createHash, randomUUID } from 'node:crypto';
import { mkdir, readFile, open, link, unlink } from 'node:fs/promises';
import path from 'node:path';

export const DAY_MS = 86_400_000;
export const OHLC_URL = 'https://api.kraken.com/0/public/OHLC?pair=XBTEUR&interval=1440';
export const PAIRS_URL = 'https://api.kraken.com/0/public/AssetPairs?pair=XBTEUR';
export function endpointsForSymbol(symbol = 'BTC-EUR') {
  if (!['BTC-EUR', 'BTC-USD'].includes(symbol)) throw new Error('Unsupported historical symbol');
  const quote = symbol.slice(4), pair = `XBT${quote}`;
  return { ohlcUrl: `https://api.kraken.com/0/public/OHLC?pair=${pair}&interval=1440`,
    pairsUrl: `https://api.kraken.com/0/public/AssetPairs?pair=${pair}`, pair, quote,
    pairKey: `XXBTZ${quote}`, providerQuote: `Z${quote}` };
}
export const SOURCE_DOCUMENTATION = [
  'https://docs.kraken.com/api-reference/market-data/get-ohlc-data',
  'https://docs.kraken.com/api-reference/market-data/get-tradable-asset-pairs',
];
export const sha256 = value => createHash('sha256').update(value).digest('hex');
const jsonText = value => `${JSON.stringify(value, null, 2)}\n`;
const unsigned = /^(0|[1-9][0-9]*)$/;
const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;

async function publishDurably(file, value) {
  // A private temporary file is fsync'ed before atomic hard-link publication.
  // link() fails if the destination exists, so a previous receipt is never replaced.
  const temporary = path.join(path.dirname(file), `.pending-${path.basename(file)}-${randomUUID()}`);
  let handle;
  try {
    handle = await open(temporary, 'wx');
    await handle.writeFile(value); await handle.sync(); await handle.close(); handle = null;
    await link(temporary, file);
  } finally {
    if (handle) await handle.close();
    await unlink(temporary).catch(error => { if (error.code !== 'ENOENT') throw error; });
  }
  // Directory fsync is not exposed consistently on Windows/NTFS. File fsync and
  // atomic namespace publication are implemented; power-loss certification is not.
  let directoryHandle;
  try { directoryHandle = await open(path.dirname(file), 'r'); await directoryHandle.sync(); }
  catch (error) { if (!['EISDIR', 'EPERM', 'EACCES', 'EINVAL', 'ENOTSUP'].includes(error.code)) throw error; }
  finally { if (directoryHandle) await directoryHandle.close(); }
}

async function boundedResponseText(response) {
  if (!response.body?.getReader) throw new Error('Streaming response body required');
  const reader = response.body.getReader(), chunks = []; let length = 0;
  try {
    for (;;) {
      const { value, done } = await reader.read(); if (done) break;
      length += value.byteLength;
      if (length > MAX_RESPONSE_BYTES) { await reader.cancel(); throw new Error('Kraken response exceeds 2 MiB limit'); }
      chunks.push(Buffer.from(value));
    }
  } finally { reader.releaseLock(); }
  return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(Buffer.concat(chunks, length));
}

/** Exact conversion: prices use quote-currency micros, BTC quantities use atoms.
 * Excess nonzero precision fails closed instead of rounding market data. */
export function decimalToUnits(value, decimals) {
  if (typeof value !== 'string' || !/^[0-9]+(?:\.[0-9]+)?$/.test(value)) throw new Error('Invalid exact decimal');
  const [whole, fraction = ''] = value.split('.');
  if (fraction.slice(decimals).replace(/0/g, '').length) throw new Error('Unsupported decimal precision');
  return (BigInt(whole) * (10n ** BigInt(decimals)) + BigInt((fraction.slice(0, decimals).padEnd(decimals, '0')) || '0')).toString();
}

function apiResult(text) {
  const response = JSON.parse(text);
  if (!response || !Array.isArray(response.error) || response.error.length || !response.result || typeof response.result !== 'object') throw new Error(`Kraken API error: ${JSON.stringify(response?.error)}`);
  return response.result;
}

function normalizeMetadata(raw, symbol) {
  const instrument = endpointsForSymbol(symbol);
  const result = apiResult(raw);
  const keys = Object.keys(result);
  if (keys.length !== 1) throw new Error('Expected exactly one Kraken asset pair');
  const pair = result[keys[0]];
  if (keys[0] !== instrument.pairKey || pair.altname !== instrument.pair || pair.base !== 'XXBT' || pair.quote !== instrument.providerQuote) throw new Error('Unexpected Kraken instrument');
  for (const key of ['pair_decimals', 'lot_decimals', 'cost_decimals']) if (!Number.isInteger(pair[key]) || pair[key] < 0) throw new Error(`Invalid metadata ${key}`);
  if (pair.pair_decimals > 6 || pair.lot_decimals > 8 || pair.cost_decimals > 6) throw new Error('Instrument precision unsupported');
  return {
    pairKey: keys[0], altname: pair.altname, base: 'BTC', quote: instrument.quote,
    priceDecimals: pair.pair_decimals, quantityDecimals: pair.lot_decimals, costDecimals: pair.cost_decimals,
    priceScale: '1000000', quantityScale: '100000000',
    quantityStepAtoms: (10n ** BigInt(8 - pair.lot_decimals)).toString(),
    tickMicros: decimalToUnits(pair.tick_size, 6),
    orderMinAtoms: decimalToUnits(pair.ordermin, 8),
    costMinMicros: decimalToUnits(pair.costmin, 6),
    statusAtCapture: pair.status ?? 'unknown',
    historicalApplicability: 'CURRENT_METADATA_ONLY_NOT_HISTORICAL_RULES',
  };
}

export function normalizeHistory(ohlcRaw, metadataRaw, asOfMs, provenanceKind = 'UNVERIFIED_TRANSPORT', symbol = 'BTC-EUR') {
  if (!Number.isSafeInteger(asOfMs) || asOfMs < 0) throw new Error('Invalid asOfMs');
  const metadata = normalizeMetadata(metadataRaw, symbol);
  const result = apiResult(ohlcRaw);
  const keys = Object.keys(result).filter(key => key !== 'last');
  if (keys.length !== 1 || keys[0] !== metadata.pairKey) throw new Error('Unexpected OHLC pair');
  const rows = result[keys[0]];
  // Kraken's docs describe up to 720 entries; the public endpoint was observed
  // returning 720 closed candles plus its mandatory uncommitted row on 2026-10-15.
  // Bound that verified service behavior explicitly; larger payloads fail closed.
  if (!Array.isArray(rows) || rows.length < 2 || rows.length > 721) throw new Error('Invalid Kraken OHLC count');
  // Official API contract: the final row is always the uncommitted current candle.
  // It is never admitted, even if a client clock would appear to call it closed.
  const bars = rows.slice(0, -1).map(row => {
    if (!Array.isArray(row) || row.length !== 8 || !Number.isSafeInteger(row[0])) throw new Error('Invalid Kraken OHLC row');
    return {
      timeMs: row[0] * 1000,
      openMicros: decimalToUnits(row[1], 6), highMicros: decimalToUnits(row[2], 6),
      lowMicros: decimalToUnits(row[3], 6), closeMicros: decimalToUnits(row[4], 6),
      volumeAtoms: decimalToUnits(row[6], 8),
    };
  });
  const dataset = {
    schemaVersion: 'g4.bars.v1', provider: 'KRAKEN', symbol, intervalMs: DAY_MS,
    provenance: { kind: provenanceKind, ohlcRawSha256: sha256(ohlcRaw), metadataRawSha256: sha256(metadataRaw) },
    asOfMs, metadata, bars,
    sourceLimits: { documentedMaximumRows: 720, acceptedMaximumRowsIncludingUncommitted: 721,
      observedMaximumClosedRows: 720, excludedUncommittedRows: 1, paginationBackfillAvailable: false,
      documentationDiscrepancy: 'Official documentation states up to 720 entries; live API capture on 2026-10-15 returned 721 including the uncommitted final row.',
      adjustments: 'RAW_SPOT_OHLC', historicalSpreadAndDepthAvailable: false,
      documentation: SOURCE_DOCUMENTATION },
  };
  validateDataset(dataset);
  return dataset;
}

export function validateDataset(dataset) {
  if (dataset?.schemaVersion !== 'g4.bars.v1' || dataset.provider !== 'KRAKEN' || !['BTC-EUR', 'BTC-USD'].includes(dataset.symbol) || dataset.intervalMs !== DAY_MS) throw new Error('Unsupported historical schema or instrument');
  if (!Number.isSafeInteger(dataset.asOfMs) || !Array.isArray(dataset.bars) || !dataset.bars.length) throw new Error('Invalid historical dataset');
  if (!['PUBLIC_HTTPS_CAPTURE', 'UNVERIFIED_TRANSPORT', 'SYNTHETIC_TEST'].includes(dataset.provenance?.kind)) throw new Error('Missing historical provenance');
  if (dataset.provenance.kind !== 'SYNTHETIC_TEST') for (const key of ['ohlcRawSha256', 'metadataRawSha256']) if (!/^[a-f0-9]{64}$/.test(dataset.provenance[key])) throw new Error('Missing historical raw source hash');
  const fields = ['openMicros', 'highMicros', 'lowMicros', 'closeMicros', 'volumeAtoms'];
  for (let i = 0; i < dataset.bars.length; i++) {
    const bar = dataset.bars[i];
    if (!Number.isSafeInteger(bar.timeMs) || bar.timeMs < 0 || bar.timeMs % DAY_MS !== 0) throw new Error('Invalid daily candle timestamp');
    if (bar.timeMs + DAY_MS > dataset.asOfMs) throw new Error('Future or unclosed candle rejected');
    if (i && bar.timeMs - dataset.bars[i - 1].timeMs !== DAY_MS) throw new Error('Missing, duplicate, or unordered daily candles');
    for (const field of fields) if (typeof bar[field] !== 'string' || !unsigned.test(bar[field])) throw new Error(`Invalid exact units: ${field}`);
    const [open, high, low, close] = fields.slice(0, 4).map(field => BigInt(bar[field]));
    if (low <= 0n || high < low || open < low || open > high || close < low || close > high) throw new Error('Invalid OHLC bounds');
  }
  const m = dataset.metadata;
  if (!m || m.priceScale !== '1000000' || m.quantityScale !== '100000000') throw new Error('Invalid unit scales');
  if (m.base !== 'BTC' || m.quote !== endpointsForSymbol(dataset.symbol).quote) throw new Error('Historical currency or base asset mismatch');
  for (const field of ['quantityStepAtoms', 'tickMicros', 'orderMinAtoms', 'costMinMicros']) if (typeof m[field] !== 'string' || !unsigned.test(m[field]) || BigInt(m[field]) <= 0n) throw new Error(`Invalid instrument constraint: ${field}`);
  return { valid: true, count: dataset.bars.length, firstOpenMs: dataset.bars[0].timeMs,
    lastOpenMs: dataset.bars.at(-1).timeMs, lastCloseMs: dataset.bars.at(-1).timeMs + DAY_MS };
}

/** Public unauthenticated GETs only; bounded timeout, no automatic retry or trading API. */
export async function fetchHistory({ directory, symbol = 'BTC-EUR', nowMs = Date.now(), fetchImpl = fetch }) {
  if (!directory) throw new Error('Historical capture directory required');
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error('Invalid capture time');
  const { ohlcUrl, pairsUrl } = endpointsForSymbol(symbol);
  await mkdir(directory, { recursive: true });
  const paths = { start: path.join(directory, 'START.json'), raw: path.join(directory, 'ohlc.raw.json'),
    metadataRaw: path.join(directory, 'asset-pairs.raw.json'), receipt: path.join(directory, 'receipt.json'),
    normalized: path.join(directory, 'bars.normalized.json') };
  const start = { schemaVersion: 'g4.capture-start.v1', operation: 'PUBLIC_HISTORY_CAPTURE', startedAtMs: nowMs,
    urls: [ohlcUrl, pairsUrl], retries: 0, tradingPermission: false };
  await publishDurably(paths.start, jsonText(start));
  const provenanceKind = fetchImpl === fetch ? 'PUBLIC_HTTPS_CAPTURE' : 'UNVERIFIED_TRANSPORT';
  const receipt = { schemaVersion: 'g4.source-receipt.v1', status: 'STARTED', asOfMs: nowMs, provider: 'KRAKEN', symbol,
    requests: [], provenanceKind, startedSha256: sha256(jsonText(start)), documentation: SOURCE_DOCUMENTATION,
    durability: 'FILE_FSYNC_ATOMIC_NO_REPLACE_PUBLICATION_DIRECTORY_FSYNC_WHERE_SUPPORTED_NOT_POWER_LOSS_CERTIFIED',
    integrityLimit: 'Hashes detect local corruption; no provider signature or independent price attestation.' };
  try {
    for (const [url, file] of [[ohlcUrl, paths.raw], [pairsUrl, paths.metadataRaw]]) {
      const request = { url, method: 'GET', requestedAtMs: Date.now(), receivedAtMs: null, file: path.basename(file) };
      receipt.requests.push(request);
      const response = await fetchImpl(url, { method: 'GET', redirect: 'error', signal: AbortSignal.timeout(20_000), headers: { accept: 'application/json' } });
      const raw = await boundedResponseText(response);
      request.receivedAtMs = Date.now(); request.httpStatus = response.status; request.rawSha256 = sha256(raw); request.bytes = Buffer.byteLength(raw);
      await publishDurably(file, raw);
      if (!response.ok) throw new Error(`Kraken HTTP ${response.status}`);
    }
    const dataset = normalizeHistory(await readFile(paths.raw, 'utf8'), await readFile(paths.metadataRaw, 'utf8'), nowMs, provenanceKind, symbol);
    const normalized = jsonText(dataset);
    await publishDurably(paths.normalized, normalized);
    receipt.normalizedSha256 = sha256(normalized); receipt.validation = validateDataset(dataset); receipt.status = 'VALIDATED';
    receipt.completedAtMs = Date.now(); receipt.closedRange = { firstOpenMs: dataset.bars[0].timeMs, lastOpenMs: dataset.bars.at(-1).timeMs, lastCloseMs: dataset.bars.at(-1).timeMs + DAY_MS };
    receipt.excludedRows = 1; receipt.format = 'JSON_EXACT_INTEGER_STRINGS';
    await publishDurably(paths.receipt, jsonText(receipt));
    return { dataset, receipt, paths };
  } catch (error) {
    receipt.status = 'FAILED'; receipt.completedAtMs = Date.now(); receipt.error = String(error.message);
    await publishDurably(paths.receipt, jsonText(receipt));
    throw error;
  }
}

export async function loadHistory(directory) {
  const paths = { start: path.join(directory, 'START.json'), raw: path.join(directory, 'ohlc.raw.json'), metadataRaw: path.join(directory, 'asset-pairs.raw.json'), receipt: path.join(directory, 'receipt.json'), normalized: path.join(directory, 'bars.normalized.json') };
  const receipt = JSON.parse(await readFile(paths.receipt, 'utf8'));
  if (receipt.schemaVersion !== 'g4.source-receipt.v1' || receipt.status !== 'VALIDATED' || receipt.provider !== 'KRAKEN'
      || !['BTC-EUR', 'BTC-USD'].includes(receipt.symbol) || receipt.requests.length !== 2) throw new Error('Historical capture is not validated');
  const { ohlcUrl, pairsUrl } = endpointsForSymbol(receipt.symbol);
  if (sha256(await readFile(paths.start)) !== receipt.startedSha256) throw new Error('START hash mismatch');
  for (const [i, file, url] of [[0, paths.raw, ohlcUrl], [1, paths.metadataRaw, pairsUrl]]) {
    if (receipt.requests[i].url !== url || receipt.requests[i].httpStatus !== 200 || sha256(await readFile(file)) !== receipt.requests[i].rawSha256) throw new Error('Raw source hash or endpoint mismatch');
  }
  const normalized = await readFile(paths.normalized, 'utf8');
  if (sha256(normalized) !== receipt.normalizedSha256) throw new Error('Normalized hash mismatch');
  const dataset = JSON.parse(normalized);
  const replayed = normalizeHistory(await readFile(paths.raw, 'utf8'), await readFile(paths.metadataRaw, 'utf8'), receipt.asOfMs, receipt.provenanceKind, receipt.symbol);
  if (jsonText(replayed) !== normalized) throw new Error('Normalization replay mismatch');
  const validation = validateDataset(dataset);
  if (JSON.stringify(validation) !== JSON.stringify(receipt.validation)) throw new Error('Receipt validation mismatch');
  return { dataset, receipt, paths };
}
