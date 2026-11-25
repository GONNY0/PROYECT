import { AlpacaTransport } from './alpaca-transport.mjs';
import { parseExactUnits18, projectLegacyUnits, PAPER_PRECISION_CONTRACT } from '../paper-precision.mjs';

export const ALPACA_CRYPTO_DATA_HOST = 'https://data.alpaca.markets';
export const ALPACA_CRYPTO_QUOTE_URL = `${ALPACA_CRYPTO_DATA_HOST}/v1beta3/crypto/us/latest/quotes?symbols=BTC%2FUSD`;
export const ALPACA_CRYPTO_DATA_DOCUMENTATION = 'https://docs.alpaca.markets/us/reference/cryptolatestquotes-1';

function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$/.test(value)) throw new Error('INVALID_QUOTE_TIMESTAMP');
  const whole = value.slice(0, 19), epoch = Date.parse(`${whole}Z`);
  if (!Number.isSafeInteger(epoch) || epoch < 0 || new Date(epoch).toISOString().slice(0, 19) !== whole) throw new Error('INVALID_QUOTE_TIMESTAMP');
  const fraction = value.includes('.') ? value.slice(20, -1) : '';
  const timestampNs = BigInt(epoch) * 1000000n + BigInt(fraction.padEnd(9, '0'));
  return { timestamp: value, timestampMs: Number(timestampNs / 1000000n), timestampNs: timestampNs.toString() };
}

/** Market data only. The location is always Alpaca US; it never substitutes Kraken EU/US quotes. */
export class AlpacaCryptoDataAdapter {
  #http;
  constructor(options = {}) {
    if (Object.keys(options).some(key => !['key', 'secret', 'fetchImpl','evidenceDirectory'].includes(key))) throw new Error('UNSUPPORTED_DATA_ADAPTER_OPTION');
    this.#http = new AlpacaTransport('DATA', options);
  }
  async getQuote(inputSymbol = 'BTC/USD') {
    if (!['BTC/USD', 'BTC-USD'].includes(inputSymbol)) throw new Error('UNSUPPORTED_DATA_SYMBOL');
    const response = await this.#http.request('/v1beta3/crypto/us/latest/quotes?symbols=BTC%2FUSD');
    const base = { schemaVersion: 'g4.alpaca-crypto-quote.v2', provider: 'ALPACA', source: 'ALPACA_CRYPTO_US',
      settlementContract: PAPER_PRECISION_CONTRACT,
      mode: 'PAPER_DATA', tradingPermission: false, realEconomicProfitMicros: '0',
      provenanceKind: this.#http.source, observedAtMs: response.receivedAtMs ?? Date.now(),
      evidence: { endpoint: ALPACA_CRYPTO_QUOTE_URL, source: this.#http.source,
        authentication: 'PUBLIC_NO_CREDENTIALS',
        httpStatus: response.httpStatus ?? null, requestedAtMs: response.requestedAtMs ?? null,
        receivedAtMs: response.receivedAtMs ?? null, rawSha256: response.rawSha256 ?? null, rawBytes: response.rawBytes ?? null,
        evidenceCapture:response.evidenceCapture??{status:'NOT_REQUESTED'},
        responseHeaders: response.headers ?? {}, integrationStatus: 'NOT_EXTERNALLY_VALIDATED',
        accountingReady: false, documentation: ALPACA_CRYPTO_DATA_DOCUMENTATION } };
    if (!response.ok) return { ...base, status: response.status, reason: response.reason ?? null };
    try {
      if (!response.data?.quotes || Object.keys(response.data.quotes).length !== 1 || !response.data.quotes['BTC/USD']) throw new Error('INVALID_QUOTE_SYMBOL');
      const raw = response.data.quotes['BTC/USD'];
      if ([raw.bp, raw.ap, raw.bs, raw.as].some(value => typeof value !== 'string' || value.length > 128)) throw new Error('INVALID_QUOTE_DECIMAL_LENGTH');
      const bidPriceUnits18 = parseExactUnits18(raw.bp), askPriceUnits18 = parseExactUnits18(raw.ap),
        bidQuantityUnits18 = parseExactUnits18(raw.bs), askQuantityUnits18 = parseExactUnits18(raw.as);
      const quote = { symbol: 'BTC/USD', currency: 'USD', baseCurrency: 'BTC', source: 'ALPACA_CRYPTO_US',
        bidPrice: raw.bp, askPrice: raw.ap, bidQuantity: raw.bs, askQuantity: raw.as,
        bidPriceUnits18, askPriceUnits18, bidQuantityUnits18, askQuantityUnits18,
        bidPriceMicros: projectLegacyUnits(bidPriceUnits18, 6), askPriceMicros: projectLegacyUnits(askPriceUnits18, 6),
        bidQuantityAtoms: projectLegacyUnits(bidQuantityUnits18, 8), askQuantityAtoms: projectLegacyUnits(askQuantityUnits18, 8), ...timestamp(raw.t) };
      if ([bidPriceUnits18, askPriceUnits18, bidQuantityUnits18, askQuantityUnits18].some(value => BigInt(value) <= 0n)
        || quote.bidPriceMicros === null || quote.askPriceMicros === null
        || BigInt(bidPriceUnits18) > BigInt(askPriceUnits18)) throw new Error('INVALID_OR_CROSSED_QUOTE');
      quote.spreadMicros = (BigInt(quote.askPriceMicros) - BigInt(quote.bidPriceMicros)).toString();
      return { ...base, status: 'QUOTE', quote };
    } catch { return { ...base, status: 'INVALID_RESPONSE', reason: 'INVALID_OR_UNREPRESENTABLE_QUOTE' }; }
  }
}
