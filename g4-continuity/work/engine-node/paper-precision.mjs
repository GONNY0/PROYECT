/**
 * Settlement domain selected by G4, not a certification of Alpaca's maximum precision.
 * Decimal API tokens stay strings. Values beyond this domain fail rather than round.
 * Legacy BTC atoms (8) and USD micros (6) remain separate, explicitly projected units.
 */
export const PAPER_SETTLEMENT_DECIMALS = 18;
export const SCALE18 = 1000000000000000000n;
export const PAPER_PRECISION_CONTRACT = Object.freeze({
  schemaVersion: 'g4.paper-precision.v2', settlementDecimals: 18,
  legacyBtcDecimals: 8, legacyUsdDecimals: 6,
  excessPrecision: 'REJECT_NONZERO_DIGITS', legacyProjection: 'EXACT_OR_NULL',
  providerMaximumPrecisionCertified: false, financialNumberInput: 'DECIMAL_STRING_ONLY',
});

function scale(decimals) {
  if (!Number.isSafeInteger(decimals) || decimals < 0 || decimals > 18) throw new Error('INVALID_LEGACY_DECIMALS');
  return 10n ** BigInt(18 - decimals);
}

function unitsInteger(value) {
  if (typeof value !== 'string' || !/^-?(0|[1-9][0-9]{0,47})$/.test(value)) throw new Error('INVALID_UNITS18_INTEGER');
  return BigInt(value);
}

/** Signed exact integer string at scale 1e18; accepts extra trailing zeros only. */
export function parseExactUnits18(value) {
  if (typeof value !== 'string' || value.length > 512
    || !/^-?(0|[1-9][0-9]{0,29})(\.[0-9]+)?$/.test(value)) throw new Error('INVALID_EXACT_DECIMAL18');
  const negative = value.startsWith('-'), [whole, fraction = ''] = (negative ? value.slice(1) : value).split('.');
  if (/[1-9]/.test(fraction.slice(18))) throw new Error('UNREPRESENTABLE_PRECISION18');
  const magnitude = BigInt(whole) * SCALE18 + BigInt(fraction.slice(0, 18).padEnd(18, '0'));
  return (negative ? -magnitude : magnitude).toString();
}

/** Canonical human/API decimal. This is formatting, never monetary quantization. */
export function formatUnits18(value) {
  const units = unitsInteger(value), magnitude = units < 0n ? -units : units;
  const whole = magnitude / SCALE18, fraction = (magnitude % SCALE18).toString().padStart(18, '0').replace(/0+$/, '');
  return `${units < 0n ? '-' : ''}${whole}${fraction ? `.${fraction}` : ''}`;
}

/** Exact projection only. null means the old representation cannot express the value. */
export function projectLegacyUnits(value, decimals) {
  const units = unitsInteger(value), divisor = scale(decimals);
  return units % divisor === 0n ? (units / divisor).toString() : null;
}

/** Explicit unit conversion for legacy integer fields; never reinterpret an old event as v2. */
export function legacyToUnits18(value, decimals) {
  if (typeof value !== 'string' || !/^-?(0|[1-9][0-9]{0,29})$/.test(value)) throw new Error('INVALID_LEGACY_INTEGER');
  return (BigInt(value) * scale(decimals)).toString();
}
