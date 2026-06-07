const DECIMAL_DIGITS = new Map<string, string>([
  ["٠", "0"], ["١", "1"], ["٢", "2"], ["٣", "3"], ["٤", "4"], ["٥", "5"], ["٦", "6"], ["٧", "7"], ["٨", "8"], ["٩", "9"],
  ["۰", "0"], ["۱", "1"], ["۲", "2"], ["۳", "3"], ["۴", "4"], ["۵", "5"], ["۶", "6"], ["۷", "7"], ["۸", "8"], ["۹", "9"],
  ["०", "0"], ["१", "1"], ["२", "2"], ["३", "3"], ["४", "4"], ["५", "5"], ["६", "6"], ["७", "7"], ["८", "8"], ["९", "9"],
  ["০", "0"], ["১", "1"], ["২", "2"], ["৩", "3"], ["৪", "4"], ["৫", "5"], ["৬", "6"], ["৭", "7"], ["৮", "8"], ["৯", "9"],
  ["၀", "0"], ["၁", "1"], ["၂", "2"], ["၃", "3"], ["၄", "4"], ["၅", "5"], ["၆", "6"], ["၇", "7"], ["၈", "8"], ["၉", "9"],
  ["೦", "0"], ["೧", "1"], ["೨", "2"], ["೩", "3"], ["೪", "4"], ["೫", "5"], ["೬", "6"], ["೭", "7"], ["೮", "8"], ["೯", "9"],
  ["០", "0"], ["១", "1"], ["២", "2"], ["៣", "3"], ["៤", "4"], ["៥", "5"], ["៦", "6"], ["៧", "7"], ["៨", "8"], ["៩", "9"],
  ["๐", "0"], ["๑", "1"], ["๒", "2"], ["๓", "3"], ["๔", "4"], ["๕", "5"], ["๖", "6"], ["๗", "7"], ["๘", "8"], ["๙", "9"],
]);

const HAN_DIGITS = new Map<string, number>([
  ["零", 0], ["〇", 0],
  ["一", 1], ["壹", 1],
  ["二", 2], ["两", 2], ["兩", 2], ["贰", 2], ["貳", 2],
  ["三", 3], ["叁", 3], ["參", 3],
  ["四", 4], ["肆", 4],
  ["五", 5], ["伍", 5],
  ["六", 6], ["陆", 6], ["陸", 6],
  ["七", 7], ["柒", 7],
  ["八", 8], ["捌", 8],
  ["九", 9], ["玖", 9],
]);

const HAN_UNITS = new Map<string, number>([
  ["十", 10], ["拾", 10],
  ["百", 100], ["佰", 100],
  ["千", 1000], ["仟", 1000],
]);

const EXACT_NUMERAL_VALUES = new Map<string, number>([
  ["፩", 1], ["፪", 2], ["፫", 3], ["፬", 4], ["፭", 5],
  ["፮", 6], ["፯", 7], ["፰", 8], ["፱", 9], ["፲", 10],
]);

const KOREAN_DIGITS = new Map<string, number>([
  ["영", 0], ["공", 0],
  ["일", 1], ["이", 2], ["삼", 3], ["사", 4], ["오", 5],
  ["육", 6], ["륙", 6], ["칠", 7], ["팔", 8], ["구", 9],
]);

const KOREAN_UNITS = new Map<string, number>([
  ["십", 10],
  ["백", 100],
  ["천", 1000],
]);

const DEVANAGARI_FORMAT_DIGITS = ["०", "१", "२", "३", "४", "५", "६", "७", "८", "९"];
const HAN_FORMAT_DIGITS = ["零", "一", "二", "三", "四", "五", "六", "七", "八", "九"];
const KOREAN_FORMAT_DIGITS = ["영", "일", "이", "삼", "사", "오", "육", "칠", "팔", "구"];

export function normalizeUnicodeCredentialText(value: string): string {
  return value.normalize("NFKC").trim();
}

export function parseLocalizedInteger(value: string): number | null {
  const normalized = normalizeUnicodeCredentialText(value);
  if (!normalized) return null;

  const exact = EXACT_NUMERAL_VALUES.get(normalized);
  if (exact !== undefined) return exact;

  let decimal = "";
  let hasLocalizedDigit = false;
  for (const char of Array.from(normalized)) {
    if (/[0-9]/.test(char)) {
      decimal += char;
      continue;
    }
    const mapped = DECIMAL_DIGITS.get(char);
    if (mapped === undefined) {
      decimal = "";
      break;
    }
    hasLocalizedDigit = true;
    decimal += mapped;
  }
  if (decimal && (/^[0-9]+$/.test(decimal) || hasLocalizedDigit)) {
    return Number.parseInt(decimal, 10);
  }

  return parseHanInteger(normalized) ?? parseKoreanInteger(normalized);
}

function parseKoreanInteger(value: string): number | null {
  const chars = Array.from(value);
  if (chars.length === 0 || chars.some((char) => !KOREAN_DIGITS.has(char) && !KOREAN_UNITS.has(char))) {
    return null;
  }

  if (chars.every((char) => KOREAN_DIGITS.has(char))) {
    return Number.parseInt(chars.map((char) => KOREAN_DIGITS.get(char)).join(""), 10);
  }

  let total = 0;
  let current: number | null = null;
  let lastUnit = Number.POSITIVE_INFINITY;

  for (const char of chars) {
    const digit = KOREAN_DIGITS.get(char);
    if (digit !== undefined) {
      if (current !== null) return null;
      current = digit;
      continue;
    }

    const unit = KOREAN_UNITS.get(char);
    if (unit === undefined || unit >= lastUnit) return null;
    total += (current ?? 1) * unit;
    current = null;
    lastUnit = unit;
  }

  total += current ?? 0;
  return Number.isFinite(total) ? total : null;
}

function parseHanInteger(value: string): number | null {
  const chars = Array.from(value);
  if (chars.length === 0 || chars.some((char) => !HAN_DIGITS.has(char) && !HAN_UNITS.has(char))) {
    return null;
  }

  if (chars.every((char) => HAN_DIGITS.has(char))) {
    return Number.parseInt(chars.map((char) => HAN_DIGITS.get(char)).join(""), 10);
  }

  let total = 0;
  let current: number | null = null;
  let lastUnit = Number.POSITIVE_INFINITY;

  for (const char of chars) {
    const digit = HAN_DIGITS.get(char);
    if (digit !== undefined) {
      if (current !== null) return null;
      current = digit;
      continue;
    }

    const unit = HAN_UNITS.get(char);
    if (unit === undefined || unit >= lastUnit) return null;
    total += (current ?? 1) * unit;
    current = null;
    lastUnit = unit;
  }

  total += current ?? 0;
  return Number.isFinite(total) ? total : null;
}

export function parseBootCajas(values: string[], messages: { missing: string; numeric: string; range: string }): number[] {
  if (values.some((value) => normalizeUnicodeCredentialText(value) === "")) {
    throw new Error(messages.missing);
  }

  const cajas = values.map(parseLocalizedInteger);
  if (cajas.some((value) => value === null)) {
    throw new Error(messages.numeric);
  }

  const parsed = cajas as number[];
  if (parsed.some((value) => value < 0 || value > 1000)) {
    throw new Error(messages.range);
  }
  return parsed;
}

function formatDigitSequence(value: number, digits: string[]) {
  return String(value).replace(/\d/g, (digit) => digits[Number(digit)]);
}

function formatHanInteger(value: number) {
  if (value === 0) return HAN_FORMAT_DIGITS[0];
  if (value === 1000) return "一千";
  if (value < 10) return HAN_FORMAT_DIGITS[value];

  const hundreds = Math.floor(value / 100);
  const tens = Math.floor((value % 100) / 10);
  const ones = value % 10;
  let result = "";
  if (hundreds > 0) result += `${HAN_FORMAT_DIGITS[hundreds]}百`;
  if (tens > 0) {
    if (hundreds > 0 && tens === 0 && ones > 0) result += "零";
    result += `${tens === 1 && hundreds === 0 ? "" : HAN_FORMAT_DIGITS[tens]}十`;
  } else if (hundreds > 0 && ones > 0) {
    result += "零";
  }
  if (ones > 0) result += HAN_FORMAT_DIGITS[ones];
  return result;
}

function formatKoreanInteger(value: number) {
  if (value === 0) return KOREAN_FORMAT_DIGITS[0];
  if (value === 1000) return "천";
  if (value < 10) return KOREAN_FORMAT_DIGITS[value];

  const hundreds = Math.floor(value / 100);
  const tens = Math.floor((value % 100) / 10);
  const ones = value % 10;
  let result = "";
  if (hundreds > 0) result += `${hundreds === 1 ? "" : KOREAN_FORMAT_DIGITS[hundreds]}백`;
  if (tens > 0) result += `${tens === 1 ? "" : KOREAN_FORMAT_DIGITS[tens]}십`;
  if (ones > 0) result += KOREAN_FORMAT_DIGITS[ones];
  return result;
}

export function formatLocalizedInteger(value: number, language: string) {
  const normalized = Math.max(0, Math.floor(value));
  switch (language) {
    case "zh":
    case "ja":
      return formatHanInteger(normalized);
    case "ko":
      return formatKoreanInteger(normalized);
    case "hi":
      return formatDigitSequence(normalized, DEVANAGARI_FORMAT_DIGITS);
    default:
      return new Intl.NumberFormat(language).format(normalized);
  }
}

export function formatLocalizedCompactNumber(value: number, language: string) {
  return new Intl.NumberFormat(language).format(value);
}

export function formatLocalizedMilliseconds(value: number, language: string) {
  return `${formatLocalizedInteger(value, language)} ms`;
}

export function formatLocalizedTime(date: Date, language: string) {
  return new Intl.DateTimeFormat(language, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(date);
}
