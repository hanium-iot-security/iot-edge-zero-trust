const EXPLICIT_OFFSET_PATTERN = /(?:Z|[+-]\d{2}:\d{2})$/i;
const LEGACY_NAIVE_PATTERN = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})$/;

export const LEGACY_KST_OPTIONS = Object.freeze({
  legacyNaiveOffset: "+09:00",
});

const KST_FORMATTER = new Intl.DateTimeFormat("ko-KR", {
  timeZone: "Asia/Seoul",
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function validDateOrNull(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function parseMqttTimestamp(value, options = {}) {
  if (typeof value !== "string") {
    return null;
  }

  const timestamp = value.trim();
  if (!timestamp) {
    return null;
  }

  if (EXPLICIT_OFFSET_PATTERN.test(timestamp)) {
    return validDateOrNull(timestamp);
  }

  const legacyMatch = timestamp.match(LEGACY_NAIVE_PATTERN);
  if (!legacyMatch || options.legacyNaiveOffset !== "+09:00") {
    return null;
  }

  return validDateOrNull(
    `${legacyMatch[1]}T${legacyMatch[2]}${options.legacyNaiveOffset}`,
  );
}

export function formatMqttTimestampKST(
  value,
  options = {},
  fallback = "-",
) {
  const date = parseMqttTimestamp(value, options);
  return date ? KST_FORMATTER.format(date) : fallback;
}

export function elapsedSecondsFromMqttTimestamp(
  value,
  now = new Date(),
  options = {},
) {
  const date = parseMqttTimestamp(value, options);
  if (!date || !(now instanceof Date) || Number.isNaN(now.getTime())) {
    return null;
  }

  return Math.max(0, Math.floor((now.getTime() - date.getTime()) / 1000));
}
