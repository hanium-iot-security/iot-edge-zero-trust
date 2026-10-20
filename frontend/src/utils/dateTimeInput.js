const pad = (value) => String(value).padStart(2, "0");

// Values are wall-clock KST strings. Never reinterpret them in the PC's timezone.
export function parseDateTimeInput(value) {
  const match = /^(\d{4}-\d{2}-\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/.exec(value || "");
  if (!match || match[1].startsWith("0000")) return null;
  const [, date, hour, minute, second = "00"] = match;
  const instant = new Date(`${date}T${hour}:${minute}:${second}Z`);
  if (!Number.isFinite(instant.getTime()) || instant.toISOString().slice(0, 19) !== `${date}T${hour}:${minute}:${second}`) return null;
  const hour24 = Number(hour);
  return { date, period: hour24 < 12 ? "AM" : "PM", hour: pad(hour24 % 12 || 12), minute, second };
}

export function dateTimeInputValue(draft, withSeconds = false) {
  const { date, period, hour, minute, second } = draft;
  const integer = (value, min, max) => /^\d{1,2}$/.test(String(value)) && Number(value) >= min && Number(value) <= max;
  if (!["AM", "PM"].includes(period) || !integer(hour, 1, 12) || !integer(minute, 0, 59) || (withSeconds && !integer(second, 0, 59))) return null;
  const hour24 = Number(hour) % 12 + (period === "PM" ? 12 : 0);
  const value = `${date}T${pad(hour24)}:${pad(minute)}${withSeconds ? `:${pad(second)}` : ""}`;
  return parseDateTimeInput(value) ? value : null;
}

export function dateTimeInputLabel(value, withSeconds = false) {
  const draft = parseDateTimeInput(value);
  if (!draft) return "날짜와 시간을 선택하세요";
  return `${draft.date} ${draft.period === "AM" ? "오전" : "오후"} ${draft.hour}:${draft.minute}${withSeconds ? `:${draft.second}` : ""}`;
}

export function currentKstInput(withSeconds = false) {
  return new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().slice(0, withSeconds ? 19 : 16);
}

export function calendarDays(month) {
  const first = new Date(`${month}-01T00:00:00Z`);
  const last = new Date(first);
  last.setUTCMonth(last.getUTCMonth() + 1, 0);
  return [
    ...Array(first.getUTCDay()).fill(null),
    ...Array.from({ length: last.getUTCDate() }, (_, index) => `${month}-${pad(index + 1)}`),
  ];
}

export function adjacentMonth(month, delta) {
  const date = new Date(`${month}-01T00:00:00Z`);
  date.setUTCMonth(date.getUTCMonth() + delta);
  const year = date.getUTCFullYear();
  return year >= 1 && year <= 9999 ? date.toISOString().slice(0, 7) : month;
}
