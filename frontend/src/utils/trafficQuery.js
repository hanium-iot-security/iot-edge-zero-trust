// Feature window timestamps are UTC, including the legacy timezone-less API form.
export function featureTime(value) {
  if (typeof value !== "string" || !value.trim()) return NaN;
  const text = value.trim();
  const timestamp = /(?:Z|[+-]\d{2}:\d{2})$/i.test(text)
    ? text
    : /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(text)
      ? `${text.replace(" ", "T")}Z`
      : "";
  return timestamp ? Date.parse(timestamp) : NaN;
}

export function assertTrafficRowsMatchQuery(rows, params) {
  const from = featureTime(params.from);
  const to = featureTime(params.to);
  if (!Number.isFinite(from) || !Number.isFinite(to) || from >= to) {
    throw new Error("올바른 조회 기간이 필요합니다.");
  }
  for (const row of rows) {
    const start = featureTime(row?.window_start);
    const end = featureTime(row?.window_end);
    if (row?.device_id !== params.device_id ||
        (params.direction && row?.direction !== params.direction) ||
        !Number.isFinite(start) || !Number.isFinite(end) ||
        start < from || end > to || start >= end) {
      throw new Error(
        "서버가 선택한 기기·기간·방향과 다른 데이터를 반환했습니다. " +
        "조회 조건을 지원하는 Backend API 버전을 확인해 주세요. " +
        "잘못된 범위의 데이터는 그래프로 표시하지 않습니다."
      );
    }
  }
}
