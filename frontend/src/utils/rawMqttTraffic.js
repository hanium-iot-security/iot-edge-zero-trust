// Raw messages have explicit timezones; legacy naive MQTT times remain unknown.
const EXPLICIT_TIME = /^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})$/;

export function mqttTimestampMicros(value) {
  const match = typeof value === "string" && EXPLICIT_TIME.exec(value);
  if (!match || Number(match[1].slice(0, 4)) < 1) return null;
  const wallClock = `${match[1]}T${match[2]}`;
  const wallMillis = Date.parse(`${wallClock}Z`);
  if (!Number.isFinite(wallMillis) || new Date(wallMillis).toISOString().slice(0, 19) !== wallClock) return null;
  const seconds = Date.parse(`${wallClock}${match[4]}`);
  if (!Number.isFinite(seconds)) return null;
  const utcYear = new Date(seconds).getUTCFullYear();
  if (utcYear < 1 || utcYear > 9999) return null;
  return BigInt(seconds) * 1000n + BigInt((match[3] ?? "").padEnd(6, "0"));
}

function safeId(value) {
  return Number.isSafeInteger(value) && value > 0;
}
function order(a, b) {
  const at = mqttTimestampMicros(a.received_at);
  const bt = mqttTimestampMicros(b.received_at);
  return at < bt ? -1 : at > bt ? 1 : a.id - b.id;
}
function validSize(value) {
  // Zero is a measured empty payload, while missing/bad values are unknown.
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

export function rawMqttChartRows({ rows = [], incomplete = false, total = null, sourceSpanCount = null } = {}) {
  const ordered = rows.map(row => ({ row, time: mqttTimestampMicros(row?.received_at) }));
  if (ordered.every(item => item.time !== null)) {
    ordered.sort((a, b) => a.time < b.time ? -1 : a.time > b.time ? 1 : a.row.id - b.row.id);
  }
  const previous = new Map();
  const reliable = !incomplete && Number.isSafeInteger(total) && total === rows.length &&
    Number.isSafeInteger(sourceSpanCount) && sourceSpanCount === total &&
    ordered.every(({ row }, index) => safeId(row?.id) && (!index || ordered[index - 1].row.id < row.id));
  return ordered.map(({ row, time }) => {
    const before = previous.get(row?.device_id);
    const difference = time !== null && before !== undefined && time >= before
      ? Number(time - before) / 1_000_000 : null;
    if (time === null) previous.delete(row?.device_id);
    else previous.set(row?.device_id, time);
    return {
      ...row,
      timestamp: time === null ? null : Number(time / 1000n),
      payload_size: time === null ? null : validSize(row?.payload_size),
      message_interval_seconds: reliable ? difference : null,
    };
  });
}

export async function loadRawMqttLogs({ request, params, signal, pageSize = 500, maxRows = 5000 }) {
  const from = mqttTimestampMicros(params.from);
  const to = mqttTimestampMicros(params.to);
  if (!params.device_id || from === null || to === null || from >= to) throw new Error("올바른 MQTT 원본 조회 조건이 필요합니다.");
  let rows = [];
  let total = null;
  let snapshot = null;
  let timestampUnavailableCount = null;
  let sourceSpanCount = null;
  let incomplete = false;
  let warning = "";
  let pages = 0;
  while (!signal.aborted && rows.length < maxRows) {
    const offset = rows.length;
    const limit = Math.min(pageSize, maxRows - offset);
    try {
      const body = await request({ ...params, limit, offset, ...(snapshot === null ? {} : { snapshot_max_id: snapshot }) }, { signal });
      if (signal.aborted) throw new Error("조회 취소");
      if (!Array.isArray(body?.items) || !Number.isSafeInteger(body.total) || body.total < 0 ||
          !Number.isSafeInteger(body.snapshot_max_id) || body.snapshot_max_id < 0 ||
          body.offset !== offset || body.limit !== limit || body.items.length > limit ||
          body.interval_predecessor_policy !== "within_range_only" ||
          body.timestamp_unavailable_count_scope !== "device_snapshot_first_page" ||
          body.source_span_count_scope !== "selected_source_ids_first_page" ||
          body.has_more !== (offset + body.items.length < body.total)) {
        throw new Error("MQTT 원본의 페이지·스냅샷 계약을 확인할 수 없습니다. Backend API 버전을 확인해 주세요.");
      }
      if (pages === 0) {
        if (!Number.isSafeInteger(body.source_span_count) || body.source_span_count < body.total) throw new Error("MQTT 원본 연속성 정보를 확인할 수 없습니다.");
        if (!Number.isSafeInteger(body.timestamp_unavailable_count) || body.timestamp_unavailable_count < 0) throw new Error("MQTT 시각 누락 정보를 확인할 수 없습니다.");
      } else if (body.total !== total || body.snapshot_max_id !== snapshot ||
          (body.timestamp_unavailable_count !== null && body.timestamp_unavailable_count !== timestampUnavailableCount) ||
          (body.source_span_count !== null && body.source_span_count !== sourceSpanCount)) {
        throw new Error("MQTT 조회 스냅샷 또는 전체 건수가 변경되었습니다.");
      }
      if (body.items.length !== Math.min(limit, Math.max(0, body.total - offset))) throw new Error("MQTT 원본 페이지가 누락되거나 잘렸습니다.");
      let previous = rows.at(-1);
      for (const row of body.items) {
        const time = mqttTimestampMicros(row?.received_at);
        if (!safeId(row?.id) || row.id > body.snapshot_max_id || row.device_id !== params.device_id ||
            time === null || time < from || time >= to || (previous && order(previous, row) <= 0)) {
          throw new Error("MQTT 원본의 기기·기간·수신 시각 순서가 조회 조건과 다릅니다.");
        }
        previous = row;
      }
      if (pages === 0) {
        total = body.total;
        snapshot = body.snapshot_max_id;
        timestampUnavailableCount = body.timestamp_unavailable_count;
        sourceSpanCount = body.source_span_count;
      }
      rows = rows.concat(body.items);
      pages += 1;
      if (!body.has_more) break;
    } catch (error) {
      if (signal.aborted || error?.isCanceled) throw error;
      if (!pages) throw error;
      incomplete = true;
      warning = `MQTT 원본 ${pages + 1}번째 페이지 조회 불완전: ${error?.message ?? "조회 실패"}`;
      break;
    }
  }
  if (signal.aborted) throw new Error("조회 취소");
  if (total !== null && rows.length < total) {
    incomplete = true;
    warning ||= `MQTT 원본 화면 보호 한도 ${maxRows.toLocaleString()}건에 도달했습니다. 기간을 줄여 주세요.`;
  }
  const sourceOrder = [...rows].reverse().every((row, index, ascending) => !index || ascending[index - 1].id < row.id);
  if (sourceSpanCount !== total || !sourceOrder) {
    warning = [warning, "선택한 원본 사이의 누락 또는 수신 순서를 확인할 수 없어 간격은 표시하지 않습니다."].filter(Boolean).join(" ");
  }
  if (timestampUnavailableCount > 0) {
    warning = [warning, `이 기기의 스냅샷에 시간대·시각 미확인 원본 ${timestampUnavailableCount}건이 있어 기간 배치는 미확인입니다. 선택한 메시지의 연속성은 원본 ID 구간으로 별도 확인합니다.`].filter(Boolean).join(" ");
  }
  return { rows, total, snapshot, timestampUnavailableCount, sourceSpanCount, incomplete, warning, pages };
}