import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { assertTrafficRowsMatchQuery, featureTime } from "../utils/trafficQuery";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  getDevices,
  getFeatureLogs,
  getPacketFeatureLogs,
  getPacketCaptureWindows,
} from "../api/api";
import "../styles/components/DeviceTrafficTrends.scss";

// Phase 9 P9-07: 한 기기와 고정 기간을 대상으로 한 조회. 서버 한 페이지는 최대 500건.
// 이 UI의 5,000건 제한은 안전장치이며 팀에서 합의한 최종 조회 한도와 별도 대조해야 합니다.
const PAGE_SIZE = 500;
const MAX_ROWS = 5000;
const WINDOW_SECONDS = 10;
const MAX_CAPTURE_METADATA = 100;
const KST_OFFSET_MS = 9 * 60 * 60 * 1000;

const isValue = (value) => value !== null && value !== undefined && value !== "";
const numberOrNull = (value) => {
  if (!isValue(value)) return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
};
const formatNumber = (value, digits = 2) =>
  value === null || value === undefined
    ? "-"
    : Number(value).toLocaleString("ko-KR", { maximumFractionDigits: digits });
const toKSTInput = (date) =>
  new Date(date.getTime() + KST_OFFSET_MS).toISOString().slice(0, 16);
const kstInputToISO = (value) => {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) return null;
  const d = new Date(`${value}:00+09:00`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
};
const kstTime = (value) => {
  if (!value) return "-";
  const d = new Date(featureTime(value));
  if (Number.isNaN(d.getTime())) return "-";
  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d);
};
const kstFull = (value) => {
  if (!value) return "-";
  const d = new Date(featureTime(value));
  if (Number.isNaN(d.getTime())) return "-";
  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(d);
};
const sessionId = (item) => item?.capture_session_id ?? item?.session_id ?? null;
const rowId = (item, index) =>
  isValue(item?.id)
    ? `id:${String(item.id)}`
    : `fallback:${sessionId(item) ?? "?"}|${item?.window_start ?? "?"}|${item?.device_id ?? "?"}|${index}`;

function unpackList(data, label) {
  const root = data?.item ?? data;
  if (Array.isArray(root)) return { items: root, total: root.length, totalKnown: false };
  if (!Array.isArray(root?.items)) throw new Error(`${label}: items 배열이 없는 응답입니다.`);
  const n = numberOrNull(root.total);
  return { items: root.items, total: n, totalKnown: n !== null };
}

async function loadPaged({ request, params, signal, label }) {
  const byId = new Map();
  let offset = 0;
  let total = null;
  let incomplete = false;
  let warning = "";
  let pages = 0;
  let missingTotal = false;

  while (!signal.aborted && offset < MAX_ROWS) {
    let result;
    try {
      result = unpackList(
        await request({ ...params, limit: PAGE_SIZE, offset }, { signal }),
        label
      );
    } catch (err) {
      if (signal.aborted || err?.isCanceled) throw err;
      if (pages === 0) throw err;
      incomplete = true;
      warning = `${label} ${pages + 1}번째 페이지를 가져오지 못해 일부 데이터만 표시합니다. (${err?.message ?? "조회 실패"})`;
      break;
    }

    assertTrafficRowsMatchQuery(result.items, params);
    pages += 1;
    if (result.totalKnown) total = result.total;
    else missingTotal = true;
    result.items.forEach((item, idx) => {
      const key = rowId(item, offset + idx);
      if (!byId.has(key)) byId.set(key, item);
    });
    offset += result.items.length;

    if (result.items.length === 0 || result.items.length < PAGE_SIZE) {
      // total 값이 있으면 서버의 페이지 경계도 확인.
      if (total !== null && offset < total) {
        incomplete = true;
        warning = "서버의 total보다 적은 행을 받아 조회가 불완전합니다.";
      }
      break;
    }
    if (total !== null && offset >= total) break;
  }

  if (offset >= MAX_ROWS && (total === null || offset < total)) {
    incomplete = true;
    warning = `화면 보호 한도 ${MAX_ROWS.toLocaleString()}행에 도달했습니다. 범위를 줄여 다시 조회해 주세요.`;
  }

  if (missingTotal) {
    incomplete = true;
    warning = [warning, `${label} 응답에 total이 없어 전체 건수를 검증할 수 없습니다.`].filter(Boolean).join(" ");
  }

  // 데이터가 조회 중에 추가되면 offset 방식의 중복/누락 가능성이 있습니다.
  // snapshot_max_id API가 제공되지 않았으므로 '완전한 스냅샷'임을 보장하지 않습니다.
  const rows = [...byId.values()].sort((a, b) => {
    const at = featureTime(a?.window_start);
    const bt = featureTime(b?.window_start);
    const order = (Number.isFinite(at) ? at : Infinity) - (Number.isFinite(bt) ? bt : Infinity);
    return order || String(a?.id ?? "").localeCompare(String(b?.id ?? ""), undefined, { numeric: true });
  });
  return { rows, total, incomplete, warning, rawCount: offset, pages };
}

function normalizePacketRow(item) {
  const eligible = item?.capture_eligible;
  const failed = String(item?.segment_status ?? "").toUpperCase() === "FAILED";
  const qualityOk = !failed && (eligible === true || eligible === 1 || eligible === "true");
  const pps = qualityOk ? numberOrNull(item?.effective_packets_per_second) : null;
  const bps = qualityOk ? numberOrNull(item?.effective_bytes_per_second) : null;
  return {
    ...item,
    chartTime: kstTime(item?.window_start),
    qualityOk,
    packets_per_second: pps,
    bytes_per_second: bps,
    state: failed ? "FAILED" : eligible === false ? "EXCLUDED" : qualityOk ? "ELIGIBLE" : "UNKNOWN",
  };
}

function normalizeMqttRow(item) {
  return {
    ...item,
    chartTime: kstTime(item?.window_start),
    publish_count: numberOrNull(item?.publish_count),
    avg_payload_size: numberOrNull(item?.avg_payload_size),
    max_payload_size: numberOrNull(item?.max_payload_size),
    avg_message_interval: numberOrNull(item?.avg_message_interval),
    min_message_interval: numberOrNull(item?.min_message_interval),
  };
}

// 누락 구간·Session 변경·Packet 제외 사이에 null 지점을 넣어 차트 선을 끊습니다.
function chartRows(rows, kind) {
  const normalized = rows.map(kind === "packet" ? normalizePacketRow : normalizeMqttRow);
  const plot = [];
  let last = null;
  for (const row of normalized) {
    const currentTime = featureTime(row.window_start);
    const lastTime = featureTime(last?.window_start);
    const changedSession =
      kind === "packet" && last && isValue(sessionId(last)) && isValue(sessionId(row)) &&
      String(sessionId(last)) !== String(sessionId(row));
    const gap = last && Number.isFinite(currentTime) && Number.isFinite(lastTime) &&
      currentTime - lastTime > WINDOW_SECONDS * 1500;
    if (last && (changedSession || gap || (kind === "packet" && !last.qualityOk))) {
      plot.push({ chartTime: "구간 단절", window_start: null, __gap: true });
    }
    plot.push(row);
    last = row;
  }
  return plot;
}

function MetricsChart({ data, lines, title, unit, isPacket }) {
  return (
    <div className="traffic-trends-chart">
      <div className="traffic-trends-chart-title">
        <strong>{title}</strong><span>{unit}</span>
      </div>
      <ResponsiveContainer width="100%" height={260}>
        <LineChart data={data} margin={{ top: 12, right: 20, left: 0, bottom: 12 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="chartTime" minTickGap={32} tick={{ fontSize: 10 }} />
          <YAxis tick={{ fontSize: 11 }} width={55} />
          <Tooltip
            labelFormatter={(_label, payload) =>
              payload?.[0]?.payload?.__gap ? "미수집/수집 세션 변경" : kstFull(payload?.[0]?.payload?.window_start)
            }
            formatter={(value, name) => [formatNumber(value), name]}
          />
          <Legend />
          {lines.map((line) => (
            <Line
              key={line.key}
              type="linear"
              dataKey={line.key}
              name={line.label}
              stroke={line.color}
              strokeWidth={2}
              dot={false}
              connectNulls={false}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
      {isPacket && (
        <small className="traffic-trends-help">
          실제 수집시간 기준 전송률입니다. 10초로 나눈 명목 전송률나 패킷 AI 입력값으로 해석하지 않습니다.
        </small>
      )}
    </div>
  );
}

function CaptureEvidence({ data, loading, error, missingSession }) {
  const list = data?.items ?? [];
  const found = useMemo(() => {
    const summary = { failed: 0, empty: 0, pending: 0, completed: 0, other: 0 };
    list.forEach((item) => {
      const status = String(item?.segment_status ?? item?.capture_status ?? item?.status ?? "").toUpperCase();
      if (status === "FAILED") summary.failed += 1;
      else if (status === "EMPTY") summary.empty += 1;
      else if (status === "PENDING" || status === "PROCESSING") summary.pending += 1;
      else if (status === "COMPLETED") summary.completed += 1;
      else summary.other += 1;
    });
    return summary;
  }, [list]);
  return (
    <div className="traffic-trends-evidence">
      <strong>수집 근거 (최근 메타 조회)</strong>
      {loading ? (
        <p>수집 근거 조회 중...</p>
      ) : missingSession ? (
        <p role="status">수집 상태 정보 조회 보류: 실제 session_id를 확인할 수 없습니다. 분석 지표 부재를 정상 수집으로 해석하지 않습니다.</p>
      ) : error ? (
        <p role="status">Capture 메타 조회 실패: {error}. Feature 그래프만 표시하며 누락 원인은 확인할 수 없습니다.</p>
      ) : !data ? (
        <p role="status">수집 근거를 아직 조회하지 않았습니다.</p>
      ) : (
        <p>
          수신 {list.length}건 · COMPLETED {found.completed} · EMPTY {found.empty} · FAILED {found.failed} · 대기 {found.pending} · 기타 {found.other}
          {data?.incomplete ? " · 일부 메타만 확인됨" : ""}
        </p>
      )}
      <small>
        이 통계는 메타 조회 결과에 한정되며, 선택 기기의 무통신 증거가 아닙니다.
        분석 지표 미수집 구간은 원인을 특정할 수 없으면 미상으로 표시하고 0으로 채우지 않습니다.
      </small>
    </div>
  );
}

export default function DeviceTrafficTrends() {
  const [searchParams] = useSearchParams();
  const requestedDevice = searchParams.get("device_id") || "";
  const now = useMemo(() => new Date(), []);
  const [deviceOptions, setDeviceOptions] = useState([]);
  const [deviceError, setDeviceError] = useState("");
  const [deviceId, setDeviceId] = useState(requestedDevice);
  const [tab, setTab] = useState("mqtt");
  const [direction, setDirection] = useState("INBOUND");
  const [fromInput, setFromInput] = useState(toKSTInput(new Date(now.getTime() - 60 * 60 * 1000)));
  const [toInput, setToInput] = useState(toKSTInput(now));
  const [criteria, setCriteria] = useState(null);
  const [rangeError, setRangeError] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [meta, setMeta] = useState({ data: null, loading: false, error: "" });
  const [preferredSession, setPreferredSession] = useState("");
  const generationRef = useRef(0);
  const controllerRef = useRef(null);

  useEffect(() => {
    const controller = new AbortController();
    (async () => {
      try {
        const root = unpackList(await getDevices({ limit: 500, offset: 0 }, { signal: controller.signal }), "기기");
        const ids = [...new Set(root.items.map((item) => item?.device_id).filter(Boolean))];
        if (controller.signal.aborted) return;
        setDeviceOptions(ids);
        setDeviceId((current) => ids.includes(current) ? current : ids[0] || "");
      } catch (err) {
        if (controller.signal.aborted) return;
        setDeviceError(err?.message || "기기 목록 조회 실패");
      }
    })();
    return () => controller.abort();
  }, []);

  const validRange = useCallback(() => {
    const from = kstInputToISO(fromInput);
    const to = kstInputToISO(toInput);
    if (!deviceId) return { error: "조회할 기기를 먼저 선택해 주세요." };
    if (!from || !to) return { error: "올바른 시작/종료 시각을 입력해 주세요." };
    if (new Date(from).getTime() >= new Date(to).getTime()) {
      return { error: "종료 시각은 시작 시각보다 늦어야 합니다." };
    }
    return { device_id: deviceId, from, to, direction };
  }, [deviceId, fromInput, toInput, direction]);

  const submit = useCallback((event) => {
    event?.preventDefault();
    const query = validRange();
    if (query.error) { setRangeError(query.error); return; }
    setRangeError("");
    setCriteria({ ...query, tab, token: Date.now() });
  }, [validRange, tab]);

  // 기기·방향·탭 변경 시 유효 기간을 유지하여 새 조회 시작.
  useEffect(() => {
    const query = validRange();
    if (query.error) return;
    setRangeError("");
    setCriteria({ ...query, tab, token: Date.now() });
  }, [deviceId, direction, tab]); // 기간은 '조회' 제출 때 확정

  useEffect(() => {
    if (!criteria) return undefined;
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const requestId = ++generationRef.current;
    setLoading(true);
    setResult(null);
    setError("");
    setMeta({ data: null, loading: false, error: "" });
    const active = () => !controller.signal.aborted && requestId === generationRef.current;
    (async () => {
      const { tab: kind, token: _token, ...params } = criteria;
      try {
        const request = kind === "mqtt" ? getFeatureLogs : getPacketFeatureLogs;
        const query = kind === "mqtt"
          ? { device_id: params.device_id, from: params.from, to: params.to }
          : { device_id: params.device_id, from: params.from, to: params.to, direction: params.direction };
        const data = await loadPaged({ request, params: query, signal: controller.signal, label: kind === "mqtt" ? "MQTT" : "Packet" });
        if (active()) setResult({ ...data, kind, criteria });
      } catch (err) {
        if (active()) setError(err?.message || "통신 추이 조회에 실패했습니다.");
      } finally {
        if (active()) setLoading(false);
      }
    })();
    return () => controller.abort();
  }, [criteria]);

  // Backend Capture Window API는 session_id/from/to를 반드시 요구합니다.
  // 조회한 Packet Feature에 있는 Session만 선택 가능하게 하여 임의 Session 요청을 막습니다.
  const captureSessions = useMemo(() => {
    if (result?.kind !== "packet") return [];
    return [...new Set(result.rows.map(sessionId).filter((id) =>
      id !== null && id !== undefined && String(id).trim() !== ""
    ).map(String))];
  }, [result]);
  const captureSession = captureSessions.includes(preferredSession)
    ? preferredSession
    : captureSessions[0] ?? "";

  useEffect(() => {
    if (result?.kind !== "packet") return undefined;
    if (!captureSession) {
      setMeta({ data: null, loading: false, error: "" });
      return undefined; // Feature가 없으면 Session ID를 알 수 없어 메타 요청은 보류.
    }
    const controller = new AbortController();
    let valid = true;
    setMeta({ data: null, loading: true, error: "" });
    (async () => {
      try {
        const response = unpackList(await getPacketCaptureWindows({
          session_id: captureSession,
          from: result.criteria.from,
          to: result.criteria.to,
          limit: MAX_CAPTURE_METADATA,
          offset: 0,
        }, { signal: controller.signal }), "Capture Windows");
        if (!valid || controller.signal.aborted) return;
        setMeta({
          data: {
            items: response.items,
            incomplete: !response.totalKnown || response.total > response.items.length,
          },
          loading: false,
          error: "",
        });
      } catch (err) {
        if (!valid || controller.signal.aborted || err?.isCanceled) return;
        setMeta({ data: null, loading: false, error: err?.message || "조회 실패" });
      }
    })();
    return () => { valid = false; controller.abort(); };
  }, [result, captureSession]);

  const chart = useMemo(() => result ? chartRows(result.rows, result.kind) : [], [result]);
  const excluded = useMemo(() => result?.kind === "packet"
    ? result.rows.filter((row) => !normalizePacketRow(row).qualityOk).length
    : 0,
  [result]);
  const knownGap = useMemo(() => {
    if (!result) return 0;
    let gaps = 0;
    for (let i = 1; i < result.rows.length; i += 1) {
      const a = featureTime(result.rows[i - 1].window_start);
      const b = featureTime(result.rows[i].window_start);
      if (Number.isFinite(a) && Number.isFinite(b) && b - a > WINDOW_SECONDS * 1500) gaps += 1;
    }
    return gaps;
  }, [result]);

  return (
    <section className="panel traffic-trends-panel" aria-label="기기별 MQTT Packet 통신 추이">
      <div className="panel-header">
        <div>
          <h2>기기별 MQTT / Packet 통신 추이</h2>
          <p className="panel-description">기기 한 대와 고정 기간을 선택해 통신 추이를 조회합니다. 표시 시각은 KST입니다.</p>
        </div>
      </div>
      <form className="traffic-trends-form" onSubmit={submit}>
        <label>기기
          <select value={deviceId} onChange={(e) => setDeviceId(e.target.value)} disabled={!deviceOptions.length}>
            {!deviceOptions.length && <option value="">기기 없음</option>}
            {deviceOptions.map((id) => <option key={id} value={id}>{id}</option>)}
          </select>
        </label>
        <label>시작 (KST)
          <input type="datetime-local" value={fromInput} onChange={(e) => setFromInput(e.target.value)} />
        </label>
        <label>종료 (KST)
          <input type="datetime-local" value={toInput} onChange={(e) => setToInput(e.target.value)} />
        </label>
        {tab === "packet" && (
          <label>통신 방향
            <select value={direction} onChange={(e) => setDirection(e.target.value)}>
              <option value="INBOUND">기기 → Pi</option>
              <option value="OUTBOUND">Pi → 기기</option>
            </select>
          </label>
        )}
        <button type="submit" className="button button-secondary" disabled={loading || !deviceId}>기간 적용 / 재조회</button>
      </form>
      {deviceError && <p role="alert" className="traffic-trends-error">기기 목록: {deviceError}</p>}
      {rangeError && <p role="alert" className="traffic-trends-error">{rangeError}</p>}
      <div className="traffic-trends-tabs" role="group" aria-label="통신 데이터 선택">
        <button type="button" className={tab === "mqtt" ? "selected" : ""} aria-pressed={tab === "mqtt"} onClick={() => setTab("mqtt")}>MQTT</button>
        <button type="button" className={tab === "packet" ? "selected" : ""} aria-pressed={tab === "packet"} onClick={() => setTab("packet")}>Packet</button>
      </div>
      {loading && <p className="traffic-trends-status" role="status">{criteria?.device_id} 조회 중... 여러 페이지를 순차 확인합니다.</p>}
      {error && <p className="traffic-trends-error" role="alert">조회 실패: {error} (0건으로 간주하지 않습니다.)</p>}
      {!loading && result && (
        <>
          <div className="traffic-trends-summary">
            <span>대상: <strong>{result.criteria.device_id}</strong></span>
            <span>구간: {kstFull(result.criteria.from)} ~ {kstFull(result.criteria.to)}</span>
            <span>조회: <strong>{result.rows.length}</strong>건 / 서버 전체 {result.total === null ? "미제공" : result.total}건</span>
            {result.kind === "packet" && <span>품질 미확인·제외: {excluded}건</span>}
            {knownGap > 0 && <span>관찰된 시간 공백: {knownGap}개</span>}
          </div>
          {(result.incomplete || result.warning) && (
            <p className="traffic-trends-error" role="alert">
              불완전 조회: {result.warning || "일부 행만 표시됩니다."} 이 그래프를 전체 기간의 완전한 결과로 해석하지 마세요.
            </p>
          )}
          <p className="traffic-trends-qualification">
            from/to는 고정하고 ID 중복을 제거한 후 분석 구간 시각순으로 표시했습니다.
            다만 백엔드 snapshot_max_id가 제공되지 않은 offset 조회이므로 조회 중 데이터 추가 시 완전한 스냅샷을 보장하지 않습니다.
          </p>
          {result.rows.length === 0 ? (
            <div className="traffic-trends-empty">분석 지표 행이 없습니다. 무통신이나 정상 상태로 단정할 수 없습니다.</div>
          ) : result.kind === "mqtt" ? (
            <div className="traffic-trends-charts">
              <MetricsChart data={chart} title="MQTT 메시지 발행 수" unit="건 / 10초" lines={[{ key: "publish_count", label: "발행 수", color: "#2563eb" }]} />
              <MetricsChart data={chart} title="MQTT 메시지 크기" unit="B" lines={[
                { key: "avg_payload_size", label: "평균", color: "#16a34a" },
                { key: "max_payload_size", label: "최대", color: "#ef4444" },
              ]} />
              <MetricsChart data={chart} title="MQTT 메시지 간격" unit="초 (s)" lines={[
                { key: "avg_message_interval", label: "평균", color: "#9333ea" },
                { key: "min_message_interval", label: "최소", color: "#f97316" },
              ]} />
              <p className="traffic-trends-qualification">메시지 1건 분석 구간의 간격 5.0초는 기존 대체값 계약이며 실측 간격으로 해석하지 않습니다.</p>
            </div>
          ) : (
            <div className="traffic-trends-charts">
              <MetricsChart isPacket data={chart} title="실제 초당 패킷 수" unit="pps" lines={[{ key: "packets_per_second", label: "실제 PPS", color: "#2563eb" }]} />
              <MetricsChart isPacket data={chart} title="실제 초당 전송량" unit="B/s" lines={[{ key: "bytes_per_second", label: "실제 B/s", color: "#16a34a" }]} />
              <p className="traffic-trends-qualification">분석 제외·FAILED·품질 미확인 분석 구간는 수치를 연결하지 않습니다. 수집 세션 변화와 10초 초과 공백도 선을 끊습니다.</p>
            </div>
          )}
          {result.kind === "packet" && (
            <>
              {captureSessions.length > 1 && (
                <label className="traffic-trends-session-selector">
                  수집 근거를 조회할 수집 세션
                  <select value={captureSession} onChange={(event) => setPreferredSession(event.target.value)}>
                    {captureSessions.map((value) => <option key={value} value={value}>{value}</option>)}
                  </select>
                </label>
              )}
              <CaptureEvidence data={meta.data} loading={meta.loading} error={meta.error} missingSession={!captureSession} />
            </>
          )}
        </>
      )}
      {!loading && !result && !error && <p className="traffic-trends-status">조회할 기기와 기간을 선택해 주세요.</p>}
    </section>
  );
}
