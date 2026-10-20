import { uiLabel } from "../utils/uiText";
import {

  useCallback,

  useEffect,

  useMemo,

  useRef,

  useState,

} from "react";

import {

  getPacketFeatureLogs,
  getPacketCaptureWindows,

} from "../api/api";

import DataTable from "../components/DataTable";

import EmptyState from "../components/EmptyState";

import PageHeader from "../components/PageHeader";

import Pagination from "../components/Pagination";

import StatusBadge from "../components/StatusBadge";

import SummaryCard from "../components/SummaryCard";

import {

  getCaptureStatus,

  getCaptureStatusLabel,

  getExclusionLabel,

  matchesCaptureStatusFilter,

} from "../utils/packetCaptureStatus";

import DeviceTrafficTrends from "../components/DeviceTrafficTrends";
import DateTimePicker from "../components/DateTimePicker";
import "../styles/pages/PacketTraffic.scss"

const DEFAULT_LIMIT = 20;

const POLLING_INTERVAL_MS = 10_000;

const IS_DEV = import.meta.env.DEV;

/*

 * DateTime을 한국 시간으로 표시합니다.

 */

function formatKST(dateString) {

  if (!dateString) {

    return "-";

  }

  const date = new Date(dateString);

  if (Number.isNaN(date.getTime())) {

    return "-";

  }

  return new Intl.DateTimeFormat(

    "ko-KR",

    {

      timeZone: "Asia/Seoul",

      year: "numeric",

      month: "2-digit",

      day: "2-digit",

      hour: "2-digit",

      minute: "2-digit",

      second: "2-digit",

      hour12: false,

    }

  ).format(date);

}

function formatNumber(

  value,

  maximumFractionDigits = 2

) {

  if (

    value === null ||

    value === undefined ||

    value === ""

  ) {

    return "-";

  }

  const number = Number(value);

  if (!Number.isFinite(number)) {

    return "-";

  }

  return number.toLocaleString(

    "ko-KR",

    {

      maximumFractionDigits,

    }

  );

}

function formatPercent(value) {

  if (

    value === null ||

    value === undefined ||

    value === ""

  ) {

    return "계산 불가";

  }

  const number = Number(value);

  if (!Number.isFinite(number)) {

    return "계산 불가";

  }

  return `${formatNumber(

    number * 100,

    1

  )}%`;

}

function formatDuration(value) {

  if (

    value === null ||

    value === undefined ||

    value === ""

  ) {

    return "계산 불가";

  }

  const number = Number(value);

  if (!Number.isFinite(number)) {

    return "계산 불가";

  }

  return `${formatNumber(

    number,

    2

  )}초`;

}

function formatRate(

  value,

  suffix

) {

  if (

    value === null ||

    value === undefined ||

    value === ""

  ) {

    return "계산 불가";

  }

  const number = Number(value);

  if (!Number.isFinite(number)) {

    return "계산 불가";

  }

  return `${formatNumber(

    number,

    2

  )} ${suffix}`;

}

function normalizeSearchValue(value) {

  return String(value ?? "")

    .trim()

    .toLowerCase();

}

function getSessionId(item) {

  return (

    item.capture_session_id ||

    item.session_id ||

    ""

  );

}

function getCoverageStatus(

  coverageRatio

) {

  const coverage =

    Number(coverageRatio);

  if (!Number.isFinite(coverage)) {

    return "unknown";

  }

  if (coverage >= 0.9) {

    return "normal";

  }

  if (coverage >= 0.7) {

    return "warning";

  }

  return "danger";

}

/* Phase 9: Packet Capture Windows (Packet Feature 목록과 분리하여 조회) */
function captureWindowList(response) {
  const root = response?.item ?? response;
  if (Array.isArray(root)) return { items: root, total: root.length };
  if (Array.isArray(root?.items)) return { items: root.items, total: root.total };
  if (Array.isArray(root?.windows)) return { items: root.windows, total: root.total };
  throw new Error("수집 구간 응답 형식을 확인할 수 없습니다.");
}

function captureWindowField(item, ...keys) {
  for (const key of keys) {
    const value = item?.[key];
    if (value !== null && value !== undefined && value !== "") return value;
  }
  return null;
}

const CAPTURE_OBSERVATION_THEMES = {
  FAILED: "failed",
  PROCESSED: "processed",
  EMPTY: "captured",
  PENDING: "pending",
  MISSING: "missing",
};

function captureWindowObservation(item) {
  const status = captureWindowField(item, "observation", "status", "capture_status", "segment_status");
  const normalized = String(status ?? "UNKNOWN").toUpperCase();
  return normalized === "READY" ? "PENDING" : normalized;
}

function captureWindowDisplay(value) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "boolean") return value ? "예" : "아니요";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

// Capture Window API는 session_id/from/to 세 파라미터가 모두 필수입니다.
// Packet Feature의 실제 Session과 시각을 사용하거나 관리자가 알려준 Session/기간을 입력합니다.
const CAPTURE_KST_OFFSET_MS = 9 * 60 * 60 * 1000;
function captureToKstInput(timestamp) {
  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) return "";
  return new Date(parsed.getTime() + CAPTURE_KST_OFFSET_MS).toISOString().slice(0, 19);
}
function captureKstToISO(localInput) {
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?$/.test(localInput)) return null;
  const parsed = new Date(`${localInput}+09:00`);
  return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
}
function availableCaptureSessions(features) {
  const sessions = new Map();
  for (const item of features) {
    const session = item?.capture_session_id ?? item?.session_id;
    if (session === null || session === undefined || String(session).trim() === "") continue;
    const start = Date.parse(item.window_start ?? "");
    const end = Date.parse(item.window_end ?? "");
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) continue;
    const id = String(session);
    const prev = sessions.get(id);
    sessions.set(id, {
      id,
      start: Math.min(prev?.start ?? start, start),
      end: Math.max(prev?.end ?? end, end),
    });
  }
  return [...sessions.values()].sort((a, b) => b.end - a.end);
}

function PacketCaptureWindows({ featureRows = [] }) {
  const [items, setItems] = useState([]);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [sessionInput, setSessionInput] = useState("");
  const [fromInput, setFromInput] = useState("");
  const [toInput, setToInput] = useState("");
  const didAutofillRef = useRef(false);
  const sessionOptions = useMemo(() => availableCaptureSessions(featureRows), [featureRows]);

  // 현재 조회 페이지에 Session/Window가 있으면 처음 한 번만 자동 입력합니다.
  // 사용자가 직접 입력한 값은 10초 Polling으로 덮어쓰지 않습니다.
  useEffect(() => {
    if (didAutofillRef.current || !sessionOptions.length) return;
    didAutofillRef.current = true;
    if (sessionInput.trim()) return;
    const first = sessionOptions[0];
    setSessionInput(first.id);
    setFromInput(captureToKstInput(first.start));
    setToInput(captureToKstInput(first.end));
  }, [sessionOptions, sessionInput]);

  const fromISO = captureKstToISO(fromInput);
  const toISO = captureKstToISO(toInput);
  const queryValidation = !sessionInput.trim()
    ? "실제 수집 세션 ID가 필요합니다. 아래 패킷 분석 지표 목록에서 자동으로 가져오거나 팀원에게 전달받아 입력해 주세요."
    : !fromISO || !toISO
      ? "조회 시작·종료 시각(KST)을 모두 입력해 주세요."
      : Date.parse(fromISO) >= Date.parse(toISO)
        ? "종료 시각은 시작 시각보다 늦어야 합니다."
        : "";
  const query = useMemo(() => queryValidation ? null : {
    session_id: sessionInput.trim(), from: fromISO, to: toISO,
  }, [queryValidation, sessionInput, fromISO, toISO]);
  const queryKey = query ? `${query.session_id}|${query.from}|${query.to}` : "";
  const [lastUpdated, setLastUpdated] = useState("");
  const [filter, setFilter] = useState("");
  const controllerRef = useRef(null);
  const requestIdRef = useRef(0);
  const pageSize = 10;

  const refresh = useCallback(async () => {
    if (!query) return; // session_id/from/to 없이 서버를 호출하지 않습니다.
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    const id = ++requestIdRef.current;
    setLoading(true);
    try {
      const response = await getPacketCaptureWindows(
        query,
        { signal: controller.signal }
      );
      if (controller.signal.aborted || id !== requestIdRef.current) return;
      const normalized = captureWindowList(response);
      setItems(normalized.items);
      setLastUpdated(new Date().toISOString());
      setError("");
    } catch (err) {
      if (controller.signal.aborted || err?.isCanceled || id !== requestIdRef.current) return;
      setError(err?.message || "수집 구간 조회에 실패했습니다.");
    } finally {
      if (id === requestIdRef.current) setLoading(false);
    }
  }, [query]);

  useEffect(() => {
    if (!queryKey) {
      controllerRef.current?.abort();
      setItems([]);
      setLastUpdated("");
      setError("");
      setLoading(false);
      return undefined;
    }
    // Session 및 기간이 바뀌었으면 이전 Session의 성공 값을 남기지 않습니다.
    setOffset(0);
    setItems([]);
    setLastUpdated("");
    refresh();
    const timer = window.setInterval(refresh, 30000);
    return () => {
      window.clearInterval(timer);
      controllerRef.current?.abort();
    };
  }, [refresh, queryKey]);

  const changeSession = (value) => {
    setSessionInput(value);
    setOffset(0);
    const matched = sessionOptions.find((option) => option.id === value);
    if (matched) {
      setFromInput(captureToKstInput(matched.start));
      setToInput(captureToKstInput(matched.end));
    }
  };

  // API는 조회 구간 전체를 반환하므로 상태 필터와 페이지 분할은 로컬에서 적용합니다.
  const filteredItems = useMemo(() => items.filter((item) => {
    return !filter || captureWindowObservation(item) === filter;
  }), [items, filter]);
  const visibleItems = filteredItems.slice(offset, offset + pageSize);
  const total = filteredItems.length;
  const hasNext = offset + pageSize < total;

  useEffect(() => {
    setOffset((value) => Math.min(value, Math.max(0, Math.ceil(total / pageSize) - 1) * pageSize));
  }, [total]);

  return (
    <section className="panel packet-capture-panel">
      <div className="panel-header">
        <div>
          <h2>패킷 수집 구간</h2>
          <p className="panel-description">
            수집 구간의 상태와 수집 시간 충족률를 표시합니다. 수집 공백은 AI 추론 실패와 다르며,
            수집 품질 저하만으로 공격 또는 격리를 의미하지 않습니다.
          </p>
        </div>
        <button type="button" className="button button-ghost" onClick={refresh} disabled={loading || !queryKey}>
          수집 상태 새로고침
        </button>
      </div>
      {error && (
        <div className="page-warning-banner" role="alert">
          <div><strong>수집 구간 조회 실패</strong><p>{error} {lastUpdated ? "이전에 수신한 데이터를 표시합니다." : ""}</p></div>
        </div>
      )}
      <details className="packet-capture-details">
        <summary>수집 구간 상세 조회</summary>
        <div className="packet-capture-query-form">
          <label className="filter-item" htmlFor="capture-session-input">
            <span>수집 세션 ID (필수)</span>
            <input
              id="capture-session-input"
              list="capture-session-suggestions"
              value={sessionInput}
              onChange={(event) => changeSession(event.target.value)}
              placeholder="실제 capture_session_id"
              autoComplete="off"
            />
            <datalist id="capture-session-suggestions">
              {sessionOptions.map((option) => <option key={option.id} value={option.id} />)}
            </datalist>
          </label>
          <div className="filter-item">
            <label htmlFor="capture-window-from">시작 (KST, 필수)</label>
            <DateTimePicker id="capture-window-from" label="수집 구간 시작 (KST)" withSeconds value={fromInput}
              onChange={(value) => { setFromInput(value); setOffset(0); }} />
          </div>
          <div className="filter-item">
            <label htmlFor="capture-window-to">종료 (KST, 필수)</label>
            <DateTimePicker id="capture-window-to" label="수집 구간 종료 (KST)" withSeconds value={toInput}
              onChange={(value) => { setToInput(value); setOffset(0); }} />
          </div>
        </div>
        {queryValidation && <p className="command-note" role="status">조회 대기: {queryValidation} 서버로 잘못된 요청을 보내지 않습니다.</p>}
        <div className="packet-capture-toolbar">
          <label htmlFor="capture-window-status">표시 상태</label>
          <select id="capture-window-status" value={filter} onChange={(event) => { setFilter(event.target.value); setOffset(0); }}>
            <option value="">전체 (조회 구간)</option>
            <option value="PROCESSED">수집 처리 완료</option>
            <option value="EMPTY">패킷 없음</option>
            <option value="MISSING">수집 자료 누락</option>
            <option value="FAILED">수집 실패</option>
            <option value="PENDING">처리 대기</option>
          </select>
          <small>필터는 조회 구간 전체에 적용됩니다.</small>
        </div>
        {!queryKey ? null : loading && !lastUpdated ? (
          <p className="section-unavailable">수집 구간을 조회하는 중입니다.</p>
        ) : !lastUpdated ? (
          <EmptyState title="수집 구간 정보를 확인할 수 없습니다." compact />
        ) : visibleItems.length === 0 ? (
          <EmptyState title="표시할 수집 구간이 없습니다." description="조회 결과가 없거나 상태 필터와 일치하지 않습니다." compact />
        ) : (
          <div className="table-scroll">
            <table className="packet-window-table">
              <thead><tr>
                <th>분석 구간 / 수집 세션</th><th>시작</th><th>종료</th><th>상태</th><th>수집 시간 충족률</th><th>분석 가능</th><th>제외·오류 사유</th>
              </tr></thead>
              <tbody>{visibleItems.map((item, index) => {
                const id = captureWindowField(item, "segment_id", "id", "window_id", "capture_window_id", "capture_session_id", "session_id");
                const status = captureWindowObservation(item);
                const coverage = captureWindowField(item, "coverage_ratio");
                const eligible = captureWindowField(item, "capture_eligible", "eligible");
                const reason = captureWindowField(item, "capture_exclusion_reason", "exclusion_reason", "segment_error_code", "error_code", "last_error");
                return (
                  <tr key={`${captureWindowDisplay(id)}-${offset + index}`}>
                    <td className="packet-window-identifier">{captureWindowDisplay(id)}</td>
                    <td>{formatKST(captureWindowField(item, "window_start", "started_at", "start_at"))}</td>
                    <td>{formatKST(captureWindowField(item, "window_end", "ended_at", "end_at"))}</td>
                    <td><StatusBadge status={CAPTURE_OBSERVATION_THEMES[status] ?? "unknown"} label={status} size="small" /></td>
                    <td>{formatPercent(coverage)}</td>
                    <td>{eligible === null ? "-" : eligible === true ? "가능" : eligible === false ? "제외" : captureWindowDisplay(eligible)}</td>
                    <td>{uiLabel(reason)}</td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
        )}
        {lastUpdated && (
          <div className="packet-capture-footer">
            <span>마지막 조회: {formatKST(lastUpdated)}</span>
            <div className="packet-capture-pagination">
              <button type="button" className="button button-secondary" disabled={loading || offset === 0} onClick={() => setOffset((n) => Math.max(0, n - pageSize))}>이전</button>
              <span>시작 위치 {total ? offset + 1 : 0} · 전체 {formatNumber(total, 0)}건</span>
              <button type="button" className="button button-secondary" disabled={loading || !hasNext} onClick={() => setOffset((n) => n + pageSize)}>다음</button>
            </div>
          </div>
        )}
      </details>
    </section>
  );
}

export default function PacketTraffic() {

  const [

    packetFeatures,

    setPacketFeatures,

  ] = useState([]);

  const [total, setTotal] =

    useState(0);

  const [direction, setDirection] =

    useState("");

  const [captureStatus, setCaptureStatus] =

    useState("");

  const [offset, setOffset] =

    useState(0);

  const [searchText, setSearchText] =

    useState("");

  const [loading, setLoading] =

    useState(true);

  const [refreshing, setRefreshing] =

    useState(false);

  const [error, setError] =

    useState("");

  const [pollWarning, setPollWarning] =

    useState("");

  const [lastUpdated, setLastUpdated] =

    useState("");

  const featureRequestRef = useRef(null);
  const featureRequestIdRef = useRef(0);

  const hasDataRef = useRef(false);

  const loadPacketFeatures = useCallback(async (manual = false) => {
    const previous = featureRequestRef.current;
    if (!manual && previous?.offset === offset && previous?.direction === direction &&
        !previous.controller.signal.aborted) return;

    previous?.controller.abort();
    const controller = new AbortController();
    const requestId = ++featureRequestIdRef.current;
    featureRequestRef.current = { controller, offset, direction };
    if (manual) setRefreshing(true);

    try {
      const data = await getPacketFeatureLogs(
        { limit: DEFAULT_LIMIT, offset, direction: direction || undefined },
        { signal: controller.signal }
      );
      if (controller.signal.aborted || requestId !== featureRequestIdRef.current) return;
      if (!Array.isArray(data?.items)) throw new Error("패킷 분석 지표 응답 형식을 확인할 수 없습니다.");
      const items = data.items;
      setPacketFeatures(items);
      const responseTotal = Number(data.total);
      setTotal(Number.isFinite(responseTotal) ? responseTotal : items.length);
      setLastUpdated(new Date().toISOString());
      hasDataRef.current = true;
      setError("");
      setPollWarning("");
    } catch (err) {
      if (controller.signal.aborted || err?.isCanceled || requestId !== featureRequestIdRef.current) return;
      if (IS_DEV) console.error("Packet feature load failed:", err);
      const message = err instanceof Error ? err.message : "패킷 통신 데이터를 불러오지 못했습니다.";
      if (hasDataRef.current) setPollWarning(message);
      else setError(message);
    } finally {
      if (requestId === featureRequestIdRef.current) {
        setLoading(false);
        setRefreshing(false);
        featureRequestRef.current = null;
      }
    }
  }, [offset, direction]);

  useEffect(() => {
    loadPacketFeatures();
    const pollingTimer = window.setInterval(() => loadPacketFeatures(), POLLING_INTERVAL_MS);
    return () => {
      window.clearInterval(pollingTimer);
      featureRequestRef.current?.controller.abort();
    };
  }, [loadPacketFeatures]);

  const filteredItems =

    useMemo(() => {

      const keyword =

        searchText

          .trim()

          .toLowerCase();

      return packetFeatures.filter(

        (item) => {

          if (

            !matchesCaptureStatusFilter(

              item,

              captureStatus

            )

          ) {

            return false;

          }

          if (!keyword) {

            return true;

          }

          const sessionId =

            getSessionId(item);

          return (

            normalizeSearchValue(

              item.device_id

            ).includes(keyword) ||

            normalizeSearchValue(

              item.peer_ip

            ).includes(keyword) ||

            normalizeSearchValue(

              sessionId

            ).includes(keyword) ||

            normalizeSearchValue(

              item.capture_segment_id

            ).includes(keyword)

          );

        }

      );

    }, [

      packetFeatures,

      searchText,

      captureStatus,

    ]);

  const pageSummary =

    useMemo(() => {

      const registeredDevices =

        new Set();

      const unmappedIps =

        new Set();

      let eligibleCount = 0;

      let excludedCount = 0;

      let failedCount = 0;

      const effectivePpsValues = [];

      packetFeatures.forEach(

        (item) => {

          if (item.device_id) {

            registeredDevices.add(

              item.device_id

            );

          } else if (item.peer_ip) {

            unmappedIps.add(

              item.peer_ip

            );

          }

          const captureState =

            getCaptureStatus(item);

          if (captureState === "failed") {

            failedCount += 1;

          } else if (captureState === "eligible") {

            eligibleCount += 1;

          } else if (captureState === "excluded") {

            excludedCount += 1;

          }

          const effectivePps =

            Number(

              item.effective_packets_per_second

            );

          if (

            Number.isFinite(

              effectivePps

            )

          ) {

            effectivePpsValues.push(

              effectivePps

            );

          }

        }

      );

      const averageEffectivePps =

        effectivePpsValues.length > 0

          ? effectivePpsValues.reduce(

            (sum, value) =>

              sum + value,

            0

          ) /

          effectivePpsValues.length

          : null;

      return {

        registeredDeviceCount:

          registeredDevices.size,

        unmappedIpCount:

          unmappedIps.size,

        eligibleCount,

        excludedCount,

        failedCount,

        averageEffectivePps,

      };

    }, [packetFeatures]);

  const currentPage =

    Math.floor(

      offset / DEFAULT_LIMIT

    ) + 1;

  const totalPages =

    Math.max(

      1,

      Math.ceil(

        total / DEFAULT_LIMIT

      )

    );

  function handleRefresh() {

    loadPacketFeatures(true);

  }

  function handleDirectionChange(

    value

  ) {

    setDirection(value);

    setOffset(0);

  }

  function handleCaptureStatusChange(

    value

  ) {

    setCaptureStatus(value);

    setOffset(0);

  }

  function handleResetFilters() {

    setDirection("");

    setCaptureStatus("");

    setSearchText("");

    setOffset(0);

  }

  function handlePrevPage() {

    setOffset((currentOffset) =>

      Math.max(

        0,

        currentOffset -

        DEFAULT_LIMIT

      )

    );

  }

  function handleNextPage() {

    setOffset((currentOffset) =>

      currentOffset +

      DEFAULT_LIMIT

    );

  }

  const columns = [

    {

      key: "capture_session_id",

      header: "수집 세션",

      width: 120,

      render: (_, item) => {

        const sessionId =

          getSessionId(item);

        return (

          <span

            className="truncate"

            title={sessionId || ""}

          >

            {sessionId

              ? sessionId.slice(0, 8)

              : "-"}

          </span>

        );

      },

    },

    {

      key: "capture_segment_id",

      header: "수집 구간",

      align: "right",

      width: 90,

      render: (value) =>

        formatNumber(value, 0),

    },

    {

      key: "device_id",

      header: "기기",

      width: 130,

      render: (value, item) => (

        <div className="device">

          <StatusBadge

            status={

              value

                ? "connected"

                : "unknown"

            }

            label={

              value ||

              "미매핑 IP"

            }

            size="small"

          />

          {!value &&

            item.peer_ip && (

              <small>

                {item.peer_ip}

              </small>

            )}

        </div>

      ),

    },

    {

      key: "peer_ip",

      header: "상대 IP",

      width: 130,

    },

    {

      key: "direction",

      header: "통신 방향",

      width: 110,

      render: (value) => (

        <StatusBadge

          status={value}

          size="small"

        />

      ),

    },

    {

      key: "window_start",

      header: "분석 구간",

      width: 210,

      render: (_, item) => (

        <div className="window">

          <span>

            {formatKST(

              item.window_start

            )}

          </span>

          <span className="window-separator">

            ~

          </span>

          <span>

            {formatKST(

              item.window_end

            )}

          </span>

        </div>

      ),

    },

    {

      key: "packet_count",

      header: "패킷 수",

      align: "right",

      width: 90,

      render: (value) =>

        formatNumber(value, 0),

    },

    {

      key: "total_bytes",

      header: "총 전송량",

      align: "right",

      width: 110,

      render: (value) =>

        formatNumber(value, 0),

    },

    {

      key: "nominal_packets_per_second",

      header: <span className="rate-column-heading">PPS<small>10초 기준</small></span>,

      align: "right",

      width: 100,

      render: (value, item) =>

        formatRate(

          value ??

          item.packets_per_second,

          "pps"

        ),

    },

    {

      key: "effective_packets_per_second",

      header: <span className="rate-column-heading">PPS<small>수집시간 기준</small></span>,

      align: "right",

      width: 110,

      render: (value) => (

        <span

          className={

            value === null ||

              value === undefined

              ? "metric-unavailable"

              : "metric-highlight"

          }

        >

          {formatRate(

            value,

            "pps"

          )}

        </span>

      ),

    },

    {

      key: "nominal_bytes_per_second",

      header: <span className="rate-column-heading">BPS<small>10초 기준</small></span>,

      align: "right",

      width: 110,

      render: (value, item) =>

        formatRate(

          value ??

          item.bytes_per_second,

          "B/s"

        ),

    },

    {

      key: "effective_bytes_per_second",

      header: <span className="rate-column-heading">BPS<small>수집시간 기준</small></span>,

      align: "right",

      width: 110,

      render: (value) => (

        <span

          className={

            value === null ||

              value === undefined

              ? "metric-unavailable"

              : "metric-highlight"

          }

        >

          {formatRate(

            value,

            "B/s"

          )}

        </span>

      ),

    },

    {

      key: "captured_duration_seconds",

      header: "실제 수집시간",

      align: "right",

      width: 120,

      render: (value) =>

        formatDuration(value),

    },

    {

      key: "coverage_ratio",

      header: "수집 시간 충족률",

      align: "right",

      width: 110,

      render: (value) => (

        <StatusBadge

          status={

            getCoverageStatus(value)

          }

          label={formatPercent(value)}

          size="small"

        />

      ),

    },

    {

      key: "capture_eligible",

      header: "분석 상태",

      width: 110,

      render: (_, item) => (

        <StatusBadge

          status={

            getCaptureStatus(item)

          }

          label={

            getCaptureStatusLabel(

              item

            )

          }

          size="small"

        />

      ),

    },

    {

      key: "capture_exclusion_reason",

      header: "제외 사유",

      width: 150,

      render: (value, item) =>

        getExclusionLabel(

          value ||

          item.segment_error_code

        ),

    },

    {

      key: "avg_packet_size",

      header: "평균 크기",

      align: "right",

      width: 100,

      render: (value) =>

        formatNumber(value),

    },

    {

      key: "max_packet_size",

      header: "최대 크기",

      align: "right",

      width: 100,

      render: (value) =>

        formatNumber(value, 0),

    },

    {

      key: "mean_inter_arrival_time",

      header: "평균 도착 간격",

      align: "right",

      width: 130,

      render: (value) =>

        value === null ||

          value === undefined

          ? "-"

          : `${formatNumber(

            value,

            4

          )}초`,

    },

    {

      key: "distinct_dest_port_count",

      header: "목적지 Port",

      align: "right",

      width: 110,

      render: (value) =>

        formatNumber(value, 0),

    },

    {

      key: "tcp_syn_count",

      header: "TCP SYN",

      align: "right",

      width: 90,

      render: (value) =>

        formatNumber(value, 0),

    },

    {

      key: "mqtt_related_packet_count",

      header: "MQTT",

      align: "right",

      width: 80,

      render: (value) =>

        formatNumber(value, 0),

    },

    {

      key: "non_mqtt_tcp_udp_packet_count",

      header: "Non-MQTT",

      align: "right",

      width: 100,

      render: (value) =>

        formatNumber(value, 0),

    },

  ];

  return (

    <div className="packet-page">

      <PageHeader

        title="통신 분석"

        description="Raspberry Pi에서 수집한 패킷 분석 지표와 실제 수집 품질을 확인합니다."

        updatedAt={

          lastUpdated

            ? formatKST(

              lastUpdated

            )

            : undefined

        }

        onRefresh={handleRefresh}

        refreshing={refreshing}

      />

      <DeviceTrafficTrends />

      {pollWarning && (

        <div

          className="page-warning-banner"

          role="alert"

        >

          <div>

            <strong>

              최신 데이터 갱신 실패

            </strong>

            <p>

              {pollWarning}

              {" "}

              이전 데이터를 계속

              표시합니다.

            </p>

          </div>

          <div className="page-warning-actions">

            <span>

              {POLLING_INTERVAL_MS /

                1000}

              초마다 자동으로 다시

              요청합니다.

            </span>

            <button

              type="button"

              className="button button-secondary"

              onClick={handleRefresh}

              disabled={refreshing}

            >

              지금 다시 시도

            </button>

          </div>

        </div>

      )}

      {!loading &&

        !error &&

        packetFeatures.length >

        0 && (

          <section

            className="summary-card-grid"

            aria-label="패킷 통신 요약"

          >

            <SummaryCard

              title="전체 분석 지표"

              value={formatNumber(

                total,

                0

              )}

              description="조회 조건에 해당하는 전체 분석 구간"

            />

            <SummaryCard

              title="분석 가능"

              value={formatNumber(

                pageSummary.eligibleCount,

                0

              )}

              description="현재 페이지의 수집 품질 통과 분석 구간"

              status="normal"

            />

            <SummaryCard

              title="분석 제외"

              value={formatNumber(

                pageSummary.excludedCount,

                0

              )}

              description="현재 페이지에서 분석이 제외된 구간"

              status="warning"

            />

            <SummaryCard

              title="수집 실패"

              value={formatNumber(

                pageSummary.failedCount,

                0

              )}

              description="현재 페이지에서 수집에 실패한 구간"

              status="danger"

            />

            <SummaryCard

              title="등록 기기"

              value={formatNumber(

                pageSummary.registeredDeviceCount,

                0

              )}

              description="현재 페이지 고유 기기"

            />

            <SummaryCard

              title="미매핑 IP"

              value={formatNumber(

                pageSummary.unmappedIpCount,

                0

              )}

              description="기기와 연결되지 않은 고유 IP"

              status="unknown"

            />

            <SummaryCard

              title="평균 실제 PPS"

              value={

                pageSummary.averageEffectivePps ===

                  null

                  ? "계산 불가"

                  : formatNumber(

                    pageSummary.averageEffectivePps,

                    2

                  )

              }

              description="실제 수집시간 기준"

            />

          </section>

        )}

      <PacketCaptureWindows featureRows={packetFeatures} />

      <section className="panel table-panel">

        <div className="panel-header">

          <div>

            <h2>

              조회 조건

            </h2>

            <p className="panel-description">

              통신 방향은 전체 조회에 적용되고,

              검색어와 분석 상태는 현재 페이지 결과에 적용됩니다.

            </p>

          </div>

          <button

            type="button"

            className="button button-ghost"

            onClick={handleResetFilters}

            disabled={

              loading || refreshing

            }

          >

            필터 초기화

          </button>

        </div>

        <div className="filter-grid">

          <div className="filter-item">

            <label htmlFor="packet-search">

              기기·IP·수집 세션 검색

            </label>

            <input

              id="packet-search"

              type="search"

              placeholder="기기 ID, 상대 IP, 수집 세션 ID"

              value={searchText}

              onChange={(event) => {

                setSearchText(

                  event.target.value

                );

              }}

            />

          </div>

          <div className="filter-item">

            <label htmlFor="direction-filter">

              통신 방향

            </label>

            <select

              id="direction-filter"

              value={direction}

              onChange={(event) => {

                handleDirectionChange(

                  event.target.value

                );

              }}

            >

              <option value="">

                전체

              </option>

              <option value="INBOUND">

                기기 → Pi

              </option>

              <option value="OUTBOUND">

                Pi → 기기

              </option>

            </select>

          </div>

          <div className="filter-item">

            <label htmlFor="capture-status-filter">

              수집 분석 상태

            </label>

            <select

              id="capture-status-filter"

              value={captureStatus}

              onChange={(event) => {

                handleCaptureStatusChange(

                  event.target.value

                );

              }}

            >

              <option value="">

                전체

              </option>

              <option value="eligible">

                분석 가능

              </option>

              <option value="excluded">

                분석 제외

              </option>

            </select>

          </div>

        </div>

      </section>

      <section className="panel">

        <div className="panel-header">

          <div>

            <h2>

              패킷 분석 지표 목록

            </h2>

            <p className="panel-description">

              전송률은 10초 기준과 실제 수집시간 기준을 구분해 표시합니다.

            </p>

          </div>

          <span className="data-count">

            {formatNumber(

              filteredItems.length,

              0

            )}

            건 표시

          </span>

        </div>

        {searchText &&

          !loading &&

          !error &&

          packetFeatures.length > 0 &&

          filteredItems.length === 0 ? (

          <EmptyState

            title="검색 조건에 맞는 데이터가 없습니다."

            description="현재 페이지에서 다른 기기 ID, IP 또는 수집 세션 ID를 검색해 주세요."

            actionLabel="검색 초기화"

            onAction={() => setSearchText("")}

          />

        ) : (

          <div className="table-scroll">

            <DataTable

              columns={columns}

              rows={filteredItems}

              loading={loading}

              error={error}

              onRetry={handleRefresh}

              rowKey="id"

              minWidth={2500}

              tableLabel="패킷 분석 지표 목록"

              emptyTitle="표시할 패킷 분석 지표가 없습니다."

              emptyDescription="패킷 수집과 특징 추출 서비스가 정상적으로 실행 중인지 확인해 주세요."

              rowClassName={(item) => {

                if (item.segment_status === "FAILED") {

                  return "row-danger";

                }

                if (item.capture_eligible === false) {

                  return "row-warning";

                }

                return "";

              }}

            />

          </div>

        )}

        {!loading &&

          !error &&

          total > 0 && (

            <Pagination

              currentPage={

                currentPage

              }

              totalPages={

                totalPages

              }

              total={total}

              pageSize={

                DEFAULT_LIMIT

              }

              onPrevious={

                handlePrevPage

              }

              onNext={

                handleNextPage

              }

              disabled={refreshing}

            />

          )}

      </section>

    </div>

  );

}
