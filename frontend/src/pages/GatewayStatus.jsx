import { uiLabel } from "../utils/uiText";

import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  getGatewayMetrics,
  getRuntimeStatus,
} from "../api/api";

import EmptyState from "../components/EmptyState";
import ErrorState from "../components/ErrorState";
import LoadingState from "../components/LoadingState";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";

import "../styles/pages/GatewayStatus.scss";

const COLLECTION_INTERVAL_SECONDS = 10;
const ONLINE_THRESHOLD_MULTIPLIER = 3;
const ONLINE_THRESHOLD_SECONDS =
  COLLECTION_INTERVAL_SECONDS * ONLINE_THRESHOLD_MULTIPLIER;

const POLLING_INTERVAL_MS =
  COLLECTION_INTERVAL_SECONDS * 1000;

const STATUS_UPDATE_INTERVAL_MS = 1000;

// Keep diagnostics available normally; set false only for the demo server.
const SHOW_GATEWAY_DIAGNOSTICS =
  import.meta.env.VITE_SHOW_GATEWAY_DIAGNOSTICS !== "false";

/* =========================================================
   Formatting
========================================================= */

function formatKST(value) {
  if (!value) return "-";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "-";
  }

  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function formatMetric(
  value,
  unit = "",
  maximumFractionDigits = 2,
  minimumFractionDigits = 0
) {
  if (value === null || value === undefined || value === "") {
    return "측정 불가";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "측정 불가";
  }

  return (
    number.toLocaleString("ko-KR", {
      minimumFractionDigits,
      maximumFractionDigits,
    }) + unit
  );
}

function formatResourceValue(value) {
  return formatMetric(value, "", 1, 1);
}

function formatInteger(value) {
  return formatMetric(value, "", 0);
}

function formatElapsedTime(value, now = Date.now()) {
  if (!value) return "-";

  const time = new Date(value).getTime();

  if (!Number.isFinite(time)) {
    return "-";
  }

  const seconds = Math.max(
    0,
    Math.floor((now - time) / 1000)
  );

  if (seconds < 60) return `${seconds}초 전`;

  const minutes = Math.floor(seconds / 60);

  if (minutes < 60) return `${minutes}분 전`;

  const hours = Math.floor(minutes / 60);

  if (hours < 24) return `${hours}시간 전`;

  return `${Math.floor(hours / 24)}일 전`;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "object") {
    return JSON.stringify(value, null, 2);
  }

  return String(value);
}

function firstDefined(object, keys) {
  if (!object || typeof object !== "object") {
    return null;
  }

  for (const key of keys) {
    const value = object[key];

    if (
      value !== null &&
      value !== undefined &&
      value !== ""
    ) {
      return value;
    }
  }

  return null;
}

function normalizeApiRoot(response) {
  return response?.item ?? response ?? null;
}

/* =========================================================
   Gateway Status Helpers
========================================================= */

function getGatewayStatus(
  collectedAt,
  hasMetric,
  hasApiError,
  now
) {
  if (hasApiError && !hasMetric) {
    return "API_ERROR";
  }

  if (!hasMetric) {
    return "NO_DATA";
  }

  if (!collectedAt) {
    return "STALE";
  }

  const timestamp = new Date(collectedAt).getTime();

  if (!Number.isFinite(timestamp)) {
    return "STALE";
  }

  const elapsedSeconds = (now - timestamp) / 1000;

  return elapsedSeconds <= ONLINE_THRESHOLD_SECONDS
    ? "ONLINE"
    : "STALE";
}

function gatewayDescription(status) {
  const descriptions = {
    ONLINE:
      "최근 수집 주기 내에 게이트웨이 지표가 수신되었습니다.",
    STALE:
      "마지막 Metric 수집 이후 허용 시간이 지났습니다.",
    NO_DATA:
      "API 요청은 성공했지만 저장된 게이트웨이 지표가 없습니다.",
    API_ERROR:
      "게이트웨이 지표 API에 연결할 수 없습니다.",
  };

  return descriptions[status] || "게이트웨이 상태 확인 불가";
}

function gatewayTheme(status) {
  const themes = {
    ONLINE: "normal",
    STALE: "warning",
    NO_DATA: "unknown",
    API_ERROR: "danger",
  };

  return themes[status] || "unknown";
}

function resourceStatus(value) {
  if (value === null || value === undefined || value === "") {
    return "unknown";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "unknown";
  }

  if (number >= 90) return "danger";
  if (number >= 75) return "warning";

  return "normal";
}

function temperatureStatus(value) {
  if (value === null || value === undefined || value === "") {
    return "unknown";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "unknown";
  }

  if (number >= 80) return "danger";
  if (number >= 65) return "warning";

  return "normal";
}

/* =========================================================
   Network Interface Helpers
========================================================= */

function getInterfaceStatus(data) {
  if (!data) {
    return {
      status: "missing",
      label: "미인식",
      description: "인터페이스 정보가 응답에 없습니다.",
    };
  }

  if (data.exists === false) {
    return {
      status: "missing",
      label: "미인식",
      description: "운영체제에서 인터페이스를 찾지 못했습니다.",
    };
  }

  if (data.exists === true && data.is_up === false) {
    return {
      status: "down",
      label: "DOWN",
      description: "인터페이스는 존재하지만 비활성 상태입니다.",
    };
  }

  if (data.exists === true && data.is_up === true) {
    return {
      status: "connected",
      label: "연결됨",
      description: "인터페이스가 활성화되어 있습니다.",
    };
  }

  return {
    status: "unknown",
    label: "상태 미확인",
    description: "인터페이스 상태 필드가 충분하지 않습니다.",
  };
}

function getInterfaceRate(data, primary, legacy) {
  return data?.[primary] ?? data?.[legacy] ?? null;
}

function InterfaceCard({
  title,
  description,
  interfaceData,
}) {
  const state = getInterfaceStatus(interfaceData);

  const rxRate = getInterfaceRate(
    interfaceData,
    "rx_bytes_per_second",
    "rx_bytes_per_sec"
  );

  const txRate = getInterfaceRate(
    interfaceData,
    "tx_bytes_per_second",
    "tx_bytes_per_sec"
  );

  return (
    <article
      className={`interface-card interface-card-${state.status}`}
    >
      <header className="interface-header">
        <div className="interface-title">
          <div className="interface-title-row">
            <h3>{title}</h3>
            <StatusBadge
              status={state.status}
              label={state.label}
              size="small"
            />
          </div>
          {description && (
            <p className="interface-description">
              {description}
            </p>
          )}
        </div>
      </header>

      <div className="interface-name">
        <span>Interface:</span>
        <strong>
          {interfaceData?.interface_name || "미할당"}
        </strong>
      </div>

      <div className="interface-details">
        <div className="metric-item">
          <span>IP 주소</span>
          <strong>
            {interfaceData?.ip_address || "-"}
          </strong>
        </div>

        <div className="metric-item">
          <span>누적 RX</span>
          <strong>
            {formatMetric(interfaceData?.rx_bytes, " B", 0)}
          </strong>
        </div>

        <div className="metric-item">
          <span>누적 TX</span>
          <strong>
            {formatMetric(interfaceData?.tx_bytes, " B", 0)}
          </strong>
        </div>

        <div className="metric-item">
          <span>RX 전송률</span>
          <strong
            className={
              rxRate == null ? "metric-unavailable" : ""
            }
          >
            {formatMetric(rxRate, " B/s", 2)}
          </strong>
        </div>

        <div className="metric-item">
          <span>TX 전송률</span>
          <strong
            className={
              txRate == null ? "metric-unavailable" : ""
            }
          >
            {formatMetric(txRate, " B/s", 2)}
          </strong>
        </div>
      </div>

      <footer className="interface-footer">
        <p>{state.description}</p>

        {interfaceData?.exists === true &&
          interfaceData?.is_up === true &&
          (rxRate == null || txRate == null) && (
            <StatusBadge
              status="degraded"
              label="전송률 계산 불가"
              size="small"
            />
          )}
      </footer>
    </article>
  );
}

/* =========================================================
   Phase 9 - AI Runtime Helpers

   RuntimeStatusResponse의 관측 상태와 단계별 근거를 표시합니다.
   Desired 상태를 Actual 상태로 간주하지 않습니다.
========================================================= */

function extractRuntimeItems(data, now = Date.now()) {
  if (!data || typeof data !== "object") return [];

  const ageSeconds = (now - Date.parse(data.observed_at)) / 1000;
  const freshness = data.freshness === "FRESH" &&
    ageSeconds > data.max_age_seconds ? "STALE" : data.freshness;
  const current = freshness === "FRESH";
  const observation = {
    name: "AI Runtime",
    status: current ? data.status : "UNKNOWN",
    last_observation_status: data.last_observation_status,
    observed_at: data.observed_at,
    error_code: data.error_code ?? data.reason_code,
    freshness,
  };

  return [observation, ...(data.stages ?? []).map((stage) => ({
    ...stage,
    status: current ? stage.status : "UNKNOWN",
    last_observation_status: stage.status,
    observed_at: stage.observed_at ?? data.observed_at,
    freshness,
  }))];
}

function runtimeTitle(item, index) {
  return displayValue(
    firstDefined(item, [
      "runtime_name",
      "name",
      "detector",
      "detector_type",
      "pipeline",
      "component",
    ]) ?? `처리 단계 ${index + 1}`
  );
}

function getRuntimeField(item, type) {
  if (type === "desired") {
    return typeof item.enabled === "boolean"
      ? item.enabled ? "ENABLED" : "DISABLED"
      : null;
  }

  if (type === "actual") {
    return item.status ?? "UNKNOWN";
  }

  return null;
}

function runtimeTheme(value) {
  if (value === null || value === undefined || value === "") {
    return "unknown";
  }

  const normalized = String(value).toUpperCase();

  if (
    ["RUNNING", "ACTIVE", "HEALTHY", "READY", "INITIALIZED", "COMPLETED", "ONLINE"].includes(normalized)
  ) {
    return "normal";
  }

  if (
    ["DEGRADED", "PENDING", "STARTING", "STOPPING"].includes(normalized)
  ) {
    return "warning";
  }

  if (
    ["ERROR", "FAILED", "UNHEALTHY", "CRASHED"].includes(normalized)
  ) {
    return "danger";
  }

  if (
    ["OFF", "DISABLED", "STOPPED"].includes(normalized)
  ) {
    return "unknown";
  }

  return "unknown";
}

function runtimeLabel(value) {
  if (value === "INITIALIZED") return "준비 완료";
  if (value === "NO_INPUT") return "입력 대기";
  return uiLabel(value);
}

function RuntimeCard({ item, index }) {
  const desired = getRuntimeField(item, "desired");
  const actual = getRuntimeField(item, "actual");
  const actualLabel = runtimeLabel(actual);

  const model = item.model_version;
  const updatedAt = item.observed_at;
  const error = item.error_code;

  return (
    <article className="ai-runtime-card">
      <div className="ai-runtime-card-header">
        <strong>{runtimeDisplayName(runtimeTitle(item, index))}</strong>
        <StatusBadge
          status={runtimeTheme(actual)}
          label={actualLabel}
          size="small"
        />
      </div>

      <dl className="ai-runtime-list">
        <div>
          <dt>실행 설정</dt>
          <dd>{uiLabel(desired)}</dd>
        </div>

        <div>
          <dt>실제 관측 상태</dt>
          <dd>{actualLabel}</dd>
        </div>

        {model != null && String(model).trim() !== "" && (
          <div>
            <dt>모델</dt>
            <dd>{displayValue(model)}</dd>
          </div>
        )}

        <div>
          <dt>관측 시각</dt>
          <dd>{updatedAt ? formatKST(updatedAt) : "-"}</dd>
        </div>

        <div>
          <dt>관측 정보 최신 여부</dt>
          <dd>{uiLabel(item.freshness)}</dd>
        </div>

        {item.freshness !== "FRESH" && (
          <div>
            <dt>마지막 관측 상태</dt>
            <dd>{runtimeLabel(item.last_observation_status)}</dd>
          </div>
        )}

        {error != null && (
          <div className="ai-runtime-error">
            <dt>마지막 오류</dt>
            <dd>{displayValue(error)}</dd>
          </div>
        )}
      </dl>
    </article>
  );
}

function CompletionCard({ item }) {
  return (
    <article className="ai-runtime-card">
      <div className="ai-runtime-card-header">
        <strong>{displayValue(item.detector_name)}</strong>
        <StatusBadge
          status="unknown"
          label={`${uiLabel(item.evidence_status)} / ${uiLabel(item.freshness)}`}
          size="small"
        />
      </div>
      <dl className="ai-runtime-list">
        <div><dt>기기</dt><dd>{displayValue(item.device_id)}</dd></div>
        <div><dt>마지막 분석 완료 구간</dt><dd>{formatKST(item.completed_window_end)}</dd></div>
        <div><dt>모델</dt><dd>{displayValue(item.model_version)}</dd></div>
        <div><dt>추론 횟수 / 입력 수</dt><dd>{item.inference_count} / {item.input_count}</dd></div>
        <div><dt>정상 / 이상 판정 수</dt><dd>{item.normal_count} / {item.anomaly_count}</dd></div>
        <div><dt>분석 제외</dt><dd>{displayValue(item.exclusion_counts)}</dd></div>
      </dl>
    </article>
  );
}

function extractCompletionItems(data, runtimeFreshness, now = Date.now()) {
  return (data?.completions ?? []).map((item) => {
    const ageSeconds = (now - Date.parse(item.observed_at)) / 1000;
    const freshness = runtimeFreshness === "API_ERROR"
      ? "API_ERROR"
      : item.freshness === "FRESH" && ageSeconds > data.max_age_seconds
        ? "STALE" : item.freshness;
    const current = item.evidence_status === "CURRENT" &&
      runtimeFreshness === "FRESH" && freshness === "FRESH";
    return {
      ...item,
      evidence_status: current ? "CURRENT" : "HISTORICAL",
      freshness,
    };
  });
}

function runtimeDisplayName(name) {
  const names = {
    "AI Runtime": "탐지 엔진", mqtt_feature_rule: "MQTT 통계 규칙",
    mqtt_message_rule: "MQTT 메시지 규칙", mqtt_if: "MQTT AI",
    packet_rule: "패킷 규칙", packet_if: "패킷 AI",
  };
  return Object.hasOwn(names, name) ? names[name] : displayValue(name);
}

// The overview keeps the latest window per device and detector. Every original
// completion, including records without a device, remains in diagnostics.
function latestCompletionRows(items) {
  const rows = new Map();
  for (const item of items) {
    if (item.device_id == null || !String(item.device_id).trim()) continue;
    const key = JSON.stringify([item.device_id, item.detector_name]);
    const previous = rows.get(key);
    const timestamp = Date.parse(item.completed_window_end);
    const previousTime = Date.parse(previous?.completed_window_end);
    if (!previous || (Number.isFinite(timestamp) && (!Number.isFinite(previousTime) || timestamp > previousTime)) ||
        (timestamp === previousTime && item.evidence_status === "CURRENT" && previous.evidence_status !== "CURRENT")) {
      rows.set(key, item);
    }
  }
  return [...rows.values()].sort((a, b) =>
    String(a.device_id).localeCompare(String(b.device_id)) ||
    String(a.detector_name).localeCompare(String(b.detector_name)));
}

function runtimeIssues(items) {
  return items.filter((item, index) => {
    if (item.freshness !== "FRESH") return false;
    const status = getRuntimeField(item, "actual");
    if (item.error_code || ["ERROR", "FAILED", "UNHEALTHY", "CRASHED", "DEGRADED"].includes(status)) return true;
    return (index === 0 || item.enabled === true) && ["OFF", "DISABLED", "STOPPED", "UNKNOWN"].includes(status);
  });
}

function RuntimeOverview({ runtimeItems, completionItems, runtimeData, runtimeError, runtimeUpdatedAt, now }) {
  const actualStatus = runtimeItems[0]?.status ?? "UNKNOWN";
  const freshness = runtimeItems[0]?.freshness ?? "MISSING";
  const rows = latestCompletionRows(completionItems);
  const issues = runtimeIssues(runtimeItems);

  return (
    <>
      <div className="ai-runtime-overview-grid">
        <SummaryCard title="실제 실행 상태" value={actualStatus}
          description="탐지 엔진의 현재 관측 상태"
          status={actualStatus === "STOPPED" ? "warning" : runtimeTheme(actualStatus)} />
        <SummaryCard title="관측 정보 최신 여부" value={uiLabel(freshness)}
          description={`관측 시각: ${formatKST(runtimeItems[0]?.observed_at)}`}
          status={freshness === "FRESH" ? "normal" : freshness === "API_ERROR" ? "danger" : "warning"} />
      </div>
      <p className="ai-runtime-fetch-note">
        실행 정보 조회: {runtimeError ? "조회 실패" : "응답 수신"} · 최근 응답 {formatElapsedTime(runtimeUpdatedAt, now)}
      </p>

      {actualStatus === "UNKNOWN" && (
        <p className="ai-runtime-attention" role="alert">
          최신 실행 상태를 확인할 수 없습니다. 이전 관측과 완료 기록은 현재 실행을 보장하지 않습니다.
        </p>
      )}
      {issues.length > 0 && (
        <div className="ai-runtime-attention" role="alert">
          <strong>확인이 필요한 실행 상태</strong>
          <ul>{issues.map((item, index) => (
            <li key={`${item.name}-${index}`}>
              {runtimeDisplayName(item.name)}: {uiLabel(item.status)}{item.error_code ? ` · ${item.error_code}` : ""}
            </li>
          ))}</ul>
        </div>
      )}

      <div className="ai-completion-heading">
        <h3>기기별 최근 AI 분석</h3>
        <span>{rows.length}개 분석 결과</span>
      </div>
      <p className="ai-runtime-note">분석 완료 기록과 현재 실행 상태는 별개입니다. 추론 횟수와 판정 결과를 함께 확인하세요.</p>
      {rows.length ? (
        <div className="ai-completion-table-scroll">
          <table className="ai-completion-table" aria-label="기기별 최근 AI 분석">
            <thead><tr>
              <th scope="col">기기</th><th scope="col">분석기</th><th scope="col">최근 분석 완료 구간 (KST)</th>
              <th scope="col">추론 / 입력</th><th scope="col">정상 / 이상</th><th scope="col">완료 근거 상태</th>
            </tr></thead>
            <tbody>{rows.map((item) => (
              <tr key={JSON.stringify([item.device_id, item.detector_name])}>
                <td>{displayValue(item.device_id)}</td><td>{runtimeDisplayName(item.detector_name)}</td>
                <td>{formatKST(item.completed_window_end)}</td>
                <td>{formatInteger(item.inference_count)} / {formatInteger(item.input_count)}</td>
                <td>{formatInteger(item.normal_count)} / {formatInteger(item.anomaly_count)}</td>
                <td><StatusBadge status={item.evidence_status === "CURRENT" && item.freshness === "FRESH" ? "info" : "warning"}
                  label={`${uiLabel(item.evidence_status)} / ${uiLabel(item.freshness)}`} size="small" /></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : <p className="ai-runtime-note">기기별 분석 완료 근거를 아직 확인할 수 없습니다. 실행 중 표시만으로 추론 완료를 판단하지 않습니다.</p>}

      <details className="ai-runtime-raw ai-runtime-details">
        <summary>처리 단계 상세 · {runtimeItems.length}개 항목</summary>
        <div className="ai-runtime-grid">
          {runtimeItems.map((item, index) => <RuntimeCard key={`${item.name}-${index}`} item={item} index={index} />)}
        </div>
      </details>
      {SHOW_GATEWAY_DIAGNOSTICS && (
        <details className="ai-runtime-raw ai-runtime-diagnostics">
          <summary>진단 정보 · 완료 기록 {completionItems.length}건과 원본 응답</summary>
          <p className="ai-runtime-note">모델, 분석 제외 사유와 기기명이 없는 과거 기록을 포함한 전체 완료 근거입니다.</p>
          <div className="ai-runtime-grid">
            {completionItems.map((item, index) => <CompletionCard key={`${item.run_id}-${item.detector_name}-${index}`} item={item} />)}
          </div>
          <details className="ai-runtime-raw">
            <summary>실행 상태 원본 응답 확인</summary>
            <pre>{JSON.stringify(runtimeData, null, 2)}</pre>
          </details>
        </details>
      )}
    </>
  );
}

/* =========================================================
   Gateway Status Page
========================================================= */

export default function GatewayStatus() {
  const [latestMetric, setLatestMetric] = useState(null);

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [pollWarning, setPollWarning] = useState("");
  const [lastSuccessfulFetchAt, setLastSuccessfulFetchAt] =
    useState("");

  const [runtimeData, setRuntimeData] = useState(null);
  const [runtimeLoading, setRuntimeLoading] = useState(true);
  const [runtimeError, setRuntimeError] = useState("");
  const [runtimeUpdatedAt, setRuntimeUpdatedAt] = useState("");


  const [now, setNow] = useState(Date.now());

  const gatewayControllerRef = useRef(null);
  const runtimeControllerRef = useRef(null);

  const gatewayRequestIdRef = useRef(0);
  const runtimeRequestIdRef = useRef(0);

  const hasSuccessfulResponseRef = useRef(false);

  /* ---------------------------------------------------------
     Gateway Metrics API
  --------------------------------------------------------- */

  const loadGatewayMetrics = useCallback(async (manual = false) => {
    gatewayControllerRef.current?.abort();

    const controller = new AbortController();
    gatewayControllerRef.current = controller;

    const requestId = ++gatewayRequestIdRef.current;

    if (manual) setRefreshing(true);

    try {
      const data = await getGatewayMetrics(
        { limit: 1, offset: 0 },
        { signal: controller.signal }
      );

      if (
        controller.signal.aborted ||
        requestId !== gatewayRequestIdRef.current
      ) {
        return;
      }

      if (!Array.isArray(data?.items)) {
        throw new Error(
          "게이트웨이 지표 응답 형식을 확인할 수 없습니다."
        );
      }

      setLatestMetric(data.items[0] ?? null);
      setLastSuccessfulFetchAt(new Date().toISOString());

      hasSuccessfulResponseRef.current = true;

      setError("");
      setPollWarning("");
    } catch (err) {
      if (
        controller.signal.aborted ||
        err?.isCanceled ||
        requestId !== gatewayRequestIdRef.current
      ) {
        return;
      }

      const message =
        err?.message || "게이트웨이 지표를 불러오지 못했습니다.";

      if (hasSuccessfulResponseRef.current) {
        setPollWarning(message);
      } else {
        setError(message);
      }
    } finally {
      if (requestId === gatewayRequestIdRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  /* ---------------------------------------------------------
     AI Runtime Status API
  --------------------------------------------------------- */

  const loadRuntimeStatus = useCallback(async () => {
    runtimeControllerRef.current?.abort();

    const controller = new AbortController();
    runtimeControllerRef.current = controller;

    const requestId = ++runtimeRequestIdRef.current;
    setRuntimeLoading(true);

    try {
      const data = await getRuntimeStatus({
        signal: controller.signal,
      });

      if (
        controller.signal.aborted ||
        requestId !== runtimeRequestIdRef.current
      ) {
        return;
      }

      const root = normalizeApiRoot(data);

      if (root === null || typeof root !== "object") {
        throw new Error("AI 실행 상태 응답 형식이 올바르지 않습니다.");
      }

      setRuntimeData(root);
      setRuntimeUpdatedAt(new Date().toISOString());
      setRuntimeError("");
    } catch (err) {
      if (
        controller.signal.aborted ||
        err?.isCanceled ||
        requestId !== runtimeRequestIdRef.current
      ) {
        return;
      }

      setRuntimeError(
        err?.message || "AI 실행 상태 조회에 실패했습니다."
      );
    } finally {
      if (requestId === runtimeRequestIdRef.current) {
        setRuntimeLoading(false);
      }
    }
  }, []);

  /* ---------------------------------------------------------
     Polling and Cleanup
  --------------------------------------------------------- */

  useEffect(() => {
    loadGatewayMetrics();
    loadRuntimeStatus();

    const pollingTimer = window.setInterval(() => {
      loadGatewayMetrics();
      loadRuntimeStatus();
    }, POLLING_INTERVAL_MS);

    return () => {
      window.clearInterval(pollingTimer);

      gatewayRequestIdRef.current += 1;
      runtimeRequestIdRef.current += 1;

      gatewayControllerRef.current?.abort();
      runtimeControllerRef.current?.abort();
    };
  }, [
    loadGatewayMetrics,
    loadRuntimeStatus,
  ]);

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(Date.now());
    }, STATUS_UPDATE_INTERVAL_MS);

    return () => window.clearInterval(timer);
  }, []);

  /* ---------------------------------------------------------
     Derived Gateway Data
  --------------------------------------------------------- */

  const collectedAt = latestMetric?.collected_at ?? null;

  const gatewayStatus = getGatewayStatus(
    collectedAt,
    Boolean(latestMetric),
    Boolean(error || pollWarning),
    now
  );

  const interfaces = latestMetric?.interface_metrics ?? {};

  const internalLan =
    interfaces.internal_lan ?? interfaces.eth0 ?? null;

  const usbLan =
    interfaces.usb_lan ?? interfaces.eth1 ?? null;

  const interfaceList = useMemo(
    () => [
      {
        key: "internal_lan",
        title: "내부 LAN",
        description:
          "IoT 내부 네트워크와 연결되는 기본 인터페이스입니다.",
        data: internalLan,
      },
      {
        key: "usb_lan",
        title: "USB LAN",
        description:
          "외부 또는 보조 네트워크와 연결되는 USB 인터페이스입니다.",
        data: usbLan,
      },
    ],
    [internalLan, usbLan]
  );

  const interfaceSummary = useMemo(() => {
    const result = {
      connected: 0,
      down: 0,
      missing: 0,
      unknown: 0,
    };

    interfaceList.forEach(({ data }) => {
      const status = getInterfaceStatus(data).status;

      if (status === "connected") result.connected++;
      else if (status === "down") result.down++;
      else if (status === "missing") result.missing++;
      else result.unknown++;
    });

    return result;
  }, [interfaceList]);

  const interfaceSummaryStatus =
    interfaceSummary.down > 0 ||
    interfaceSummary.missing > 0 ||
    interfaceSummary.unknown > 0
      ? "warning"
      : "normal";

  const runtimeItems = useMemo(
    () => extractRuntimeItems(runtimeError
      ? { ...runtimeData, freshness: "API_ERROR" }
      : runtimeData, now),
    [runtimeData, runtimeError, now]
  );

  const completionItems = useMemo(
    () => extractCompletionItems(runtimeData, runtimeItems[0]?.freshness, now),
    [runtimeData, runtimeItems, now]
  );

  /* ---------------------------------------------------------
     Actions
  --------------------------------------------------------- */

  function handleRefresh() {
    loadGatewayMetrics(true);
    loadRuntimeStatus();
  }

  /* ---------------------------------------------------------
     Render
  --------------------------------------------------------- */

  return (
    <div className="gateway-page">
      <PageHeader
        title="게이트웨이 상태"
        description="Raspberry Pi 게이트웨이 자원, 네트워크 인터페이스 및 AI 실행 상태의 실제 상태를 확인합니다."
        updatedAt={
          lastSuccessfulFetchAt
            ? formatKST(lastSuccessfulFetchAt)
            : undefined
        }
        onRefresh={handleRefresh}
        refreshing={
          refreshing || runtimeLoading
        }
      />

      {pollWarning && (
        <div
          className="page-warning-banner"
          role="alert"
        >
          <div>
            <strong>게이트웨이 지표 갱신 실패</strong>
            <p>
              {pollWarning} 이전에 수신한 Metric을 계속 표시합니다.
            </p>
          </div>

          <div className="page-warning-actions">
            <span>
              {POLLING_INTERVAL_MS / 1000}초마다 재조회합니다.
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

      {/* =====================================================
          Gateway Metrics - 기존 기능 유지
      ===================================================== */}

      {loading && !hasSuccessfulResponseRef.current ? (
        <LoadingState
          title="게이트웨이 지표를 불러오는 중입니다."
          description="Raspberry Pi 시스템 상태와 인터페이스 정보를 확인하고 있습니다."
        />
      ) : error && !hasSuccessfulResponseRef.current ? (
        <ErrorState
          title="게이트웨이 API에 연결할 수 없습니다."
          message={error}
          onRetry={handleRefresh}
        />
      ) : !latestMetric ? (
        <>
          <section className="summary-card-grid">
            <SummaryCard
              title="게이트웨이 상태"
              value="NO DATA"
              description="API 응답에 저장된 Metric이 없습니다."
              status="unknown"
            />
          </section>

          <EmptyState
            title="수집된 게이트웨이 지표가 없습니다."
            description="게이트웨이 지표 수집 서비스와 DB 저장 상태를 확인해 주세요."
            actionLabel="다시 조회"
            onAction={handleRefresh}
          />
        </>
      ) : (
        <>
          <section
            className="summary-card-grid"
            aria-label="게이트웨이 상태 요약"
          >
            <SummaryCard
              title="게이트웨이 상태"
              value={gatewayStatus}
              description={gatewayDescription(gatewayStatus)}
              status={gatewayTheme(gatewayStatus)}
            />

            <SummaryCard
              title="마지막 수집"
              value={formatElapsedTime(collectedAt, now)}
              description={formatKST(collectedAt)}
              status={gatewayTheme(gatewayStatus)}
            />

            <SummaryCard
              title="실제 수집 간격"
              value={formatMetric(
                latestMetric.sample_interval_seconds,
                "초",
                2
              )}
              description={`기준 수집 주기 ${COLLECTION_INTERVAL_SECONDS}초`}
            />

            <SummaryCard
              title="연결된 인터페이스"
              value={interfaceSummary.connected}
              description={[
                `비활성 ${interfaceSummary.down}`,
                `미인식 ${interfaceSummary.missing}`,
                interfaceSummary.unknown > 0
                  ? `미확인 ${interfaceSummary.unknown}`
                  : null,
              ]
                .filter(Boolean)
                .join(" · ")}
              status={interfaceSummaryStatus}
            />
          </section>

          <section className="panel overview">
            <div className="overview-main">
              <span className="section-label">
                수집 상태
              </span>

              <div className="status-row">
                <span className="last-collected">
                  마지막 수집: {formatKST(collectedAt)}
                </span>
              </div>

              <p className="threshold-note">
                수집 주기 {COLLECTION_INTERVAL_SECONDS}초 ×{" "}
                {ONLINE_THRESHOLD_MULTIPLIER}배인{" "}
                {ONLINE_THRESHOLD_SECONDS}초 이내에 Metric이
                수집되면 ‘최근 수신’으로 표시합니다.
              </p>
            </div>

            <div className="overview-detail">
              <div>
                <span>수집 지표 ID</span>
                <strong>
                  {formatInteger(latestMetric.id)}
                </strong>
              </div>

              <div>
                <span>마지막 API 성공</span>
                <strong>
                  {formatKST(lastSuccessfulFetchAt)}
                </strong>
              </div>
            </div>
          </section>

          <section>
            <div className="section-heading">
              <div>
                <h2>시스템 자원</h2>
                <p>
                  Raspberry Pi의 CPU, 메모리, 저장공간,
                  온도 사용 상태입니다.
                </p>
              </div>
            </div>

            <div className="metric-card-grid">
              <MetricCard
                label="CPU"
                value={formatResourceValue(
                  latestMetric.cpu_percent
                )}
                unit="%"
                percentage={latestMetric.cpu_percent}
                status={resourceStatus(
                  latestMetric.cpu_percent
                )}
                description="현재 CPU 사용률"
              />

              <MetricCard
                label="메모리"
                value={formatResourceValue(
                  latestMetric.memory_percent
                )}
                unit="%"
                percentage={latestMetric.memory_percent}
                status={resourceStatus(
                  latestMetric.memory_percent
                )}
                description="현재 메모리 사용률"
              />

              <MetricCard
                label="저장공간"
                value={formatResourceValue(
                  latestMetric.disk_percent
                )}
                unit="%"
                percentage={latestMetric.disk_percent}
                status={resourceStatus(
                  latestMetric.disk_percent
                )}
                description={`사용량 ${formatMetric(
                  latestMetric.disk_used_mb,
                  " MB",
                  1
                )}`}
              />

              <MetricCard
                label="온도"
                value={formatResourceValue(
                  latestMetric.temperature_c
                )}
                unit="℃"
                status={temperatureStatus(
                  latestMetric.temperature_c
                )}
                description="Raspberry Pi CPU 온도"
              />
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2>네트워크 인터페이스</h2>
                <p className="panel-description">
                  운영 인터페이스인 internal_lan(eth0)과
                  usb_lan(eth1)의 상태를 확인합니다.
                </p>
              </div>

              <div className="interface-summary">
                <StatusBadge
                  status="connected"
                  label={`연결 ${interfaceSummary.connected}`}
                  size="small"
                />

                <StatusBadge
                  status="down"
                  label={`비활성 ${interfaceSummary.down}`}
                  size="small"
                />

                <StatusBadge
                  status="missing"
                  label={`미인식 ${interfaceSummary.missing}`}
                  size="small"
                />

                {interfaceSummary.unknown > 0 && (
                  <StatusBadge
                    status="unknown"
                    label={`미확인 ${interfaceSummary.unknown}`}
                    size="small"
                  />
                )}
              </div>
            </div>

            <div className="interface-grid">
              {interfaceList.map((item) => (
                <InterfaceCard
                  key={item.key}
                  title={item.title}
                  description={item.description}
                  interfaceData={item.data}
                />
              ))}
            </div>
          </section>
        </>
      )}

      {/* =====================================================
          Phase 9 - AI Runtime Status
      ===================================================== */}

      <section className="panel ai-runtime-panel" aria-label="AI 실행 상태">
        <div className="panel-header">
          <div>
            <h2>AI 실행 상태</h2>
            <p className="panel-description">
              실행 설정과 실제 실행 상태를 구분합니다.
              AI 정책이 관찰 모드여도 추론 엔진의 실행이 확인된 것은 아닙니다.
            </p>
          </div>

          <button
            type="button"
            className="button button-ghost"
            onClick={loadRuntimeStatus}
            disabled={runtimeLoading}
          >
            실행 상태 새로고침
          </button>
        </div>

        {runtimeError && (
          <div
            className="page-warning-banner"
            role="alert"
          >
            <div>
              <strong>AI 실행 상태 조회 실패</strong>
              <p>
                {runtimeError}
                {runtimeData
                  ? " 마지막으로 받은 데이터가 표시됩니다."
                  : ""}
              </p>
            </div>
          </div>
        )}

        {runtimeLoading && !runtimeData ? (
          <LoadingState
            title="AI 실행 상태를 확인하는 중입니다."
            compact
          />
        ) : !runtimeData ? (
          <EmptyState
            title="AI 실행 상태를 확인할 수 없습니다."
            description="실행 상태 조회 API 연결 및 서비스 상태를 확인해 주세요."
            compact
          />
        ) : (
          <RuntimeOverview runtimeItems={runtimeItems} completionItems={completionItems}
            runtimeData={runtimeData} runtimeError={runtimeError} runtimeUpdatedAt={runtimeUpdatedAt} now={now} />
        )}
      </section>

    </div>
  );
}
