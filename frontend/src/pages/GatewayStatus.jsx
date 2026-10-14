
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
  getModels,
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
      "최근 수집 주기 내에 Gateway Metric이 수신되었습니다.",
    STALE:
      "마지막 Metric 수집 이후 허용 시간이 지났습니다.",
    NO_DATA:
      "API 요청은 성공했지만 저장된 Gateway Metric이 없습니다.",
    API_ERROR:
      "Gateway Metrics API에 연결할 수 없습니다.",
  };

  return descriptions[status] || "Gateway 상태 확인 불가";
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
      description: "Interface 정보가 응답에 없습니다.",
    };
  }

  if (data.exists === false) {
    return {
      status: "missing",
      label: "미인식",
      description: "운영체제에서 Interface를 찾지 못했습니다.",
    };
  }

  if (data.exists === true && data.is_up === false) {
    return {
      status: "down",
      label: "DOWN",
      description: "Interface는 존재하지만 비활성 상태입니다.",
    };
  }

  if (data.exists === true && data.is_up === true) {
    return {
      status: "connected",
      label: "연결됨",
      description: "Interface가 활성화되어 있습니다.",
    };
  }

  return {
    status: "unknown",
    label: "상태 미확인",
    description: "Interface 상태 필드가 충분하지 않습니다.",
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
          <span>IP Address</span>
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
              label="Rate 계산 불가"
              size="small"
            />
          )}
      </footer>
    </article>
  );
}

/* =========================================================
   Phase 9 - AI Runtime Helpers

   Runtime 응답 필드가 불명확하면 UNKNOWN으로 표시합니다.
   Desired 상태를 Actual 상태로 간주하지 않습니다.
========================================================= */

function extractRuntimeItems(data) {
  if (!data) return [];

  if (Array.isArray(data)) return data;

  if (Array.isArray(data.items)) {
    return data.items;
  }

  if (Array.isArray(data.runtimes)) {
    return data.runtimes;
  }

  const result = [];

  if (data.mqtt && typeof data.mqtt === "object") {
    result.push({ runtime_name: "MQTT", ...data.mqtt });
  }

  if (data.packet && typeof data.packet === "object") {
    result.push({ runtime_name: "Packet", ...data.packet });
  }

  if (data.mqtt_ai && typeof data.mqtt_ai === "object") {
    result.push({ runtime_name: "MQTT", ...data.mqtt_ai });
  }

  if (data.packet_ai && typeof data.packet_ai === "object") {
    result.push({ runtime_name: "Packet", ...data.packet_ai });
  }

  if (result.length) return result;

  if (typeof data === "object") {
    return [data];
  }

  return [];
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
    ]) ?? `Runtime ${index + 1}`
  );
}

function getRuntimeField(item, type) {
  if (type === "desired") {
    return firstDefined(item, [
      "desired_state",
      "desired_status",
      "desired_mode",
      "configured_mode",
      "requested_mode",
    ]);
  }

  if (type === "actual") {
    return firstDefined(item, [
      "actual_state",
      "actual_status",
      "actual_mode",
      "effective_mode",
      "runtime_state",
      "runtime_status",
    ]);
  }

  return null;
}

function runtimeTheme(value) {
  if (value === null || value === undefined || value === "") {
    return "unknown";
  }

  const normalized = String(value).toUpperCase();

  if (
    ["RUNNING", "ACTIVE", "HEALTHY", "READY", "ONLINE"].includes(normalized)
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

function RuntimeCard({ item, index }) {
  const desired = getRuntimeField(item, "desired");
  const actual = getRuntimeField(item, "actual");

  const model = firstDefined(item, [
    "model_name",
    "model_id",
    "loaded_model",
    "model",
  ]);

  const updatedAt = firstDefined(item, [
    "updated_at",
    "checked_at",
    "last_heartbeat_at",
  ]);

  const error = firstDefined(item, [
    "last_error",
    "error",
    "error_message",
  ]);

  return (
    <article className="ai-runtime-card">
      <div className="ai-runtime-card-header">
        <strong>{runtimeTitle(item, index)}</strong>
        <StatusBadge
          status={runtimeTheme(actual)}
          label={actual == null ? "UNKNOWN" : displayValue(actual)}
          size="small"
        />
      </div>

      <dl className="ai-runtime-list">
        <div>
          <dt>Desired</dt>
          <dd>{displayValue(desired)}</dd>
        </div>

        <div>
          <dt>Actual</dt>
          <dd>{displayValue(actual)}</dd>
        </div>

        <div>
          <dt>Model</dt>
          <dd>{displayValue(model)}</dd>
        </div>

        <div>
          <dt>Updated At</dt>
          <dd>{updatedAt ? formatKST(updatedAt) : "-"}</dd>
        </div>

        {error != null && (
          <div className="ai-runtime-error">
            <dt>Last Error</dt>
            <dd>{displayValue(error)}</dd>
          </div>
        )}
      </dl>
    </article>
  );
}

/* =========================================================
   Phase 9 - Model Helpers
========================================================= */

function extractModels(data) {
  if (Array.isArray(data)) {
    return data;
  }

  if (Array.isArray(data?.items)) {
    return data.items;
  }

  if (Array.isArray(data?.models)) {
    return data.models;
  }

  return [];
}

function ModelCard({ model, index }) {
  const name = firstDefined(model, [
    "name",
    "model_name",
    "model_id",
    "id",
  ]);

  const version = firstDefined(model, [
    "version",
    "model_version",
  ]);

  const framework = firstDefined(model, [
    "framework",
    "runtime",
    "format",
  ]);

  const status = firstDefined(model, [
    "status",
    "state",
    "load_status",
  ]);

  const detector = firstDefined(model, [
    "detector_type",
    "detector",
    "pipeline",
  ]);

  return (
    <article className="ai-model-card">
      <div className="ai-runtime-card-header">
        <strong>
          {displayValue(name ?? `Model ${index + 1}`)}
        </strong>

        <StatusBadge
          status={runtimeTheme(status)}
          label={status == null ? "상태 미제공" : displayValue(status)}
          size="small"
        />
      </div>

      <dl className="ai-runtime-list">
        <div>
          <dt>Version</dt>
          <dd>{displayValue(version)}</dd>
        </div>

        <div>
          <dt>Detector</dt>
          <dd>{displayValue(detector)}</dd>
        </div>

        <div>
          <dt>Framework</dt>
          <dd>{displayValue(framework)}</dd>
        </div>
      </dl>
    </article>
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

  const [modelsData, setModelsData] = useState(null);
  const [modelsLoading, setModelsLoading] = useState(true);
  const [modelsError, setModelsError] = useState("");

  const [now, setNow] = useState(Date.now());

  const gatewayControllerRef = useRef(null);
  const runtimeControllerRef = useRef(null);
  const modelsControllerRef = useRef(null);

  const gatewayRequestIdRef = useRef(0);
  const runtimeRequestIdRef = useRef(0);
  const modelsRequestIdRef = useRef(0);

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
          "Gateway Metrics 응답 형식을 확인할 수 없습니다."
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
        err?.message || "Gateway Metrics를 불러오지 못했습니다.";

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
        throw new Error("AI Runtime 응답 형식이 올바르지 않습니다.");
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
        err?.message || "AI Runtime 상태 조회에 실패했습니다."
      );
    } finally {
      if (requestId === runtimeRequestIdRef.current) {
        setRuntimeLoading(false);
      }
    }
  }, []);

  /* ---------------------------------------------------------
     Models API
  --------------------------------------------------------- */

  const loadModels = useCallback(async () => {
    modelsControllerRef.current?.abort();

    const controller = new AbortController();
    modelsControllerRef.current = controller;

    const requestId = ++modelsRequestIdRef.current;
    setModelsLoading(true);

    try {
      const data = await getModels({
        signal: controller.signal,
      });

      if (
        controller.signal.aborted ||
        requestId !== modelsRequestIdRef.current
      ) {
        return;
      }

      const root = normalizeApiRoot(data);

      if (root === null || typeof root !== "object") {
        throw new Error("Models API 응답 형식이 올바르지 않습니다.");
      }

      setModelsData(root);
      setModelsError("");
    } catch (err) {
      if (
        controller.signal.aborted ||
        err?.isCanceled ||
        requestId !== modelsRequestIdRef.current
      ) {
        return;
      }

      setModelsError(
        err?.message || "AI 모델 목록을 불러오지 못했습니다."
      );
    } finally {
      if (requestId === modelsRequestIdRef.current) {
        setModelsLoading(false);
      }
    }
  }, []);

  /* ---------------------------------------------------------
     Polling and Cleanup
  --------------------------------------------------------- */

  useEffect(() => {
    loadGatewayMetrics();
    loadRuntimeStatus();
    loadModels();

    const pollingTimer = window.setInterval(() => {
      loadGatewayMetrics();
      loadRuntimeStatus();
    }, POLLING_INTERVAL_MS);

    return () => {
      window.clearInterval(pollingTimer);

      gatewayRequestIdRef.current += 1;
      runtimeRequestIdRef.current += 1;
      modelsRequestIdRef.current += 1;

      gatewayControllerRef.current?.abort();
      runtimeControllerRef.current?.abort();
      modelsControllerRef.current?.abort();
    };
  }, [
    loadGatewayMetrics,
    loadRuntimeStatus,
    loadModels,
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
          "IoT 내부 네트워크와 연결되는 기본 Interface입니다.",
        data: internalLan,
      },
      {
        key: "usb_lan",
        title: "USB LAN",
        description:
          "외부 또는 보조 네트워크와 연결되는 USB Interface입니다.",
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
    () => extractRuntimeItems(runtimeData),
    [runtimeData]
  );

  const modelItems = useMemo(
    () => extractModels(modelsData),
    [modelsData]
  );

  const actualRuntimeKnown = runtimeItems.some(
    (item) => getRuntimeField(item, "actual") != null
  );

  /* ---------------------------------------------------------
     Actions
  --------------------------------------------------------- */

  function handleRefresh() {
    loadGatewayMetrics(true);
    loadRuntimeStatus();
    loadModels();
  }

  /* ---------------------------------------------------------
     Render
  --------------------------------------------------------- */

  return (
    <div className="gateway-page">
      <PageHeader
        title="Gateway Status"
        description="Raspberry Pi Gateway 자원, 네트워크 Interface 및 AI Runtime의 실제 상태를 확인합니다."
        updatedAt={
          lastSuccessfulFetchAt
            ? formatKST(lastSuccessfulFetchAt)
            : undefined
        }
        onRefresh={handleRefresh}
        refreshing={
          refreshing || runtimeLoading || modelsLoading
        }
      />

      {pollWarning && (
        <div
          className="page-warning-banner"
          role="alert"
        >
          <div>
            <strong>Gateway Metrics 갱신 실패</strong>
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
          Phase 9 - AI Runtime Status
      ===================================================== */}

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>AI Runtime Status</h2>
            <p className="panel-description">
              Desired 설정과 Actual 실행 상태를 구분합니다.
              AI 정책이 OBSERVE라고 해서 추론 엔진의 실행이
              확인된 것은 아닙니다.
            </p>
          </div>

          <button
            type="button"
            className="button button-ghost"
            onClick={loadRuntimeStatus}
            disabled={runtimeLoading}
          >
            Runtime 새로고침
          </button>
        </div>

        {runtimeError && (
          <div
            className="page-warning-banner"
            role="alert"
          >
            <div>
              <strong>AI Runtime 조회 실패</strong>
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
            title="AI Runtime 상태를 확인하는 중입니다."
            compact
          />
        ) : !runtimeData ? (
          <EmptyState
            title="AI Runtime 상태를 확인할 수 없습니다."
            description="Runtime API 연결 및 서비스 상태를 확인해 주세요."
            compact
          />
        ) : (
          <>
            <div className="summary-card-grid">
              <SummaryCard
                title="Runtime API"
                value={
                  runtimeError ? "ERROR" : "RESPONSE"
                }
                description={
                  runtimeError
                    ? "최근 갱신에 실패했습니다."
                    : "Runtime 상태 API 응답을 수신했습니다."
                }
                status={
                  runtimeError ? "danger" : "normal"
                }
              />

              <SummaryCard
                title="Actual 상태 확인"
                value={
                  actualRuntimeKnown
                    ? "필드 확인"
                    : "UNKNOWN"
                }
                description={
                  actualRuntimeKnown
                    ? "Actual 상태 필드가 제공되었습니다."
                    : "실제 실행 상태를 판단할 필드가 없습니다."
                }
                status={
                  actualRuntimeKnown ? "normal" : "warning"
                }
              />

              <SummaryCard
                title="마지막 API 응답"
                value={formatElapsedTime(runtimeUpdatedAt, now)}
                description={formatKST(runtimeUpdatedAt)}
              />
            </div>

            <div className="ai-runtime-grid">
              {runtimeItems.map((item, index) => (
                <RuntimeCard
                  key={
                    String(
                      firstDefined(item, [
                        "runtime_name",
                        "name",
                        "component",
                      ]) ?? index
                    ) + index
                  }
                  item={item}
                  index={index}
                />
              ))}
            </div>

            {!actualRuntimeKnown && (
              <p className="ai-runtime-note">
                Actual 필드가 없으므로 Runtime을 정상 실행 중이라고
                판단할 수 없습니다. 정확한 필드명은 Swagger의
                RuntimeStatusResponse 스키마와 대조해야 합니다.
              </p>
            )}

            <details className="ai-runtime-raw">
              <summary>Runtime 원본 응답 확인</summary>
              <pre>
                {JSON.stringify(runtimeData, null, 2)}
              </pre>
            </details>
          </>
        )}
      </section>

      {/* =====================================================
          Phase 9 - Model Information
      ===================================================== */}

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>AI Models</h2>
            <p className="panel-description">
              등록 모델 메타데이터를 조회합니다.
              목록 존재 여부는 실제 모델 적재 및 추론 성공과 다릅니다.
            </p>
          </div>

          <button
            type="button"
            className="button button-ghost"
            onClick={loadModels}
            disabled={modelsLoading}
          >
            모델 새로고침
          </button>
        </div>

        {modelsError && (
          <div
            className="page-warning-banner"
            role="alert"
          >
            <div>
              <strong>AI Models 조회 실패</strong>
              <p>{modelsError}</p>
            </div>
          </div>
        )}

        {modelsLoading && !modelsData ? (
          <LoadingState
            title="AI 모델 정보를 불러오는 중입니다."
            compact
          />
        ) : !modelsData ? (
          <EmptyState
            title="모델 정보를 확인할 수 없습니다."
            compact
          />
        ) : modelItems.length === 0 ? (
          <>
            <EmptyState
              title="표시할 모델이 없습니다."
              description="등록된 모델이 없거나 응답 구조가 예상과 다를 수 있습니다."
              compact
            />

            <details className="ai-runtime-raw">
              <summary>Models 원본 응답 확인</summary>
              <pre>
                {JSON.stringify(modelsData, null, 2)}
              </pre>
            </details>
          </>
        ) : (
          <>
            <div className="ai-model-grid">
              {modelItems.map((model, index) => (
                <ModelCard
                  key={
                    String(
                      firstDefined(model, [
                        "id",
                        "model_id",
                        "name",
                      ]) ?? index
                    ) + index
                  }
                  model={model}
                  index={index}
                />
              ))}
            </div>

            <details className="ai-runtime-raw">
              <summary>Models 원본 응답 확인</summary>
              <pre>
                {JSON.stringify(modelsData, null, 2)}
              </pre>
            </details>
          </>
        )}
      </section>

      {/* =====================================================
          Gateway Metrics - 기존 기능 유지
      ===================================================== */}

      {loading && !hasSuccessfulResponseRef.current ? (
        <LoadingState
          title="Gateway Metrics를 불러오는 중입니다."
          description="Raspberry Pi 시스템 상태와 Interface 정보를 확인하고 있습니다."
        />
      ) : error && !hasSuccessfulResponseRef.current ? (
        <ErrorState
          title="Gateway API에 연결할 수 없습니다."
          message={error}
          onRetry={handleRefresh}
        />
      ) : !latestMetric ? (
        <>
          <section className="summary-card-grid">
            <SummaryCard
              title="Gateway 상태"
              value="NO DATA"
              description="API 응답에 저장된 Metric이 없습니다."
              status="unknown"
            />
          </section>

          <EmptyState
            title="수집된 Gateway Metrics가 없습니다."
            description="Gateway Metrics Collector와 DB 저장 상태를 확인해 주세요."
            actionLabel="다시 조회"
            onAction={handleRefresh}
          />
        </>
      ) : (
        <>
          <section
            className="summary-card-grid"
            aria-label="Gateway 상태 요약"
          >
            <SummaryCard
              title="Gateway 상태"
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
              title="연결된 Interface"
              value={interfaceSummary.connected}
              description={[
                `DOWN ${interfaceSummary.down}`,
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
                수집되면 ONLINE으로 표시합니다.
              </p>
            </div>

            <div className="overview-detail">
              <div>
                <span>Metric ID</span>
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
                  Raspberry Pi의 CPU, Memory, Disk,
                  Temperature 사용 상태입니다.
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
                label="Memory"
                value={formatResourceValue(
                  latestMetric.memory_percent
                )}
                unit="%"
                percentage={latestMetric.memory_percent}
                status={resourceStatus(
                  latestMetric.memory_percent
                )}
                description="현재 Memory 사용률"
              />

              <MetricCard
                label="Disk"
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
                label="Temperature"
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
                <h2>Network Interface</h2>
                <p className="panel-description">
                  운영 Interface인 internal_lan(eth0)과
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
                  label={`DOWN ${interfaceSummary.down}`}
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
    </div>
  );
}
