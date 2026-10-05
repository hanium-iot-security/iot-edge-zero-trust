import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  getEvents,
  getFeatureLogs,
  getDevices,
  getFirewallRules,
  getGatewayMetrics,
  getHealth,
  getMqttLogs,
  getPacketFeatureLogs,
  getSummary,
  getTrustScoreSummary,
} from "../api/api";
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
import DataTable from "../components/DataTable";
import EmptyState from "../components/EmptyState";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";
import "../styles/pages/Dashboard.scss";

const POLLING_INTERVAL_MS = 10_000;
const ONLINE_THRESHOLD_SECONDS = 30;
const IS_DEV = import.meta.env.DEV;
const SOURCE_KEYS = [
  "summary",
  "devices",
  "logs",
  "features",
  "events",
  "trustScores",
  "gateway",
  "packetFeatures",
  "firewall",
  "health",
];

function createInitialSourceState() {
  return Object.fromEntries(
    SOURCE_KEYS.map((key) => [
      key,
      {
        status: "idle",
        error: "",
        lastSuccessAt: "",
      },
    ])
  );
}

function formatKST(dateString) {
  if (!dateString) {
    return "-";
  }
  const date = new Date(dateString);
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

function formatChartTime(dateString) {
  if (!dateString) {
    return "-";
  }
  const date = new Date(dateString);
  if (Number.isNaN(date.getTime())) {
    return "-";
  }
  return new Intl.DateTimeFormat("ko-KR", {
    timeZone: "Asia/Seoul",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }).format(date);
}

function formatNumber(value, maximumFractionDigits = 0) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "-";
  }
  return number.toLocaleString("ko-KR", {
    maximumFractionDigits,
  });
}

function formatScoreDelta(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "-";
  }
  return number > 0 ? `+${number}` : String(number);
}

function normalizeBoolean(value) {
  return value === true || value === 1 || value === "1" || value === "true";
}

function hasFiniteNumber(value) {
  return Number.isFinite(Number(value));
}

function getTrustStatus(score, status) {
  if (status) {
    return String(status).toLowerCase();
  }
  const number = Number(score);
  if (!Number.isFinite(number)) {
    return "unknown";
  }
  if (number < 30) {
    return "isolated";
  }
  if (number < 60) {
    return "danger";
  }
  if (number < 80) {
    return "warning";
  }
  return "normal";
}

function getTrustStatusLabel(status) {
  const labels = {
    normal: "정상",
    warning: "주의",
    danger: "위험",
    isolated: "격리",
    unknown: "확인 불가",
  };
  const normalized = String(status || "").toLowerCase();
  return labels[normalized] || status || "확인 불가";
}

function normalizeRegistrationState(value) {
  const normalized = String(value || "").trim().toUpperCase();
  return ["PENDING", "ACTIVE", "DISABLED"].includes(normalized)
    ? normalized
    : "UNKNOWN";
}

function getRegistrationState(item) {
  return normalizeRegistrationState(
    item?.registration_state ??
      item?.current_registration_state ??
      item?.current_policy?.registration_state ??
      item?.policy?.registration_state
  );
}

function getRegistrationStateLabel(status) {
  const labels = {
    PENDING: "등록 준비 중",
    ACTIVE: "등록 활성",
    DISABLED: "관리 비활성",
    UNKNOWN: "확인 불가",
  };
  return labels[normalizeRegistrationState(status)] || "확인 불가";
}

function getRegistrationStateTheme(status) {
  const normalized = normalizeRegistrationState(status);
  if (normalized === "PENDING") {
    return "pending";
  }
  if (normalized === "ACTIVE") {
    return "normal";
  }
  if (normalized === "DISABLED") {
    return "unknown";
  }
  return "unknown";
}

function getRegistrationResponseLabel(item) {
  const current = getRegistrationState(item);
  if (item?.auto_response_eligible === true) {
    return "자동 대응 적용 대상";
  }
  if (current === "PENDING") {
    return "자동 대응 미적용";
  }
  if (current === "DISABLED") {
    return "자동 대응 중지";
  }
  if (item?.auto_response_exclusion_reason) {
    return `자동 대응 제외 · ${item.auto_response_exclusion_reason}`;
  }
  if (current === "ACTIVE") {
    return "자동 대응 상태 확인 필요";
  }
  return "자동 대응 상태 확인 불가";
}

function getSeverityStatus(severity) {
  const normalized = String(severity || "").toLowerCase();
  if (normalized === "high" || normalized === "medium" || normalized === "low") {
    return normalized;
  }
  return "unknown";
}

function getDetectorStatus(event) {
  const detectorType = String(event?.detector_type || "").toUpperCase();
  if (
    detectorType === "AI" ||
    event?.event_type === "AI_ANOMALY" ||
    event?.event_type === "AI_PACKET_ANOMALY"
  ) {
    return "ai";
  }
  if (detectorType === "RULE") {
    return "rule";
  }
  return "unknown";
}

function getFirewallStatusTheme(status) {
  const normalized = String(status || "").toUpperCase();
  if (normalized === "APPLIED") {
    return "applied";
  }
  if (normalized === "PENDING") {
    return "pending";
  }
  if (normalized === "FAILED") {
    return "failed";
  }
  if (normalized === "REMOVED") {
    return "removed";
  }
  return "unknown";
}

function getFirewallStatusLabel(status) {
  const labels = {
    APPLIED: "차단 적용",
    PENDING: "적용 대기",
    FAILED: "적용 실패",
    REMOVED: "차단 해제",
  };
  const normalized = String(status || "").toUpperCase();
  return labels[normalized] || status || "Firewall 기록 없음";
}

function getGatewayStatus(metric) {
  if (!metric) {
    return "NO_DATA";
  }
  if (!metric.collected_at) {
    return "STALE";
  }
  const collectedAt = new Date(metric.collected_at).getTime();
  if (Number.isNaN(collectedAt)) {
    return "STALE";
  }
  const elapsedSeconds = (Date.now() - collectedAt) / 1000;
  return elapsedSeconds <= ONLINE_THRESHOLD_SECONDS ? "ONLINE" : "STALE";
}

function getGatewayStatusTheme(status) {
  const themes = {
    ONLINE: "online",
    STALE: "stale",
    NO_DATA: "unknown",
    API_ERROR: "failed",
  };
  return themes[status] || "unknown";
}

function getHealthDisplayLabel(value) {
  const normalized = String(value || "").trim().toUpperCase();
  const labels = {
    OK: "정상",
    HEALTHY: "정상",
    UP: "정상",
    DEGRADED: "주의",
    WARNING: "주의",
    ERROR: "오류",
    DOWN: "오류",
    UNHEALTHY: "오류",
  };
  return labels[normalized] || value || "-";
}

function getHealthStatus(health) {
  const rawStatus = String(health?.status || "").toUpperCase();
  if (rawStatus === "OK" || rawStatus === "HEALTHY" || rawStatus === "UP") {
    return { status: "online", label: "정상" };
  }
  if (rawStatus === "DEGRADED" || rawStatus === "WARNING") {
    return { status: "degraded", label: "일부 저하" };
  }
  if (rawStatus === "ERROR" || rawStatus === "DOWN" || rawStatus === "UNHEALTHY") {
    return { status: "failed", label: "오류" };
  }
  return { status: "unknown", label: "확인 불가" };
}

function getCaptureSummary(packetFeatures) {
  let eligible = 0;
  let excluded = 0;
  let failed = 0;
  const coverageValues = [];
  packetFeatures.forEach((item) => {
    if (item.segment_status === "FAILED") {
      failed += 1;
    }
    if (item.capture_eligible === true) {
      eligible += 1;
    }
    if (item.capture_eligible === false) {
      excluded += 1;
    }
    const coverage = Number(item.coverage_ratio);
    if (Number.isFinite(coverage)) {
      coverageValues.push(coverage);
    }
  });
  const averageCoverage =
    coverageValues.length > 0
      ? coverageValues.reduce((sum, value) => sum + value, 0) / coverageValues.length
      : null;
  return {
    eligible,
    excluded,
    failed,
    averageCoverage,
  };
}

function getFeatureChartData(features) {
  return features.map((item) => ({
    ...item,
    chart_time: formatChartTime(item.window_start),
  }));
}

function formatResourceValue(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "-";
  }
  return number.toLocaleString("ko-KR", {
    minimumFractionDigits: 1,
    maximumFractionDigits: 1,
  });
}

function getResourceStatus(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "unknown";
  }
  if (number >= 90) {
    return "danger";
  }
  if (number >= 75) {
    return "warning";
  }
  return "normal";
}

function getTemperatureStatus(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "unknown";
  }
  if (number >= 80) {
    return "danger";
  }
  if (number >= 65) {
    return "warning";
  }
  return "normal";
}

function SourceStateNotice({ state, label }) {
  if (!state || state.status !== "error") {
    return null;
  }
  const hasPrevious = Boolean(state.lastSuccessAt);
  return (
    <div
      className={`source-state-note ${hasPrevious ? "source-state-stale" : "source-state-error"}`}
      role="status"
    >
      <strong>{hasPrevious ? `${label} 최신 조회 실패` : `${label} 확인 불가`}</strong>
      <span>
        {hasPrevious
          ? `이전 성공 데이터(${formatKST(state.lastSuccessAt)})를 계속 표시합니다.`
          : state.error || "데이터를 조회하지 못했습니다."}
      </span>
    </div>
  );
}

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [devices, setDevices] = useState([]);
  const [logs, setLogs] = useState([]);
  const [features, setFeatures] = useState([]);
  const [events, setEvents] = useState([]);
  const [trustScores, setTrustScores] = useState([]);
  const [gatewayMetric, setGatewayMetric] = useState(null);
  const [packetFeatures, setPacketFeatures] = useState([]);
  const [firewallRules, setFirewallRules] = useState([]);
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [partialWarnings, setPartialWarnings] = useState([]);
  const [lastUpdated, setLastUpdated] = useState("");
  const [sourceState, setSourceState] = useState(createInitialSourceState);
  const requestControllerRef = useRef(null);
  const requestIdRef = useRef(0);
  const hasSuccessfulDataRef = useRef(false);

  const loadData = useCallback(async (isManualRefresh = false) => {
    const requestId = requestIdRef.current + 1;
    requestIdRef.current = requestId;
    requestControllerRef.current?.abort();
    const controller = new AbortController();
    requestControllerRef.current = controller;

    if (isManualRefresh) {
      setRefreshing(true);
    }

    const options = { signal: controller.signal };
    const requests = [
      { key: "summary", label: "기기 요약", request: getSummary(options) },
      {
        key: "devices",
        label: "기기 등록 상태",
        request: getDevices({ limit: 500, offset: 0 }, options),
      },
      {
        key: "logs",
        label: "MQTT 로그",
        request: getMqttLogs({ limit: 5, offset: 0 }, options),
      },
      {
        key: "features",
        label: "MQTT Feature",
        request: getFeatureLogs({ limit: 20, offset: 0 }, options),
      },
      {
        key: "events",
        label: "탐지 이벤트",
        request: getEvents({ limit: 5, offset: 0 }, options),
      },
      {
        key: "trustScores",
        label: "Trust Score",
        request: getTrustScoreSummary({ limit: 10, offset: 0 }, options),
      },
      {
        key: "gateway",
        label: "Gateway Metric",
        request: getGatewayMetrics({ limit: 1, offset: 0 }, options),
      },
      {
        key: "packetFeatures",
        label: "Packet Feature",
        request: getPacketFeatureLogs({ limit: 20, offset: 0 }, options),
      },
      {
        key: "firewall",
        label: "Firewall Rule",
        request: getFirewallRules({ limit: 100, offset: 0 }, options),
      },
      { key: "health", label: "API Health", request: getHealth(options) },
    ];

    try {
      const results = await Promise.allSettled(requests.map((item) => item.request));
      if (requestId !== requestIdRef.current || controller.signal.aborted) {
        return;
      }

      const now = new Date().toISOString();
      const warnings = [];
      let successCount = 0;
      const stateUpdates = {};

      results.forEach((result, index) => {
        const requestInfo = requests[index];
        if (result.status === "rejected") {
          const message =
            result.reason instanceof Error ? result.reason.message : "조회 실패";
          warnings.push(`${requestInfo.label}: ${message}`);
          stateUpdates[requestInfo.key] = {
            status: "error",
            error: message,
          };
          return;
        }

        successCount += 1;
        stateUpdates[requestInfo.key] = {
          status: "success",
          error: "",
          lastSuccessAt: now,
        };
        const data = result.value;

        switch (requestInfo.key) {
          case "summary":
            setSummary(data || {});
            break;
          case "devices":
            setDevices(Array.isArray(data?.items) ? data.items : []);
            break;
          case "logs":
            setLogs(Array.isArray(data?.items) ? data.items : []);
            break;
          case "features":
            setFeatures(Array.isArray(data?.items) ? data.items : []);
            break;
          case "events":
            setEvents(Array.isArray(data?.items) ? data.items : []);
            break;
          case "trustScores":
            setTrustScores(Array.isArray(data?.items) ? data.items : []);
            break;
          case "gateway":
            setGatewayMetric(Array.isArray(data?.items) ? data.items[0] ?? null : null);
            break;
          case "packetFeatures":
            setPacketFeatures(Array.isArray(data?.items) ? data.items : []);
            break;
          case "firewall":
            setFirewallRules(Array.isArray(data?.items) ? data.items : []);
            break;
          case "health":
            setHealth(data || null);
            break;
          default:
            break;
        }
      });

      setSourceState((previous) => {
        const next = { ...previous };
        Object.entries(stateUpdates).forEach(([key, update]) => {
          next[key] = {
            ...previous[key],
            ...update,
            lastSuccessAt:
              update.lastSuccessAt ?? previous[key]?.lastSuccessAt ?? "",
          };
        });
        return next;
      });

      if (successCount === 0) {
        throw new Error("모든 Dashboard API 요청에 실패했습니다.");
      }

      hasSuccessfulDataRef.current = true;
      setLastUpdated(now);
      setPartialWarnings(warnings);
      setError("");
    } catch (err) {
      if (requestId !== requestIdRef.current || controller.signal.aborted) {
        return;
      }
      if (IS_DEV) {
        console.error("Dashboard data load failed:", err);
      }
      const message =
        err instanceof Error ? err.message : "대시보드 데이터를 불러오지 못했습니다.";
      if (hasSuccessfulDataRef.current) {
        setPartialWarnings((current) =>
          current.length > 0 ? current : [message]
        );
      } else {
        setError(message);
      }
    } finally {
      if (requestId === requestIdRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, []);

  useEffect(() => {
    loadData();
    const timer = window.setInterval(() => {
      loadData();
    }, POLLING_INTERVAL_MS);
    return () => {
      window.clearInterval(timer);
      requestControllerRef.current?.abort();
    };
  }, [loadData]);

  const sourceHasSuccess = useCallback(
    (key) => Boolean(sourceState[key]?.lastSuccessAt),
    [sourceState]
  );

  const sourceIsStale = useCallback(
    (key) => sourceState[key]?.status === "error" && sourceHasSuccess(key),
    [sourceHasSuccess, sourceState]
  );

  const sourceUpdatedAt = useCallback(
    (key) => sourceState[key]?.lastSuccessAt || "",
    [sourceState]
  );

  const firewallSummary = useMemo(() => {
    const result = {
      applied: 0,
      pending: 0,
      failed: 0,
      removed: 0,
    };
    firewallRules.forEach((rule) => {
      const status = String(rule.status || "").toUpperCase();
      if (status === "APPLIED") {
        result.applied += 1;
      } else if (status === "PENDING") {
        result.pending += 1;
      } else if (status === "FAILED") {
        result.failed += 1;
      } else if (status === "REMOVED") {
        result.removed += 1;
      }
    });
    return result;
  }, [firewallRules]);

  const captureSummary = useMemo(
    () => getCaptureSummary(packetFeatures),
    [packetFeatures]
  );
  const gatewayStatus = useMemo(
    () => getGatewayStatus(gatewayMetric),
    [gatewayMetric]
  );
  const healthStatus = useMemo(() => getHealthStatus(health), [health]);
  const featureChartData = useMemo(
    () => getFeatureChartData(features),
    [features]
  );

  const deviceMap = useMemo(
    () => new Map(devices.map((device) => [device.device_id, device])),
    [devices]
  );

  const registrationSummary = useMemo(() => {
    const result = {
      PENDING: 0,
      ACTIVE: 0,
      DISABLED: 0,
      UNKNOWN: 0,
    };
    devices.forEach((device) => {
      result[getRegistrationState(device)] += 1;
    });
    return result;
  }, [devices]);

  const firewallRuleMap = useMemo(() => {
    const result = new Map();
    firewallRules.forEach((rule) => {
      if (!rule?.device_id) {
        return;
      }
      const existing = result.get(rule.device_id);
      if (!existing) {
        result.set(rule.device_id, rule);
        return;
      }
      const currentTime = new Date(
        rule.updated_at || rule.created_at || 0
      ).getTime();
      const existingTime = new Date(
        existing.updated_at || existing.created_at || 0
      ).getTime();
      if (currentTime > existingTime) {
        result.set(rule.device_id, rule);
      }
    });
    return result;
  }, [firewallRules]);

  const trustRows = useMemo(
    () =>
      trustScores.map((item) => {
        const device = deviceMap.get(item.device_id);
        const firewallRule = firewallRuleMap.get(item.device_id);
        return {
          ...item,
          ...(device || {}),
          status: item.status ?? device?.status,
          trust_score: item.trust_score ?? device?.trust_score,
          last_seen_at: item.last_seen_at ?? device?.last_seen_at,
          firewall_status:
            firewallRule?.status ?? device?.firewall_status ?? null,
        };
      }),
    [deviceMap, firewallRuleMap, trustScores]
  );

  function getSummaryCardValue(field) {
    if (!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.[field])) {
      return null;
    }
    return formatNumber(summary[field]);
  }

  function getFirewallCard(field, fallbackKey) {
    if (
      sourceHasSuccess("summary") &&
      hasFiniteNumber(summary?.[field]) &&
      sourceState.summary?.status === "success"
    ) {
      return { value: Number(summary[field]), sourceKey: "summary" };
    }
    if (sourceHasSuccess("firewall")) {
      return { value: firewallSummary[fallbackKey], sourceKey: "firewall" };
    }
    if (sourceHasSuccess("summary") && hasFiniteNumber(summary?.[field])) {
      return { value: Number(summary[field]), sourceKey: "summary" };
    }
    return { value: null, sourceKey: null };
  }

  const registrationPendingValue = sourceHasSuccess("devices")
    ? registrationSummary.PENDING
    : null;
  const registrationActiveValue = sourceHasSuccess("devices")
    ? registrationSummary.ACTIVE
    : null;
  const registrationDisabledValue = sourceHasSuccess("devices")
    ? registrationSummary.DISABLED
    : null;
  const registrationUnknownValue = sourceHasSuccess("devices")
    ? registrationSummary.UNKNOWN
    : null;
  const firewallAppliedCard = getFirewallCard("firewall_applied", "applied");
  const firewallPendingCard = getFirewallCard("firewall_pending", "pending");
  const firewallFailedCard = getFirewallCard("firewall_failed", "failed");

  const trustColumns = [
    {
      key: "device_id",
      header: "Device",
      width: 150,
      render: (value) => <strong title={value || ""}>{value || "-"}</strong>,
    },
    {
      key: "registration_state",
      header: "등록 상태",
      width: 170,
      render: (_value, item) => {
        const registrationState = getRegistrationState(item);
        return (
          <div className="registration-cell">
            <StatusBadge
              status={getRegistrationStateTheme(registrationState)}
              label={getRegistrationStateLabel(registrationState)}
              size="small"
            />
            <small>
              {getRegistrationResponseLabel(item)}
            </small>
          </div>
        );
      },
    },
    {
      key: "trust_score",
      header: "Trust Score",
      align: "right",
      width: 120,
      render: (value, item) => {
        const status = getTrustStatus(value, item.status);
        const registrationState = getRegistrationState(item);
        return (
          <div className="score-cell">
            <strong>{formatNumber(value)}</strong>
            <div className="score-bar">
              <div
                className={`score-fill score-${status}`}
                style={{
                  width: `${Math.min(Math.max(Number(value) || 0, 0), 100)}%`,
                }}
              />
            </div>
            {registrationState === "PENDING" && (
              <small className="score-context">등록 준비 상태의 점수</small>
            )}
          </div>
        );
      },
    },
    {
      key: "status",
      header: "Trust 상태",
      width: 110,
      render: (value, item) => {
        const status = getTrustStatus(item.trust_score, value);
        return (
          <StatusBadge
            status={status}
            label={getTrustStatusLabel(status)}
            size="small"
          />
        );
      },
    },
    {
      key: "firewall_status",
      header: "Firewall",
      width: 140,
      render: (value) => (
        <StatusBadge
          status={getFirewallStatusTheme(value)}
          label={getFirewallStatusLabel(value)}
          size="small"
        />
      ),
    },
    {
      key: "last_seen_at",
      header: "Last Seen",
      width: 180,
      render: (value) => formatKST(value),
    },
  ];

  const eventColumns = [
    {
      key: "device_id",
      header: "Device",
      width: 130,
      render: (value, event) => value || event.subject_ip || "미매핑",
    },
    {
      key: "detector_type",
      header: "Detector",
      width: 100,
      render: (value, event) => (
        <StatusBadge
          status={getDetectorStatus(event)}
          label={value || "-"}
          size="small"
        />
      ),
    },
    {
      key: "event_type",
      header: "Event",
      width: 210,
      render: (value) => (
        <span className="event-name" title={value || ""}>
          {value || "-"}
        </span>
      ),
    },
    {
      key: "severity",
      header: "Severity",
      width: 100,
      render: (value) => (
        <StatusBadge
          status={getSeverityStatus(value)}
          label={String(value || "UNKNOWN").toUpperCase()}
          size="small"
        />
      ),
    },
    {
      key: "score_delta",
      header: "Delta",
      align: "right",
      width: 90,
      render: (value) => (
        <span className={Number(value) < 0 ? "delta-negative" : ""}>
          {formatScoreDelta(value)}
        </span>
      ),
    },
    {
      key: "applied_to_score",
      header: "Trust 반영",
      width: 120,
      render: (value, event) => {
        const captureGap = event.processing_reason === "CAPTURE_GAP_UNSCORED";
        return (
          <StatusBadge
            status={
              captureGap
                ? "degraded"
                : normalizeBoolean(value)
                  ? "scored"
                  : "unscored"
            }
            label={
              captureGap
                ? "Capture Gap"
                : normalizeBoolean(value)
                  ? "반영"
                  : "미반영"
            }
            size="small"
          />
        );
      },
    },
    {
      key: "detected_at",
      header: "Detected At",
      width: 180,
      render: (value) => formatKST(value),
    },
  ];

  const mqttColumns = [
    {
      key: "device_id",
      header: "Device",
      width: 130,
      render: (value) => value || "미매핑",
    },
    {
      key: "topic",
      header: "Topic",
      width: 260,
      render: (value) => (
        <span className="topic-cell" title={value || ""}>
          {value || "-"}
        </span>
      ),
    },
    {
      key: "payload_size",
      header: "Payload",
      align: "right",
      width: 100,
      render: (value) => `${formatNumber(value)} B`,
    },
    {
      key: "is_json_valid",
      header: "JSON",
      width: 90,
      render: (value) => (
        <StatusBadge
          status={normalizeBoolean(value) ? "normal" : "danger"}
          label={normalizeBoolean(value) ? "정상" : "오류"}
          size="small"
        />
      ),
    },
    {
      key: "is_topic_valid",
      header: "Topic",
      width: 90,
      render: (value) => (
        <StatusBadge
          status={normalizeBoolean(value) ? "normal" : "warning"}
          label={normalizeBoolean(value) ? "정상" : "비정상"}
          size="small"
        />
      ),
    },
    {
      key: "received_at",
      header: "Received At",
      width: 180,
      render: (value) => formatKST(value),
    },
  ];

  return (
    <div className="dashboard-page">
      <div className="page-container">
        <PageHeader
          title="Dashboard"
          description="IoT Gateway, 등록 상태, Trust Score, Detection, Firewall 상태를 한눈에 확인합니다."
          updatedAt={lastUpdated ? formatKST(lastUpdated) : undefined}
          onRefresh={() => loadData(true)}
          refreshing={refreshing}
        />

        {partialWarnings.length > 0 && (
          <div className="page-warning-banner" role="alert">
            <div>
              <strong>일부 Dashboard 데이터 갱신 실패</strong>
              <p>실패한 항목은 0으로 바꾸지 않고, 이전 성공 데이터가 있으면 그대로 유지합니다.</p>
              <ul className="warning-message-list">
                {partialWarnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </div>
            <div className="page-warning-actions">
              <span>{POLLING_INTERVAL_MS / 1000}초마다 자동으로 다시 요청합니다.</span>
              <button
                type="button"
                className="button button-secondary"
                onClick={() => loadData(true)}
                disabled={refreshing}
              >
                지금 다시 시도
              </button>
            </div>
          </div>
        )}

        {error && !hasSuccessfulDataRef.current ? (
          <section className="panel">
            <div className="error-box">
              <div>
                <strong>Dashboard를 불러오지 못했습니다.</strong>
                <p>{error}</p>
              </div>
              <button
                type="button"
                className="button button-secondary"
                onClick={() => loadData(true)}
                disabled={refreshing}
              >
                다시 시도
              </button>
            </div>
          </section>
        ) : (
          <>
            <section className="summary-card-grid" aria-label="전체 상태 요약">
              <SummaryCard
                title="전체 기기"
                value={getSummaryCardValue("total_devices")}
                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.total_devices)}
                description="등록된 IoT 기기"
                updatedAt={sourceUpdatedAt("summary")}
                stale={sourceIsStale("summary")}
              />
              <SummaryCard
                title="등록 준비"
                value={
                  registrationPendingValue === null
                    ? null
                    : formatNumber(registrationPendingValue)
                }
                unavailable={registrationPendingValue === null}
                description="PENDING · 자동 대응 미적용"
                status={
                  registrationPendingValue !== null && registrationPendingValue > 0
                    ? "warning"
                    : "default"
                }
                updatedAt={sourceUpdatedAt("devices")}
                stale={sourceIsStale("devices")}
              />
              <SummaryCard
                title="등록 활성"
                value={
                  registrationActiveValue === null
                    ? null
                    : formatNumber(registrationActiveValue)
                }
                unavailable={registrationActiveValue === null}
                description="ACTIVE · 자동 대응 적용 대상"
                status="normal"
                updatedAt={sourceUpdatedAt("devices")}
                stale={sourceIsStale("devices")}
              />
              <SummaryCard
                title="관리 비활성"
                value={
                  registrationDisabledValue === null
                    ? null
                    : formatNumber(registrationDisabledValue)
                }
                unavailable={registrationDisabledValue === null}
                description="DISABLED · 새 자동 대응 중지"
                updatedAt={sourceUpdatedAt("devices")}
                stale={sourceIsStale("devices")}
              />
              <SummaryCard
                title="등록 상태 확인 불가"
                value={
                  registrationUnknownValue === null
                    ? null
                    : formatNumber(registrationUnknownValue)
                }
                unavailable={registrationUnknownValue === null}
                description="정책 migration/backfill 또는 상태 확인 필요"
                status={
                  registrationUnknownValue !== null && registrationUnknownValue > 0
                    ? "warning"
                    : "default"
                }
                updatedAt={sourceUpdatedAt("devices")}
                stale={sourceIsStale("devices")}
              />
              <SummaryCard
                title="정상"
                value={getSummaryCardValue("normal_devices")}
                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.normal_devices)}
                description="Trust Score 80 이상"
                status="normal"
                updatedAt={sourceUpdatedAt("summary")}
                stale={sourceIsStale("summary")}
              />
              <SummaryCard
                title="주의"
                value={getSummaryCardValue("warning_devices")}
                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.warning_devices)}
                description="Trust Score 60~79"
                status="warning"
                updatedAt={sourceUpdatedAt("summary")}
                stale={sourceIsStale("summary")}
              />
              <SummaryCard
                title="위험"
                value={getSummaryCardValue("danger_devices")}
                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.danger_devices)}
                description="Trust Score 30~59"
                status="danger"
                updatedAt={sourceUpdatedAt("summary")}
                stale={sourceIsStale("summary")}
              />
              <SummaryCard
                title="격리"
                value={getSummaryCardValue("isolated_devices")}
                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.isolated_devices)}
                description="Trust Score 30 미만"
                status="isolated"
                updatedAt={sourceUpdatedAt("summary")}
                stale={sourceIsStale("summary")}
              />
              <SummaryCard
                title="Firewall 적용"
                value={
                  firewallAppliedCard.value === null
                    ? null
                    : formatNumber(firewallAppliedCard.value)
                }
                unavailable={firewallAppliedCard.value === null}
                description="실제 차단 규칙 적용"
                status="normal"
                updatedAt={
                  firewallAppliedCard.sourceKey
                    ? sourceUpdatedAt(firewallAppliedCard.sourceKey)
                    : ""
                }
                stale={
                  firewallAppliedCard.sourceKey
                    ? sourceIsStale(firewallAppliedCard.sourceKey)
                    : false
                }
              />
              <SummaryCard
                title="Firewall 대기"
                value={
                  firewallPendingCard.value === null
                    ? null
                    : formatNumber(firewallPendingCard.value)
                }
                unavailable={firewallPendingCard.value === null}
                description="차단 규칙 적용 대기"
                status={
                  firewallPendingCard.value !== null && firewallPendingCard.value > 0
                    ? "warning"
                    : "default"
                }
                updatedAt={
                  firewallPendingCard.sourceKey
                    ? sourceUpdatedAt(firewallPendingCard.sourceKey)
                    : ""
                }
                stale={
                  firewallPendingCard.sourceKey
                    ? sourceIsStale(firewallPendingCard.sourceKey)
                    : false
                }
              />
              <SummaryCard
                title="Firewall 실패"
                value={
                  firewallFailedCard.value === null
                    ? null
                    : formatNumber(firewallFailedCard.value)
                }
                unavailable={firewallFailedCard.value === null}
                description="차단 규칙 적용 실패"
                status={
                  firewallFailedCard.value !== null && firewallFailedCard.value > 0
                    ? "danger"
                    : "default"
                }
                updatedAt={
                  firewallFailedCard.sourceKey
                    ? sourceUpdatedAt(firewallFailedCard.sourceKey)
                    : ""
                }
                stale={
                  firewallFailedCard.sourceKey
                    ? sourceIsStale(firewallFailedCard.sourceKey)
                    : false
                }
              />
            </section>

            <SourceStateNotice state={sourceState.summary} label="기기 요약" />
            <SourceStateNotice
              state={sourceState.devices}
              label="기기 등록 상태"
            />
            <div className="registration-state-guide" role="note">
              <strong>등록 상태와 Trust 상태는 별개입니다.</strong>
              <span>
                PENDING의 초기 Trust Score 100은 보안 검증 완료를 의미하지 않으며,
                자동 감점·차단은 적용되지 않습니다.
              </span>
            </div>

            <section className="status-grid">
              <article className="panel status-panel">
                <div className="panel-header">
                  <div>
                    <h2>Gateway 상태</h2>
                    <p className="panel-description">
                      Raspberry Pi의 마지막 Metric 수집 상태입니다.
                    </p>
                  </div>
                  <StatusBadge
                    status={
                      sourceHasSuccess("gateway")
                        ? getGatewayStatusTheme(gatewayStatus)
                        : sourceState.gateway?.status === "error"
                          ? "failed"
                          : "unknown"
                    }
                    label={
                      sourceHasSuccess("gateway")
                        ? gatewayStatus
                        : sourceState.gateway?.status === "error"
                          ? "확인 불가"
                          : "조회 중"
                    }
                  />
                </div>

                <SourceStateNotice state={sourceState.gateway} label="Gateway Metric" />

                {sourceHasSuccess("gateway") && gatewayMetric ? (
                  <>
                    <div className="metric-card-grid">
                      <MetricCard
                        label="CPU"
                        value={formatResourceValue(gatewayMetric.cpu_percent)}
                        unit="%"
                        percentage={gatewayMetric.cpu_percent}
                        status={getResourceStatus(gatewayMetric.cpu_percent)}
                        description="현재 CPU 사용률"
                        updatedAt={sourceUpdatedAt("gateway")}
                        stale={sourceIsStale("gateway")}
                      />
                      <MetricCard
                        label="Memory"
                        value={formatResourceValue(gatewayMetric.memory_percent)}
                        unit="%"
                        percentage={gatewayMetric.memory_percent}
                        status={getResourceStatus(gatewayMetric.memory_percent)}
                        description="현재 Memory 사용률"
                        updatedAt={sourceUpdatedAt("gateway")}
                        stale={sourceIsStale("gateway")}
                      />
                      <MetricCard
                        label="Disk"
                        value={formatResourceValue(gatewayMetric.disk_percent)}
                        unit="%"
                        percentage={gatewayMetric.disk_percent}
                        status={getResourceStatus(gatewayMetric.disk_percent)}
                        description="현재 Disk 사용률"
                        updatedAt={sourceUpdatedAt("gateway")}
                        stale={sourceIsStale("gateway")}
                      />
                      <MetricCard
                        label="Temperature"
                        value={formatResourceValue(gatewayMetric.temperature_c)}
                        unit="℃"
                        status={getTemperatureStatus(gatewayMetric.temperature_c)}
                        description="CPU 온도"
                        updatedAt={sourceUpdatedAt("gateway")}
                        stale={sourceIsStale("gateway")}
                      />
                    </div>
                    <p className="status-footer">
                      마지막 수집: {formatKST(gatewayMetric.collected_at)}
                    </p>
                  </>
                ) : sourceHasSuccess("gateway") ? (
                  <EmptyState
                    title="Gateway Metric이 없습니다."
                    description="조회는 성공했지만 최근 Gateway Metric 데이터가 없습니다."
                    compact
                  />
                ) : (
                  <div className="section-unavailable">
                    {loading ? "Gateway Metric을 조회하는 중입니다." : "Gateway Metric을 확인할 수 없습니다."}
                  </div>
                )}
              </article>

              <article className="panel status-panel">
                <div className="panel-header">
                  <div>
                    <h2>Packet Capture</h2>
                    <p className="panel-description">
                      최근 Packet Feature의 Capture 품질입니다.
                    </p>
                  </div>
                  <StatusBadge
                    status={
                      sourceHasSuccess("packetFeatures")
                        ? captureSummary.failed > 0 || captureSummary.excluded > 0
                          ? "degraded"
                          : "normal"
                        : sourceState.packetFeatures?.status === "error"
                          ? "failed"
                          : "unknown"
                    }
                    label={
                      sourceHasSuccess("packetFeatures")
                        ? captureSummary.failed > 0 || captureSummary.excluded > 0
                          ? "DEGRADED"
                          : "NORMAL"
                        : sourceState.packetFeatures?.status === "error"
                          ? "확인 불가"
                          : "조회 중"
                    }
                  />
                </div>

                <SourceStateNotice
                  state={sourceState.packetFeatures}
                  label="Packet Feature"
                />

                <div className="mini-grid">
                  <SummaryCard
                    title="분석 가능"
                    value={
                      sourceHasSuccess("packetFeatures")
                        ? formatNumber(captureSummary.eligible)
                        : null
                    }
                    unavailable={!sourceHasSuccess("packetFeatures")}
                    description="Capture 품질 통과"
                    status="normal"
                    updatedAt={sourceUpdatedAt("packetFeatures")}
                    stale={sourceIsStale("packetFeatures")}
                  />
                  <SummaryCard
                    title="분석 제외"
                    value={
                      sourceHasSuccess("packetFeatures")
                        ? formatNumber(captureSummary.excluded)
                        : null
                    }
                    unavailable={!sourceHasSuccess("packetFeatures")}
                    description="Coverage 또는 Timing 문제"
                    status={
                      sourceHasSuccess("packetFeatures") && captureSummary.excluded > 0
                        ? "warning"
                        : "default"
                    }
                    updatedAt={sourceUpdatedAt("packetFeatures")}
                    stale={sourceIsStale("packetFeatures")}
                  />
                  <SummaryCard
                    title="수집 실패"
                    value={
                      sourceHasSuccess("packetFeatures")
                        ? formatNumber(captureSummary.failed)
                        : null
                    }
                    unavailable={!sourceHasSuccess("packetFeatures")}
                    description="Segment 처리 실패"
                    status={
                      sourceHasSuccess("packetFeatures") && captureSummary.failed > 0
                        ? "danger"
                        : "default"
                    }
                    updatedAt={sourceUpdatedAt("packetFeatures")}
                    stale={sourceIsStale("packetFeatures")}
                  />
                  <SummaryCard
                    title="평균 Coverage"
                    value={
                      !sourceHasSuccess("packetFeatures")
                        ? null
                        : captureSummary.averageCoverage === null
                          ? "계산 불가"
                          : `${formatNumber(captureSummary.averageCoverage * 100, 1)}%`
                    }
                    unavailable={!sourceHasSuccess("packetFeatures")}
                    description="최근 Packet Window"
                    updatedAt={sourceUpdatedAt("packetFeatures")}
                    stale={sourceIsStale("packetFeatures")}
                  />
                </div>
              </article>
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>API Health</h2>
                  <p className="panel-description">
                    Backend API와 Database 연결 상태를 확인합니다.
                  </p>
                </div>
                <StatusBadge
                  status={
                    sourceHasSuccess("health")
                      ? healthStatus.status
                      : sourceState.health?.status === "error"
                        ? "failed"
                        : "unknown"
                  }
                  label={
                    sourceHasSuccess("health")
                      ? healthStatus.label
                      : sourceState.health?.status === "error"
                        ? "확인 불가"
                        : "조회 중"
                  }
                />
              </div>

              <SourceStateNotice state={sourceState.health} label="API Health" />

              {sourceHasSuccess("health") && health ? (
                <div className="health-grid">
                  <div className="health-item">
                    <span>API Status</span>
                    <strong>{getHealthDisplayLabel(health.status)}</strong>
                  </div>
                  <div className="health-item">
                    <span>Database</span>
                    <strong>{getHealthDisplayLabel(health.database)}</strong>
                  </div>
                  <div className="health-item">
                    <span>DB Connection</span>
                    <StatusBadge
                      status={normalizeBoolean(health.db_connected) ? "connected" : "failed"}
                      label={normalizeBoolean(health.db_connected) ? "연결됨" : "연결 실패"}
                      size="small"
                    />
                  </div>
                  <div className="health-item">
                    <span>Server Time</span>
                    <strong>{formatKST(health.server_time)}</strong>
                  </div>
                </div>
              ) : sourceHasSuccess("health") ? (
                <EmptyState
                  title="Health 정보가 없습니다."
                  description="Health API 조회는 성공했지만 응답 데이터가 비어 있습니다."
                  compact
                />
              ) : (
                <div className="section-unavailable">
                  {loading ? "Health 정보를 조회하는 중입니다." : "Health 정보를 확인할 수 없습니다."}
                </div>
              )}

              {sourceUpdatedAt("health") && (
                <p className="status-footer">
                  최근 성공 조회: {formatKST(sourceUpdatedAt("health"))}
                </p>
              )}
            </section>

            <section className="panel table-panel">
              <div className="panel-header">
                <div>
                  <h2>Trust Score Summary</h2>
                  <p className="panel-description">
                    Device별 등록 상태와 현재 Trust·Firewall 상태를 분리해 표시합니다.
                  </p>
                </div>
                <span className={`data-count ${!sourceHasSuccess("trustScores") ? "unavailable" : ""}`}>
                  {sourceHasSuccess("trustScores")
                    ? `${formatNumber(trustScores.length)}건`
                    : "확인 불가"}
                </span>
              </div>
              <SourceStateNotice state={sourceState.trustScores} label="Trust Score" />
              {sourceHasSuccess("trustScores") ? (
                <div className="table-scroll">
                  <DataTable
                    columns={trustColumns}
                    rows={trustRows}
                    loading={loading && trustScores.length === 0}
                    rowKey="device_id"
                    minWidth={1020}
                    tableLabel="등록 상태 및 Trust Score 요약"
                    emptyTitle="표시할 Trust Score 데이터가 없습니다."
                    emptyDescription="조회는 성공했지만 현재 Trust Score 데이터가 없습니다."
                    rowClassName={(item) => {
                      const status = getTrustStatus(item.trust_score, item.status);
                      if (status === "isolated") {
                        return "row-danger";
                      }
                      if (status === "danger" || status === "warning") {
                        return "row-warning";
                      }
                      return "";
                    }}
                  />
                </div>
              ) : (
                <div className="section-unavailable">
                  {loading ? "Trust Score를 조회하는 중입니다." : "Trust Score를 확인할 수 없습니다."}
                </div>
              )}
            </section>

            <section className="panel">
              <div className="panel-header">
                <div>
                  <h2>MQTT Feature Graph</h2>
                  <p className="panel-description">
                    10초 Window별 MQTT 발행량, Payload 크기, 메시지 간격을 표시합니다.
                  </p>
                </div>
                <span className={`data-count ${!sourceHasSuccess("features") ? "unavailable" : ""}`}>
                  {sourceHasSuccess("features")
                    ? `${formatNumber(features.length)}개 Window`
                    : "확인 불가"}
                </span>
              </div>
              <SourceStateNotice state={sourceState.features} label="MQTT Feature" />
              {!sourceHasSuccess("features") ? (
                <div className="section-unavailable">
                  {loading ? "그래프 데이터를 조회하는 중입니다." : "MQTT Feature를 확인할 수 없습니다."}
                </div>
              ) : features.length === 0 ? (
                <EmptyState
                  title="표시할 Feature Log가 없습니다."
                  description="조회는 성공했지만 최근 MQTT Feature 데이터가 없습니다."
                  compact
                />
              ) : (
                <div className="chart-wrap">
                  <ResponsiveContainer width="100%" height={360}>
                    <LineChart
                      data={featureChartData}
                      margin={{ top: 10, right: 20, left: 0, bottom: 10 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" />
                      <XAxis dataKey="chart_time" minTickGap={25} />
                      <YAxis />
                      <Tooltip
                        labelFormatter={(_, payload) =>
                          formatKST(payload?.[0]?.payload?.window_start)
                        }
                      />
                      <Legend />
                      <Line
                        type="monotone"
                        dataKey="publish_count"
                        stroke="#2563eb"
                        strokeWidth={3}
                        dot={false}
                        name="Publish Count"
                      />
                      <Line
                        type="monotone"
                        dataKey="avg_payload_size"
                        stroke="#16a34a"
                        strokeWidth={2}
                        dot={false}
                        name="Avg Payload Size"
                      />
                      <Line
                        type="monotone"
                        dataKey="max_payload_size"
                        stroke="#ef4444"
                        strokeWidth={3}
                        dot={false}
                        name="Max Payload Size"
                      />
                      <Line
                        type="monotone"
                        dataKey="avg_message_interval"
                        stroke="#9333ea"
                        strokeWidth={2}
                        dot={false}
                        name="Avg Message Interval"
                      />
                      <Line
                        type="monotone"
                        dataKey="min_message_interval"
                        stroke="#f97316"
                        strokeWidth={2}
                        dot={false}
                        name="Min Message Interval"
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              )}
            </section>

            <section className="panel table-panel">
              <div className="panel-header">
                <div>
                  <h2>최근 탐지 이벤트</h2>
                  <p className="panel-description">
                    Rule 및 AI 탐지 결과와 Trust Score 반영 여부를 표시합니다.
                  </p>
                </div>
                <span className={`data-count ${!sourceHasSuccess("events") ? "unavailable" : ""}`}>
                  {sourceHasSuccess("events")
                    ? `최근 ${formatNumber(events.length)}건`
                    : "확인 불가"}
                </span>
              </div>
              <SourceStateNotice state={sourceState.events} label="탐지 이벤트" />
              {sourceHasSuccess("events") ? (
                <div className="table-scroll">
                  <DataTable
                    columns={eventColumns}
                    rows={events}
                    loading={loading && events.length === 0}
                    rowKey="id"
                    minWidth={1100}
                    tableLabel="최근 탐지 이벤트"
                    emptyTitle="표시할 탐지 이벤트가 없습니다."
                    emptyDescription="조회는 성공했지만 최근 탐지 이벤트가 없습니다."
                    rowClassName={(event) => {
                      if (event.processing_reason === "CAPTURE_GAP_UNSCORED") {
                        return "row-warning";
                      }
                      if (String(event.severity).toLowerCase() === "high") {
                        return "row-danger";
                      }
                      if (getDetectorStatus(event) === "ai") {
                        return "row-ai";
                      }
                      return "";
                    }}
                  />
                </div>
              ) : (
                <div className="section-unavailable">
                  {loading ? "탐지 이벤트를 조회하는 중입니다." : "탐지 이벤트를 확인할 수 없습니다."}
                </div>
              )}
            </section>

            <section className="panel table-panel">
              <div className="panel-header">
                <div>
                  <h2>최근 MQTT 로그</h2>
                  <p className="panel-description">
                    최근 수신한 Topic과 Payload 유효성입니다.
                  </p>
                </div>
                <span className={`data-count ${!sourceHasSuccess("logs") ? "unavailable" : ""}`}>
                  {sourceHasSuccess("logs")
                    ? `최근 ${formatNumber(logs.length)}건`
                    : "확인 불가"}
                </span>
              </div>
              <SourceStateNotice state={sourceState.logs} label="MQTT 로그" />
              {sourceHasSuccess("logs") ? (
                <div className="table-scroll">
                  <DataTable
                    columns={mqttColumns}
                    rows={logs}
                    loading={loading && logs.length === 0}
                    rowKey="id"
                    minWidth={950}
                    tableLabel="최근 MQTT 로그"
                    emptyTitle="표시할 MQTT 로그가 없습니다."
                    emptyDescription="조회는 성공했지만 최근 MQTT 로그가 없습니다."
                    rowClassName={(log) => {
                      if (
                        !normalizeBoolean(log.is_json_valid) ||
                        !normalizeBoolean(log.is_topic_valid)
                      ) {
                        return "row-warning";
                      }
                      return "";
                    }}
                  />
                </div>
              ) : (
                <div className="section-unavailable">
                  {loading ? "MQTT 로그를 조회하는 중입니다." : "MQTT 로그를 확인할 수 없습니다."}
                </div>
              )}
            </section>
          </>
        )}
      </div>
    </div>
  );
}
