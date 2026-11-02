import { formatScoreDelta, formatActualScoreDelta, getScoreEffectDescription, getAppliedStatus, getProcessingReasonLabel } from "../utils/eventScoreEffect";
import { uiLabel } from "../utils/uiText";
import { observationState } from "../utils/runtimeStatus";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {

  getAiWarnings,
  getRuntimeStatus,
  getPacketCaptureWindows,
  getEvents,


  getDevices,

  getFirewallRules,

  getGatewayMetrics,

  getHealth,

  getMqttLogs,

  getPacketFeatureLogs,

  getSummary,

  getTrustScoreSummary,

} from "../api/api";



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



/**
 * Capture API requires a real session_id plus timezone-aware from/to.
 * Restrict the dashboard snapshot to one session represented in the currently
 * fetched Packet Feature page. This is NOT a global capture-window total.
 */
function getDashboardCaptureQuery(packetResponse) {
  const items = Array.isArray(packetResponse?.items) ? packetResponse.items : [];
  const valid = items.filter((item) => {
    const sid = item?.capture_session_id ?? item?.session_id;
    const start = Date.parse(item?.window_start ?? "");
    const end = Date.parse(item?.window_end ?? "");
    return sid !== null && sid !== undefined && String(sid).trim() !== "" &&
      Number.isFinite(start) && Number.isFinite(end) && start <= end;
  });
  if (!valid.length) return null;

  const latest = [...valid].sort((a, b) =>
    Date.parse(b.window_end) - Date.parse(a.window_end)
  )[0];
  const sessionId = String(latest.capture_session_id ?? latest.session_id);
  const sameSession = valid.filter((item) =>
    String(item.capture_session_id ?? item.session_id) === sessionId
  );
  const starts = sameSession.map((item) => Date.parse(item.window_start));
  const ends = sameSession.map((item) => Date.parse(item.window_end));
  return {
    session_id: sessionId,
    from: new Date(Math.min(...starts)).toISOString(),
    to: new Date(Math.max(...ends)).toISOString(),
    limit: 20,
    offset: 0,
  };
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



function normalizeBoolean(value) {

  return value === true || value === 1 || value === "1" || value === "true";

}



function hasFiniteNumber(value) {

  return value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));

}



function getTrustStatus(score, status) {

  if (status) {

    return String(status).toLowerCase();

  }

  if (score === null || score === undefined || score === "") return "unknown";

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

  return labels[normalized] || status || "방화벽 기록 없음";

}



function getGatewayStatus(metric, now = Date.now()) {

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

  const elapsedSeconds = (now - collectedAt) / 1000;

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



function getCaptureBadge(summary, count, state) {
  if (state?.status === "error") return { status: "unknown", label: "확인 불가" };
  if (!state?.lastSuccessAt) return { status: "unknown", label: "조회 중" };
  if (count === 0) return { status: "no_data", label: "자료 없음" };
  if (summary.failed > 0 || summary.excluded > 0) {
    return { status: "degraded", label: "수집 품질 저하" };
  }
  if (summary.eligible !== count) return { status: "unknown", label: "확인 불가" };
  return { status: "normal", label: "수집 양호" };
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


  const [events, setEvents] = useState([]);

  const [trustScores, setTrustScores] = useState([]);

  const [gatewayMetric, setGatewayMetric] = useState(null);

  const [packetFeatures, setPacketFeatures] = useState([]);

  const [firewallRules, setFirewallRules] = useState([]);

  const [health, setHealth] = useState(null);
  const [aiWarnings, setAiWarnings] = useState([]);
  const [runtime, setRuntime] = useState(null);
  const [observationNow, setObservationNow] = useState(Date.now);
  useEffect(() => {
    const timer = window.setInterval(() => setObservationNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);
  const [captureWindows, setCaptureWindows] = useState([]);
  const [captureContext, setCaptureContext] = useState(null);

  const [loading, setLoading] = useState(true);

  const [refreshing, setRefreshing] = useState(false);

  const [error, setError] = useState("");

  const [partialWarnings, setPartialWarnings] = useState([]);

  const [lastUpdated, setLastUpdated] = useState("");

  const [sourceState, setSourceState] = useState(createInitialSourceState);

  const requestControllerRef = useRef(null);

  const requestIdRef = useRef(0);

  const hasSuccessfulDataRef = useRef(false);
  const captureQueryKeyRef = useRef("");



  const loadData = useCallback(async (isManualRefresh = false) => {

    if (

      requestControllerRef.current &&

      !requestControllerRef.current.signal.aborted

    ) {

      if (isManualRefresh) {

        setRefreshing(true);

      }

      return;

    }

    const requestId = requestIdRef.current + 1;

    requestIdRef.current = requestId;

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

        key: "events",

        label: "탐지 이벤트",

        request: getEvents({ limit: 5, offset: 0 }, options),

      },

      {

        key: "trustScores",

        label: "신뢰점수",

        request: getTrustScoreSummary({ limit: 10, offset: 0 }, options),

      },

      {

        key: "gateway",

        label: "게이트웨이 지표",

        request: getGatewayMetrics({ limit: 1, offset: 0 }, options),

      },

      {

        key: "packetFeatures",

        label: "패킷 분석 지표",

        request: getPacketFeatureLogs({ limit: 20, offset: 0 }, options),

      },

      {

        key: "firewall",

        label: "방화벽 규칙",

        request: getFirewallRules({ limit: 100, offset: 0 }, options),

      },

      { key: "health", label: "API 연결 상태", request: getHealth(options) },
      { key: "aiWarnings", label: "AI 경고", request: getAiWarnings({ limit: 10, offset: 0 }, options) },
      { key: "runtime", label: "AI 실행 상태", request: getRuntimeStatus(options) },

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



        const data = result.value;
        try {
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
          case "aiWarnings":
            if (!Array.isArray(data?.items)) throw new Error("AI warnings 응답 형식 오류");
            setAiWarnings(data.items);
            break;
          case "runtime":
            if (!data || typeof data !== "object") throw new Error("실행 상태 응답 형식 오류");
            setRuntime(data?.item ?? data);
            break;

          default:
            break;
          }
          successCount += 1;
          stateUpdates[requestInfo.key] = {
            status: "success",
            error: "",
            lastSuccessAt: now,
          };
        } catch (parseError) {
          const message = parseError instanceof Error ? parseError.message : "응답 형식 오류";
          warnings.push(`${requestInfo.label}: ${message}`);
          stateUpdates[requestInfo.key] = { status: "error", error: message };
        }
      });

      // Capture Window 조회는 세 가지 필수값이 있어야 합니다.
      // Packet Feature에서 유효한 단일 Session + Window 기간을 확보한 뒤 요청합니다.
      const packetFeatureResult = results[requests.findIndex((r) => r.key === "packetFeatures")];
      const captureQuery = packetFeatureResult?.status === "fulfilled"
        ? getDashboardCaptureQuery(packetFeatureResult.value)
        : null;

      if (!captureQuery) {
        // Context를 확인하지 못한 데이터를 성공/0건으로 해석하지 않습니다.
        captureQueryKeyRef.current = "";
        setCaptureContext(null);
        setCaptureWindows([]);
        stateUpdates.captureWindows = {
          status: "skipped",
          error: "수집 세션 ID와 분석 기간이 없어 조회를 보류했습니다.",
          lastSuccessAt: "",
        };
      } else {
        const { session_id, from, to } = captureQuery;
        const captureQueryKey = `${session_id}|${from}|${to}`;
        if (captureQueryKeyRef.current !== captureQueryKey) {
          setCaptureWindows([]);
          captureQueryKeyRef.current = captureQueryKey;
          // 다른 Session의 이전 성공 자료를 새 Session에 표시하지 않습니다.
          stateUpdates.captureWindows = { status: "idle", error: "", lastSuccessAt: "" };
        }
        setCaptureContext({ session_id, from, to });
        try {
          const captureData = await getPacketCaptureWindows(captureQuery, options);
          if (requestId !== requestIdRef.current || controller.signal.aborted) return;
          if (!Array.isArray(captureData?.items)) {
            throw new Error("수집 구간 응답 형식 오류");
          }
          setCaptureWindows(captureData.items);
          successCount += 1;
          stateUpdates.captureWindows = {
            status: "success", error: "", lastSuccessAt: new Date().toISOString(),
          };
        } catch (captureError) {
          if (controller.signal.aborted || captureError?.isCanceled) return;
          const message = captureError instanceof Error
            ? captureError.message
            : "수집 구간 조회 실패";
          warnings.push(`Packet Capture Window: ${message}`);
          stateUpdates.captureWindows = {
            status: "error", error: message,
            ...(stateUpdates.captureWindows?.lastSuccessAt === "" ? { lastSuccessAt: "" } : {}),
          };
        }
      }

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

        throw new Error("모든 종합 현황 API 요청에 실패했습니다.");

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

        if (requestControllerRef.current === controller) {

          requestControllerRef.current = null;

        }

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

      requestControllerRef.current = null;

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

  const captureBadge = getCaptureBadge(captureSummary, packetFeatures.length, sourceState.packetFeatures);

  const gatewayStatus = useMemo(

    () => getGatewayStatus(gatewayMetric, observationNow),

    [gatewayMetric, observationNow]

  );

  const healthStatus = useMemo(() => getHealthStatus(health), [health]);

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

      header: "기기",

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

      header: "신뢰점수",

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

      header: "신뢰 상태",

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

      header: "방화벽",

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

      header: "마지막 수신 시각",

      width: 180,

      render: (value) => formatKST(value),

    },

  ];



  const eventColumns = [

    {

      key: "device_id",

      header: "기기",

      width: 130,

      render: (value, event) => value || event.subject_ip || "미매핑",

    },

    {

      key: "detector_type",

      header: "탐지 방식",

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

      header: "탐지 유형",

      width: 210,

      render: (value) => (

        <span className="event-name" title={value || ""}>

          {uiLabel(value || "-")}

        </span>

      ),

    },

    {

      key: "severity",

      header: "심각도",

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
      key: "actual_score_delta",
      header: "실제 점수 변화량",
      align: "right",
      width: 110,
      render: (value, event) => (
        <span
          className={typeof value === "number" && value < 0 ? "delta-negative" : ""}
          title={`정책상 점수 변화량 ${formatScoreDelta(event.policy_score_delta ?? event.score_delta)} · ${getScoreEffectDescription(event)}`}
        >
          {formatActualScoreDelta(event)}
        </span>
      ),
    },
    {
      key: "applied_to_score",
      header: "신뢰점수 반영",
      width: 120,
      render: (_, event) => {
        const applied = getAppliedStatus(event);
        return <StatusBadge status={applied.status} label={applied.label} size="small" />;
      },
    },
    {
      key: "processing_reason",
      header: "처리 결과",
      width: 230,
      render: (value) => (
        <span className={value === "CAPTURE_GAP_UNSCORED" ? "reason-warning" : ""} title={value || ""}>
          {getProcessingReasonLabel(value)}
        </span>
      ),
    },

    {

      key: "detected_at",

      header: "탐지 시각",

      width: 180,

      render: (value) => formatKST(value),

    },

  ];



  const mqttColumns = [

    {

      key: "device_id",

      header: "기기",

      width: 130,

      render: (value) => value || "미매핑",

    },

    {

      key: "topic",

      header: "토픽",

      width: 260,

      render: (value) => (

        <span className="topic-cell" title={value || ""}>

          {value || "-"}

        </span>

      ),

    },

    {

      key: "payload_size",

      header: "메시지 내용",

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

      header: "토픽",

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

      header: "수신 시각",

      width: 180,

      render: (value) => formatKST(value),

    },

  ];



  const runtimeView = observationState(runtime, {
    failed: sourceState.runtime?.status === "error", now: observationNow,
  });
  const latestCompletion = (Array.isArray(runtime?.completions) ? runtime.completions : [])
    .map((item) => item.completed_window_end)
    .filter((value) => value && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0];
  const captureQuality = captureWindows.reduce((counts, item) => {
    const observation = item.observation ?? item.capture_status ?? item.segment_status ?? item.status;
    if (observation === "FAILED" || item.segment_status === "FAILED") counts.failed += 1;
    else if (item.capture_eligible === true) counts.eligible += 1;
    else if (item.capture_eligible === false || observation === "MISSING") counts.excluded += 1;
    else counts.unknown += 1;
    return counts;
  }, { eligible: 0, excluded: 0, failed: 0, unknown: 0 });

  return (

    <div className="dashboard-page">

      <div className="page-container">

        <PageHeader

          title="종합 현황"

          description="IoT 게이트웨이, 등록 상태, 신뢰점수, 탐지, 방화벽 상태를 한눈에 확인합니다."

          updatedAt={lastUpdated ? formatKST(lastUpdated) : undefined}

          onRefresh={() => loadData(true)}

          refreshing={refreshing}

        />



        {partialWarnings.length > 0 && (

          <div className="page-warning-banner" role="alert">

            <div>

              <strong>일부 종합 현황 데이터 갱신 실패</strong>

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

                <strong>종합 현황를 불러오지 못했습니다.</strong>

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

                description="등록 대기 · 자동 대응 미적용"

                status="warning"

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

                description="등록 활성 · 자동 대응 적용 대상"

                status="normal"

                updatedAt={sourceUpdatedAt("devices")}

                stale={sourceIsStale("devices")}

              />

              <SummaryCard

                title="관리 비활성"

                status="unknown"

                value={

                  registrationDisabledValue === null

                    ? null

                    : formatNumber(registrationDisabledValue)

                }

                unavailable={registrationDisabledValue === null}

                description="관리 비활성 · 새 자동 대응 중지"

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

                description="등록 정책 정보 확인 필요"

                status="unknown"

                updatedAt={sourceUpdatedAt("devices")}

                stale={sourceIsStale("devices")}

              />

              <SummaryCard

                title="정상"

                value={getSummaryCardValue("normal_devices")}

                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.normal_devices)}

                description="신뢰점수 80 이상"

                status="normal"

                updatedAt={sourceUpdatedAt("summary")}

                stale={sourceIsStale("summary")}

              />

              <SummaryCard

                title="주의"

                value={getSummaryCardValue("warning_devices")}

                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.warning_devices)}

                description="신뢰점수 60~79"

                status="warning"

                updatedAt={sourceUpdatedAt("summary")}

                stale={sourceIsStale("summary")}

              />

              <SummaryCard

                title="위험"

                value={getSummaryCardValue("danger_devices")}

                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.danger_devices)}

                description="신뢰점수 30~59"

                status="danger"

                updatedAt={sourceUpdatedAt("summary")}

                stale={sourceIsStale("summary")}

              />

              <SummaryCard

                title="격리"

                value={getSummaryCardValue("isolated_devices")}

                unavailable={!sourceHasSuccess("summary") || !hasFiniteNumber(summary?.isolated_devices)}

                description="신뢰점수 30 미만"

                status="isolated"

                updatedAt={sourceUpdatedAt("summary")}

                stale={sourceIsStale("summary")}

              />

              <SummaryCard

                title="방화벽 적용"

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

                title="방화벽 대기"

                value={

                  firewallPendingCard.value === null

                    ? null

                    : formatNumber(firewallPendingCard.value)

                }

                unavailable={firewallPendingCard.value === null}

                description="차단 규칙 적용 대기"

                status="warning"

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

                title="방화벽 실패"

                value={

                  firewallFailedCard.value === null

                    ? null

                    : formatNumber(firewallFailedCard.value)

                }

                unavailable={firewallFailedCard.value === null}

                description="차단 규칙 적용 실패"

                status="danger"

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



            {/* Phase 9: 새 API는 Trust/Firewall 운영 판정과 분리하여 표시 */}
            <section className="panel" aria-label="AI 및 Packet 운영 상태">
              <div className="panel-header">
                <div>
                  <h2>AI 분석 및 패킷 수집 현황</h2>
                  <p className="panel-description">
                    AI 경고는 보조 관찰 결과이며 단독으로 감점이나 격리를 의미하지 않습니다.
                    모델 설정과 실제 실행 상태도 별개입니다.
                  </p>
                </div>
              </div>
              <div className="summary-card-grid">
                <SummaryCard
                  title="AI 경고 (최근 조회)"
                  value={sourceHasSuccess("aiWarnings") ? formatNumber(aiWarnings.length) : null}
                  unavailable={!sourceHasSuccess("aiWarnings")}
                  description="최근 최대 10건 · 전체 누적 건수 아님"
                  status="ai"
                  stale={sourceIsStale("aiWarnings")}
                  updatedAt={sourceUpdatedAt("aiWarnings")}
                />
                <SummaryCard
                  title="AI 실제 실행 상태"
                  value={runtimeView.status}
                  unavailable={!sourceHasSuccess("runtime")}
                  description={`관측 정보: ${!sourceHasSuccess("runtime") && sourceState.runtime?.status !== "error" ? "조회 중" : uiLabel(runtimeView.freshness)} · 설정과 실제 실행은 별개입니다`}
                  status={["RUNNING", "ACTIVE", "HEALTHY", "READY"].includes(runtimeView.status) ? "normal" : ["FAILED", "ERROR", "CRASHED", "UNHEALTHY"].includes(runtimeView.status) ? "danger" : "unknown"}
                  stale={sourceIsStale("runtime") || runtimeView.freshness === "STALE"}
                  updatedAt={sourceUpdatedAt("runtime")}
                />
                <SummaryCard
                  title="수집 구간 (선택 수집 세션)"
                  value={sourceHasSuccess("captureWindows") ? formatNumber(captureWindows.length) : null}
                  unavailable={!sourceHasSuccess("captureWindows")}
                  description="최근 패킷 분석 지표의 단일 수집 세션 · 최대 20건 · 전체 수집 건수 아님"
                  stale={sourceIsStale("captureWindows")}
                  updatedAt={sourceUpdatedAt("captureWindows")}
                />
              </div>
              <SourceStateNotice state={sourceState.aiWarnings} label="AI 경고" />
              <SourceStateNotice state={sourceState.runtime} label="AI 실행 상태" />
              <SourceStateNotice state={sourceState.captureWindows} label="패킷 수집 구간" />
              {sourceState.captureWindows?.status === "skipped" && (
                <p className="text-muted" role="status" style={{ marginTop: 10 }}>
                  수집 구간 조회 대기: 최근 패킷 분석 지표에 실제 수집 세션 ID와
                  분석 구간 기간이 없습니다. 오류를 만들지 않도록 서버 요청을 보류했습니다.
                  실제 수집 세션이 있으면 패킷 통신 페이지에서도 확인할 수 있습니다.
                </p>
              )}
              {captureContext && (
                <p className="text-muted" style={{ marginTop: 10 }}>
                  조회 범위: 수집 세션 {captureContext.session_id} · {formatKST(captureContext.from)}
                  {" ~ "}{formatKST(captureContext.to)} (KST).
                  최근 패킷 분석 지표 페이지의 일부 구간만 다루며 전체 통계가 아닙니다.
                </p>
              )}
              <div className="health-grid" style={{ marginTop: 12 }}>
                <div className="health-item">
                  <span>실행 상태 관측 시각</span>
                  <strong>{sourceHasSuccess("runtime") ? formatKST(runtime?.observed_at) : "확인 불가"}</strong>
                </div>
                <div className="health-item">
                  <span>최근 추론 완료 구간 · 과거 완료 근거</span>
                  <strong>{sourceHasSuccess("runtime") && latestCompletion ? formatKST(latestCompletion) : "완료 근거 확인 불가"}</strong>
                </div>
                <div className="health-item">
                  <span>수집 품질 · 위 조회 범위 기준</span>
                  <strong>{sourceHasSuccess("captureWindows")
                    ? captureWindows.length
                      ? `분석 가능 ${captureQuality.eligible} · 제외·미수집 ${captureQuality.excluded} · 실패 ${captureQuality.failed} · 미확인 ${captureQuality.unknown}`
                      : "조회된 수집 구간 없음 · 정상 수집 여부 확인 불가"
                    : "확인 불가"}</strong>
                </div>
                <div className="health-item">
                  <span>최근 AI 경고</span>
                  <strong>
                    {sourceHasSuccess("aiWarnings")
                      ? aiWarnings.length
                        ? aiWarnings.map((item, index) =>
                            uiLabel(item.event_type ?? item.warning_type ?? item.id ?? `경고 ${index + 1}`)
                          ).join(", ")
                        : "조회된 경고 없음"
                      : "확인 불가"}
                  </strong>
                </div>
              </div>
              <details className="phase9-json-details" style={{ marginTop: 12 }}>
                <summary>상세 정보 보기 · 실행 상태와 수집 구간 원본</summary>
                <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{JSON.stringify({ runtime, capture_windows: captureWindows }, null, 2)}</pre>
              </details>
            </section>

            <section className="status-grid">

              <article className="panel status-panel">

                <div className="panel-header">

                  <div>

                    <h2>게이트웨이 상태</h2>

                    <p className="panel-description">

                      Raspberry Pi의 마지막 지표 수집 상태입니다.

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



                <SourceStateNotice state={sourceState.gateway} label="게이트웨이 지표" />



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

                        label="메모리"

                        value={formatResourceValue(gatewayMetric.memory_percent)}

                        unit="%"

                        percentage={gatewayMetric.memory_percent}

                        status={getResourceStatus(gatewayMetric.memory_percent)}

                        description="현재 메모리 사용률"

                        updatedAt={sourceUpdatedAt("gateway")}

                        stale={sourceIsStale("gateway")}

                      />

                      <MetricCard

                        label="저장공간"

                        value={formatResourceValue(gatewayMetric.disk_percent)}

                        unit="%"

                        percentage={gatewayMetric.disk_percent}

                        status={getResourceStatus(gatewayMetric.disk_percent)}

                        description="현재 저장공간 사용률"

                        updatedAt={sourceUpdatedAt("gateway")}

                        stale={sourceIsStale("gateway")}

                      />

                      <MetricCard

                        label="온도"

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

                    title="게이트웨이 지표이 없습니다."

                    description="조회는 성공했지만 최근 게이트웨이 지표 데이터가 없습니다."

                    compact

                  />

                ) : (

                  <div className="section-unavailable">

                    {loading ? "게이트웨이 지표를 조회하는 중입니다." : "게이트웨이 지표를 확인할 수 없습니다."}

                  </div>

                )}

              </article>



              <article className="panel status-panel">

                <div className="panel-header">

                  <div>

                    <h2>패킷 수집 상태</h2>

                    <p className="panel-description">

                      최근 패킷 분석 지표의 수집 품질입니다.

                    </p>

                  </div>

                  <StatusBadge status={captureBadge.status} label={captureBadge.label} />

                </div>



                <SourceStateNotice

                  state={sourceState.packetFeatures}

                  label="패킷 분석 지표"

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

                    description="수집 품질 통과"

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

                    description="수집 시간 충족률 또는 수집 시간 정보 문제"

                    status="warning"

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

                    description="수집 구간 처리 실패"

                    status="danger"

                    updatedAt={sourceUpdatedAt("packetFeatures")}

                    stale={sourceIsStale("packetFeatures")}

                  />

                  <SummaryCard

                    title="평균 수집 시간 충족률"

                    value={

                      !sourceHasSuccess("packetFeatures")

                        ? null

                        : captureSummary.averageCoverage === null

                          ? "계산 불가"

                          : `${formatNumber(captureSummary.averageCoverage * 100, 1)}%`

                    }

                    unavailable={!sourceHasSuccess("packetFeatures")}

                    description="최근 패킷 분석 구간"

                    updatedAt={sourceUpdatedAt("packetFeatures")}

                    stale={sourceIsStale("packetFeatures")}

                  />

                </div>

              </article>

            </section>



            <section className="panel">

              <div className="panel-header">

                <div>

                  <h2>API 연결 상태</h2>

                  <p className="panel-description">

                    백엔드 API와 데이터베이스 연결 상태를 확인합니다.

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



              <SourceStateNotice state={sourceState.health} label="API 연결 상태" />



              {sourceHasSuccess("health") && health ? (

                <div className="health-grid">

                  <div className="health-item">

                    <span>API 상태</span>

                    <strong>{getHealthDisplayLabel(health.status)}</strong>

                  </div>

                  <div className="health-item">

                    <span>데이터베이스</span>

                    <strong>{getHealthDisplayLabel(health.database)}</strong>

                  </div>

                  <div className="health-item">

                    <span>DB 연결</span>

                    <StatusBadge

                      status={normalizeBoolean(health.db_connected) ? "connected" : "failed"}

                      label={normalizeBoolean(health.db_connected) ? "연결됨" : "연결 실패"}

                      size="small"

                    />

                  </div>

                  <div className="health-item">

                    <span>서버 시각</span>

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

                  <h2>기기별 신뢰점수</h2>

                  <p className="panel-description">

                    기기별 등록 상태와 현재 신뢰점수·방화벽 상태를 분리해 표시합니다.

                  </p>

                </div>

                <span className={`data-count ${!sourceHasSuccess("trustScores") ? "unavailable" : ""}`}>

                  {sourceHasSuccess("trustScores")

                    ? `${formatNumber(trustScores.length)}건`

                    : "확인 불가"}

                </span>

              </div>

              <SourceStateNotice state={sourceState.trustScores} label="신뢰점수" />

              {sourceHasSuccess("trustScores") ? (

                <div className="table-scroll">

                  <DataTable

                    columns={trustColumns}

                    rows={trustRows}

                    loading={loading && trustScores.length === 0}

                    rowKey="device_id"

                    minWidth={1020}

                    tableLabel="등록 상태 및 신뢰점수 요약"

                    emptyTitle="표시할 신뢰점수 데이터가 없습니다."

                    emptyDescription="조회는 성공했지만 현재 신뢰점수 데이터가 없습니다."

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

                  {loading ? "신뢰점수를 조회하는 중입니다." : "신뢰점수를 확인할 수 없습니다."}

                </div>

              )}

            </section>



            <section className="panel table-panel">

              <div className="panel-header">

                <div>

                  <h2>최근 탐지 이벤트</h2>

                  <p className="panel-description">

                    규칙 및 AI 탐지 결과와 신뢰점수 반영 여부를 표시합니다.

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

                    minWidth={1200}

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

                    최근 수신한 토픽과 메시지 내용 유효성입니다.

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
