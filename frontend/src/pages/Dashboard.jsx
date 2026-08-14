import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  getEvents,
  getFeatureLogs,
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

const POLLING_INTERVAL_MS = 10_000;
const ONLINE_THRESHOLD_SECONDS = 30;
const IS_DEV = import.meta.env.DEV;

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

function formatChartTime(dateString) {
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
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }
  ).format(date);
}

function formatNumber(
  value,
  maximumFractionDigits = 0
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

function formatScoreDelta(value) {
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

  return number > 0
    ? `+${number}`
    : String(number);
}

function normalizeBoolean(value) {
  return (
    value === true ||
    value === 1 ||
    value === "1" ||
    value === "true"
  );
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

  const normalized =
    String(status || "")
      .toLowerCase();

  return (
    labels[normalized] ||
    status ||
    "확인 불가"
  );
}

function getSeverityStatus(severity) {
  const normalized =
    String(severity || "")
      .toLowerCase();

  if (
    normalized === "high" ||
    normalized === "medium" ||
    normalized === "low"
  ) {
    return normalized;
  }

  return "unknown";
}

function getDetectorStatus(event) {
  const detectorType =
    String(
      event?.detector_type || ""
    ).toUpperCase();

  if (
    detectorType === "AI" ||
    event?.event_type ===
    "AI_ANOMALY" ||
    event?.event_type ===
    "AI_PACKET_ANOMALY"
  ) {
    return "ai";
  }

  if (detectorType === "RULE") {
    return "rule";
  }

  return "unknown";
}

function getFirewallStatusTheme(status) {
  const normalized =
    String(status || "")
      .toUpperCase();

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

  const normalized =
    String(status || "")
      .toUpperCase();

  return (
    labels[normalized] ||
    status ||
    "규칙 없음"
  );
}

function getGatewayStatus(metric) {
  if (!metric) {
    return "NO_DATA";
  }

  if (!metric.collected_at) {
    return "STALE";
  }

  const collectedAt =
    new Date(
      metric.collected_at
    ).getTime();

  if (Number.isNaN(collectedAt)) {
    return "STALE";
  }

  const elapsedSeconds =
    (Date.now() - collectedAt) /
    1000;

  return elapsedSeconds <=
    ONLINE_THRESHOLD_SECONDS
    ? "ONLINE"
    : "STALE";
}

function getGatewayStatusTheme(status) {
  const themes = {
    ONLINE: "online",
    STALE: "stale",
    NO_DATA: "unknown",
    API_ERROR: "failed",
  };

  return (
    themes[status] ||
    "unknown"
  );
}
function getHealthStatus(health) {
  const rawStatus =
    String(
      health?.status || ""
    ).toUpperCase();

  if (
    rawStatus === "OK" ||
    rawStatus === "HEALTHY" ||
    rawStatus === "UP"
  ) {
    return {
      status: "online",
      label: "정상",
    };
  }

  if (
    rawStatus === "DEGRADED" ||
    rawStatus === "WARNING"
  ) {
    return {
      status: "degraded",
      label: "일부 저하",
    };
  }

  if (
    rawStatus === "ERROR" ||
    rawStatus === "DOWN" ||
    rawStatus === "UNHEALTHY"
  ) {
    return {
      status: "failed",
      label: "오류",
    };
  }

  return {
    status: "unknown",
    label: "확인 불가",
  };
}

function getCaptureSummary(packetFeatures) {
  let eligible = 0;
  let excluded = 0;
  let failed = 0;

  const coverageValues = [];

  packetFeatures.forEach((item) => {
    if (
      item.segment_status === "FAILED"
    ) {
      failed += 1;
    }

    if (
      item.capture_eligible === true
    ) {
      eligible += 1;
    }

    if (
      item.capture_eligible === false
    ) {
      excluded += 1;
    }

    const coverage =
      Number(item.coverage_ratio);

    if (Number.isFinite(coverage)) {
      coverageValues.push(coverage);
    }
  });

  const averageCoverage =
    coverageValues.length > 0
      ? coverageValues.reduce(
        (sum, value) =>
          sum + value,
        0
      ) /
      coverageValues.length
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

    chart_time:
      formatChartTime(
        item.window_start
      ),
  }));
}

function formatResourceValue(value) {
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
      minimumFractionDigits: 1,
      maximumFractionDigits: 1,
    }
  );
}

export default function Dashboard() {
  const [summary, setSummary] =
    useState(null);

  const [logs, setLogs] =
    useState([]);

  const [features, setFeatures] =
    useState([]);

  const [events, setEvents] =
    useState([]);

  const [
    trustScores,
    setTrustScores,
  ] = useState([]);

  const [
    gatewayMetric,
    setGatewayMetric,
  ] = useState(null);

  const [
    packetFeatures,
    setPacketFeatures,
  ] = useState([]);

  const [
    firewallRules,
    setFirewallRules,
  ] = useState([]);

  const [health, setHealth] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [
    partialWarnings,
    setPartialWarnings,
  ] = useState([]);

  const [
    lastUpdated,
    setLastUpdated,
  ] = useState("");

  const isFetchingRef =
    useRef(false);

  const hasSuccessfulDataRef =
    useRef(false);

  const loadData =
    useCallback(
      async (
        isManualRefresh = false
      ) => {
        if (isFetchingRef.current) {
          return;
        }

        isFetchingRef.current = true;

        if (isManualRefresh) {
          setRefreshing(true);
        }

        const requests = [
          {
            key: "summary",
            label: "기기 요약",
            request: getSummary(),
          },
          {
            key: "logs",
            label: "MQTT 로그",
            request: getMqttLogs({
              limit: 5,
              offset: 0,
            }),
          },
          {
            key: "features",
            label: "MQTT Feature",
            request: getFeatureLogs({
              limit: 20,
              offset: 0,
            }),
          },
          {
            key: "events",
            label: "탐지 이벤트",
            request: getEvents({
              limit: 5,
              offset: 0,
            }),
          },
          {
            key: "trustScores",
            label: "Trust Score",
            request:
              getTrustScoreSummary({
                limit: 10,
                offset: 0,
              }),
          },
          {
            key: "gateway",
            label: "Gateway Metric",
            request:
              getGatewayMetrics({
                limit: 1,
                offset: 0,
              }),
          },
          {
            key: "packetFeatures",
            label: "Packet Feature",
            request:
              getPacketFeatureLogs({
                limit: 20,
                offset: 0,
              }),
          },
          {
            key: "firewall",
            label: "Firewall Rule",
            request:
              getFirewallRules({
                limit: 100,
                offset: 0,
              }),
          },
          {
            key: "health",
            label: "API Health",
            request: getHealth(),
          },
        ];

        try {
          const results =
            await Promise.allSettled(
              requests.map(
                (item) =>
                  item.request
              )
            );

          const warnings = [];
          let successCount = 0;

          results.forEach(
            (result, index) => {
              const requestInfo =
                requests[index];

              if (
                result.status ===
                "rejected"
              ) {
                warnings.push(
                  `${requestInfo.label}: ${result.reason
                    instanceof Error
                    ? result.reason
                      .message
                    : "조회 실패"
                  }`
                );

                return;
              }

              successCount += 1;

              const data =
                result.value;

              switch (
              requestInfo.key
              ) {
                case "summary":
                  setSummary(
                    data || {}
                  );
                  break;

                case "logs":
                  setLogs(
                    Array.isArray(
                      data?.items
                    )
                      ? data.items
                      : []
                  );
                  break;

                case "features":
                  setFeatures(
                    Array.isArray(
                      data?.items
                    )
                      ? data.items
                      : []
                  );
                  break;

                case "events":
                  setEvents(
                    Array.isArray(
                      data?.items
                    )
                      ? data.items
                      : []
                  );
                  break;

                case "trustScores":
                  setTrustScores(
                    Array.isArray(
                      data?.items
                    )
                      ? data.items
                      : []
                  );
                  break;

                case "gateway":
                  setGatewayMetric(
                    Array.isArray(
                      data?.items
                    )
                      ? data.items[0] ??
                      null
                      : null
                  );
                  break;

                case "packetFeatures":
                  setPacketFeatures(
                    Array.isArray(
                      data?.items
                    )
                      ? data.items
                      : []
                  );
                  break;

                case "firewall":
                  setFirewallRules(
                    Array.isArray(
                      data?.items
                    )
                      ? data.items
                      : []
                  );
                  break;

                case "health":
                  setHealth(
                    data || null
                  );
                  break;

                default:
                  break;
              }
            }
          );

          if (successCount === 0) {
            throw new Error(
              "모든 Dashboard API 요청에 실패했습니다."
            );
          }

          hasSuccessfulDataRef.current =
            true;

          setLastUpdated(
            new Date().toISOString()
          );

          setPartialWarnings(
            warnings
          );

          setError("");
        } catch (err) {
          if (IS_DEV) {
            console.error(
              "Dashboard data load failed:",
              err
            );
          }

          const message =
            err instanceof Error
              ? err.message
              : "대시보드 데이터를 불러오지 못했습니다.";

          if (
            hasSuccessfulDataRef.current
          ) {
            setPartialWarnings([
              message,
            ]);
          } else {
            setError(message);
          }
        } finally {
          setLoading(false);
          setRefreshing(false);

          isFetchingRef.current =
            false;
        }
      },
      []
    );

  useEffect(() => {
    loadData();

    const timer =
      window.setInterval(() => {
        loadData();
      }, POLLING_INTERVAL_MS);

    return () => {
      window.clearInterval(timer);
    };
  }, [loadData]);

  const firewallSummary =
    useMemo(() => {
      const result = {
        applied: 0,
        pending: 0,
        failed: 0,
        removed: 0,
      };

      firewallRules.forEach(
        (rule) => {
          const status =
            String(
              rule.status || ""
            ).toUpperCase();

          if (status === "APPLIED") {
            result.applied += 1;
          } else if (
            status === "PENDING"
          ) {
            result.pending += 1;
          } else if (
            status === "FAILED"
          ) {
            result.failed += 1;
          } else if (
            status === "REMOVED"
          ) {
            result.removed += 1;
          }
        }
      );

      return result;
    }, [firewallRules]);

  const captureSummary =
    useMemo(
      () =>
        getCaptureSummary(
          packetFeatures
        ),
      [packetFeatures]
    );

  const gatewayStatus =
    useMemo(
      () =>
        getGatewayStatus(
          gatewayMetric
        ),
      [gatewayMetric]
    );

  const healthStatus =
    useMemo(
      () =>
        getHealthStatus(health),
      [health]
    );

  const featureChartData =
    useMemo(
      () =>
        getFeatureChartData(
          features
        ),
      [features]
    );

  const trustColumns = [
    {
      key: "device_id",
      header: "Device",
      width: 150,
      render: (value) => (
        <strong
          title={value || ""}
        >
          {value || "-"}
        </strong>
      ),
    },
    {
      key: "trust_score",
      header: "Trust Score",
      align: "right",
      width: 120,
      render: (value, item) => {
        const status =
          getTrustStatus(
            value,
            item.status
          );

        return (
          <div className="trust-score-cell">
            <strong>
              {formatNumber(value)}
            </strong>

            <div className="trust-score-bar">
              <div
                className={`trust-score-bar-value trust-score-${status}`}
                style={{
                  width: `${Math.min(
                    Math.max(
                      Number(value) ||
                      0,
                      0
                    ),
                    100
                  )}%`,
                }}
              />
            </div>
          </div>
        );
      },
    },
    {
      key: "status",
      header: "Trust 상태",
      width: 110,
      render: (value, item) => {
        const status =
          getTrustStatus(
            item.trust_score,
            value
          );

        return (
          <StatusBadge
            status={status}
            label={
              getTrustStatusLabel(
                status
              )
            }
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
          status={
            getFirewallStatusTheme(
              value
            )
          }
          label={
            getFirewallStatusLabel(
              value
            )
          }
          size="small"
        />
      ),
    },
    {
      key: "last_seen_at",
      header: "Last Seen",
      width: 180,
      render: (value) =>
        formatKST(value),
    },
  ];

  const eventColumns = [
    {
      key: "device_id",
      header: "Device",
      width: 130,
      render: (value, event) =>
        value ||
        event.subject_ip ||
        "미매핑",
    },
    {
      key: "detector_type",
      header: "Detector",
      width: 100,
      render: (value, event) => (
        <StatusBadge
          status={
            getDetectorStatus(
              event
            )
          }
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
        <span
          className="event-type-cell"
          title={value || ""}
        >
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
          status={
            getSeverityStatus(value)
          }
          label={String(
            value || "UNKNOWN"
          ).toUpperCase()}
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
        <span
          className={
            Number(value) < 0
              ? "score-delta-negative"
              : ""
          }
        >
          {formatScoreDelta(value)}
        </span>
      ),
    },
    {
      key: "applied_to_score",
      header: "Trust 반영",
      width: 120,
      render: (value, event) => {
        const captureGap =
          event.processing_reason ===
          "CAPTURE_GAP_UNSCORED";

        return (
          <StatusBadge
            status={
              captureGap
                ? "degraded"
                : normalizeBoolean(
                  value
                )
                  ? "scored"
                  : "unscored"
            }
            label={
              captureGap
                ? "Capture Gap"
                : normalizeBoolean(
                  value
                )
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
      render: (value) =>
        formatKST(value),
    },
  ];

  const mqttColumns = [
    {
      key: "device_id",
      header: "Device",
      width: 130,
      render: (value) =>
        value || "미매핑",
    },
    {
      key: "topic",
      header: "Topic",
      width: 260,
      render: (value) => (
        <span
          className="description-cell"
          title={value || ""}
        >
          {value || "-"}
        </span>
      ),
    },
    {
      key: "payload_size",
      header: "Payload",
      align: "right",
      width: 100,
      render: (value) =>
        `${formatNumber(
          value
        )} B`,
    },
    {
      key: "is_json_valid",
      header: "JSON",
      width: 90,
      render: (value) => (
        <StatusBadge
          status={
            normalizeBoolean(value)
              ? "normal"
              : "danger"
          }
          label={
            normalizeBoolean(value)
              ? "정상"
              : "오류"
          }
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
          status={
            normalizeBoolean(value)
              ? "normal"
              : "warning"
          }
          label={
            normalizeBoolean(value)
              ? "정상"
              : "비정상"
          }
          size="small"
        />
      ),
    },
    {
      key: "received_at",
      header: "Received At",
      width: 180,
      render: (value) =>
        formatKST(value),
    },
  ];

  return (
    <div className="page-container">
      <PageHeader
        title="Dashboard"
        description="IoT Gateway, Packet Capture, Detection, Trust Score, Firewall 상태를 한눈에 확인합니다."
        updatedAt={
          lastUpdated
            ? formatKST(
              lastUpdated
            )
            : undefined
        }
        onRefresh={() =>
          loadData(true)
        }
        refreshing={refreshing}
      />

      {partialWarnings.length >
        0 && (
          <div
            className="page-warning-banner"
            role="alert"
          >
            <div>
              <strong>
                일부 Dashboard 데이터
                갱신 실패
              </strong>

              <p>
                정상적으로 조회된 데이터는
                계속 표시합니다.
              </p>

              <ul className="warning-message-list">
                {partialWarnings.map(
                  (warning) => (
                    <li key={warning}>
                      {warning}
                    </li>
                  )
                )}
              </ul>
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
                onClick={() =>
                  loadData(true)
                }
                disabled={refreshing}
              >
                지금 다시 시도
              </button>
            </div>
          </div>
        )}

      {error &&
        !hasSuccessfulDataRef.current ? (
        <section className="panel">
          <div className="error-box">
            <div>
              <strong>
                Dashboard를 불러오지
                못했습니다.
              </strong>

              <p>{error}</p>
            </div>

            <button
              type="button"
              className="button button-secondary"
              onClick={() =>
                loadData(true)
              }
              disabled={refreshing}
            >
              다시 시도
            </button>
          </div>
        </section>
      ) : (
        <>
          <section
            className="summary-card-grid"
            aria-label="전체 상태 요약"
          >
            <SummaryCard
              title="전체 기기"
              value={formatNumber(
                summary?.total_devices ??
                0
              )}
              description="등록된 IoT 기기"
            />

            <SummaryCard
              title="정상"
              value={formatNumber(
                summary?.normal_devices ??
                0
              )}
              description="Trust Score 80 이상"
              status="normal"
            />

            <SummaryCard
              title="주의"
              value={formatNumber(
                summary?.warning_devices ??
                0
              )}
              description="Trust Score 60~79"
              status="warning"
            />

            <SummaryCard
              title="위험"
              value={formatNumber(
                summary?.danger_devices ??
                0
              )}
              description="Trust Score 30~59"
              status="danger"
            />

            <SummaryCard
              title="격리"
              value={formatNumber(
                summary?.isolated_devices ?? 0
              )}
              description="Trust Score 30 미만"
              status={
                Number(
                  summary?.isolated_devices
                ) > 0
                  ? "isolated"
                  : "default"
              }
            />

            <SummaryCard
              title="Firewall 적용"
              value={formatNumber(
                summary?.firewall_applied ??
                firewallSummary.applied
              )}
              description="실제 차단 규칙 적용"
              status="normal"
            />

            <SummaryCard
              title="Firewall 대기"
              value={formatNumber(
                summary?.firewall_pending ??
                firewallSummary.pending
              )}
              description="차단 규칙 적용 대기"
              status={
                firewallSummary.pending >
                  0
                  ? "warning"
                  : "default"
              }
            />

            <SummaryCard
              title="Firewall 실패"
              value={formatNumber(
                summary?.firewall_failed ??
                firewallSummary.failed
              )}
              description="차단 규칙 적용 실패"
              status={
                firewallSummary.failed >
                  0
                  ? "danger"
                  : "default"
              }
            />
          </section>

          <section className="dashboard-status-grid">
            <article className="panel dashboard-status-panel">
              <div className="panel-header">
                <div>
                  <h2>
                    Gateway 상태
                  </h2>

                  <p className="panel-description">
                    Raspberry Pi의 마지막
                    Metric 수집 상태입니다.
                  </p>
                </div>

                <StatusBadge
                  status={getGatewayStatusTheme(
                    gatewayStatus
                  )}
                  label={gatewayStatus}
                />
              </div>

              {gatewayMetric ? (
                <div className="metric-card-grid">
                  <MetricCard
                    label="CPU"
                    value={formatResourceValue(
                      gatewayMetric.cpu_percent
                    )}
                    unit="%"
                    percentage={
                      gatewayMetric.cpu_percent
                    }
                    description="현재 CPU 사용률"
                  />

                  <MetricCard
                    label="Memory"
                    value={formatResourceValue(
                      gatewayMetric.memory_percent
                    )}
                    unit="%"
                    percentage={
                      gatewayMetric.memory_percent
                    }
                    description="현재 Memory 사용률"
                  />

                  <MetricCard
                    label="Disk"
                    value={formatResourceValue(
                      gatewayMetric.disk_percent
                    )}
                    unit="%"
                    percentage={
                      gatewayMetric.disk_percent
                    }
                    description="현재 Disk 사용률"
                  />

                  <MetricCard
                    label="Temperature"
                    value={formatResourceValue(
                      gatewayMetric.temperature_c
                    )}
                    unit="℃"
                    description="CPU 온도"
                  />
                </div>
              ) : (
                <EmptyState
                  title="Gateway Metric이 없습니다."
                  description="Gateway Metrics Collector가 실행 중인지 확인해 주세요."
                  compact
                />
              )}

              {gatewayMetric && (
                <p className="dashboard-status-footer">
                  마지막 수집:{" "}
                  {formatKST(
                    gatewayMetric.collected_at
                  )}
                </p>
              )}
            </article>

            <article className="panel dashboard-status-panel">
              <div className="panel-header">
                <div>
                  <h2>
                    Packet Capture
                  </h2>

                  <p className="panel-description">
                    최근 Packet Feature의
                    Capture 품질입니다.
                  </p>
                </div>

                <StatusBadge
                  status={
                    captureSummary.failed >
                      0 ||
                      captureSummary.excluded >
                      0
                      ? "degraded"
                      : "normal"
                  }
                  label={
                    captureSummary.failed >
                      0 ||
                      captureSummary.excluded >
                      0
                      ? "DEGRADED"
                      : "NORMAL"
                  }
                />
              </div>

              <div className="dashboard-mini-summary-grid">
                <SummaryCard
                  title="분석 가능"
                  value={formatNumber(
                    captureSummary.eligible
                  )}
                  description="Capture 품질 통과"
                  status="normal"
                />

                <SummaryCard
                  title="분석 제외"
                  value={formatNumber(
                    captureSummary.excluded
                  )}
                  description="Coverage 또는 Timing 문제"
                  status={
                    captureSummary.excluded >
                      0
                      ? "warning"
                      : "default"
                  }
                />

                <SummaryCard
                  title="수집 실패"
                  value={formatNumber(
                    captureSummary.failed
                  )}
                  description="Segment 처리 실패"
                  status={
                    captureSummary.failed >
                      0
                      ? "danger"
                      : "default"
                  }
                />

                <SummaryCard
                  title="평균 Coverage"
                  value={
                    captureSummary.averageCoverage ===
                      null
                      ? "계산 불가"
                      : `${formatNumber(
                        captureSummary.averageCoverage *
                        100,
                        1
                      )}%`
                  }
                  description="최근 Packet Window"
                />
              </div>
            </article>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2>API Health</h2>

                <p className="panel-description">
                  Backend API와 Database 연결 상태를
                  확인합니다.
                </p>
              </div>

              <StatusBadge
                status={
                  healthStatus.status
                }
                label={
                  healthStatus.label
                }
              />
            </div>

            {health ? (
              <div className="health-detail-grid">
                <div className="health-detail-item">
                  <span>
                    API Status
                  </span>

                  <strong>
                    {health.status || "-"}
                  </strong>
                </div>

                <div className="health-detail-item">
                  <span>
                    Database
                  </span>

                  <strong>
                    {health.database || "-"}
                  </strong>
                </div>

                <div className="health-detail-item">
                  <span>
                    DB Connection
                  </span>

                  <StatusBadge
                    status={
                      normalizeBoolean(
                        health.db_connected
                      )
                        ? "connected"
                        : "failed"
                    }
                    label={
                      normalizeBoolean(
                        health.db_connected
                      )
                        ? "연결됨"
                        : "연결 실패"
                    }
                    size="small"
                  />
                </div>

                <div className="health-detail-item">
                  <span>
                    Server Time
                  </span>

                  <strong>
                    {formatKST(
                      health.server_time
                    )}
                  </strong>
                </div>
              </div>
            ) : (
              <EmptyState
                title="Health 정보가 없습니다."
                description="Health API가 정상적으로 응답하는지 확인해 주세요."
                compact
              />
            )}
          </section>

          <section className="panel packet-table-panel">
            <div className="panel-header">
              <div>
                <h2>Trust Score Summary</h2>

                <p className="panel-description">
                  Device별 현재 Trust 상태와 Firewall 적용
                  상태입니다.
                </p>
              </div>

              <span className="data-count">
                {formatNumber(
                  trustScores.length
                )}
                건
              </span>
            </div>

            <div className="packet-table-scroll">
              <DataTable
                columns={trustColumns}
                rows={trustScores}
                loading={
                  loading &&
                  trustScores.length === 0
                }
                rowKey="device_id"
                minWidth={850}
                tableLabel="Trust Score 요약"
                emptyTitle="표시할 Trust Score 데이터가 없습니다."
                emptyDescription="기기 등록 및 Trust Score 계산 결과를 확인해 주세요."
                rowClassName={(item) => {
                  const status =
                    getTrustStatus(
                      item.trust_score,
                      item.status
                    );

                  if (
                    status === "isolated"
                  ) {
                    return "table-row-danger";
                  }

                  if (
                    status === "danger" ||
                    status === "warning"
                  ) {
                    return "table-row-warning";
                  }

                  return "";
                }}
              />
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2>
                  MQTT Feature Graph
                </h2>

                <p className="panel-description">
                  10초 Window별 MQTT
                  발행량, Payload 크기,
                  메시지 간격을 표시합니다.
                </p>
              </div>

              <span className="data-count">
                {formatNumber(
                  features.length
                )}
                개 Window
              </span>
            </div>

            {loading &&
              features.length === 0 ? (
              <div className="chart-loading">
                그래프 데이터를 불러오는
                중입니다.
              </div>
            ) : features.length === 0 ? (
              <EmptyState
                title="표시할 Feature Log가 없습니다."
                description="MQTT Feature Worker가 실행 중인지 확인해 주세요."
                compact
              />
            ) : (
              <div className="dashboard-chart-container">
                <ResponsiveContainer
                  width="100%"
                  height={360}
                >
                  <LineChart
                    data={
                      featureChartData
                    }
                    margin={{
                      top: 10,
                      right: 20,
                      left: 0,
                      bottom: 10,
                    }}
                  >
                    <CartesianGrid
                      strokeDasharray="3 3"
                    />

                    <XAxis
                      dataKey="chart_time"
                      minTickGap={25}
                    />

                    <YAxis />

                    <Tooltip
                      labelFormatter={(
                        _,
                        payload
                      ) =>
                        formatKST(
                          payload?.[0]
                            ?.payload
                            ?.window_start
                        )
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

          <section className="panel packet-table-panel">
            <div className="panel-header">
              <div>
                <h2>
                  최근 탐지 이벤트
                </h2>

                <p className="panel-description">
                  Rule 및 AI 탐지 결과와
                  Trust Score 반영 여부를
                  표시합니다.
                </p>
              </div>

              <span className="data-count">
                최근{" "}
                {formatNumber(
                  events.length
                )}
                건
              </span>
            </div>

            <div className="packet-table-scroll">
              <DataTable
                columns={eventColumns}
                rows={events}
                loading={
                  loading &&
                  events.length === 0
                }
                rowKey="id"
                minWidth={1100}
                tableLabel="최근 탐지 이벤트"
                emptyTitle="표시할 탐지 이벤트가 없습니다."
                emptyDescription="아직 생성된 Rule 또는 AI 탐지 이벤트가 없습니다."
                rowClassName={(event) => {
                  if (
                    event.processing_reason ===
                    "CAPTURE_GAP_UNSCORED"
                  ) {
                    return "table-row-warning";
                  }

                  if (
                    String(
                      event.severity
                    ).toLowerCase() === "high"
                  ) {
                    return "table-row-danger";
                  }

                  if (
                    getDetectorStatus(
                      event
                    ) === "ai"
                  ) {
                    return "table-row-ai";
                  }

                  return "";
                }}
              />
            </div>
          </section>

          <section className="panel packet-table-panel">
            <div className="panel-header">
              <div>
                <h2>
                  최근 MQTT 로그
                </h2>

                <p className="panel-description">
                  최근 수신한 Topic과
                  Payload 유효성입니다.
                </p>
              </div>

              <span className="data-count">
                최근{" "}
                {formatNumber(
                  logs.length
                )}
                건
              </span>
            </div>

            <div className="packet-table-scroll">
              <DataTable
                columns={mqttColumns}
                rows={logs}
                loading={
                  loading &&
                  logs.length === 0
                }
                rowKey="id"
                minWidth={950}
                tableLabel="최근 MQTT 로그"
                emptyTitle="표시할 MQTT 로그가 없습니다."
                emptyDescription="MQTT Subscriber가 정상적으로 메시지를 수신하는지 확인해 주세요."
                rowClassName={(log) => {
                  if (
                    !normalizeBoolean(
                      log.is_json_valid
                    ) ||
                    !normalizeBoolean(
                      log.is_topic_valid
                    )
                  ) {
                    return "table-row-warning";
                  }

                  return "";
                }}
              />
            </div>
          </section>
        </>
      )}
    </div>
  );
}