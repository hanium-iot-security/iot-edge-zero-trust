import {
  useCallback,
  useEffect,
  useState,
} from "react";
import { getGatewayMetrics } from "../api/api";

const ONLINE_THRESHOLD_SECONDS = 30;
const POLLING_INTERVAL_MS = 10_000;
const STATUS_UPDATE_INTERVAL_MS = 1_000;

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

function formatMetric(
  value,
  unit = "",
  maximumFractionDigits = 2
) {
  if (
    value === null ||
    value === undefined ||
    value === ""
  ) {
    return "측정 불가";
  }

  const number = Number(value);

  if (!Number.isFinite(number)) {
    return "측정 불가";
  }

  return `${number.toLocaleString("ko-KR", {
    maximumFractionDigits,
  })}${unit}`;
}

function getProgressValue(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return 0;
  }

  return Math.min(Math.max(number, 0), 100);
}

function getGatewayStatus(collectedAt) {
  if (!collectedAt) {
    return "UNKNOWN";
  }

  const collectedTime = new Date(collectedAt).getTime();

  if (Number.isNaN(collectedTime)) {
    return "UNKNOWN";
  }

  const elapsedSeconds =
    (Date.now() - collectedTime) / 1_000;

  return elapsedSeconds <= ONLINE_THRESHOLD_SECONDS
    ? "ONLINE"
    : "STALE";
}

function getInterfaceStatus(interfaceData) {
  if (!interfaceData?.exists) {
    return {
      text: "미인식",
      className: "unknown",
    };
  }

  if (!interfaceData.is_up) {
    return {
      text: "연결 끊김",
      className: "stale",
    };
  }

  return {
    text: "연결됨",
    className: "online",
  };
}

function InterfaceCard({
  title,
  interfaceData,
}) {
  const status =
    getInterfaceStatus(interfaceData);

  return (
    <div className="interface-card">
      <div className="interface-header">
        <div>
          <h3>{title}</h3>

          <p>
            {interfaceData?.interface_name ||
              "인터페이스 없음"}
          </p>
        </div>

        <span
          className={`status-badge ${status.className}`}
        >
          {status.text}
        </span>
      </div>

      <div className="interface-detail-grid">
        <div className="metric-item">
          <span>IP Address</span>

          <strong>
            {interfaceData?.ip_address || "-"}
          </strong>
        </div>

        <div className="metric-item">
          <span>누적 RX</span>

          <strong>
            {formatMetric(
              interfaceData?.rx_bytes,
              " B",
              0
            )}
          </strong>
        </div>

        <div className="metric-item">
          <span>누적 TX</span>

          <strong>
            {formatMetric(
              interfaceData?.tx_bytes,
              " B",
              0
            )}
          </strong>
        </div>

        <div className="metric-item">
          <span>RX 전송률</span>

          <strong>
            {formatMetric(
              interfaceData?.rx_bytes_per_sec,
              " B/s"
            )}
          </strong>
        </div>

        <div className="metric-item">
          <span>TX 전송률</span>

          <strong>
            {formatMetric(
              interfaceData?.tx_bytes_per_sec,
              " B/s"
            )}
          </strong>
        </div>
      </div>
    </div>
  );
}

export default function GatewayStatus() {
  const [latestMetric, setLatestMetric] =
    useState(null);

  const [gatewayStatus, setGatewayStatus] =
    useState("UNKNOWN");

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const loadGatewayMetrics =
    useCallback(async (isManualRefresh = false) => {
      if (isManualRefresh) {
        setRefreshing(true);
      }

      try {
        const data =
          await getGatewayMetrics();

        const metric =
          Array.isArray(data?.items)
            ? data.items[0] ?? null
            : null;

        setLatestMetric(metric);
        setError("");
      } catch (err) {
        console.error(
          "Gateway metrics load failed:",
          err
        );

        setError(
          err instanceof Error
            ? err.message
            : "Gateway Metrics를 불러오지 못했습니다."
        );
      } finally {
        setLoading(false);
        setRefreshing(false);
      }
    }, []);

  useEffect(() => {
    loadGatewayMetrics();

    const pollingTimer =
      window.setInterval(() => {
        loadGatewayMetrics();
      }, POLLING_INTERVAL_MS);

    return () => {
      window.clearInterval(
        pollingTimer
      );
    };
  }, [loadGatewayMetrics]);

  const collectedAt =
    latestMetric?.collected_at ?? null;

  useEffect(() => {
    function updateGatewayStatus() {
      setGatewayStatus(
        getGatewayStatus(collectedAt)
      );
    }

    updateGatewayStatus();

    const statusTimer =
      window.setInterval(
        updateGatewayStatus,
        STATUS_UPDATE_INTERVAL_MS
      );

    return () => {
      window.clearInterval(
        statusTimer
      );
    };
  }, [collectedAt]);

  const interfaces =
    latestMetric?.interface_metrics ?? {};

  const internalLan =
    interfaces.internal_lan ?? null;

  const usbLan =
    interfaces.usb_lan ?? null;

  function handleRefresh() {
    loadGatewayMetrics(true);
  }

  let content;

  if (loading) {
    content = (
      <section className="panel">
        <p>
          Gateway Metrics를 불러오는 중입니다.
        </p>
      </section>
    );
  } else if (error) {
    content = (
      <section className="panel">
        <div className="error-box gateway-error-box">
          <span>{error}</span>

          <button
            type="button"
            onClick={() =>
              loadGatewayMetrics(true)
            }
            disabled={refreshing}
          >
            {refreshing
              ? "불러오는 중..."
              : "다시 시도"}
          </button>
        </div>
      </section>
    );
  } else if (!latestMetric) {
    content = (
      <section className="panel gateway-empty">
        <span className="status-badge unknown">
          UNKNOWN
        </span>

        <h2>
          수집된 Gateway Metrics가 없습니다.
        </h2>

        <p>
          Gateway Metrics Collector가 실행
          중인지 확인해주세요.
        </p>
      </section>
    );
  } else {
    content = (
      <>
        <section className="panel gateway-overview">
          <div>
            <span className="section-label">
              Gateway 상태
            </span>

            <div className="gateway-status-row">
              <span
                className={`status-badge ${gatewayStatus.toLowerCase()}`}
              >
                {gatewayStatus}
              </span>

              <span className="last-collected">
                마지막 수집:{" "}
                {formatKST(
                  latestMetric.collected_at
                )}
              </span>
            </div>
          </div>

          <div className="sample-interval">
            <span>실제 수집 간격</span>

            <strong>
              {formatMetric(
                latestMetric.sample_interval_seconds,
                "초"
              )}
            </strong>
          </div>
        </section>

        <div className="gateway-resource-grid">
          <div className="resource-card">
            <span>CPU</span>

            <strong>
              {formatMetric(
                latestMetric.cpu_percent,
                "%"
              )}
            </strong>

            <div className="progress-bar">
              <div
                className="progress-value"
                style={{
                  width: `${getProgressValue(
                    latestMetric.cpu_percent
                  )}%`,
                }}
              />
            </div>
          </div>

          <div className="resource-card">
            <span>Memory</span>

            <strong>
              {formatMetric(
                latestMetric.memory_percent,
                "%"
              )}
            </strong>

            <div className="progress-bar">
              <div
                className="progress-value"
                style={{
                  width: `${getProgressValue(
                    latestMetric.memory_percent
                  )}%`,
                }}
              />
            </div>
          </div>

          <div className="resource-card">
            <span>Disk</span>

            <strong>
              {formatMetric(
                latestMetric.disk_percent,
                "%"
              )}
            </strong>

            <small>
              사용량:{" "}
              {formatMetric(
                latestMetric.disk_used_mb,
                " MB"
              )}
            </small>

            <div className="progress-bar">
              <div
                className="progress-value"
                style={{
                  width: `${getProgressValue(
                    latestMetric.disk_percent
                  )}%`,
                }}
              />
            </div>
          </div>

          <div className="resource-card">
            <span>온도</span>

            <strong>
              {formatMetric(
                latestMetric.temperature_c,
                "℃"
              )}
            </strong>

            <small>
              Raspberry Pi CPU Temperature
            </small>
          </div>
        </div>

        <section className="panel">
          <div className="panel-header">
            <div>
              <h2>Network Interface</h2>

              <p className="panel-description">
                내부 LAN과 USB LAN을
                독립적으로 표시합니다.
              </p>
            </div>
          </div>

          <div className="interface-grid">
            <InterfaceCard
              title="내부 LAN"
              interfaceData={internalLan}
            />

            <InterfaceCard
              title="USB LAN"
              interfaceData={usbLan}
            />
          </div>
        </section>
      </>
    );
  }

  return (
    <div>
      <div className="page-header">
        <div>
          <h1>Gateway Status</h1>

          <p className="page-description">
            Raspberry Pi Gateway의 시스템
            자원과 네트워크 상태를 확인합니다.
          </p>
        </div>

        <button
          type="button"
          className="refresh-button"
          onClick={handleRefresh}
          disabled={
            loading || refreshing
          }
        >
          {refreshing
            ? "새로고침 중..."
            : "새로고침"}
        </button>
      </div>

      {content}
    </div>
  );
}