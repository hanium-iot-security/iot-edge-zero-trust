import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  getGatewayMetrics,
} from "../api/api";

import EmptyState from "../components/EmptyState";
import ErrorState from "../components/ErrorState";
import LoadingState from "../components/LoadingState";
import MetricCard from "../components/MetricCard";
import PageHeader from "../components/PageHeader";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";

const COLLECTION_INTERVAL_SECONDS = 10;
const ONLINE_THRESHOLD_MULTIPLIER = 3;

const ONLINE_THRESHOLD_SECONDS =
  COLLECTION_INTERVAL_SECONDS *
  ONLINE_THRESHOLD_MULTIPLIER;

const POLLING_INTERVAL_MS =
  COLLECTION_INTERVAL_SECONDS * 1_000;

const STATUS_UPDATE_INTERVAL_MS = 1_000;

const IS_DEV = import.meta.env.DEV;

/* =========================================================
   Formatting
   ========================================================= */

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

function formatMetric(
  value,
  unit = "",
  maximumFractionDigits = 2,
  minimumFractionDigits = 0
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

  return `${number.toLocaleString(
    "ko-KR",
    {
      minimumFractionDigits,
      maximumFractionDigits,
    }
  )}${unit}`;
}

function formatResourceValue(value) {
  return formatMetric(
    value,
    "",
    1,
    1
  );
}

function formatInteger(value) {
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

  return number.toLocaleString(
    "ko-KR",
    {
      maximumFractionDigits: 0,
    }
  );
}

function formatElapsedTime(dateString) {
  if (!dateString) {
    return "-";
  }

  const timestamp =
    new Date(dateString).getTime();

  if (Number.isNaN(timestamp)) {
    return "-";
  }

  const elapsedSeconds =
    Math.max(
      0,
      Math.floor(
        (Date.now() - timestamp) /
          1_000
      )
    );

  if (elapsedSeconds < 60) {
    return `${elapsedSeconds}초 전`;
  }

  const elapsedMinutes =
    Math.floor(
      elapsedSeconds / 60
    );

  if (elapsedMinutes < 60) {
    return `${elapsedMinutes}분 전`;
  }

  const elapsedHours =
    Math.floor(
      elapsedMinutes / 60
    );

  return `${elapsedHours}시간 전`;
}

/* =========================================================
   Gateway Status
   ========================================================= */

function getGatewayStatus(
  collectedAt,
  hasMetric,
  hasApiError
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

  const collectedTime =
    new Date(collectedAt).getTime();

  if (Number.isNaN(collectedTime)) {
    return "STALE";
  }

  const elapsedSeconds =
    (Date.now() - collectedTime) /
    1_000;

  return elapsedSeconds <=
    ONLINE_THRESHOLD_SECONDS
    ? "ONLINE"
    : "STALE";
}

function getGatewayStatusDescription(
  gatewayStatus
) {
  const descriptions = {
    ONLINE:
      "최근 수집 주기 내에 Gateway Metric이 정상적으로 수신되었습니다.",

    STALE:
      "마지막 Metric 수집 이후 허용 시간이 지났습니다.",

    NO_DATA:
      "API 요청은 성공했지만 저장된 Gateway Metric이 없습니다.",

    API_ERROR:
      "Gateway Metric API에 연결할 수 없습니다.",
  };

  return (
    descriptions[gatewayStatus] ||
    "Gateway 상태를 확인할 수 없습니다."
  );
}

function getGatewayStatusTheme(
  gatewayStatus
) {
  const themes = {
    ONLINE: "normal",
    STALE: "warning",
    NO_DATA: "unknown",
    API_ERROR: "danger",
  };

  return (
    themes[gatewayStatus] ||
    "unknown"
  );
}

/* =========================================================
   Resource Status
   ========================================================= */

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

/* =========================================================
   Network Interface
   ========================================================= */

function getInterfaceStatus(
  interfaceData
) {
  if (!interfaceData) {
    return {
      status: "missing",
      label: "미인식",
      description:
        "Interface 정보가 응답에 없습니다.",
    };
  }

  if (interfaceData.exists === false) {
    return {
      status: "missing",
      label: "미인식",
      description:
        "운영체제에서 Interface를 찾지 못했습니다.",
    };
  }

  if (
    interfaceData.exists === true &&
    interfaceData.is_up === false
  ) {
    return {
      status: "down",
      label: "DOWN",
      description:
        "Interface는 존재하지만 비활성 상태입니다.",
    };
  }

  if (
    interfaceData.exists === true &&
    interfaceData.is_up === true
  ) {
    return {
      status: "connected",
      label: "연결됨",
      description:
        "Interface가 정상적으로 활성화되어 있습니다.",
    };
  }

  return {
    status: "unknown",
    label: "상태 미확인",
    description:
      "Interface 상태 필드가 충분하지 않습니다.",
  };
}

function getInterfaceRate(
  interfaceData,
  primaryKey,
  legacyKey
) {
  return (
    interfaceData?.[primaryKey] ??
    interfaceData?.[legacyKey] ??
    null
  );
}

function InterfaceCard({
  title,
  description,
  interfaceData,
}) {
  const interfaceStatus =
    getInterfaceStatus(
      interfaceData
    );

  const rxRate =
    getInterfaceRate(
      interfaceData,
      "rx_bytes_per_second",
      "rx_bytes_per_sec"
    );

  const txRate =
    getInterfaceRate(
      interfaceData,
      "tx_bytes_per_second",
      "tx_bytes_per_sec"
    );

  return (
    <article
      className={[
        "interface-card",
        `interface-card-${interfaceStatus.status}`,
      ].join(" ")}
    >
      <header className="interface-header">
        <div className="interface-title-area">
          <div className="interface-title-row">
            <h3>{title}</h3>

            <StatusBadge
              status={
                interfaceStatus.status
              }
              label={
                interfaceStatus.label
              }
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

      <div className="interface-name-row">
        <span>
          Interface:
        </span>

        <strong>
          {interfaceData?.interface_name ||
            "미할당"}
        </strong>
      </div>

      <div className="interface-detail-grid">
        <div className="metric-item">
          <span>IP Address</span>

          <strong>
            {interfaceData?.ip_address ||
              "-"}
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

          <strong
            className={
              rxRate === null ||
              rxRate === undefined
                ? "metric-unavailable"
                : ""
            }
          >
            {formatMetric(
              rxRate,
              " B/s",
              2
            )}
          </strong>
        </div>

        <div className="metric-item">
          <span>TX 전송률</span>

          <strong
            className={
              txRate === null ||
              txRate === undefined
                ? "metric-unavailable"
                : ""
            }
          >
            {formatMetric(
              txRate,
              " B/s",
              2
            )}
          </strong>
        </div>
      </div>

      <footer className="interface-footer">
        <p>
          {interfaceStatus.description}
        </p>

        {interfaceData?.exists === true &&
          interfaceData?.is_up === true &&
          (rxRate === null ||
            rxRate === undefined ||
            txRate === null ||
            txRate === undefined) && (
            <StatusBadge
              status="degraded"
              label="Rate 계산 불가"
              size="small"
              title="Interface는 활성화되어 있지만 전송률을 계산할 수 없습니다."
            />
          )}
      </footer>
    </article>
  );
}

/* =========================================================
   Gateway Status Page
   ========================================================= */

export default function GatewayStatus() {
  const [
    latestMetric,
    setLatestMetric,
  ] = useState(null);

  const [
    gatewayStatus,
    setGatewayStatus,
  ] = useState("NO_DATA");

  const [loading, setLoading] =
    useState(true);

  const [refreshing, setRefreshing] =
    useState(false);

  const [error, setError] =
    useState("");

  const [pollWarning, setPollWarning] =
    useState("");

  const [
    lastSuccessfulFetchAt,
    setLastSuccessfulFetchAt,
  ] = useState("");

  const isFetchingRef =
    useRef(false);

  const hasSuccessfulResponseRef =
    useRef(false);

  const loadGatewayMetrics =
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

        try {
          const data =
            await getGatewayMetrics({
              limit: 1,
              offset: 0,
            });

          const metric =
            Array.isArray(data?.items)
              ? data.items[0] ?? null
              : null;

          setLatestMetric(metric);

          hasSuccessfulResponseRef.current =
            true;

          setLastSuccessfulFetchAt(
            new Date().toISOString()
          );

          setError("");
          setPollWarning("");
        } catch (err) {
          if (IS_DEV) {
            console.error(
              "Gateway metrics load failed:",
              err
            );
          }

          const message =
            err instanceof Error
              ? err.message
              : "Gateway Metrics를 불러오지 못했습니다.";

          if (
            hasSuccessfulResponseRef.current
          ) {
            setPollWarning(message);
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
    latestMetric?.collected_at ??
    null;

  useEffect(() => {
    function updateGatewayStatus() {
      setGatewayStatus(
        getGatewayStatus(
          collectedAt,
          Boolean(latestMetric),
          Boolean(error)
        )
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
  }, [
    collectedAt,
    latestMetric,
    error,
  ]);

  const interfaces =
    latestMetric?.interface_metrics ??
    {};

  /*
   * Phase 6-A 실제 Backend 계약:
   * internal_lan = eth0
   * usb_lan = eth1
   *
   * wlan0 / wireless_lan은 운영 표시 대상에서 제외합니다.
   */
  const internalLan =
    interfaces.internal_lan ??
    interfaces.eth0 ??
    null;

  const usbLan =
    interfaces.usb_lan ??
    interfaces.eth1 ??
    null;

  const interfaceList =
    useMemo(
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
      [
        internalLan,
        usbLan,
      ]
    );

  const interfaceSummary =
    useMemo(() => {
      let connected = 0;
      let down = 0;
      let missing = 0;
      let unknown = 0;

      interfaceList.forEach(
        ({ data }) => {
          const status =
            getInterfaceStatus(data)
              .status;

          if (status === "connected") {
            connected += 1;
          } else if (
            status === "down"
          ) {
            down += 1;
          } else if (
            status === "missing"
          ) {
            missing += 1;
          } else {
            unknown += 1;
          }
        }
      );

      return {
        connected,
        down,
        missing,
        unknown,
      };
    }, [interfaceList]);

  function handleRefresh() {
    loadGatewayMetrics(true);
  }

  const gatewayTheme =
    getGatewayStatusTheme(
      gatewayStatus
    );

  const interfaceSummaryStatus =
    interfaceSummary.down > 0 ||
    interfaceSummary.missing > 0 ||
    interfaceSummary.unknown > 0
      ? "warning"
      : "normal";

  return (
    <div className="page-container">
      <PageHeader
        title="Gateway Status"
        description="Raspberry Pi Gateway의 시스템 자원, 수집 상태, 네트워크 Interface 상태를 확인합니다."
        updatedAt={
          lastSuccessfulFetchAt
            ? formatKST(
                lastSuccessfulFetchAt
              )
            : undefined
        }
        onRefresh={handleRefresh}
        refreshing={refreshing}
      />

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
              {pollWarning} 마지막으로
              수신한 Gateway Metric을
              계속 표시합니다.
            </p>
          </div>

          <div className="page-warning-actions">
            <span>
              {POLLING_INTERVAL_MS /
                1_000}
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

      {loading &&
      !hasSuccessfulResponseRef.current ? (
        <LoadingState
          title="Gateway Metrics를 불러오는 중입니다."
          description="Raspberry Pi 시스템 상태와 Interface 정보를 확인하고 있습니다."
        />
      ) : error &&
        !hasSuccessfulResponseRef.current ? (
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
              description="API 요청은 성공했지만 Metric이 없습니다."
              status="unknown"
              footer={
                <StatusBadge
                  status="NO_DATA"
                  size="small"
                />
              }
            />
          </section>

          <EmptyState
            title="수집된 Gateway Metrics가 없습니다."
            description="Gateway Metrics Collector가 실행 중인지 확인하고, DB에 Metric이 저장되고 있는지 확인해 주세요."
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
              description={
                getGatewayStatusDescription(
                  gatewayStatus
                )
              }
              status={gatewayTheme}
              footer={
                <StatusBadge
                  status={gatewayStatus}
                  size="small"
                />
              }
            />

            <SummaryCard
              title="마지막 수집"
              value={formatElapsedTime(
                latestMetric.collected_at
              )}
              description={formatKST(
                latestMetric.collected_at
              )}
              status={gatewayTheme}
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
              value={
                interfaceSummary.connected
              }
              description={[
                `DOWN ${interfaceSummary.down}`,
                `미인식 ${interfaceSummary.missing}`,
                interfaceSummary.unknown > 0
                  ? `미확인 ${interfaceSummary.unknown}`
                  : null,
              ]
                .filter(Boolean)
                .join(" · ")}
              status={
                interfaceSummaryStatus
              }
            />
          </section>

          <section className="panel gateway-overview">
            <div className="gateway-overview-main">
              <span className="section-label">
                수집 상태
              </span>

              <div className="gateway-status-row">
                <StatusBadge
                  status={gatewayStatus}
                />

                <span className="last-collected">
                  마지막 수집:{" "}
                  {formatKST(
                    latestMetric.collected_at
                  )}
                </span>
              </div>

              <p className="threshold-note">
                수집 주기{" "}
                {
                  COLLECTION_INTERVAL_SECONDS
                }
                초 ×{" "}
                {
                  ONLINE_THRESHOLD_MULTIPLIER
                }
                배인{" "}
                {
                  ONLINE_THRESHOLD_SECONDS
                }
                초 이내에 Metric이
                수집되면 ONLINE으로
                표시합니다.
              </p>
            </div>

            <div className="gateway-overview-detail">
              <div>
                <span>Metric ID</span>

                <strong>
                  {formatInteger(
                    latestMetric.id
                  )}
                </strong>
              </div>

              <div>
                <span>
                  마지막 API 성공
                </span>

                <strong>
                  {formatKST(
                    lastSuccessfulFetchAt
                  )}
                </strong>
              </div>
            </div>
          </section>

          <section>
            <div className="section-heading">
              <div>
                <h2>시스템 자원</h2>

                <p>
                  Raspberry Pi의 현재
                  CPU, Memory, Disk,
                  Temperature 사용
                  상태입니다.
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
                percentage={
                  latestMetric.cpu_percent
                }
                status={getResourceStatus(
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
                percentage={
                  latestMetric.memory_percent
                }
                status={getResourceStatus(
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
                percentage={
                  latestMetric.disk_percent
                }
                status={getResourceStatus(
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
                status={getTemperatureStatus(
                  latestMetric.temperature_c
                )}
                description="Raspberry Pi CPU 온도"
              />
            </div>
          </section>

          <section className="panel">
            <div className="panel-header">
              <div>
                <h2>
                  Network Interface
                </h2>

                <p className="panel-description">
                  운영 Interface인
                  internal_lan(eth0)과
                  usb_lan(eth1)의 상태를
                  확인합니다.
                </p>
              </div>

              <div className="interface-summary-badges">
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

                {interfaceSummary.unknown >
                  0 && (
                  <StatusBadge
                    status="unknown"
                    label={`미확인 ${interfaceSummary.unknown}`}
                    size="small"
                  />
                )}
              </div>
            </div>

            <div className="interface-grid">
              {interfaceList.map(
                (interfaceItem) => (
                  <InterfaceCard
                    key={
                      interfaceItem.key
                    }
                    title={
                      interfaceItem.title
                    }
                    description={
                      interfaceItem.description
                    }
                    interfaceData={
                      interfaceItem.data
                    }
                  />
                )
              )}
            </div>
          </section>
        </>
      )}
    </div>
  );
}