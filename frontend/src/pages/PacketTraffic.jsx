import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  getPacketFeatureLogs,
} from "../api/api";

import DataTable from "../components/DataTable";
import EmptyState from "../components/EmptyState";
import PageHeader from "../components/PageHeader";
import Pagination from "../components/Pagination";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";

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

function getCaptureStatus(item) {
  if (
    item.capture_eligible === false
  ) {
    return "excluded";
  }

  if (
    item.segment_status === "FAILED"
  ) {
    return "failed";
  }

  if (
    item.capture_eligible === true
  ) {
    return "eligible";
  }

  return "unknown";
}

function getCaptureStatusLabel(item) {
  if (
    item.segment_status === "FAILED"
  ) {
    return "수집 실패";
  }

  if (
    item.capture_eligible === false
  ) {
    return "분석 제외";
  }

  if (
    item.capture_eligible === true
  ) {
    return "분석 가능";
  }

  return "상태 미확인";
}

function getExclusionLabel(reason) {
  const labels = {
    LATE_CAPTURE:
      "지연 수집",
    MISSING_TIMING_METADATA:
      "Timing 정보 없음",
    EMPTY_CAPTURE:
      "수집 Packet 없음",
    SEGMENT_FAILED:
      "Segment 처리 실패",
    PACKET_CAPTURE_GAP:
      "Packet Capture Gap",
  };

  return (
    labels[reason] ||
    reason ||
    "-"
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

  const isFetchingRef = useRef(false);
  const hasDataRef = useRef(false);

  const loadPacketFeatures =
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
          const params = {
            limit: DEFAULT_LIMIT,
            offset,
            direction:
              direction ||
              undefined,
          };

          if (
            captureStatus ===
            "eligible"
          ) {
            params.capture_eligible =
              true;
          }

          if (
            captureStatus ===
            "excluded"
          ) {
            params.capture_eligible =
              false;
          }

          const data =
            await getPacketFeatureLogs(
              params
            );

          const items =
            Array.isArray(data?.items)
              ? data.items
              : [];

          const responseTotal =
            Number(data?.total);

          setPacketFeatures(items);

          setTotal(
            Number.isFinite(
              responseTotal
            )
              ? responseTotal
              : 0
          );

          setLastUpdated(
            new Date().toISOString()
          );

          hasDataRef.current = true;

          setError("");
          setPollWarning("");
        } catch (err) {
          if (IS_DEV) {
            console.error(
              "Packet feature load failed:",
              err
            );
          }

          const message =
            err instanceof Error
              ? err.message
              : "Packet Traffic 데이터를 불러오지 못했습니다.";

          if (hasDataRef.current) {
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
      [
        offset,
        direction,
        captureStatus,
      ]
    );

  useEffect(() => {
    loadPacketFeatures();

    const pollingTimer =
      window.setInterval(() => {
        loadPacketFeatures();
      }, POLLING_INTERVAL_MS);

    return () => {
      window.clearInterval(
        pollingTimer
      );
    };
  }, [loadPacketFeatures]);

  const filteredItems =
    useMemo(() => {
      const keyword =
        searchText
          .trim()
          .toLowerCase();

      if (!keyword) {
        return packetFeatures;
      }

      return packetFeatures.filter(
        (item) => {
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

          if (
            item.segment_status ===
            "FAILED"
          ) {
            failedCount += 1;
          }

          if (
            item.capture_eligible ===
            true
          ) {
            eligibleCount += 1;
          }

          if (
            item.capture_eligible ===
            false
          ) {
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
      header: "Session",
      width: 120,
      render: (_, item) => {
        const sessionId =
          getSessionId(item);

        return (
          <span
            className="truncate-cell"
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
      header: "Segment",
      align: "right",
      width: 90,
      render: (value) =>
        formatNumber(value, 0),
    },
    {
      key: "device_id",
      header: "Device",
      width: 130,
      render: (value, item) => (
        <div className="device-cell">
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
      header: "Peer IP",
      width: 130,
    },
    {
      key: "direction",
      header: "Direction",
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
      header: "분석 Window",
      width: 210,
      render: (_, item) => (
        <div className="window-cell">
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
      header: "Packets",
      align: "right",
      width: 90,
      render: (value) =>
        formatNumber(value, 0),
    },
    {
      key: "total_bytes",
      header: "Total Bytes",
      align: "right",
      width: 110,
      render: (value) =>
        formatNumber(value, 0),
    },
    {
      key: "nominal_packets_per_second",
      header: "명목 PPS",
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
      header: "실제 PPS",
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
      header: "명목 BPS",
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
      header: "실제 BPS",
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
      header: "Capture 시간",
      align: "right",
      width: 120,
      render: (value) =>
        formatDuration(value),
    },
    {
      key: "coverage_ratio",
      header: "Coverage",
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
    <div className="page-container">
      <PageHeader
        title="Packet Traffic"
        description="Raspberry Pi에서 수집한 Packet Feature와 실제 Capture 품질을 확인합니다."
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
            aria-label="Packet Traffic 요약"
          >
            <SummaryCard
              title="전체 Feature"
              value={formatNumber(
                total,
                0
              )}
              description="조회 조건에 해당하는 전체 Window"
            />

            <SummaryCard
              title="분석 가능"
              value={formatNumber(
                pageSummary.eligibleCount,
                0
              )}
              description="Capture 품질 기준을 통과한 Window"
              status="normal"
            />

            <SummaryCard
              title="분석 제외"
              value={formatNumber(
                pageSummary.excludedCount,
                0
              )}
              description="Timing 또는 Capture 품질 문제"
              status={
                pageSummary.excludedCount >
                  0
                  ? "warning"
                  : "default"
              }
            />

            <SummaryCard
              title="수집 실패"
              value={formatNumber(
                pageSummary.failedCount,
                0
              )}
              description="Segment 처리에 실패한 Window"
              status={
                pageSummary.failedCount >
                  0
                  ? "danger"
                  : "default"
              }
            />

            <SummaryCard
              title="등록 기기"
              value={formatNumber(
                pageSummary.registeredDeviceCount,
                0
              )}
              description="현재 페이지 고유 Device"
            />

            <SummaryCard
              title="미매핑 IP"
              value={formatNumber(
                pageSummary.unmappedIpCount,
                0
              )}
              description="Device와 연결되지 않은 고유 IP"
              status={
                pageSummary.unmappedIpCount >
                  0
                  ? "warning"
                  : "default"
              }
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
              description="실제 Capture Duration 기준"
            />
          </section>
        )}

      <section className="panel packet-table-panel">
        <div className="panel-header">
          <div>
            <h2>
              조회 조건
            </h2>

            <p className="panel-description">
              Direction과 분석 상태는
              전체 조회에 적용되고,
              검색어는 현재 페이지 결과에
              적용됩니다.
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
              기기·IP·Session 검색
            </label>

            <input
              id="packet-search"
              type="search"
              placeholder="device_id, peer_ip, session_id"
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
              Direction
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
                INBOUND
              </option>

              <option value="OUTBOUND">
                OUTBOUND
              </option>
            </select>
          </div>

          <div className="filter-item">
            <label htmlFor="capture-status-filter">
              Capture 분석 상태
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
              Packet Feature 목록
            </h2>

            <p className="panel-description">
              명목 Rate는 10초 Window
              기준이며, 실제 Rate는
              Capture Duration 기준입니다.
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
            description="현재 페이지에서 다른 기기 ID, IP 또는 Session ID를 검색해 주세요."
            actionLabel="검색 초기화"
            onAction={() => setSearchText("")}
          />
        ) : (
          <div className="packet-table-scroll">
            <DataTable
              columns={columns}
              rows={filteredItems}
              loading={loading}
              error={error}
              onRetry={handleRefresh}
              rowKey="id"
              minWidth={2500}
              tableLabel="Packet Feature 목록"
              emptyTitle="표시할 Packet Feature가 없습니다."
              emptyDescription="Packet Capture와 Feature Extractor가 정상적으로 실행 중인지 확인해 주세요."
              rowClassName={(item) => {
                if (item.segment_status === "FAILED") {
                  return "table-row-danger";
                }

                if (item.capture_eligible === false) {
                  return "table-row-warning";
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