import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { getMqttLogs } from "../api/api";

import DataTable from "../components/DataTable";
import DetailModal from "../components/DetailModal";
import EmptyState from "../components/EmptyState";
import JsonViewer from "../components/JsonViewer";
import PageHeader from "../components/PageHeader";
import Pagination from "../components/Pagination";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";
import {
  formatMqttLogTimestamp,
  formatMqttTimestampKST,
} from "../utils/mqttTimestamp";

import "../styles/pages/Logs.scss"

const DEFAULT_LIMIT = 20;
const POLLING_INTERVAL_MS = 10_000;
const IS_DEV = import.meta.env.DEV;

function formatKST(dateString) {
  return formatMqttTimestampKST(
    dateString,
    undefined,
    "시간대 미확인",
  );
}

function formatNumber(value, maximumFractionDigits = 0) {
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

  return number.toLocaleString("ko-KR", {
    maximumFractionDigits,
  });
}

function normalizeBoolean(value) {
  return (
    value === true ||
    value === 1 ||
    value === "1" ||
    value === "true"
  );
}

function normalizeSearchValue(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function parsePayload(payload) {
  if (
    payload === null ||
    payload === undefined ||
    payload === ""
  ) {
    return null;
  }

  if (
    typeof payload === "object"
  ) {
    return payload;
  }

  try {
    return JSON.parse(payload);
  } catch {
    return null;
  }
}

function formatPayloadPreview(payload) {
  if (
    payload === null ||
    payload === undefined ||
    payload === ""
  ) {
    return "-";
  }

  if (
    typeof payload === "object"
  ) {
    try {
      return JSON.stringify(payload);
    } catch {
      return String(payload);
    }
  }

  return String(payload);
}

function getPayloadSizeStatus(size) {
  const number = Number(size);

  if (!Number.isFinite(number)) {
    return "unknown";
  }

  if (number > 5120) {
    return "danger";
  }

  if (number > 1024) {
    return "warning";
  }

  return "normal";
}

function getPayloadSizeLabel(size) {
  const number = Number(size);

  if (!Number.isFinite(number)) {
    return "확인 불가";
  }

  if (number > 5120) {
    return "대용량";
  }

  if (number > 1024) {
    return "주의";
  }

  return "정상";
}

export default function Logs() {
  const [logs, setLogs] =
    useState([]);

  const [total, setTotal] =
    useState(0);

  const [offset, setOffset] =
    useState(0);

  const [searchText, setSearchText] =
    useState("");

  const [
    jsonValidityFilter,
    setJsonValidityFilter,
  ] = useState("");

  const [
    topicValidityFilter,
    setTopicValidityFilter,
  ] = useState("");

  const [
    selectedLog,
    setSelectedLog,
  ] = useState(null);

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

  const isFetchingRef =
    useRef(false);

  const hasDataRef =
    useRef(false);

  const loadData = useCallback(
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
        };

        if (
          jsonValidityFilter ===
          "valid"
        ) {
          params.is_json_valid = true;
        }

        if (
          jsonValidityFilter ===
          "invalid"
        ) {
          params.is_json_valid = false;
        }

        if (
          topicValidityFilter ===
          "valid"
        ) {
          params.is_topic_valid = true;
        }

        if (
          topicValidityFilter ===
          "invalid"
        ) {
          params.is_topic_valid = false;
        }

        const data =
          await getMqttLogs(params);

        const items =
          Array.isArray(data?.items)
            ? data.items
            : [];

        const responseTotal =
          Number(data?.total);

        setLogs(items);

        setTotal(
          Number.isFinite(
            responseTotal
          )
            ? responseTotal
            : items.length
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
            "MQTT logs load failed:",
            err
          );
        }

        const message =
          err instanceof Error
            ? err.message
            : "MQTT 로그를 불러오지 못했습니다.";

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
      jsonValidityFilter,
      topicValidityFilter,
    ]
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

  const filteredLogs =
    useMemo(() => {
      const keyword =
        searchText
          .trim()
          .toLowerCase();

      if (!keyword) {
        return logs;
      }

      return logs.filter(
        (log) =>
          normalizeSearchValue(
            log.device_id
          ).includes(keyword) ||
          normalizeSearchValue(
            log.topic
          ).includes(keyword) ||
          normalizeSearchValue(
            log.payload
          ).includes(keyword) ||
          normalizeSearchValue(
            log.error_message
          ).includes(keyword) ||
          normalizeSearchValue(
            log.id
          ).includes(keyword)
      );
    }, [logs, searchText]);

  const logSummary =
    useMemo(() => {
      let jsonValidCount = 0;
      let jsonInvalidCount = 0;
      let topicValidCount = 0;
      let topicInvalidCount = 0;
      let largePayloadCount = 0;
      let unknownDeviceCount = 0;

      logs.forEach((log) => {
        if (
          normalizeBoolean(
            log.is_json_valid
          )
        ) {
          jsonValidCount += 1;
        } else {
          jsonInvalidCount += 1;
        }

        if (
          normalizeBoolean(
            log.is_topic_valid
          )
        ) {
          topicValidCount += 1;
        } else {
          topicInvalidCount += 1;
        }

        if (
          Number(log.payload_size) >
          5120
        ) {
          largePayloadCount += 1;
        }

        if (!log.device_id) {
          unknownDeviceCount += 1;
        }
      });

      return {
        jsonValidCount,
        jsonInvalidCount,
        topicValidCount,
        topicInvalidCount,
        largePayloadCount,
        unknownDeviceCount,
      };
    }, [logs]);

  const currentPage =
    Math.floor(
      offset / DEFAULT_LIMIT
    ) + 1;

  const totalPages = Math.max(
    1,
    Math.ceil(
      total / DEFAULT_LIMIT
    )
  );

  function handleRefresh() {
    loadData(true);
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
    setOffset(
      (currentOffset) =>
        currentOffset +
        DEFAULT_LIMIT
    );
  }

  function handleJsonFilterChange(
    value
  ) {
    setJsonValidityFilter(value);
    setOffset(0);
  }

  function handleTopicFilterChange(
    value
  ) {
    setTopicValidityFilter(value);
    setOffset(0);
  }

  function handleResetFilters() {
    setSearchText("");
    setJsonValidityFilter("");
    setTopicValidityFilter("");
    setOffset(0);
  }

  const columns = [
  {
    key: "id",
    header: "ID",
    align: "right",
    width: 70,
    render: (value) =>
      value ?? "-",
  },
  {
    key: "device_id",
    header: "Device",
    width: 150,
    render: (value) => (
      <strong
        className="device-id"
        title={value || ""}
      >
        {value || "미매핑"}
      </strong>
    ),
  },
  {
    key: "topic",
    header: "Topic",
    width: 280,
    render: (value) => (
      <span
        className="topic"
        title={value || ""}
      >
        {value || "-"}
      </span>
    ),
  },
  {
    key: "payload",
    header: "Payload",
    width: 320,
    render: (value) => (
      <span
        className="payload"
        title={formatPayloadPreview(
          value
        )}
      >
        {formatPayloadPreview(
          value
        )}
      </span>
    ),
  },
  {
    key: "payload_size",
    header: "Size",
    align: "right",
    width: 130,
    render: (value) => (
      <div className="payload-size">
        <strong>
          {value === null ||
          value === undefined
            ? "-"
            : `${formatNumber(
                value
              )} B`}
        </strong>

      </div>
    ),
  },
  {
    key: "is_json_valid",
    header: "JSON",
    width: 100,
    render: (value) => (
      <StatusBadge
        status={
          normalizeBoolean(value)
            ? "normal"
            : "danger"
        }
        label={
          normalizeBoolean(value)
            ? "Valid"
            : "Invalid"
        }
        size="small"
      />
    ),
  },
  {
    key: "is_topic_valid",
    header: "Topic Valid",
    width: 120,
    render: (value) => (
      <StatusBadge
        status={
          normalizeBoolean(value)
            ? "normal"
            : "warning"
        }
        label={
          normalizeBoolean(value)
            ? "Valid"
            : "Invalid"
        }
        size="small"
      />
    ),
  },
  {
    key: "error_message",
    header: "Error",
    width: 260,
    render: (value) => (
      <span
        className={
          value
            ? "log-error"
            : "text-muted"
        }
        title={value || ""}
      >
        {value || "-"}
      </span>
    ),
  },
  {
    key: "received_at",
    header: "Received At",
    width: 190,
    render: (value) =>
      formatMqttLogTimestamp(value),
  },
];

  return (
    <div className="logs-page">
      <PageHeader
        title="MQTT Logs"
        description="수신된 MQTT Topic과 Payload, JSON 및 Topic 유효성 검사 결과를 확인합니다."
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
              최신 MQTT 로그 갱신 실패
            </strong>

            <p>
              {pollWarning} 이전에 조회한
              로그를 계속 표시합니다.
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
        logs.length > 0 && (
          <section
            className="summary-card-grid"
            aria-label="MQTT 로그 요약"
          >
            <SummaryCard
              title="전체 로그"
              value={formatNumber(total)}
              description="현재 조회 조건에 해당하는 로그"
            />

            <SummaryCard
              title="JSON 정상"
              value={formatNumber(
                logSummary.jsonValidCount
              )}
              description="현재 페이지 JSON Valid"
              status="normal"
            />

            <SummaryCard
              title="JSON 오류"
              value={formatNumber(
                logSummary.jsonInvalidCount
              )}
              description="현재 페이지 JSON Invalid"
              status={
                logSummary.jsonInvalidCount >
                  0
                  ? "danger"
                  : "default"
              }
            />

            <SummaryCard
              title="Topic 정상"
              value={formatNumber(
                logSummary.topicValidCount
              )}
              description="현재 페이지 Topic Valid"
              status="normal"
            />

            <SummaryCard
              title="Topic 오류"
              value={formatNumber(
                logSummary.topicInvalidCount
              )}
              description="현재 페이지 Topic Invalid"
              status={
                logSummary.topicInvalidCount >
                  0
                  ? "warning"
                  : "default"
              }
            />

            <SummaryCard
              title="대용량 Payload"
              value={formatNumber(
                logSummary.largePayloadCount
              )}
              description="Payload가 5KB를 초과한 로그"
              status={
                logSummary.largePayloadCount >
                  0
                  ? "danger"
                  : "default"
              }
            />

            <SummaryCard
              title="미매핑 Device"
              value={formatNumber(
                logSummary.unknownDeviceCount
              )}
              description="Device ID를 확인하지 못한 로그"
              status={
                logSummary.unknownDeviceCount >
                  0
                  ? "warning"
                  : "default"
              }
            />
          </section>
        )}

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>조회 조건</h2>

            <p className="panel-description">
              유효성 필터는 API 요청에
              적용되고, 검색어는 현재 페이지
              결과에 적용됩니다.
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
            <label htmlFor="mqtt-log-search">
              로그 검색
            </label>

            <input
              id="mqtt-log-search"
              type="search"
              placeholder="Device, Topic, Payload, Error"
              value={searchText}
              onChange={(event) => {
                setSearchText(
                  event.target.value
                );
              }}
            />
          </div>

          <div className="filter-item">
            <label htmlFor="json-validity-filter">
              JSON 유효성
            </label>

            <select
              id="json-validity-filter"
              value={jsonValidityFilter}
              onChange={(event) => {
                handleJsonFilterChange(
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="valid">
                Valid
              </option>

              <option value="invalid">
                Invalid
              </option>
            </select>
          </div>

          <div className="filter-item">
            <label htmlFor="topic-validity-filter">
              Topic 유효성
            </label>

            <select
              id="topic-validity-filter"
              value={topicValidityFilter}
              onChange={(event) => {
                handleTopicFilterChange(
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="valid">
                Valid
              </option>

              <option value="invalid">
                Invalid
              </option>
            </select>
          </div>
        </div>
      </section>

      <section className="panel table-panel">
        <div className="panel-header">
          <div>
            <h2>MQTT 로그 목록</h2>

            <p className="panel-description">
              Payload는 표에서 일부만
              표시하고 상세 모달에서 전체
              내용을 확인합니다.
            </p>
          </div>

          <span className="data-count">
            {formatNumber(
              filteredLogs.length
            )}
            건 표시
          </span>
        </div>

        {searchText &&
          !loading &&
          !error &&
          logs.length > 0 &&
          filteredLogs.length === 0 ? (
          <EmptyState
            title="검색 조건에 맞는 MQTT 로그가 없습니다."
            description="다른 Device ID, Topic 또는 Payload를 검색해 주세요."
            actionLabel="검색 초기화"
            onAction={() =>
              setSearchText("")
            }
          />
        ) : (
          <div className="table-scroll">
            <DataTable
              columns={columns}
              rows={filteredLogs}
              loading={loading}
              error={error}
              onRetry={handleRefresh}
              rowKey="id"
              minWidth={1550}
              tableLabel="MQTT 로그 목록"
              emptyTitle="표시할 MQTT 로그가 없습니다."
              emptyDescription="MQTT Subscriber가 실행 중이고 메시지를 정상적으로 수신하는지 확인해 주세요."
              rowClassName={(log) => {
                if (
                  !normalizeBoolean(
                    log.is_json_valid
                  )
                ) {
                  return "row-danger";
                }

                if (
                  !normalizeBoolean(
                    log.is_topic_valid
                  ) ||
                  Number(
                    log.payload_size
                  ) > 5120
                ) {
                  return "row-warning";
                }

                return "";
              }}
              onRowClick={setSelectedLog}
            />
          </div>
        )}

        {!loading &&
          !error &&
          total > 0 && (
            <Pagination
              currentPage={currentPage}
              totalPages={totalPages}
              total={total}
              pageSize={DEFAULT_LIMIT}
              onPrevious={
                handlePrevPage
              }
              onNext={handleNextPage}
              disabled={refreshing}
            />
          )}
      </section>

      <DetailModal
        open={Boolean(selectedLog)}
        title={
          selectedLog
            ? `MQTT Log #${selectedLog.id}`
            : "MQTT Log 상세"
        }
        description={
          selectedLog
            ? `${selectedLog.device_id || "미매핑 Device"} · ${selectedLog.topic || "Topic 없음"}`
            : undefined
        }
        onClose={() =>
          setSelectedLog(null)
        }
        size="large"
        footer={
          <button
            type="button"
            className="button button-secondary"
            onClick={() =>
              setSelectedLog(null)
            }
          >
            닫기
          </button>
        }
      >
        {selectedLog && (
          <div className="detail">
            <section className="detail-grid">
              <div className="detail-item">
                <span>Device</span>

                <strong>
                  {selectedLog.device_id ||
                    "미매핑"}
                </strong>
              </div>

              <div className="detail-item">
                <span>Payload Size</span>

                <strong>
                  {selectedLog.payload_size ===
                    null ||
                    selectedLog.payload_size ===
                    undefined
                    ? "-"
                    : `${formatNumber(
                      selectedLog.payload_size
                    )} B`}
                </strong>
              </div>

              <div className="detail-item">
                <span>JSON 검사</span>

                <StatusBadge
                  status={
                    normalizeBoolean(
                      selectedLog.is_json_valid
                    )
                      ? "normal"
                      : "danger"
                  }
                  label={
                    normalizeBoolean(
                      selectedLog.is_json_valid
                    )
                      ? "Valid"
                      : "Invalid"
                  }
                />
              </div>

              <div className="detail-item">
                <span>Topic 검사</span>

                <StatusBadge
                  status={
                    normalizeBoolean(
                      selectedLog.is_topic_valid
                    )
                      ? "normal"
                      : "warning"
                  }
                  label={
                    normalizeBoolean(
                      selectedLog.is_topic_valid
                    )
                      ? "Valid"
                      : "Invalid"
                  }
                />
              </div>

              <div className="detail-item">
                <span>Received At</span>

                <strong>
                  {formatMqttLogTimestamp(
                    selectedLog.received_at
                  )}
                </strong>
              </div>
            </section>

            <section className="detail-section">
              <h3>Topic</h3>

              <p className="break-word topic-detail">
                {selectedLog.topic || "-"}
              </p>
            </section>

            <section className="detail-section">
              <h3>검증 오류</h3>

              {selectedLog.error_message ? (
                <div className="error-box">
                  {selectedLog.error_message}
                </div>
              ) : (
                <p className="text-muted">
                  기록된 검증 오류가 없습니다.
                </p>
              )}
            </section>

            <section className="detail-section">
              <h3>Payload</h3>

              {parsePayload(
                selectedLog.payload
              ) !== null ? (
                <JsonViewer
                  data={parsePayload(
                    selectedLog.payload
                  )}
                />
              ) : (
                <pre className="raw-payload">
                  {formatPayloadPreview(
                    selectedLog.payload
                  )}
                </pre>
              )}
            </section>
          </div>
        )}
      </DetailModal>
    </div>
  );
}
