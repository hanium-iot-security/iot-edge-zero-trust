import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  getEvents,
} from "../api/api";

import DataTable from "../components/DataTable";
import DetailModal from "../components/DetailModal";
import EmptyState from "../components/EmptyState";
import JsonViewer from "../components/JsonViewer";
import PageHeader from "../components/PageHeader";
import Pagination from "../components/Pagination";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";

const DEFAULT_LIMIT = 20;
const POLLING_INTERVAL_MS = 10_000;
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

function normalizeSearchValue(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
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

  if (number > 0) {
    return `+${number}`;
  }

  return String(number);
}

function isAppliedToScore(value) {
  return (
    value === true ||
    value === 1 ||
    value === "1" ||
    value === "true"
  );
}

function getAppliedStatus(event) {
  if (
    event.processing_reason ===
    "CAPTURE_GAP_UNSCORED"
  ) {
    return {
      status: "degraded",
      label: "Capture Gap 미반영",
    };
  }

  if (isAppliedToScore(
    event.applied_to_score
  )) {
    return {
      status: "scored",
      label: "감점 반영",
    };
  }

  return {
    status: "unscored",
    label: "미반영",
  };
}

function getProcessingReasonLabel(reason) {
  const labels = {
    REPRESENTATIVE_RULE_EVENT:
      "대표 Rule 이벤트",

    AI_SUPPORTING_EVIDENCE:
      "AI 보조 증거",

    CAPTURE_GAP_UNSCORED:
      "Capture Gap으로 미반영",

    UNMAPPED_SUBJECT_IP:
      "기기 매핑 없음",

    DUPLICATE_EVENT:
      "중복 이벤트",

    WINDOW_ALREADY_PROCESSED:
      "이미 처리된 Window",

    SCORE_CAP_APPLIED:
      "Window 감점 상한 적용",
  };

  return (
    labels[reason] ||
    reason ||
    "-"
  );
}

function getIncidentFamilyLabel(
  incidentFamily
) {
  const labels = {
    FLOODING: "Flooding",
    SCAN: "Port Scan",
    AI_ONLY: "AI 단독 탐지",
    MALFORMED: "Malformed",
    UNKNOWN_DEVICE:
      "미등록 기기",
    TOPIC_ABUSE:
      "비정상 Topic",
  };

  return (
    labels[incidentFamily] ||
    incidentFamily ||
    "-"
  );
}

function getSeverityStatus(severity) {
  const normalized =
    String(severity || "")
      .toLowerCase();

  if (
    normalized === "critical" ||
    normalized === "high"
  ) {
    return normalized;
  }

  if (
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
      event.detector_type ||
      ""
    ).toUpperCase();

  if (
    detectorType === "AI" ||
    event.event_type ===
    "AI_PACKET_ANOMALY" ||
    event.event_type ===
    "AI_ANOMALY"
  ) {
    return "ai";
  }

  if (detectorType === "RULE") {
    return "rule";
  }

  return "unknown";
}

export default function Events() {
  const [events, setEvents] =
    useState([]);

  const [total, setTotal] =
    useState(0);

  const [offset, setOffset] =
    useState(0);

  const [
    selectedEvent,
    setSelectedEvent,
  ] = useState(null);

  const [searchText, setSearchText] =
    useState("");

  const [
    detectorType,
    setDetectorType,
  ] = useState("");

  const [
    severity,
    setSeverity,
  ] = useState("");

  const [
    incidentFamily,
    setIncidentFamily,
  ] = useState("");

  const [
    appliedFilter,
    setAppliedFilter,
  ] = useState("");

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

        try {
          const params = {
            limit: DEFAULT_LIMIT,
            offset,

            detector_type:
              detectorType ||
              undefined,

            severity:
              severity ||
              undefined,

            incident_family:
              incidentFamily ||
              undefined,
          };

          if (
            appliedFilter ===
            "applied"
          ) {
            params.applied_to_score =
              true;
          }

          if (
            appliedFilter ===
            "unapplied"
          ) {
            params.applied_to_score =
              false;
          }

          const data =
            await getEvents(params);

          const items =
            Array.isArray(data?.items)
              ? data.items
              : [];

          const responseTotal =
            Number(data?.total);

          setEvents(items);

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
              "Events data load failed:",
              err
            );
          }

          const message =
            err instanceof Error
              ? err.message
              : "탐지 이벤트를 불러오지 못했습니다.";

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
        detectorType,
        severity,
        incidentFamily,
        appliedFilter,
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

  const filteredEvents =
    useMemo(() => {
      const keyword =
        searchText
          .trim()
          .toLowerCase();

      if (!keyword) {
        return events;
      }

      return events.filter(
        (event) =>
          normalizeSearchValue(
            event.device_id
          ).includes(keyword) ||
          normalizeSearchValue(
            event.subject_ip
          ).includes(keyword) ||
          normalizeSearchValue(
            event.event_type
          ).includes(keyword) ||
          normalizeSearchValue(
            event.incident_family
          ).includes(keyword) ||
          normalizeSearchValue(
            event.description
          ).includes(keyword) ||
          normalizeSearchValue(
            event.processing_reason
          ).includes(keyword)
      );
    }, [
      events,
      searchText,
    ]);

  const eventSummary =
    useMemo(() => {
      let ruleCount = 0;
      let aiCount = 0;
      let appliedCount = 0;
      let unappliedCount = 0;
      let captureGapCount = 0;
      let highSeverityCount = 0;

      events.forEach((event) => {
        const detectorStatus =
          getDetectorStatus(event);

        if (
          detectorStatus === "rule"
        ) {
          ruleCount += 1;
        }

        if (
          detectorStatus === "ai"
        ) {
          aiCount += 1;
        }

        if (
          isAppliedToScore(
            event.applied_to_score
          )
        ) {
          appliedCount += 1;
        } else {
          unappliedCount += 1;
        }

        if (
          event.processing_reason ===
          "CAPTURE_GAP_UNSCORED"
        ) {
          captureGapCount += 1;
        }

        if (
          String(
            event.severity
          ).toLowerCase() === "high" ||
          String(
            event.severity
          ).toLowerCase() ===
          "critical"
        ) {
          highSeverityCount += 1;
        }
      });

      return {
        ruleCount,
        aiCount,
        appliedCount,
        unappliedCount,
        captureGapCount,
        highSeverityCount,
      };
    }, [events]);

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
    setOffset((currentOffset) =>
      currentOffset +
      DEFAULT_LIMIT
    );
  }

  function handleResetFilters() {
    setSearchText("");
    setDetectorType("");
    setSeverity("");
    setIncidentFamily("");
    setAppliedFilter("");
    setOffset(0);
  }

  function handleFilterChange(
    setter,
    value
  ) {
    setter(value);
    setOffset(0);
  }

  const columns = [
    {
      key: "id",
      header: "ID",
      align: "right",
      width: 70,
    },
    {
      key: "device_id",
      header: "Device",
      width: 130,
      render: (value, event) => (
        <div className="device-cell">
          <span>
            {value || "미매핑"}
          </span>

          {event.subject_ip && (
            <small>
              {event.subject_ip}
            </small>
          )}
        </div>
      ),
    },
    {
      key: "detector_type",
      header: "Detector",
      width: 100,
      render: (_, event) => (
        <StatusBadge
          status={
            getDetectorStatus(
              event
            )
          }
          label={
            event.detector_type ||
            "-"
          }
          size="small"
        />
      ),
    },
    {
      key: "event_type",
      header: "Event Type",
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
      key: "incident_family",
      header: "Incident Family",
      width: 150,
      render: (value) => (
        <StatusBadge
          status={
            value || "unknown"
          }
          label={
            getIncidentFamilyLabel(
              value
            )
          }
          size="small"
        />
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
          label={
            String(
              value || "UNKNOWN"
            ).toUpperCase()
          }
          size="small"
        />
      ),
    },
    {
      key: "score_delta",
      header: "Score Delta",
      align: "right",
      width: 110,
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
      width: 150,
      render: (_, event) => {
        const appliedStatus =
          getAppliedStatus(event);

        return (
          <StatusBadge
            status={
              appliedStatus.status
            }
            label={
              appliedStatus.label
            }
            size="small"
          />
        );
      },
    },
    {
      key: "processing_reason",
      header: "처리 결과",
      width: 190,
      render: (value) => (
        <span
          className={
            value ===
              "CAPTURE_GAP_UNSCORED"
              ? "processing-reason-warning"
              : ""
          }
          title={value || ""}
        >
          {getProcessingReasonLabel(
            value
          )}
        </span>
      ),
    },
    {
      key: "policy_version",
      header: "Policy",
      width: 140,
      render: (value) =>
        value || "-",
    },
    {
      key: "analysis_window_start",
      header: "분석 Window",
      width: 210,
      render: (_, event) => (
        <div className="window-cell">
          <span>
            {formatKST(
              event.analysis_window_start
            )}
          </span>

          <span className="window-separator">
            ~
          </span>

          <span>
            {formatKST(
              event.analysis_window_end
            )}
          </span>
        </div>
      ),
    },
    {
      key: "description",
      header: "Description",
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
      key: "detected_at",
      header: "Detected At",
      width: 180,
      render: (value) =>
        formatKST(value),
    },
    {
      key: "evidence",
      header: "Evidence",
      width: 110,
      render: (_, event) => (
        <button
          type="button"
          className="button button-small button-secondary"
          onClick={(clickEvent) => {
            clickEvent.stopPropagation();
            setSelectedEvent(event);
          }}
        >
          상세보기
        </button>
      ),
    },
  ];

  return (
    <div className="page-container">
      <PageHeader
        title="Detection Events"
        description="Rule 및 AI 탐지 결과와 Trust Score 반영 여부, 근거 Evidence를 확인합니다."
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
              최신 탐지 이벤트 갱신 실패
            </strong>

            <p>
              {pollWarning}
              {" "}
              이전에 조회한 이벤트를
              계속 표시합니다.
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
        events.length > 0 && (
          <section
            className="summary-card-grid"
            aria-label="탐지 이벤트 요약"
          >
            <SummaryCard
              title="전체 이벤트"
              value={formatNumber(
                total,
                0
              )}
              description="현재 조회 조건에 해당하는 전체 이벤트"
            />

            <SummaryCard
              title="Rule 탐지"
              value={formatNumber(
                eventSummary.ruleCount,
                0
              )}
              description="현재 페이지 Rule 기반 탐지"
            />

            <SummaryCard
              title="AI 탐지"
              value={formatNumber(
                eventSummary.aiCount,
                0
              )}
              description="현재 페이지 AI 기반 탐지"
              status="warning"
            />

            <SummaryCard
              title="Trust 반영"
              value={formatNumber(
                eventSummary.appliedCount,
                0
              )}
              description="실제 Trust Score 감점에 사용됨"
              status="danger"
            />

            <SummaryCard
              title="Trust 미반영"
              value={formatNumber(
                eventSummary.unappliedCount,
                0
              )}
              description="보조 증거 또는 정책상 제외"
            />

            <SummaryCard
              title="Capture Gap"
              value={formatNumber(
                eventSummary.captureGapCount,
                0
              )}
              description="Capture Gap으로 Score 미반영"
              status={
                eventSummary.captureGapCount >
                  0
                  ? "warning"
                  : "default"
              }
            />

            <SummaryCard
              title="High 이상"
              value={formatNumber(
                eventSummary.highSeverityCount,
                0
              )}
              description="High 또는 Critical Severity"
              status={
                eventSummary.highSeverityCount >
                  0
                  ? "danger"
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
              서버 Filter와 현재 페이지
              검색을 함께 사용할 수 있습니다.
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

        <div className="filter-grid event-filter-grid">
          <div className="filter-item">
            <label htmlFor="event-search">
              이벤트 검색
            </label>

            <input
              id="event-search"
              type="search"
              placeholder="기기, IP, Event Type, 설명"
              value={searchText}
              onChange={(event) => {
                setSearchText(
                  event.target.value
                );
              }}
            />
          </div>

          <div className="filter-item">
            <label htmlFor="detector-filter">
              Detector
            </label>

            <select
              id="detector-filter"
              value={detectorType}
              onChange={(event) => {
                handleFilterChange(
                  setDetectorType,
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="RULE">
                RULE
              </option>

              <option value="AI">
                AI
              </option>
            </select>
          </div>

          <div className="filter-item">
            <label htmlFor="severity-filter">
              Severity
            </label>

            <select
              id="severity-filter"
              value={severity}
              onChange={(event) => {
                handleFilterChange(
                  setSeverity,
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="critical">
                CRITICAL
              </option>

              <option value="high">
                HIGH
              </option>

              <option value="medium">
                MEDIUM
              </option>

              <option value="low">
                LOW
              </option>
            </select>
          </div>

          <div className="filter-item">
            <label htmlFor="incident-family-filter">
              Incident Family
            </label>

            <select
              id="incident-family-filter"
              value={incidentFamily}
              onChange={(event) => {
                handleFilterChange(
                  setIncidentFamily,
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="FLOODING">
                FLOODING
              </option>

              <option value="SCAN">
                SCAN
              </option>

              <option value="AI_ONLY">
                AI_ONLY
              </option>

              <option value="MALFORMED">
                MALFORMED
              </option>

              <option value="UNKNOWN_DEVICE">
                UNKNOWN_DEVICE
              </option>
            </select>
          </div>

          <div className="filter-item">
            <label htmlFor="applied-filter">
              Trust 반영
            </label>

            <select
              id="applied-filter"
              value={appliedFilter}
              onChange={(event) => {
                handleFilterChange(
                  setAppliedFilter,
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="applied">
                반영
              </option>

              <option value="unapplied">
                미반영
              </option>
            </select>
          </div>
        </div>
      </section>

      <section className="panel packet-table-panel">
        <div className="panel-header">
          <div>
            <h2>
              탐지 이벤트 목록
            </h2>

            <p className="panel-description">
              동일 Window의 Rule 이벤트와
              AI 이벤트는 서로 다른
              Evidence로 저장될 수 있습니다.
            </p>
          </div>

          <span className="data-count">
            {formatNumber(
              filteredEvents.length,
              0
            )}
            건 표시
          </span>
        </div>

        {searchText &&
          !loading &&
          !error &&
          events.length > 0 &&
          filteredEvents.length === 0 ? (
          <EmptyState
            title="검색 조건에 맞는 탐지 이벤트가 없습니다."
            description="현재 페이지에서 다른 기기, IP 또는 Event Type을 검색해 주세요."
            actionLabel="검색 초기화"
            onAction={() =>
              setSearchText("")
            }
          />
        ) : (
          <div className="packet-table-scroll">
            <DataTable
              columns={columns}
              rows={filteredEvents}
              loading={loading}
              error={error}
              onRetry={handleRefresh}
              rowKey="id"
              minWidth={2300}
              tableLabel="탐지 이벤트 목록"
              emptyTitle="표시할 탐지 이벤트가 없습니다."
              emptyDescription="탐지 Worker가 실행 중인지 확인하거나 다른 조회 조건을 선택해 주세요."
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
                  ).toLowerCase() ===
                  "high" ||
                  String(
                    event.severity
                  ).toLowerCase() ===
                  "critical"
                ) {
                  return "table-row-danger";
                }

                if (
                  getDetectorStatus(event) ===
                  "ai"
                ) {
                  return "table-row-ai";
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

      <DetailModal
        open={Boolean(
          selectedEvent
        )}
        title={
          selectedEvent
            ? `Detection Event #${selectedEvent.id}`
            : "Detection Event"
        }
        description={
          selectedEvent
            ? `${selectedEvent.event_type || "-"} · ${selectedEvent.device_id || selectedEvent.subject_ip || "미매핑 대상"}`
            : undefined
        }
        onClose={() =>
          setSelectedEvent(null)
        }
        size="large"
        footer={
          <button
            type="button"
            className="button button-secondary"
            onClick={() =>
              setSelectedEvent(null)
            }
          >
            닫기
          </button>
        }
      >
        {selectedEvent && (
          <div className="event-detail">
            <section className="event-detail-summary">
              <div className="event-detail-item">
                <span>
                  Detector
                </span>

                <StatusBadge
                  status={
                    getDetectorStatus(
                      selectedEvent
                    )
                  }
                  label={
                    selectedEvent.detector_type ||
                    "-"
                  }
                />
              </div>

              <div className="event-detail-item">
                <span>
                  Incident Family
                </span>

                <strong>
                  {getIncidentFamilyLabel(
                    selectedEvent.incident_family
                  )}
                </strong>
              </div>

              <div className="event-detail-item">
                <span>
                  Severity
                </span>

                <StatusBadge
                  status={
                    getSeverityStatus(
                      selectedEvent.severity
                    )
                  }
                  label={String(
                    selectedEvent.severity ||
                    "UNKNOWN"
                  ).toUpperCase()}
                />
              </div>

              <div className="event-detail-item">
                <span>
                  Trust Score
                </span>

                <strong>
                  {formatScoreDelta(
                    selectedEvent.score_delta
                  )}
                </strong>
              </div>

              <div className="event-detail-item">
                <span>
                  Score 반영
                </span>

                <StatusBadge
                  status={
                    getAppliedStatus(
                      selectedEvent
                    ).status
                  }
                  label={
                    getAppliedStatus(
                      selectedEvent
                    ).label
                  }
                />
              </div>

              <div className="event-detail-item">
                <span>
                  Policy Version
                </span>

                <strong>
                  {selectedEvent.policy_version ||
                    "-"}
                </strong>
              </div>
            </section>

            <section className="event-detail-section">
              <h3>처리 정보</h3>

              <dl className="detail-list">
                <div>
                  <dt>
                    Processing Reason
                  </dt>

                  <dd>
                    {getProcessingReasonLabel(
                      selectedEvent.processing_reason
                    )}
                  </dd>
                </div>

                <div>
                  <dt>
                    Evidence Schema
                  </dt>

                  <dd>
                    {selectedEvent.evidence_schema_version ||
                      "-"}
                  </dd>
                </div>

                <div>
                  <dt>
                    Dedupe Key
                  </dt>

                  <dd className="break-word">
                    {selectedEvent.dedupe_key ||
                      "-"}
                  </dd>
                </div>

                <div>
                  <dt>
                    Detected At
                  </dt>

                  <dd>
                    {formatKST(
                      selectedEvent.detected_at
                    )}
                  </dd>
                </div>

                <div>
                  <dt>
                    Processed At
                  </dt>

                  <dd>
                    {formatKST(
                      selectedEvent.processed_at
                    )}
                  </dd>
                </div>
              </dl>
            </section>

            <section className="event-detail-section">
              <h3>분석 Window</h3>

              <div className="event-window-detail">
                <span>
                  {formatKST(
                    selectedEvent.analysis_window_start
                  )}
                </span>

                <span>→</span>

                <span>
                  {formatKST(
                    selectedEvent.analysis_window_end
                  )}
                </span>
              </div>
            </section>

            <section className="event-detail-section">
              <h3>설명</h3>

              <p className="event-description">
                {selectedEvent.description ||
                  "설명이 없습니다."}
              </p>
            </section>

            <section className="event-detail-section">
              <h3>Detection Evidence</h3>

              <JsonViewer
                data={
                  selectedEvent.evidence
                }
              />
            </section>
          </div>
        )}
      </DetailModal>
    </div>
  );
}