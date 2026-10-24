import { uiLabel } from "../utils/uiText";
import {

  useCallback,

  useEffect,

  useMemo,

  useRef,

  useState,

} from "react";

import {

  getEvents,
  getAiWarnings,

} from "../api/api";

import DataTable from "../components/DataTable";

import DetailModal from "../components/DetailModal";

import EmptyState from "../components/EmptyState";

import JsonViewer from "../components/JsonViewer";

import PageHeader from "../components/PageHeader";

import Pagination from "../components/Pagination";

import StatusBadge from "../components/StatusBadge";

import SummaryCard from "../components/SummaryCard";

import "../styles/pages/Events.scss";

const DEFAULT_LIMIT = 20;
const AI_WARNING_LIMIT = 10;

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

      label: "수집 공백 미반영",

    };

  }

  if (isAppliedToScore(

    event.applied_to_score

  )) {

    return {

      status: "scored",

      label: "점수 반영",

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

      "대표 규칙 이벤트",

    AI_SUPPORTING_EVIDENCE:

      "AI 보조 증거",

    CAPTURE_GAP_UNSCORED:

      "수집 공백으로 미반영",

    UNMAPPED_SUBJECT_IP:

      "기기 매핑 없음",

    DUPLICATE_EVENT:

      "중복 이벤트",

    WINDOW_ALREADY_PROCESSED:

      "이미 처리된 분석 구간",

    SCORE_CAP_APPLIED:

      "분석 구간 감점 상한 적용",

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

    IDENTITY: "기기 식별",

    MESSAGE_POLICY: "메시지 정책",

    FLOODING: "트래픽 폭주",

    NETWORK_POLICY: "네트워크 정책",

    SCAN: "포트 스캔",

    AI_ONLY: "AI 단독 이상탐지",

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

  if (normalized === "high") {

    return "high";

  }

  if (normalized === "medium") {

    return "medium";

  }

  if (normalized === "low") {

    return "low";

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

/* Phase 9: AI Warning 스키마의 선택 필드만 표시하며, 누락된 값은 추측하지 않습니다. */
function warningField(item, keys) {
  if (!item || typeof item !== "object") return null;
  for (const key of keys) {
    const value = item[key];
    if (value !== undefined && value !== null && value !== "") return value;
  }
  return null;
}

function warningText(value) {
  if (value === undefined || value === null || value === "") return "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function warningTimestamp(item) {
  return item?.latest_window ?? item?.bucket_start ?? null;
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

  /* Phase 9: 조회 조건이 바뀌면 이전 응답이 새 화면을 덮지 않도록 요청을 구분합니다. */
  const eventsRequestRef = useRef({ id: 0, controller: null, key: "" });
  const eventsLastSuccessKeyRef = useRef("");
  const hasDataRef = useRef(false);

  const [aiWarnings, setAiWarnings] = useState([]);
  const [aiWarningTotal, setAiWarningTotal] = useState(0);
  const [aiWarningOffset, setAiWarningOffset] = useState(0);
  const [aiWarningLoading, setAiWarningLoading] = useState(true);
  const [aiWarningRefreshing, setAiWarningRefreshing] = useState(false);
  const [aiWarningError, setAiWarningError] = useState("");
  const [aiWarningPollWarning, setAiWarningPollWarning] = useState("");
  const [aiWarningUpdatedAt, setAiWarningUpdatedAt] = useState("");
  const [selectedAiWarning, setSelectedAiWarning] = useState(null);
  const aiWarningsRequestRef = useRef({ id: 0, controller: null, key: "" });
  const aiWarningsLastSuccessKeyRef = useRef("");

  const loadData = useCallback(async (isManualRefresh = false) => {
    const queryKey = JSON.stringify({ offset, detectorType, severity, incidentFamily, appliedFilter });
    const previous = eventsRequestRef.current;
    if (!isManualRefresh && previous.controller && !previous.controller.signal.aborted && previous.key === queryKey) return;

    previous.controller?.abort();
    const controller = new AbortController();
    const requestId = previous.id + 1;
    eventsRequestRef.current = { id: requestId, controller, key: queryKey };
    const criteriaChanged = previous.key !== queryKey || eventsLastSuccessKeyRef.current !== queryKey;
    if (criteriaChanged) {
      setLoading(true);
      setEvents([]);
      setTotal(0);
      setError("");
      setPollWarning("");
    }
    if (isManualRefresh) setRefreshing(true);

    try {
      const params = {
        limit: DEFAULT_LIMIT,
        offset,
        detector_type: detectorType || undefined,
        severity: severity || undefined,
        incident_family: incidentFamily || undefined,
      };
      if (appliedFilter === "applied") params.applied_to_score = 1;
      if (appliedFilter === "unapplied") params.applied_to_score = 0;

      const data = await getEvents(params, { signal: controller.signal });
      if (controller.signal.aborted || eventsRequestRef.current.id !== requestId) return;
      if (!Array.isArray(data?.items)) {
        throw new Error("탐지 Events API 응답에 items 목록이 없습니다.");
      }
      const parsedTotal = Number(data?.total);
      setEvents(data.items);
      setTotal(Number.isFinite(parsedTotal) && parsedTotal >= 0 ? parsedTotal : data.items.length);
      setLastUpdated(new Date().toISOString());
      eventsLastSuccessKeyRef.current = queryKey;
      hasDataRef.current = true;
      setError("");
      setPollWarning("");
    } catch (err) {
      if (controller.signal.aborted || err?.isCanceled || eventsRequestRef.current.id !== requestId) return;
      if (IS_DEV) console.error("Detection Events load failed:", err);
      const message = err instanceof Error ? err.message : "탐지 이벤트를 불러오지 못했습니다.";
      if (hasDataRef.current && !criteriaChanged && eventsLastSuccessKeyRef.current === queryKey) {
        setPollWarning(message);
      } else {
        setError(message);
      }
    } finally {
      if (eventsRequestRef.current.id === requestId) {
        eventsRequestRef.current.controller = null;
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, [offset, detectorType, severity, incidentFamily, appliedFilter]);

  /* Phase 9: AI 경고는 Detection Event와 별개로 조회합니다. */
  const loadAiWarnings = useCallback(async (isManualRefresh = false) => {
    const queryKey = String(aiWarningOffset);
    const previous = aiWarningsRequestRef.current;
    if (!isManualRefresh && previous.controller && !previous.controller.signal.aborted && previous.key === queryKey) return;

    previous.controller?.abort();
    const controller = new AbortController();
    const requestId = previous.id + 1;
    aiWarningsRequestRef.current = { id: requestId, controller, key: queryKey };
    const criteriaChanged = previous.key !== queryKey || aiWarningsLastSuccessKeyRef.current !== queryKey;
    if (criteriaChanged) {
      setAiWarningLoading(true);
      setAiWarnings([]);
      setAiWarningTotal(0);
      setAiWarningError("");
      setAiWarningPollWarning("");
    }
    if (isManualRefresh) setAiWarningRefreshing(true);

    try {
      const data = await getAiWarnings(
        { limit: AI_WARNING_LIMIT, offset: aiWarningOffset },
        { signal: controller.signal }
      );
      if (controller.signal.aborted || aiWarningsRequestRef.current.id !== requestId) return;
      const items = Array.isArray(data) ? data : data?.items;
      if (!Array.isArray(items)) {
        throw new Error("AI Warnings API 응답에 목록이 없습니다.");
      }
      const parsedTotal = Number(data?.total);
      setAiWarnings(items.map((item, index) => ({
        ...item,
        __phase9_row_key: String(item?.id ?? item?.warning_id ?? `${aiWarningOffset + index}`),
      })));
      setAiWarningTotal(Number.isFinite(parsedTotal) && parsedTotal >= 0 ? parsedTotal : items.length);
      aiWarningsLastSuccessKeyRef.current = queryKey;
      setAiWarningUpdatedAt(new Date().toISOString());
      setAiWarningError("");
      setAiWarningPollWarning("");
    } catch (err) {
      if (controller.signal.aborted || err?.isCanceled || aiWarningsRequestRef.current.id !== requestId) return;
      if (IS_DEV) console.error("AI Warnings load failed:", err);
      const message = err instanceof Error ? err.message : "AI 경고를 불러오지 못했습니다.";
      if (!criteriaChanged && aiWarningsLastSuccessKeyRef.current === queryKey) {
        setAiWarningPollWarning(message);
      } else {
        setAiWarningError(message);
      }
    } finally {
      if (aiWarningsRequestRef.current.id === requestId) {
        aiWarningsRequestRef.current.controller = null;
        setAiWarningLoading(false);
        setAiWarningRefreshing(false);
      }
    }
  }, [aiWarningOffset]);

  useEffect(() => {
    loadData();
    const timer = window.setInterval(() => loadData(), POLLING_INTERVAL_MS);
    return () => {
      window.clearInterval(timer);
      eventsRequestRef.current.controller?.abort();
    };
  }, [loadData]);

  useEffect(() => {
    loadAiWarnings();
    const timer = window.setInterval(() => loadAiWarnings(), POLLING_INTERVAL_MS);
    return () => {
      window.clearInterval(timer);
      aiWarningsRequestRef.current.controller?.abort();
    };
  }, [loadAiWarnings]);

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

          ).toLowerCase() === "high"

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
    loadAiWarnings(true);
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

  const aiWarningColumns = [
    {
      key: "latest_window",
      header: "최근 분석 시각",
      width: 180,
      render: (_value, warning) => formatKST(warningTimestamp(warning)),
    },
    {
      key: "device_id",
      header: "대상 기기 / IP",
      width: 165,
      render: (_value, warning) => (
        <div className="device-info">
          <span>{warningText(warningField(warning, ["device_id", "target_device_id"]))}</span>
          <small>{warningText(warningField(warning, ["subject_ip", "peer_ip", "source_ip"]))}</small>
        </div>
      ),
    },
    {
      key: "warning_type",
      header: "AI 경고",
      width: 220,
      render: (_value, warning) => (
        <span className="event-name" title={warningText(warningField(warning, ["warning_type", "event_type", "type", "reason"]))}>
          {uiLabel(warningField(warning, ["warning_type", "event_type", "type", "reason"]))}
        </span>
      ),
    },
    {
      key: "count",
      header: "경고 횟수",
      width: 115,
      render: (_value, warning) => warningText(warning.count),
    },
    {
      key: "model_version",
      header: "모델",
      width: 165,
      render: (_value, warning) => (
        <div className="device-info">
          <span>{warningText(warning.detector_name)}</span>
          <small>{warningText(warning.model_version)}</small>
        </div>
      ),
    },
    {
      key: "last_decision",
      header: "처리 상태",
      width: 125,
      render: (_value, warning) => (
        <div className="device-info">
          <span>{uiLabel(warning.last_decision)}</span>
          <small>{warning.closed ? "마감" : "진행 중"} / 억제 {warningText(warning.suppressed_count)}회</small>
        </div>
      ),
    },
  ];

  const columns = [

    {

      key: "detected_at",

      header: "탐지 시각",

      width: 180,

      render: (value) =>

        formatKST(value),

    },

    {

      key: "device_id",

      header: "기기 / 대상 IP",

      width: 170,

      render: (value, event) => (

        <div className="device-info">

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

      header: "탐지 방식",

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

      header: "탐지 유형",

      width: 210,

      render: (value) => (

        <span

          className="event-name"

          title={value || ""}

        >

          {uiLabel(value || "-")}

        </span>

      ),

    },

    {

      key: "incident_family",

      header: "사건 분류",

      width: 160,

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

      header: "심각도",

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

      header: "정책상 점수 변화량",

      align: "right",

      width: 110,

      render: (value) => (

        <span

          className={

            Number(value) < 0

              ? "delta-negative"

              : ""

          }

        >

          {formatScoreDelta(value)}

        </span>

      ),

    },

    {

      key: "applied_to_score",

      header: "신뢰점수 반영",

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

              ? "reason-warning"

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

  ];

  return (

    <div className="events-page">

      <PageHeader

        title="탐지 이벤트"

        description="규칙·AI 탐지 이벤트의 처리 근거와 점수 반영 여부를 확인하고, AI 경고를 별도로 조회합니다."

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

              title="높음"

              value={formatNumber(

                eventSummary.highSeverityCount,

                0

              )}

              description="현재 페이지 심각도 높음"

              status="danger"

            />

            <SummaryCard

              title="규칙 탐지"

              value={formatNumber(

                eventSummary.ruleCount,

                0

              )}

              description="현재 페이지 규칙 기반 탐지"

              status="rule"

            />

            <SummaryCard

              title="AI 이상탐지"

              value={formatNumber(

                eventSummary.aiCount,

                0

              )}

              description="현재 페이지 AI 기반 이상치 탐지"

              status="ai"

            />

            <SummaryCard

              title="신뢰점수 반영"

              value={formatNumber(

                eventSummary.appliedCount,

                0

              )}

              description="현재 페이지에서 점수에 반영된 이벤트"

            />

            <SummaryCard

              title="신뢰점수 미반영"

              status="unknown"

              value={formatNumber(

                eventSummary.unappliedCount,

                0

              )}

              description="보조 증거 또는 정책상 제외"

            />

            <SummaryCard

              title="수집 공백"

              value={formatNumber(

                eventSummary.captureGapCount,

                0

              )}

              description="수집 공백으로 점수 미반영"

              status="warning"

            />

          </section>

        )}

      {/* =====================================================
          Phase 9 - AI Warning (Detection Event와 독립된 근거)
      ===================================================== */}
      <section className="panel table-panel" aria-label="AI 경고">
        <div className="panel-header">
          <div>
            <h2>AI 경고</h2>
            <p className="panel-description">
              AI 이상징후 및 경고 기록입니다. AI 경고는 보조 근거이며,
              경고 발생만으로 신뢰점수 감점이나 자동 격리가 확정되지 않습니다.
            </p>
          </div>
          <button
            type="button"
            className="button button-ghost"
            disabled={aiWarningLoading || aiWarningRefreshing}
            onClick={() => loadAiWarnings(true)}
          >
            AI 경고 새로고침
          </button>
        </div>

        {aiWarningPollWarning && (
          <div className="page-warning-banner" role="alert">
            <div>
              <strong>AI 경고 갱신 실패</strong>
              <p>{aiWarningPollWarning} 마지막 성공 데이터를 표시합니다.</p>
            </div>
          </div>
        )}

        {aiWarningError && (
          <div className="page-warning-banner" role="alert">
            <div>
              <strong>AI 경고 조회 실패</strong>
              <p>{aiWarningError}</p>
            </div>
          </div>
        )}

        {!aiWarningError && (
          <>
            <div className="table-scroll">
              <DataTable
                columns={aiWarningColumns}
                rows={aiWarnings}
                loading={aiWarningLoading && aiWarnings.length === 0}
                rowKey="__phase9_row_key"
                minWidth={970}
                tableLabel="AI 경고 목록"
                emptyTitle="표시할 AI 경고가 없습니다."
                emptyDescription="현재 페이지에 조회된 AI 경고가 없습니다. AI 실행 상태는 별도로 확인해야 합니다."
                onRowClick={setSelectedAiWarning}
              />
            </div>
            {aiWarningTotal > AI_WARNING_LIMIT && (
              <Pagination
                currentPage={Math.floor(aiWarningOffset / AI_WARNING_LIMIT) + 1}
                totalPages={Math.max(1, Math.ceil(aiWarningTotal / AI_WARNING_LIMIT))}
                total={aiWarningTotal}
                pageSize={AI_WARNING_LIMIT}
                disabled={aiWarningLoading || aiWarningRefreshing}
                onPrevious={() => setAiWarningOffset((current) => Math.max(0, current - AI_WARNING_LIMIT))}
                onNext={() => setAiWarningOffset((current) => current + AI_WARNING_LIMIT)}
              />
            )}
            {aiWarningUpdatedAt && (
              <p className="text-muted">AI 경고 최근 성공 조회: {formatKST(aiWarningUpdatedAt)}</p>
            )}
          </>
        )}
      </section>

      <section className="panel">

        <div className="panel-header">

          <div>

            <h2>조회 조건</h2>

            <p className="panel-description">

              서버 필터와 현재 페이지

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

        <div className="filter-grid filters">

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

              탐지 방식

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

                규칙 기반

              </option>

              <option value="AI">

                AI

              </option>

            </select>

          </div>

          <div className="filter-item">

            <label htmlFor="severity-filter">

              심각도

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

              <option value="high">

                높음

              </option>

              <option value="medium">

                보통

              </option>

              <option value="low">

                낮음

              </option>

            </select>

          </div>

          <div className="filter-item">

            <label htmlFor="incident-family-filter">

              사건 분류

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

              <option value="IDENTITY">

                기기 식별

              </option>

              <option value="MESSAGE_POLICY">

                메시지 정책

              </option>

              <option value="FLOODING">

                트래픽 폭주

              </option>

              <option value="NETWORK_POLICY">

                네트워크 정책

              </option>

              <option value="SCAN">

                포트 스캔

              </option>

              <option value="AI_ONLY">

                AI 단독 이상징후

              </option>

            </select>

          </div>

          <div className="filter-item">

            <label htmlFor="applied-filter">

              신뢰점수 반영

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

      <section className="panel table-panel">

        <div className="panel-header">

          <div>

            <h2>

              탐지 이벤트 목록

            </h2>

            <p className="panel-description">

              동일 분석 구간의 규칙 이벤트와

              AI 이벤트는 서로 다른

              근거로 저장될 수 있습니다.

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

          <div className="table-scroll">

            <DataTable

              columns={columns}

              rows={filteredEvents}

              loading={loading}

              error={error}

              onRetry={handleRefresh}

              rowKey="id"

              minWidth={1450}

              tableLabel="탐지 이벤트 목록"

              emptyTitle="표시할 탐지 이벤트가 없습니다."

              emptyDescription="탐지 Worker가 실행 중인지 확인하거나 다른 조회 조건을 선택해 주세요."

              rowClassName={(event) => {

                if (

                  event.processing_reason ===

                  "CAPTURE_GAP_UNSCORED"

                ) {

                  return "row-warning";

                }

                if (

                  String(

                    event.severity

                  ).toLowerCase() === "high"

                ) {

                  return "row-danger";

                }

                if (

                  getDetectorStatus(event) ===

                  "ai"

                ) {

                  return "row-ai";

                }

                return "";

              }}

              onRowClick={setSelectedEvent}

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

            ? `탐지 이벤트 #${selectedEvent.id}`

            : "Detection Event"

        }

        description={

          selectedEvent

            ? `${uiLabel(selectedEvent.event_type) || "-"} · ${selectedEvent.device_id || selectedEvent.subject_ip || "미매핑 대상"}`

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

          <div className="detail">

            <section className="detail-grid">

              <div className="detail-item">

                <span>

                  정책상 점수 변화량

                </span>

                <strong>

                  {formatScoreDelta(

                    selectedEvent.score_delta

                  )}

                </strong>

              </div>

              <div className="detail-item">

                <span>

                  사건 분류

                </span>

                <strong>

                  {getIncidentFamilyLabel(

                    selectedEvent.incident_family

                  )}

                </strong>

              </div>

              <div className="detail-item">

                <span>

                  심각도

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

              <div className="detail-item">
                <span>탐지 방식</span>
                <StatusBadge
                  status={getDetectorStatus(selectedEvent)}
                  label={selectedEvent.detector_type || "UNKNOWN"}
                />
              </div>

              <div className="detail-item">

                <span>

                  점수 반영

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

              <div className="detail-item">

                <span>

                  정책 버전

                </span>

                <strong>

                  {selectedEvent.policy_version ||

                    "-"}

                </strong>

              </div>

            </section>

            <section className="detail-section">

              <h3>처리 정보</h3>

              <dl className="detail-list">

                <div>

                  <dt>

                    처리 사유

                  </dt>

                  <dd>

                    {getProcessingReasonLabel(

                      selectedEvent.processing_reason

                    )}

                  </dd>

                </div>

                <div>

                  <dt>

                    근거 형식 버전

                  </dt>

                  <dd>

                    {selectedEvent.evidence_schema_version ||

                      "-"}

                  </dd>

                </div>

                <div>

                  <dt>

                    중복 판별 키

                  </dt>

                  <dd className="break-word">

                    {selectedEvent.dedupe_key ||

                      "-"}

                  </dd>

                </div>

                <div>

                  <dt>

                    탐지 시각

                  </dt>

                  <dd>

                    {formatKST(

                      selectedEvent.detected_at

                    )}

                  </dd>

                </div>

                <div>

                  <dt>

                    처리 시각

                  </dt>

                  <dd>

                    {formatKST(

                      selectedEvent.processed_at

                    )}

                  </dd>

                </div>

              </dl>

            </section>

            <section className="detail-section">

              <h3>분석 구간</h3>

              <div className="window">

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

            <section className="detail-section">

              <h3>설명</h3>

              <p className="description">

                {selectedEvent.description ||

                  "설명이 없습니다."}

              </p>

            </section>

            {getDetectorStatus(

              selectedEvent

            ) === "ai" && (

                <section className="detail-section">

                  <h3>AI 이상탐지 정보</h3>

                  <p className="text-muted">

                    AI 탐지는 이상치 여부를 판단한

                    결과이며, 공격 유형을 직접

                    분류한 결과가 아닙니다.

                  </p>

                </section>

              )}

            <section className="detail-section">

              <h3>탐지 근거</h3>

              <JsonViewer translateKeys

                data={selectedEvent.evidence}

              />

            </section>

          </div>

        )}

      </DetailModal>

      <DetailModal
        open={Boolean(selectedAiWarning)}
        title="AI 경고 상세"
        description="AI 경고 원본과 분석 근거를 확인합니다. 실제 신뢰점수 반영 여부는 탐지 이벤트 및 신뢰점수 이력에서 검증하세요."
        size="large"
        onClose={() => setSelectedAiWarning(null)}
        footer={
          <button type="button" className="button button-secondary" onClick={() => setSelectedAiWarning(null)}>
            닫기
          </button>
        }
      >
        {selectedAiWarning && (
          <div className="detail">
            <section className="detail-grid">
              <div className="detail-item">
                <span>AI 경고 ID</span>
                <strong>{warningText(warningField(selectedAiWarning, ["id", "warning_id"]))}</strong>
              </div>
              <div className="detail-item">
                <span>대상 기기</span>
                <strong>{warningText(warningField(selectedAiWarning, ["device_id", "target_device_id"]))}</strong>
              </div>
              <div className="detail-item">
                <span>발생 시각</span>
                <strong>{formatKST(warningTimestamp(selectedAiWarning))}</strong>
              </div>
            </section>
            <section className="detail-section">
              <h3>AI 경고 원본 응답</h3>
              <JsonViewer translateKeys data={selectedAiWarning} />
            </section>
          </div>
        )}
      </DetailModal>

    </div>

  );

}
