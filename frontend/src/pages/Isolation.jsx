import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  getFirewallRules,
  getIsolatedDevices,
  getIsolationHistory,
} from "../api/api";

import DataTable from "../components/DataTable";
import DetailModal from "../components/DetailModal";
import EmptyState from "../components/EmptyState";
import PageHeader from "../components/PageHeader";
import Pagination from "../components/Pagination";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";

const DEFAULT_LIMIT = 20;
const POLLING_INTERVAL_MS = 10_000;
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

  return number.toLocaleString("ko-KR", {
    maximumFractionDigits,
  });
}

function normalizeSearchValue(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

/* =========================================================
   Firewall
   ========================================================= */

function getFirewallStatusTheme(status) {
  const normalized = String(status || "")
    .trim()
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

  const normalized = String(status || "")
    .trim()
    .toUpperCase();

  return (
    labels[normalized] ||
    status ||
    "규칙 없음"
  );
}

/*
 * 현재 격리된 Device에는 해당 Device의 최신 Firewall Rule을
 * 연결합니다.
 *
 * 이 Map은 "현재 격리된 기기" 표시에서만 사용합니다.
 * 과거 Isolation History에는 사용하지 않습니다.
 */
function getLatestRuleMap(rules) {
  const ruleMap = new Map();

  rules.forEach((rule) => {
    if (!rule.device_id) {
      return;
    }

    const existingRule =
      ruleMap.get(rule.device_id);

    if (!existingRule) {
      ruleMap.set(
        rule.device_id,
        rule
      );

      return;
    }

    const currentTime = new Date(
      rule.updated_at ||
        rule.created_at ||
        0
    ).getTime();

    const existingTime = new Date(
      existingRule.updated_at ||
        existingRule.created_at ||
        0
    ).getTime();

    if (currentTime > existingTime) {
      ruleMap.set(
        rule.device_id,
        rule
      );
    }
  });

  return ruleMap;
}

/*
 * Isolation History는 같은 Device라는 이유만으로
 * 현재/최신 Firewall Rule을 연결하면 안 됩니다.
 *
 * History.trigger_event_id와
 * FirewallRule.trigger_event_id가 정확히 같은 경우에만
 * 해당 Rule을 연결합니다.
 */
function findFirewallRuleByTriggerEvent(
  rules,
  triggerEventId
) {
  if (
    triggerEventId === null ||
    triggerEventId === undefined ||
    triggerEventId === ""
  ) {
    return null;
  }

  const normalizedTriggerEventId =
    String(triggerEventId);

  return (
    rules.find((rule) => {
      if (
        rule.trigger_event_id === null ||
        rule.trigger_event_id === undefined ||
        rule.trigger_event_id === ""
      ) {
        return false;
      }

      return (
        String(rule.trigger_event_id) ===
        normalizedTriggerEventId
      );
    }) || null
  );
}

/* =========================================================
   Isolation
   ========================================================= */

function getIsolationActionStatus(action) {
  const normalized = String(action || "")
    .trim()
    .toUpperCase();

  if (
    normalized === "ISOLATED" ||
    normalized === "ISOLATE"
  ) {
    return "isolated";
  }

  if (
    normalized === "RELEASED" ||
    normalized === "RELEASE" ||
    normalized === "UNISOLATED"
  ) {
    return "removed";
  }

  return "unknown";
}

function getIsolationActionLabel(action) {
  const normalized = String(action || "")
    .trim()
    .toUpperCase();

  const labels = {
    ISOLATED: "격리",
    ISOLATE: "격리",
    RELEASED: "격리 해제",
    RELEASE: "격리 해제",
    UNISOLATED: "격리 해제",
  };

  return (
    labels[normalized] ||
    action ||
    "-"
  );
}

function getTrustStatus(score) {
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

  const normalized = String(status || "")
    .trim()
    .toLowerCase();

  return (
    labels[normalized] ||
    status ||
    "확인 불가"
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

  const elapsedSeconds = Math.max(
    0,
    Math.floor(
      (Date.now() - timestamp) /
        1000
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

  if (elapsedHours < 24) {
    return `${elapsedHours}시간 전`;
  }

  return `${Math.floor(
    elapsedHours / 24
  )}일 전`;
}

/* =========================================================
   Recovery UI
   ========================================================= */

/*
 * 현재 api.js에는 Recovery Command API가 없습니다.
 *
 * 따라서 여기서는 Recovery 실행 가능 여부를
 * Frontend에서 확정하지 않고 현재 상태만 보여줍니다.
 *
 * 실제 Preflight / approval / execute 결과는
 * Backend Recovery API가 추가된 뒤 연결해야 합니다.
 */
function getRecoveryUiStatus(device) {
  if (!device) {
    return {
      status: "unknown",
      label: "확인 불가",
      description:
        "기기 상태를 확인할 수 없습니다.",
    };
  }

  const trustStatus = String(
    device.status ||
      getTrustStatus(
        device.trust_score
      )
  ).toLowerCase();

  const firewallStatus = String(
    device.firewall_status || ""
  ).toUpperCase();

  if (trustStatus !== "isolated") {
    return {
      status: "unknown",
      label: "대상 아님",
      description:
        "현재 isolated 상태의 기기가 아닙니다.",
    };
  }

  if (firewallStatus === "FAILED") {
    return {
      status: "failed",
      label: "확인 필요",
      description:
        "Firewall 상태가 FAILED입니다. Recovery 실행 전 백엔드 Preflight 확인이 필요합니다.",
    };
  }

  if (firewallStatus === "PENDING") {
    return {
      status: "pending",
      label: "대기 중",
      description:
        "Firewall 적용이 아직 완료되지 않았습니다.",
    };
  }

  if (firewallStatus === "APPLIED") {
    return {
      status: "warning",
      label: "차단 해제 필요",
      description:
        "적용 중인 Firewall Rule을 해제한 뒤 Backend Preflight를 확인해야 합니다.",
    };
  }

  if (!firewallStatus) {
    return {
      status: "unknown",
      label: "확인 필요",
      description:
        "연결된 Firewall Rule을 확인할 수 없습니다.",
    };
  }

  return {
    status: "eligible",
    label: "Recovery 확인 가능",
    description:
      "현재 격리 상태를 확인했습니다. 실제 Recovery 가능 여부는 Backend Preflight 결과를 기준으로 판단해야 합니다.",
  };
}

/* =========================================================
   Page
   ========================================================= */

export default function Isolation() {
  const [history, setHistory] =
    useState([]);

  const [
    isolatedDevices,
    setIsolatedDevices,
  ] = useState([]);

  const [
    firewallRules,
    setFirewallRules,
  ] = useState([]);

  const [total, setTotal] =
    useState(0);

  const [offset, setOffset] =
    useState(0);

  const [
    searchText,
    setSearchText,
  ] = useState("");

  const [
    actionFilter,
    setActionFilter,
  ] = useState("");

  const [
    firewallFilter,
    setFirewallFilter,
  ] = useState("");

  const [
    selectedHistory,
    setSelectedHistory,
  ] = useState(null);

  const [
    selectedIsolatedDevice,
    setSelectedIsolatedDevice,
  ] = useState(null);

  const [loading, setLoading] =
    useState(true);

  const [
    refreshing,
    setRefreshing,
  ] = useState(false);

  const [error, setError] =
    useState("");

  const [
    pollWarning,
    setPollWarning,
  ] = useState("");

  const [
    lastUpdated,
    setLastUpdated,
  ] = useState("");

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
        const [
          historyData,
          isolatedDeviceData,
          firewallData,
        ] = await Promise.all([
          getIsolationHistory({
            limit: DEFAULT_LIMIT,
            offset,
            action:
              actionFilter ||
              undefined,
          }),

          getIsolatedDevices({
            limit: 100,
            offset: 0,
          }),

          getFirewallRules({
            limit: 100,
            offset: 0,
          }),
        ]);

        const historyItems =
          Array.isArray(
            historyData?.items
          )
            ? historyData.items
            : [];

        const deviceItems =
          Array.isArray(
            isolatedDeviceData?.items
          )
            ? isolatedDeviceData.items
            : [];

        const firewallItems =
          Array.isArray(
            firewallData?.items
          )
            ? firewallData.items
            : [];

        const responseTotal =
          Number(historyData?.total);

        setHistory(historyItems);
        setIsolatedDevices(
          deviceItems
        );
        setFirewallRules(
          firewallItems
        );

        setTotal(
          Number.isFinite(
            responseTotal
          )
            ? responseTotal
            : historyItems.length
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
            "Isolation data load failed:",
            err
          );
        }

        const message =
          err instanceof Error
            ? err.message
            : "격리 데이터를 불러오지 못했습니다.";

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
      actionFilter,
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

  /*
   * 현재 격리 Device는 해당 Device의 최신 Firewall Rule을 사용합니다.
   */
  const firewallRuleMap =
    useMemo(
      () =>
        getLatestRuleMap(
          firewallRules
        ),
      [firewallRules]
    );

  const isolatedDevicesWithFirewall =
    useMemo(
      () =>
        isolatedDevices.map(
          (device) => {
            const firewallRule =
              firewallRuleMap.get(
                device.device_id
              ) || null;

            return {
              ...device,

              firewall_status:
                firewallRule?.status ??
                device.firewall_status ??
                null,

              firewall_rule:
                firewallRule,
            };
          }
        ),
      [
        isolatedDevices,
        firewallRuleMap,
      ]
    );

  /*
   * 과거 Isolation History는 Device ID 기준으로
   * 최신 Firewall Rule을 연결하지 않습니다.
   *
   * trigger_event_id가 동일한 Rule만 연결합니다.
   * 일치하는 Rule이 없으면 firewall_rule은 null입니다.
   */
  const historyWithFirewall =
    useMemo(
      () =>
        history.map((item) => {
          const firewallRule =
            findFirewallRuleByTriggerEvent(
              firewallRules,
              item.trigger_event_id
            );

          return {
            ...item,

            firewall_status:
              firewallRule?.status ??
              null,

            firewall_rule:
              firewallRule,
          };
        }),
      [
        history,
        firewallRules,
      ]
    );

  const filteredHistory =
    useMemo(() => {
      const keyword =
        searchText
          .trim()
          .toLowerCase();

      return historyWithFirewall.filter(
        (item) => {
          const matchesSearch =
            !keyword ||
            normalizeSearchValue(
              item.device_id
            ).includes(keyword) ||
            normalizeSearchValue(
              item.reason
            ).includes(keyword) ||
            normalizeSearchValue(
              item.action
            ).includes(keyword) ||
            normalizeSearchValue(
              item.firewall_status
            ).includes(keyword) ||
            normalizeSearchValue(
              item.trigger_event_id
            ).includes(keyword);

          /*
           * api.js의 Mock getIsolationHistory는
           * action filter를 직접 적용하지 않으므로
           * 화면에서도 한 번 더 보정합니다.
           */
          const matchesAction =
            !actionFilter ||
            String(
              item.action || ""
            ).toUpperCase() ===
              actionFilter;

          const matchesFirewall =
            !firewallFilter ||
            String(
              item.firewall_status ||
                ""
            ).toUpperCase() ===
              firewallFilter;

          return (
            matchesSearch &&
            matchesAction &&
            matchesFirewall
          );
        }
      );
    }, [
      historyWithFirewall,
      searchText,
      actionFilter,
      firewallFilter,
    ]);

  const isolationSummary =
    useMemo(() => {
      let applied = 0;
      let pending = 0;
      let failed = 0;
      let missing = 0;

      isolatedDevicesWithFirewall.forEach(
        (device) => {
          const status = String(
            device.firewall_status ||
              ""
          ).toUpperCase();

          if (status === "APPLIED") {
            applied += 1;
          } else if (
            status === "PENDING"
          ) {
            pending += 1;
          } else if (
            status === "FAILED"
          ) {
            failed += 1;
          } else {
            missing += 1;
          }
        }
      );

      return {
        isolated:
          isolatedDevicesWithFirewall.length,
        applied,
        pending,
        failed,
        missing,
      };
    }, [
      isolatedDevicesWithFirewall,
    ]);

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
    setOffset(
      (currentOffset) =>
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

  function handleActionChange(
    value
  ) {
    setActionFilter(value);
    setOffset(0);
  }

  function handleFirewallChange(
    value
  ) {
    setFirewallFilter(value);
  }

  function handleResetFilters() {
    setSearchText("");
    setActionFilter("");
    setFirewallFilter("");
    setOffset(0);
  }

  function closeHistoryDetail() {
    setSelectedHistory(null);
  }

  function closeRecoveryDetail() {
    setSelectedIsolatedDevice(
      null
    );
  }

  /* =========================================================
     Current Isolation Table
     ========================================================= */

  const isolatedDeviceColumns = [
    {
      key: "device_id",
      header: "Device",
      width: 150,
      render: (value) => (
        <strong
          className="device-id-cell"
          title={value || ""}
        >
          {value || "-"}
        </strong>
      ),
    },
    {
      key: "ip_address",
      header: "IP Address",
      width: 140,
      render: (value) =>
        value || "-",
    },
    {
      key: "status",
      header: "Trust 상태",
      width: 120,
      render: (
        value,
        device
      ) => {
        const status = String(
          value ||
            getTrustStatus(
              device.trust_score
            )
        ).toLowerCase();

        return (
          <StatusBadge
            status={status}
            label={getTrustStatusLabel(
              status
            )}
            size="small"
          />
        );
      },
    },
    {
      key: "trust_score",
      header: "Trust Score",
      align: "right",
      width: 120,
      render: (value) => {
        const status =
          getTrustStatus(value);

        return (
          <div className="trust-score-cell">
            <strong>
              {formatNumber(value)}
            </strong>

            <StatusBadge
              status={status}
              label={getTrustStatusLabel(
                status
              )}
              size="small"
            />
          </div>
        );
      },
    },
    {
      key: "firewall_status",
      header: "Firewall 상태",
      width: 140,
      render: (value) => (
        <StatusBadge
          status={getFirewallStatusTheme(
            value
          )}
          label={getFirewallStatusLabel(
            value
          )}
          size="small"
        />
      ),
    },
    {
      key: "last_seen_at",
      header: "마지막 통신",
      width: 190,
      render: (value) => (
        <div className="last-seen-cell">
          <span>
            {formatElapsedTime(
              value
            )}
          </span>

          <small>
            {formatKST(value)}
          </small>
        </div>
      ),
    },
  ];

  /* =========================================================
     Isolation History Table
     ========================================================= */

  const isolationHistoryColumns = [
    {
      key: "id",
      header: "ID",
      align: "right",
      width: 70,
    },
    {
      key: "device_id",
      header: "Device",
      width: 150,
      render: (value) => (
        <strong
          className="device-id-cell"
          title={value || ""}
        >
          {value || "-"}
        </strong>
      ),
    },
    {
      key: "action",
      header: "격리 Action",
      width: 120,
      render: (value) => (
        <StatusBadge
          status={getIsolationActionStatus(
            value
          )}
          label={getIsolationActionLabel(
            value
          )}
          size="small"
        />
      ),
    },
    {
      key: "firewall_status",
      header: "Firewall 상태",
      width: 140,
      render: (value) => (
        <StatusBadge
          status={getFirewallStatusTheme(
            value
          )}
          label={getFirewallStatusLabel(
            value
          )}
          size="small"
        />
      ),
    },
    {
      key: "reason",
      header: "Reason",
      width: 280,
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
      key: "previous_score",
      header: "이전 Score",
      align: "right",
      width: 100,
      render: (
        value,
        item
      ) =>
        formatNumber(
          value ??
            item.trust_score_before
        ),
    },
    {
      key: "new_score",
      header: "변경 Score",
      align: "right",
      width: 100,
      render: (
        value,
        item
      ) =>
        formatNumber(
          value ??
            item.trust_score
        ),
    },
    {
      key: "trust_score_history_id",
      header: "Trust History",
      align: "right",
      width: 120,
      render: (value) =>
        value ?? "-",
    },
    {
      key: "trigger_event_id",
      header: "Trigger Event",
      align: "right",
      width: 120,
      render: (value) =>
        value ?? "-",
    },
    {
      key: "created_at",
      header: "Created At",
      width: 180,
      render: (value) =>
        formatKST(value),
    },
  ];

  const selectedRecoveryStatus =
    getRecoveryUiStatus(
      selectedIsolatedDevice
    );

  return (
    <div className="page-container">
      <PageHeader
        title="Isolation"
        description="Trust Score 기반 격리 판단과 실제 Firewall 차단 적용 상태를 함께 확인합니다."
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
              최신 격리 데이터 갱신 실패
            </strong>

            <p>
              {pollWarning} 이전에 조회한
              격리 데이터를 계속 표시합니다.
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
        !error && (
          <section
            className="summary-card-grid"
            aria-label="격리 상태 요약"
          >
            <SummaryCard
              title="현재 격리"
              value={formatNumber(
                isolationSummary.isolated
              )}
              description="Trust 상태가 isolated인 기기"
              status={
                isolationSummary.isolated >
                0
                  ? "isolated"
                  : "default"
              }
            />

            <SummaryCard
              title="Firewall 적용"
              value={formatNumber(
                isolationSummary.applied
              )}
              description="실제 네트워크 차단 완료"
              status="normal"
            />

            <SummaryCard
              title="적용 대기"
              value={formatNumber(
                isolationSummary.pending
              )}
              description="격리 결정 후 차단 적용 대기"
              status={
                isolationSummary.pending >
                0
                  ? "warning"
                  : "default"
              }
            />

            <SummaryCard
              title="Firewall 실패"
              value={formatNumber(
                isolationSummary.failed
              )}
              description="차단 규칙 적용 실패"
              status={
                isolationSummary.failed >
                0
                  ? "danger"
                  : "default"
              }
            />

            <SummaryCard
              title="Firewall 미확인"
              value={formatNumber(
                isolationSummary.missing
              )}
              description="연결된 Firewall Rule 없음"
              status={
                isolationSummary.missing >
                0
                  ? "warning"
                  : "default"
              }
            />

            <SummaryCard
              title="전체 격리 이력"
              value={formatNumber(
                total
              )}
              description="현재 조회 조건의 전체 기록"
            />
          </section>
        )}

      {/* Current Isolated Devices */}

      <section className="panel packet-table-panel">
        <div className="panel-header">
          <div>
            <h2>
              현재 격리된 기기
            </h2>

            <p className="panel-description">
              행을 선택하면 Trust,
              Firewall 상태와 Recovery
              준비 상태를 확인할 수
              있습니다.
            </p>
          </div>

          <span className="data-count">
            {formatNumber(
              isolatedDevicesWithFirewall.length
            )}
            건
          </span>
        </div>

        <div className="packet-table-scroll">
          <DataTable
            columns={
              isolatedDeviceColumns
            }
            rows={
              isolatedDevicesWithFirewall
            }
            loading={
              loading &&
              isolatedDevices.length ===
                0
            }
            error={
              isolatedDevices.length ===
              0
                ? error
                : ""
            }
            onRetry={handleRefresh}
            rowKey="device_id"
            minWidth={1000}
            tableLabel="현재 격리된 기기"
            emptyTitle="현재 격리된 기기가 없습니다."
            emptyDescription="Trust Score가 격리 기준 아래로 내려간 기기가 없습니다."
            rowClassName={(
              device
            ) => {
              if (
                device.firewall_status ===
                "FAILED"
              ) {
                return "table-row-danger";
              }

              if (
                device.firewall_status ===
                  "PENDING" ||
                !device.firewall_status
              ) {
                return "table-row-warning";
              }

              return "";
            }}
            onRowClick={
              setSelectedIsolatedDevice
            }
          />
        </div>
      </section>

      {/* Isolation History */}

      <section className="panel packet-table-panel">
        <div className="panel-header">
          <div>
            <h2>격리 이력</h2>

            <p className="panel-description">
              행을 선택하면 격리·해제
              판단과 연결된 Trust Score
              History 및 Trigger Event를
              확인할 수 있습니다.
            </p>
          </div>

          <button
            type="button"
            className="button button-ghost"
            onClick={
              handleResetFilters
            }
            disabled={
              loading ||
              refreshing
            }
          >
            필터 초기화
          </button>
        </div>

        <div className="filter-grid">
          <div className="filter-item">
            <label htmlFor="isolation-search">
              이력 검색
            </label>

            <input
              id="isolation-search"
              type="search"
              placeholder="device_id, reason, event ID"
              value={searchText}
              onChange={(event) => {
                setSearchText(
                  event.target.value
                );
              }}
            />
          </div>

          <div className="filter-item">
            <label htmlFor="isolation-action-filter">
              격리 Action
            </label>

            <select
              id="isolation-action-filter"
              value={actionFilter}
              onChange={(event) => {
                handleActionChange(
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="ISOLATED">
                격리
              </option>

              <option value="RELEASED">
                격리 해제
              </option>
            </select>
          </div>

          <div className="filter-item">
            <label htmlFor="firewall-status-filter">
              Firewall 상태
            </label>

            <select
              id="firewall-status-filter"
              value={firewallFilter}
              onChange={(event) => {
                handleFirewallChange(
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="APPLIED">
                차단 적용
              </option>

              <option value="PENDING">
                적용 대기
              </option>

              <option value="FAILED">
                적용 실패
              </option>

              <option value="REMOVED">
                차단 해제
              </option>
            </select>
          </div>
        </div>

        {searchText &&
        !loading &&
        !error &&
        history.length > 0 &&
        filteredHistory.length === 0 ? (
          <EmptyState
            title="검색 조건에 맞는 격리 이력이 없습니다."
            description="다른 Device ID, 사유 또는 Trigger Event ID를 검색해 주세요."
            actionLabel="검색 초기화"
            onAction={() =>
              setSearchText("")
            }
          />
        ) : (
          <div className="packet-table-scroll">
            <DataTable
              columns={
                isolationHistoryColumns
              }
              rows={filteredHistory}
              loading={loading}
              error={error}
              onRetry={handleRefresh}
              rowKey="id"
              minWidth={1450}
              tableLabel="격리 이력"
              emptyTitle="표시할 격리 이력이 없습니다."
              emptyDescription="아직 격리 또는 격리 해제 기록이 생성되지 않았습니다."
              rowClassName={(
                item
              ) => {
                if (
                  item.firewall_status ===
                  "FAILED"
                ) {
                  return "table-row-danger";
                }

                if (
                  item.firewall_status ===
                    "PENDING" ||
                  !item.firewall_status
                ) {
                  return "table-row-warning";
                }

                return "";
              }}
              onRowClick={
                setSelectedHistory
              }
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
              disabled={
                refreshing
              }
            />
          )}
      </section>

      {/* Recovery Detail */}

      <DetailModal
        open={Boolean(
          selectedIsolatedDevice
        )}
        title={
          selectedIsolatedDevice
            ? `${selectedIsolatedDevice.device_id} Recovery`
            : "Recovery"
        }
        description="현재 격리 상태와 Firewall 상태를 확인한 뒤 Recovery를 수행합니다."
        onClose={
          closeRecoveryDetail
        }
        size="large"
        footer={
          <>
            <button
              type="button"
              className="button button-ghost"
              onClick={
                closeRecoveryDetail
              }
            >
              닫기
            </button>

            <button
              type="button"
              className="button"
              disabled
              title="Backend Recovery API 연동 후 활성화됩니다."
            >
              Recovery 실행
            </button>
          </>
        }
      >
        {selectedIsolatedDevice && (
          <div className="isolation-detail">
            <section className="isolation-detail-summary">
              <div className="isolation-detail-item">
                <span>
                  Device ID
                </span>

                <strong>
                  {
                    selectedIsolatedDevice.device_id
                  }
                </strong>
              </div>

              <div className="isolation-detail-item">
                <span>
                  IP Address
                </span>

                <strong>
                  {selectedIsolatedDevice.ip_address ||
                    "-"}
                </strong>
              </div>

              <div className="isolation-detail-item">
                <span>
                  현재 Trust Score
                </span>

                <strong>
                  {formatNumber(
                    selectedIsolatedDevice.trust_score
                  )}
                </strong>
              </div>

              <div className="isolation-detail-item">
                <span>
                  Trust 상태
                </span>

                <StatusBadge
                  status={
                    selectedIsolatedDevice.status ||
                    getTrustStatus(
                      selectedIsolatedDevice.trust_score
                    )
                  }
                  label={getTrustStatusLabel(
                    selectedIsolatedDevice.status ||
                      getTrustStatus(
                        selectedIsolatedDevice.trust_score
                      )
                  )}
                />
              </div>

              <div className="isolation-detail-item">
                <span>
                  Firewall 상태
                </span>

                <StatusBadge
                  status={getFirewallStatusTheme(
                    selectedIsolatedDevice.firewall_status
                  )}
                  label={getFirewallStatusLabel(
                    selectedIsolatedDevice.firewall_status
                  )}
                />
              </div>

              <div className="isolation-detail-item">
                <span>
                  마지막 통신
                </span>

                <strong>
                  {formatKST(
                    selectedIsolatedDevice.last_seen_at
                  )}
                </strong>
              </div>
            </section>

            <section className="isolation-detail-section">
              <h3>
                Recovery 준비 상태
              </h3>

              <div className="detail-list">
                <div>
                  <dt>상태</dt>

                  <dd>
                    <StatusBadge
                      status={
                        selectedRecoveryStatus.status
                      }
                      label={
                        selectedRecoveryStatus.label
                      }
                    />
                  </dd>
                </div>

                <div>
                  <dt>
                    Preflight
                  </dt>

                  <dd>
                    Backend 연동 대기
                  </dd>
                </div>
              </div>

              <p className="text-muted">
                {
                  selectedRecoveryStatus.description
                }
              </p>
            </section>

            {selectedIsolatedDevice.firewall_rule && (
              <section className="isolation-detail-section">
                <h3>
                  현재 Firewall Rule
                </h3>

                <dl className="detail-list">
                  <div>
                    <dt>Rule ID</dt>

                    <dd>
                      {selectedIsolatedDevice.firewall_rule.id ??
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Source IP
                    </dt>

                    <dd>
                      {selectedIsolatedDevice.firewall_rule.source_ip ||
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Protocol
                    </dt>

                    <dd>
                      {selectedIsolatedDevice.firewall_rule.protocol ||
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>Port</dt>

                    <dd>
                      {selectedIsolatedDevice.firewall_rule.dest_port ??
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>Action</dt>

                    <dd>
                      {selectedIsolatedDevice.firewall_rule.action ||
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Retry Count
                    </dt>

                    <dd>
                      {selectedIsolatedDevice.firewall_rule.retry_count ??
                        0}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Last Error
                    </dt>

                    <dd className="break-word">
                      {selectedIsolatedDevice.firewall_rule.last_error ||
                        "-"}
                    </dd>
                  </div>
                </dl>
              </section>
            )}

            <section className="isolation-detail-section">
              <h3>
                Recovery 실행 조건
              </h3>

              <p className="text-muted">
                실제 Recovery 실행 전에는
                Backend의 Preflight 결과와
                운영자 승인 여부를 확인해야
                합니다. 현재 Frontend API
                모듈에는 Recovery Command
                Endpoint가 없어 실행 버튼은
                비활성화되어 있습니다.
              </p>
            </section>
          </div>
        )}
      </DetailModal>

      {/* Isolation History Detail */}

      <DetailModal
        open={Boolean(
          selectedHistory
        )}
        title={
          selectedHistory
            ? `격리 이력 #${selectedHistory.id}`
            : "격리 이력 상세"
        }
        description={
          selectedHistory
            ? `${selectedHistory.device_id || "Device 없음"} · ${getIsolationActionLabel(
                selectedHistory.action
              )}`
            : undefined
        }
        onClose={
          closeHistoryDetail
        }
        size="large"
        footer={
          <button
            type="button"
            className="button button-secondary"
            onClick={
              closeHistoryDetail
            }
          >
            닫기
          </button>
        }
      >
        {selectedHistory && (
          <div className="isolation-detail">
            <section className="isolation-detail-summary">
              <div className="isolation-detail-item">
                <span>
                  Device
                </span>

                <strong>
                  {selectedHistory.device_id ||
                    "-"}
                </strong>
              </div>

              <div className="isolation-detail-item">
                <span>
                  격리 Action
                </span>

                <StatusBadge
                  status={getIsolationActionStatus(
                    selectedHistory.action
                  )}
                  label={getIsolationActionLabel(
                    selectedHistory.action
                  )}
                />
              </div>

              <div className="isolation-detail-item">
                <span>
                  Firewall 상태
                </span>

                <StatusBadge
                  status={getFirewallStatusTheme(
                    selectedHistory.firewall_status
                  )}
                  label={getFirewallStatusLabel(
                    selectedHistory.firewall_status
                  )}
                />
              </div>

              <div className="isolation-detail-item">
                <span>
                  이전 Score
                </span>

                <strong>
                  {formatNumber(
                    selectedHistory.previous_score ??
                      selectedHistory.trust_score_before
                  )}
                </strong>
              </div>

              <div className="isolation-detail-item">
                <span>
                  변경 Score
                </span>

                <strong>
                  {formatNumber(
                    selectedHistory.new_score ??
                      selectedHistory.trust_score
                  )}
                </strong>
              </div>

              <div className="isolation-detail-item">
                <span>
                  Created At
                </span>

                <strong>
                  {formatKST(
                    selectedHistory.created_at
                  )}
                </strong>
              </div>
            </section>

            <section className="isolation-detail-section">
              <h3>격리 근거</h3>

              <dl className="detail-list">
                <div>
                  <dt>
                    Reason
                  </dt>

                  <dd className="break-word">
                    {selectedHistory.reason ||
                      "-"}
                  </dd>
                </div>

                <div>
                  <dt>
                    Trust History ID
                  </dt>

                  <dd>
                    {selectedHistory.trust_score_history_id ??
                      "-"}
                  </dd>
                </div>

                <div>
                  <dt>
                    Trigger Event ID
                  </dt>

                  <dd>
                    {selectedHistory.trigger_event_id ??
                      "-"}
                  </dd>
                </div>
              </dl>
            </section>

            <section className="isolation-detail-section">
              <h3>
                Firewall Rule
              </h3>

              {selectedHistory.firewall_rule ? (
                <dl className="detail-list">
                  <div>
                    <dt>
                      Rule ID
                    </dt>

                    <dd>
                      {selectedHistory.firewall_rule.id ??
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Source IP
                    </dt>

                    <dd>
                      {selectedHistory.firewall_rule.source_ip ||
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Protocol
                    </dt>

                    <dd>
                      {selectedHistory.firewall_rule.protocol ||
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>Port</dt>

                    <dd>
                      {selectedHistory.firewall_rule.dest_port ??
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Action
                    </dt>

                    <dd>
                      {selectedHistory.firewall_rule.action ||
                        "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Retry Count
                    </dt>

                    <dd>
                      {selectedHistory.firewall_rule.retry_count ??
                        0}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Last Error
                    </dt>

                    <dd className="break-word">
                      {selectedHistory.firewall_rule.last_error ||
                        "-"}
                    </dd>
                  </div>
                </dl>
              ) : (
                <EmptyState
                  title="연결된 Firewall Rule이 없습니다."
                  description="이 격리 이력의 Trigger Event ID와 일치하는 Firewall Rule이 없습니다. 다른 Device의 Rule을 임의로 연결하지 않습니다."
                  compact
                />
              )}
            </section>
          </div>
        )}
      </DetailModal>
    </div>
  );
}
