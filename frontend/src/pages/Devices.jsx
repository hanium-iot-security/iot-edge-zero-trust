import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  getDevices,
  getFirewallRules,
  getTrustScoreHistory,
} from "../api/api";

import DataTable from "../components/DataTable";
import DetailModal from "../components/DetailModal";
import EmptyState from "../components/EmptyState";
import ErrorState from "../components/ErrorState";
import LoadingState from "../components/LoadingState";
import PageHeader from "../components/PageHeader";
import Pagination from "../components/Pagination";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";
import {
  LEGACY_KST_OPTIONS,
  elapsedSecondsFromMqttTimestamp,
  formatMqttTimestampKST,
} from "../utils/mqttTimestamp";

import "../styles/pages/Devices.scss"

const DEFAULT_LIMIT = 20;
const POLLING_INTERVAL_MS = 10_000;
const IS_DEV = import.meta.env.DEV;

function formatKST(dateString) {
  return formatMqttTimestampKST(
    dateString,
    LEGACY_KST_OPTIONS,
  );
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

function normalizeSearchValue(value) {
  return String(value ?? "")
    .trim()
    .toLowerCase();
}

function getTrustStatusFromScore(score) {
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

  return (
    labels[
    String(status || "")
      .toLowerCase()
    ] ||
    status ||
    "확인 불가"
  );
}

function getFirewallStatusLabel(status) {
  const labels = {
    PENDING: "적용 대기",
    APPLIED: "차단 적용",
    FAILED: "적용 실패",
    REMOVED: "차단 해제",
  };

  return (
    labels[
    String(status || "")
      .toUpperCase()
    ] ||
    status ||
    "Firewall 기록 없음"
  );
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

function getLastSeenStatus(lastSeenAt) {
  if (!lastSeenAt) {
    return {
      status: "unknown",
      label: "통신 정보 없음",
    };
  }

  const elapsedSeconds =
    elapsedSecondsFromMqttTimestamp(
      lastSeenAt,
      new Date(),
      LEGACY_KST_OPTIONS,
    );

  if (elapsedSeconds === null) {
    return {
      status: "unknown",
      label: "시간 확인 불가",
    };
  }

  if (elapsedSeconds <= 30) {
    return {
      status: "online",
      label: "최근 통신",
    };
  }

  if (elapsedSeconds <= 120) {
    return {
      status: "stale",
      label: "통신 지연",
    };
  }

  return {
    status: "offline",
    label: "장기 미수신",
  };
}

function formatElapsedTime(dateString) {
  if (!dateString) {
    return "-";
  }

  const elapsedSeconds =
    elapsedSecondsFromMqttTimestamp(
      dateString,
      new Date(),
      LEGACY_KST_OPTIONS,
    );

  if (elapsedSeconds === null) {
    return "-";
  }

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

export default function Devices() {
  const [devices, setDevices] =
    useState([]);

  const [firewallRules, setFirewallRules] =
    useState([]);

  const [total, setTotal] =
    useState(0);

  const [offset, setOffset] =
    useState(0);

  const [statusFilter, setStatusFilter] =
    useState("");

  const [searchText, setSearchText] =
    useState("");

  const [
    selectedDevice,
    setSelectedDevice,
  ] = useState(null);

  const [
    trustHistory,
    setTrustHistory,
  ] = useState([]);

  const [
    trustHistoryLoading,
    setTrustHistoryLoading,
  ] = useState(false);

  const [
    trustHistoryError,
    setTrustHistoryError,
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

  const isFetchingRef = useRef(false);
  const hasDataRef = useRef(false);

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
          const [
            deviceData,
            firewallData,
          ] = await Promise.all([
            getDevices({
              limit: DEFAULT_LIMIT,
              offset,
              status:
                statusFilter ||
                undefined,
            }),

            getFirewallRules({
              limit: 100,
              offset: 0,
            }),
          ]);

          const deviceItems =
            Array.isArray(
              deviceData?.items
            )
              ? deviceData.items
              : [];

          const firewallItems =
            Array.isArray(
              firewallData?.items
            )
              ? firewallData.items
              : [];

          const responseTotal =
            Number(deviceData?.total);

          setDevices(deviceItems);

          setFirewallRules(
            firewallItems
          );

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
              "Devices data load failed:",
              err
            );
          }

          const message =
            err instanceof Error
              ? err.message
              : "기기 목록을 불러오지 못했습니다.";

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
        statusFilter,
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

  const firewallRuleMap =
    useMemo(() => {
      const result = new Map();

      firewallRules.forEach(
        (rule) => {
          if (!rule.device_id) {
            return;
          }

          const existingRule =
            result.get(
              rule.device_id
            );

          if (!existingRule) {
            result.set(
              rule.device_id,
              rule
            );

            return;
          }

          const currentTime =
            new Date(
              rule.updated_at ||
              rule.created_at ||
              0
            ).getTime();

          const existingTime =
            new Date(
              existingRule.updated_at ||
              existingRule.created_at ||
              0
            ).getTime();

          if (
            currentTime >
            existingTime
          ) {
            result.set(
              rule.device_id,
              rule
            );
          }
        }
      );

      return result;
    }, [firewallRules]);

  const devicesWithFirewall =
    useMemo(
      () =>
        devices.map((device) => {
          const firewallRule =
            firewallRuleMap.get(
              device.device_id
            );

          return {
            ...device,

            firewall_status:
              firewallRule?.status ??
              device.firewall_status ??
              null,

            firewall_rule:
              firewallRule ?? null,
          };
        }),
      [
        devices,
        firewallRuleMap,
      ]
    );

  const filteredDevices =
    useMemo(() => {
      const keyword =
        searchText
          .trim()
          .toLowerCase();

      if (!keyword) {
        return devicesWithFirewall;
      }

      return devicesWithFirewall.filter(
        (device) =>
          normalizeSearchValue(
            device.device_id
          ).includes(keyword) ||
          normalizeSearchValue(
            device.ip_address
          ).includes(keyword) ||
          normalizeSearchValue(
            device.status
          ).includes(keyword) ||
          normalizeSearchValue(
            device.firewall_status
          ).includes(keyword)
      );
    }, [
      devicesWithFirewall,
      searchText,
    ]);

  const deviceSummary =
    useMemo(() => {
      const summary = {
        normal: 0,
        warning: 0,
        danger: 0,
        isolated: 0,
        firewallApplied: 0,
        firewallPending: 0,
        firewallFailed: 0,
      };

      devicesWithFirewall.forEach(
        (device) => {
          const trustStatus =
            String(
              device.status ||
              getTrustStatusFromScore(
                device.trust_score
              )
            ).toLowerCase();

          if (
            Object.prototype.hasOwnProperty.call(
              summary,
              trustStatus
            )
          ) {
            summary[trustStatus] += 1;
          }

          const firewallStatus =
            String(
              device.firewall_status ||
              ""
            ).toUpperCase();

          if (
            firewallStatus ===
            "APPLIED"
          ) {
            summary.firewallApplied += 1;
          }

          if (
            firewallStatus ===
            "PENDING"
          ) {
            summary.firewallPending += 1;
          }

          if (
            firewallStatus ===
            "FAILED"
          ) {
            summary.firewallFailed += 1;
          }
        }
      );

      return summary;
    }, [devicesWithFirewall]);

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

  async function openDeviceDetail(
    device
  ) {
    setSelectedDevice(device);

    setTrustHistory([]);
    setTrustHistoryError("");
    setTrustHistoryLoading(true);

    try {
      const data =
        await getTrustScoreHistory(
          device.device_id,
          {
            limit: 50,
            offset: 0,
          }
        );

      setTrustHistory(
        Array.isArray(data?.items)
          ? data.items
          : []
      );
    } catch (err) {
      if (IS_DEV) {
        console.error(
          "Trust history load failed:",
          err
        );
      }

      setTrustHistoryError(
        err instanceof Error
          ? err.message
          : "Trust Score 이력을 불러오지 못했습니다."
      );
    } finally {
      setTrustHistoryLoading(false);
    }
  }

  function handleRefresh() {
    loadData(true);
  }

  function handleStatusChange(value) {
    setStatusFilter(value);
    setOffset(0);
  }

  function handleResetFilters() {
    setSearchText("");
    setStatusFilter("");
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
      key: "device_id",
      header: "Device ID",
      width: 150,
      render: (value) => (
        <strong
          className="device-id"
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
      render: (value, device) => {
        const trustStatus =
          value ||
          getTrustStatusFromScore(
            device.trust_score
          );

        return (
          <StatusBadge
            status={trustStatus}
            label={getTrustStatusLabel(
              trustStatus
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
        const trustStatus =
          getTrustStatusFromScore(
            value
          );

        return (
          <div className="score-cell">
            <strong>
              {formatNumber(
                value,
                0
              )}
            </strong>

            <div className="score-bar">
              <div
                className={`score-fill score-${trustStatus}`}
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
      key: "firewall_status",
      header: "Firewall 상태",
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
      header: "마지막 통신",
      width: 190,
      render: (value) => {
        const communicationStatus =
          getLastSeenStatus(value);

        return (
          <div className="last-seen">
            <StatusBadge
              status={
                communicationStatus.status
              }
              label={
                communicationStatus.label
              }
              size="small"
            />

            <span>
              {formatElapsedTime(
                value
              )}
            </span>

            <small>
              {formatKST(value)}
            </small>
          </div>
        );
      },
    },
  ];

  return (
    <div className="devices-page">
      <PageHeader
        title="Devices"
        description="등록 기기의 Trust Score와 Trust 상태, 실제 Firewall 적용 상태를 함께 확인합니다."
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
              최신 기기 상태 갱신 실패
            </strong>

            <p>
              {pollWarning}
              {" "}
              이전 기기 데이터를 계속
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
        devices.length > 0 && (
          <section
            className="summary-card-grid"
            aria-label="기기 상태 요약"
          >
            <SummaryCard
              title="전체 기기"
              value={formatNumber(
                total,
                0
              )}
              description="현재 조회 조건에 해당하는 등록 기기"
            />

            <SummaryCard
              title="정상"
              value={formatNumber(
                deviceSummary.normal,
                0
              )}
              description="Trust Score 80 이상"
              status="normal"
            />

            <SummaryCard
              title="주의"
              value={formatNumber(
                deviceSummary.warning,
                0
              )}
              description="Trust Score 60~79"
              status="warning"
            />

            <SummaryCard
              title="위험"
              value={formatNumber(
                deviceSummary.danger,
                0
              )}
              description="Trust Score 30~59"
              status="danger"
            />

            <SummaryCard
              title="격리"
              value={formatNumber(
                deviceSummary.isolated,
                0
              )}
              description="Trust Score 30 미만"
              status="isolated"
            />

            <SummaryCard
              title="Firewall 적용"
              value={formatNumber(
                deviceSummary.firewallApplied,
                0
              )}
              description="실제 차단 규칙이 적용됨"
              status="normal"
            />

            <SummaryCard
              title="Firewall 대기"
              value={formatNumber(
                deviceSummary.firewallPending,
                0
              )}
              description="차단 적용을 기다리는 상태"
              status="warning"
            />

            <SummaryCard
              title="Firewall 실패"
              value={formatNumber(
                deviceSummary.firewallFailed,
                0
              )}
              description="최대 재시도 후 적용 실패"
              status={
                deviceSummary.firewallFailed >
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
              Trust 상태는 전체 조회에
              적용되고, 검색어는 현재
              페이지 결과에 적용됩니다.
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
            <label htmlFor="device-search">
              기기 또는 IP 검색
            </label>

            <input
              id="device-search"
              type="search"
              placeholder="device_id, IP Address"
              value={searchText}
              onChange={(event) => {
                setSearchText(
                  event.target.value
                );
              }}
            />
          </div>

          <div className="filter-item">
            <label htmlFor="device-status-filter">
              Trust 상태
            </label>

            <select
              id="device-status-filter"
              value={statusFilter}
              onChange={(event) => {
                handleStatusChange(
                  event.target.value
                );
              }}
            >
              <option value="">
                전체
              </option>

              <option value="normal">
                정상
              </option>

              <option value="warning">
                주의
              </option>

              <option value="danger">
                위험
              </option>

              <option value="isolated">
                격리
              </option>
            </select>
          </div>
        </div>
      </section>

      <section className="panel table-panel">
        <div className="panel-header">
          <div>
            <h2>등록 기기 목록</h2>

            <p className="panel-description">
              Trust 상태와 Firewall
              상태는 서로 독립적으로
              표시됩니다.
            </p>
          </div>

          <span className="data-count">
            {formatNumber(
              filteredDevices.length,
              0
            )}
            건 표시
          </span>
        </div>

        {loading &&
          devices.length === 0 ? (
          <LoadingState
            title="기기 목록을 불러오는 중입니다."
            description="Trust Score와 Firewall 상태를 함께 확인하고 있습니다."
          />
        ) : error &&
          devices.length === 0 ? (
          <ErrorState
            title="기기 목록을 불러오지 못했습니다."
            message={error}
            onRetry={handleRefresh}
          />
        ) : searchText &&
          devices.length > 0 &&
          filteredDevices.length === 0 ? (
          <EmptyState
            title="검색 조건에 맞는 기기가 없습니다."
            description="다른 Device ID 또는 IP Address를 검색해 주세요."
            actionLabel="검색 초기화"
            onAction={() =>
              setSearchText("")
            }
          />
        ) : (
          <div className="table-scroll">
            <DataTable
              columns={columns}
              rows={filteredDevices}
              loading={loading}
              error={error}
              onRetry={handleRefresh}
              rowKey="device_id"
              minWidth={1100}
              tableLabel="등록 기기 목록"
              emptyTitle="표시할 등록 기기가 없습니다."
              emptyDescription="기기 Seed 또는 등록 작업이 완료되었는지 확인해 주세요."
              rowClassName={(device) => {
                if (
                  device.firewall_status ===
                  "FAILED"
                ) {
                  return "row-danger";
                }

                if (
                  device.status ===
                  "isolated"
                ) {
                  return "row-warning";
                }

                return "";
              }}
              onRowClick={openDeviceDetail}
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
          selectedDevice
        )}
        title={
          selectedDevice
            ? `${selectedDevice.device_id} 상세 상태`
            : "기기 상세 상태"
        }
        description={
          selectedDevice
            ? `${selectedDevice.ip_address || "IP 없음"} · Trust와 Firewall 상태를 분리해 표시합니다.`
            : undefined
        }
        onClose={() => {
          setSelectedDevice(null);
          setTrustHistory([]);
          setTrustHistoryError("");
        }}
        size="large"
        footer={
          <button
            type="button"
            className="button button-secondary"
            onClick={() => {
              setSelectedDevice(null);
              setTrustHistory([]);
              setTrustHistoryError("");
            }}
          >
            닫기
          </button>
        }
      >
        {selectedDevice && (
          <div className="detail">
            <section className="detail-grid">
              <div className="detail-item">
                <span>Device ID</span>

                <strong>
                  {selectedDevice.device_id}
                </strong>
              </div>

              <div className="detail-item">
                <span>IP Address</span>

                <strong>
                  {selectedDevice.ip_address ||
                    "-"}
                </strong>
              </div>

              <div className="detail-item">
                <span>Trust 상태</span>

                <StatusBadge
                  status={
                    selectedDevice.status ||
                    getTrustStatusFromScore(
                      selectedDevice.trust_score
                    )
                  }
                  label={getTrustStatusLabel(
                    selectedDevice.status ||
                    getTrustStatusFromScore(
                      selectedDevice.trust_score
                    )
                  )}
                />
              </div>

              <div className="detail-item">
                <span>현재 Trust Score</span>

                <strong>
                  {formatNumber(
                    selectedDevice.trust_score,
                    0
                  )}
                </strong>
              </div>

              <div className="detail-item">
                <span>Firewall 상태</span>

                <StatusBadge
                  status={getFirewallStatusTheme(
                    selectedDevice.firewall_status
                  )}
                  label={getFirewallStatusLabel(
                    selectedDevice.firewall_status
                  )}
                />
              </div>

              <div className="detail-item">
                <span>마지막 통신</span>

                <strong>
                  {formatKST(
                    selectedDevice.last_seen_at
                  )}
                </strong>
              </div>
            </section>

            {selectedDevice.firewall_rule && (
              <section className="detail-section">
                <h3>Firewall Rule</h3>

                <dl className="detail-list">
                  <div>
                    <dt>Source IP</dt>

                    <dd>
                      {selectedDevice.firewall_rule
                        .source_ip || "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>Protocol</dt>

                    <dd>
                      {selectedDevice.firewall_rule
                        .protocol || "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>Port</dt>

                    <dd>
                      {selectedDevice.firewall_rule.dest_port ?? "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>Action</dt>

                    <dd>
                      {selectedDevice.firewall_rule
                        .action || "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>Retry Count</dt>

                    <dd>
                      {selectedDevice.firewall_rule
                        .retry_count ?? 0}
                    </dd>
                  </div>

                  <div>
                    <dt>Last Error</dt>

                    <dd className="break-word">
                      {selectedDevice.firewall_rule
                        .last_error ||
                        "-"}
                    </dd>
                  </div>
                </dl>
              </section>
            )}

            <section className="detail-section">
              <div className="section-heading">
                <div>
                  <h3>
                    Trust Score 이력
                  </h3>

                  <p>
                    Frontend에서 Event
                    Delta를 다시 계산하지
                    않고 API의 실제 Score
                    변화값을 표시합니다.
                  </p>
                </div>
              </div>

              {trustHistoryLoading ? (
                <LoadingState
                  title="Trust Score 이력을 불러오는 중입니다."
                  compact
                />
              ) : trustHistoryError ? (
                <ErrorState
                  message={
                    trustHistoryError
                  }
                  onRetry={() =>
                    openDeviceDetail(
                      selectedDevice
                    )
                  }
                  compact
                />
              ) : trustHistory.length ===
                0 ? (
                <EmptyState
                  title="Trust Score 변화 이력이 없습니다."
                  description="현재 기기에 저장된 Trust Window 이력이 없습니다."
                  compact
                />
              ) : (
                <div className="history-list">
                  {trustHistory.map(
                    (history) => (
                      <article
                        className="history-item"
                        key={history.id}
                      >
                        <div className="history-score">
                          <strong>
                            {formatNumber(
                              history.previous_score,
                              0
                            )}
                          </strong>

                          <span>→</span>

                          <strong>
                            {formatNumber(
                              history.new_score,
                              0
                            )}
                          </strong>
                        </div>

                        <div className="history-meta">
                          <StatusBadge
                            status={
                              Number(
                                history.actual_delta
                              ) < 0
                                ? "danger"
                                : "normal"
                            }
                            label={`실제 변화 ${formatScoreDelta(
                              history.actual_delta
                            )}`}
                            size="small"
                          />

                          <span>
                            {formatKST(
                              history.analysis_window_start
                            )}
                          </span>

                          <span>~</span>

                          <span>
                            {formatKST(
                              history.analysis_window_end
                            )}
                          </span>
                        </div>

                        <dl className="history-info">
                          <div>
                            <dt>
                              계산 Delta
                            </dt>

                            <dd>
                              {formatScoreDelta(
                                history.calculated_delta
                              )}
                            </dd>
                          </div>

                          <div>
                            <dt>
                              상한 적용 Delta
                            </dt>

                            <dd>
                              {formatScoreDelta(
                                history.capped_delta
                              )}
                            </dd>
                          </div>

                          <div>
                            <dt>
                              대표 Event
                            </dt>

                            <dd>
                              {Array.isArray(
                                history.representative_event_ids
                              ) &&
                                history.representative_event_ids
                                  .length > 0
                                ? history.representative_event_ids.join(
                                  ", "
                                )
                                : "-"}
                            </dd>
                          </div>

                          <div>
                            <dt>
                              Policy
                            </dt>

                            <dd>
                              {history.policy_version ||
                                "-"}
                            </dd>
                          </div>
                        </dl>
                      </article>
                    )
                  )}
                </div>
              )}
            </section>
          </div>
        )}
      </DetailModal>
    </div>
  );
}
