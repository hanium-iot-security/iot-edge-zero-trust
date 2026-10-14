
import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import {
  createDevice,
  createDevicePolicyRevision,
  createDeviceAiPolicyRevision,
  getDeviceDetail,
  getDevicePolicy,
  getDeviceAiPolicy,
  getAiWarnings,
  getDevices,
  getFirewallRules,
  getTrustScoreHistory,
} from "../api/api";

import DataTable from "../components/DataTable";
import DetailModal from "../components/DetailModal";
import EmptyState from "../components/EmptyState";
import ErrorState from "../components/ErrorState";
import FirewallTrafficFields from "../components/FirewallTrafficFields";
import LoadingState from "../components/LoadingState";
import PageHeader from "../components/PageHeader";
import Pagination from "../components/Pagination";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";

import { getCurrentFirewallRuleMap } from "../utils/firewallRuleSelection";
import {
  LEGACY_KST_OPTIONS,
  elapsedSecondsFromMqttTimestamp,
  formatMqttTimestampKST,
} from "../utils/mqttTimestamp";

import "../styles/pages/Devices.scss";

const LIMIT = 20;
const POLLING_MS = 10000;
const PROFILE = "periodic-sensor-v1";
const DEVICE_TYPES = ["SENSOR", "CAMERA", "ACTUATOR", "OTHER"];

const DEFAULT_POLICY = {
  expected_publish_interval: "5",
  publish_count_max: "15",
  payload_size_max: "5120",
  packet_rate_max: "10",
  byte_rate_max: "2500",
};

const EMPTY_REGISTRATION = {
  device_id: "",
  ip_address: "",
  device_type: "SENSOR",
  mqtt_principal: "",
  reason: "",
  ...DEFAULT_POLICY,
};

const EMPTY_DRAFT = {
  expected_publish_interval: "",
  publish_count_max: "",
  payload_size_max: "",
  packet_rate_max: "",
  byte_rate_max: "",
  registration_state: "",
  reason: "",
};

const EMPTY_POLICY = {
  current: null,
  pending: null,
  latest_revision: null,
  server_time: null,
};

const POLICY_LIMITS = {
  expected_publish_interval: 86400,
  publish_count_max: 10000,
  payload_size_max: 1048576,
  packet_rate_max: 100000,
  byte_rate_max: 125000000,
};

function formatKST(value) {
  return value
    ? formatMqttTimestampKST(value, LEGACY_KST_OPTIONS)
    : "-";
}

function formatNumber(value, digits = 0) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const n = Number(value);
  return Number.isFinite(n)
    ? n.toLocaleString("ko-KR", {
        maximumFractionDigits: digits,
      })
    : "-";
}

function formatDelta(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const n = Number(value);
  return Number.isFinite(n)
    ? n > 0 ? `+${n}` : String(n)
    : "-";
}

function getTrustStatus(score) {
  if (score === null || score === undefined || score === "") {
    return "unknown";
  }
  const n = Number(score);
  if (!Number.isFinite(n)) return "unknown";
  if (n < 30) return "isolated";
  if (n < 60) return "danger";
  if (n < 80) return "warning";
  return "normal";
}

function trustLabel(status) {
  return {
    normal: "정상",
    warning: "주의",
    danger: "위험",
    isolated: "격리",
    unknown: "확인 불가",
  }[String(status || "").toLowerCase()] || "확인 불가";
}

function registrationState(device, policy) {
  return String(
    policy?.registration_state ??
    device?.registration_state ??
    device?.registration_status ??
    ""
  ).toUpperCase();
}

function registrationLabel(state) {
  return {
    ACTIVE: "등록 활성",
    PENDING: "등록 준비 중",
    DISABLED: "관리 비활성",
  }[String(state || "").toUpperCase()] || "확인 불가";
}

function registrationTheme(state) {
  return {
    ACTIVE: "normal",
    PENDING: "pending",
    DISABLED: "removed",
  }[String(state || "").toUpperCase()] || "unknown";
}

function automationLabel(state) {
  return {
    ACTIVE: "자동 대응 적용",
    PENDING: "자동 대응 미적용",
    DISABLED: "자동 대응 중지",
  }[String(state || "").toUpperCase()] || "자동 대응 상태 확인 필요";
}

function firewallLabel(status) {
  return {
    PENDING: "적용 대기",
    APPLIED: "차단 적용",
    FAILED: "적용 실패",
    REMOVED: "차단 해제",
  }[String(status || "").toUpperCase()] || "Firewall 기록 없음";
}

function firewallTheme(status) {
  return {
    PENDING: "pending",
    APPLIED: "applied",
    FAILED: "failed",
    REMOVED: "removed",
  }[String(status || "").toUpperCase()] || "unknown";
}

function lastSeenStatus(value) {
  if (!value) return { status: "unknown", label: "통신 정보 없음" };

  const seconds = elapsedSecondsFromMqttTimestamp(
    value,
    new Date(),
    LEGACY_KST_OPTIONS
  );

  if (seconds === null) {
    return { status: "unknown", label: "시간 확인 불가" };
  }
  if (seconds <= 30) {
    return { status: "online", label: "최근 통신" };
  }
  if (seconds <= 120) {
    return { status: "stale", label: "통신 지연" };
  }
  return { status: "offline", label: "장기 미수신" };
}

function elapsedLabel(value) {
  if (!value) return "-";
  const seconds = elapsedSecondsFromMqttTimestamp(
    value,
    new Date(),
    LEGACY_KST_OPTIONS
  );
  if (seconds === null) return "-";
  if (seconds < 60) return `${seconds}초 전`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}분 전`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}시간 전`;
  return `${Math.floor(seconds / 86400)}일 전`;
}

function normalizePolicy(data) {
  const root = data?.item ?? data ?? {};
  return {
    current: root.current ?? null,
    pending: root.pending ?? null,
    latest_revision: root.latest_revision ?? null,
    server_time: root.server_time ?? null,
  };
}

function policyRevision(info) {
  const n = Number(
    info?.latest_revision ?? info?.current?.revision
  );
  return Number.isSafeInteger(n) && n >= 1 ? n : null;
}

function policyPayload(revision) {
  return revision?.policy ?? revision ?? {};
}

function policyValue(revision, key) {
  const p = policyPayload(revision);
  const aliases = {
    expected_publish_interval: [
      "expected_publish_interval_seconds",
      "expected_publish_interval",
    ],
    publish_count_max: ["publish_count_max"],
    payload_size_max: ["payload_size_max_bytes", "payload_size_max"],
    packet_rate_max: ["packet_rate_max_pps", "packet_rate_max"],
    byte_rate_max: [
      "byte_rate_max_bytes_per_second",
      "byte_rate_max",
    ],
  };
  for (const name of aliases[key] || [key]) {
    if (p[name] !== null && p[name] !== undefined && p[name] !== "") {
      return p[name];
    }
  }
  return null;
}

function draftFromPolicy(revision, device) {
  return {
    expected_publish_interval: String(
      policyValue(revision, "expected_publish_interval") ??
      device?.expected_publish_interval ??
      device?.expected_publish_interval_seconds ??
      ""
    ),
    publish_count_max: String(
      policyValue(revision, "publish_count_max") ?? ""
    ),
    payload_size_max: String(
      policyValue(revision, "payload_size_max") ?? ""
    ),
    packet_rate_max: String(
      policyValue(revision, "packet_rate_max") ?? ""
    ),
    byte_rate_max: String(
      policyValue(revision, "byte_rate_max") ?? ""
    ),
    registration_state: registrationState(device, revision),
    reason: "",
  };
}

function effectiveFrom(revision) {
  return revision?.effective_from ?? revision?.effective_at ?? null;
}

function availableRegistrationStates(state) {
  if (state === "PENDING") return ["PENDING", "ACTIVE", "DISABLED"];
  if (state === "ACTIVE") return ["ACTIVE", "DISABLED"];
  if (state === "DISABLED") return ["DISABLED"];
  return state ? [state] : [];
}

function validatePolicyValues(form) {
  const errors = [];
  const fields = [
    ["expected_publish_interval", "Expected Publish Interval", false],
    ["publish_count_max", "Publish Count Max", true],
    ["payload_size_max", "Payload Size Max", true],
    ["packet_rate_max", "Packet Rate Max", false],
    ["byte_rate_max", "Byte Rate Max", false],
  ];

  for (const [key, label, integer] of fields) {
    const n = Number(form[key]);
    if (
      form[key] === "" ||
      !Number.isFinite(n) ||
      n <= 0 ||
      (integer && !Number.isInteger(n)) ||
      n > POLICY_LIMITS[key]
    ) {
      errors.push(`${label} 값을 확인해 주세요.`);
    }
  }
  return errors;
}

function isPrivateIPv4(value) {
  const parts = String(value || "").split(".");
  if (parts.length !== 4) return false;

  const nums = parts.map(Number);
  if (nums.some((n, i) =>
    !Number.isInteger(n) ||
    n < 0 || n > 255 ||
    String(n) !== parts[i]
  )) return false;

  const [a, b] = nums;
  return a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168);
}

function uncertainError(error) {
  return !error?.status ||
    error.code === "ERR_NETWORK" ||
    error.code === "ECONNABORTED" ||
    error.code === "ETIMEDOUT";
}

function getWarningItems(response) {
  const root = response?.item ?? response;
  if (Array.isArray(root?.items)) return root.items;
  return null;
}

function displayValue(value) {
  if (value === null || value === undefined || value === "") return "-";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

/* =========================================================
   Phase 9 - AI Policy and AI Warnings
========================================================= */

function DeviceAiManagement({ deviceId, registration }) {
  const [policy, setPolicy] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [mode, setMode] = useState("");
  const [reason, setReason] = useState("");
  const [adminKey, setAdminKey] = useState("");
  const [saving, setSaving] = useState(false);
  const [writeError, setWriteError] = useState("");
  const [writeMessage, setWriteMessage] = useState("");
  const [needsVerification, setNeedsVerification] = useState(false);
  const [warnings, setWarnings] = useState([]);
  const [warningTotal, setWarningTotal] = useState(0);
  const [warningOffset, setWarningOffset] = useState(0);
  const [warningsLoading, setWarningsLoading] = useState(true);
  const [warningsError, setWarningsError] = useState("");

  const writeLock = useRef(false);
  const mounted = useRef(false);
  const lastRequest = useRef(0);
  const warningsRequest = useRef(0);
  const draftDirty = useRef(false);
  const LIMIT_WARNINGS = 10;

  const refreshPolicy = useCallback(async (signal) => {
    const id = ++lastRequest.current;
    setLoading(true);
    setError("");

    try {
      const result = await getDeviceAiPolicy(deviceId, { signal });
      if (signal?.aborted || !mounted.current ||
          id !== lastRequest.current) return null;

      const data = normalizePolicy(result);
      setPolicy(data);

      if (!draftDirty.current) {
        setMode(data.current?.mode ?? "");
      }
      return data;
    } catch (err) {
      if (mounted.current && !signal?.aborted &&
          id === lastRequest.current) {
        setError(err?.message || "AI 정책을 조회하지 못했습니다.");
      }
      return null;
    } finally {
      if (mounted.current && id === lastRequest.current) {
        setLoading(false);
      }
    }
  }, [deviceId]);

  const refreshWarnings = useCallback(async (signal) => {
    const id = ++warningsRequest.current;
    setWarningsLoading(true);
    setWarningsError("");

    try {
      const data = await getAiWarnings(
        {
          device_id: deviceId,
          limit: LIMIT_WARNINGS,
          offset: warningOffset,
        },
        { signal }
      );

      if (signal?.aborted || !mounted.current ||
          id !== warningsRequest.current) return;

      const items = getWarningItems(data);
      if (!items) throw new Error("AI 경고 응답 형식을 확인해 주세요.");

      setWarnings(items);
      const root = data?.item ?? data;
      setWarningTotal(
        Number.isFinite(Number(root?.total))
          ? Number(root.total)
          : items.length
      );
    } catch (err) {
      if (mounted.current && !signal?.aborted &&
          id === warningsRequest.current) {
        setWarningsError(err?.message || "AI 경고 조회에 실패했습니다.");
      }
    } finally {
      if (mounted.current && id === warningsRequest.current) {
        setWarningsLoading(false);
      }
    }
  }, [deviceId, warningOffset]);

  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    refreshPolicy(controller.signal);

    return () => {
      mounted.current = false;
      lastRequest.current += 1;
      controller.abort();
    };
  }, [refreshPolicy]);

  useEffect(() => {
    const controller = new AbortController();
    refreshWarnings(controller.signal);

    return () => {
      warningsRequest.current += 1;
      controller.abort();
    };
  }, [refreshWarnings]);

  const current = policy?.current ?? null;
  const pending = policy?.pending ?? null;
  const revision = policyRevision(policy);

  const pendingTime = effectiveFrom(pending);

  useEffect(() => {
    if (!pendingTime || saving) return undefined;

    const time = Date.parse(pendingTime);
    if (!Number.isFinite(time)) return undefined;

    const delay = Math.max(250, time - Date.now() + 750);
    const timer = window.setTimeout(() => refreshPolicy(), delay);
    return () => window.clearTimeout(timer);
  }, [pendingTime, saving, refreshPolicy]);

  async function saveAiPolicy() {
    if (writeLock.current || saving) return;

    if (!current || revision === null) {
      setWriteError("현재 AI 정책 Revision을 확인할 수 없습니다.");
      return;
    }
    if (pending) {
      setWriteError("이미 적용 예정인 AI 정책이 있습니다.");
      return;
    }
    if (!["OFF", "OBSERVE"].includes(mode)) {
      setWriteError("AI 모드는 OFF 또는 OBSERVE만 가능합니다.");
      return;
    }
    if (mode === current.mode) {
      setWriteError("현재와 동일한 AI 모드입니다.");
      return;
    }
    if (!reason.trim() || !adminKey.trim()) {
      setWriteError("변경 사유와 관리자 Key를 모두 입력해 주세요.");
      return;
    }

    writeLock.current = true;
    setSaving(true);
    setWriteError("");
    setWriteMessage("");
    setNeedsVerification(false);

    try {
      await createDeviceAiPolicyRevision(
        deviceId,
        {
          expected_revision: revision,
          mode,
          reason: reason.trim(),
        },
        adminKey
      );

      draftDirty.current = false;
      const updated = await refreshPolicy();

      if (updated) {
        setWriteMessage(
          "AI 정책 변경 요청을 저장하고 현재/예정 상태를 재조회했습니다."
        );
        setReason("");
        setAdminKey("");
      } else {
        setNeedsVerification(true);
        setWriteMessage(
          "저장 응답을 받았지만 서버 재조회 결과는 확인하지 못했습니다."
        );
      }
    } catch (err) {
      if (err?.status === 409) {
        setWriteError("Revision 충돌입니다. 최신 AI 정책을 재조회했습니다.");
        await refreshPolicy();
      } else if (uncertainError(err)) {
        setNeedsVerification(true);
        setWriteMessage(
          "요청 결과가 불확실합니다. 자동 재전송하지 않고 서버 상태를 재조회합니다."
        );
        await refreshPolicy();
      } else {
        setWriteError(err?.message || "AI 정책 저장 실패");
      }
    } finally {
      writeLock.current = false;
      if (mounted.current) setSaving(false);
    }
  }

  return (
    <>
      <section className="detail-section">
        <div className="section-heading">
          <div>
            <h3>AI 정책 관리 (Phase 9)</h3>
            <p>
              기기별 MQTT/Packet 공통 AI 모드를 설정합니다.
              AI 경고만으로 Trust Score 감점이나 격리를 수행하지 않습니다.
            </p>
          </div>
          <button
            type="button"
            className="button button-ghost"
            onClick={() => refreshPolicy()}
            disabled={loading || saving}
          >
            AI 정책 새로고침
          </button>
        </div>

        {loading && !policy ? (
          <LoadingState title="AI 정책 조회 중" compact />
        ) : error && !policy ? (
          <ErrorState
            title="AI 정책 조회 실패"
            message={error}
            onRetry={() => refreshPolicy()}
            compact
          />
        ) : (
          <>
            {error && <p className="inline-error">{error}</p>}

            <div className="policy-state-grid">
              <article className="policy-card">
                <div className="policy-card-header">
                  <strong>현재 AI 정책</strong>
                  <StatusBadge
                    status={current ? "normal" : "unknown"}
                    label={current ? "CURRENT" : "UNKNOWN"}
                    size="small"
                  />
                </div>
                {current ? (
                  <dl className="policy-list">
                    <div><dt>Mode</dt><dd>{displayValue(current.mode)}</dd></div>
                    <div><dt>Revision</dt><dd>{displayValue(current.revision)}</dd></div>
                    <div><dt>Effective From</dt><dd>{formatKST(effectiveFrom(current))}</dd></div>
                    <div><dt>Reason</dt><dd>{displayValue(current.reason)}</dd></div>
                    <div><dt>Created By</dt><dd>{displayValue(current.created_by)}</dd></div>
                  </dl>
                ) : (
                  <p className="text-muted">현재 정책을 확인할 수 없습니다.</p>
                )}
              </article>

              <article className="policy-card">
                <div className="policy-card-header">
                  <strong>적용 예정 AI 정책</strong>
                  <StatusBadge
                    status={pending ? "pending" : "unknown"}
                    label={pending ? "PENDING" : "없음"}
                    size="small"
                  />
                </div>
                {pending ? (
                  <dl className="policy-list">
                    <div><dt>Mode</dt><dd>{displayValue(pending.mode)}</dd></div>
                    <div><dt>Revision</dt><dd>{displayValue(pending.revision)}</dd></div>
                    <div><dt>Effective From</dt><dd>{formatKST(effectiveFrom(pending))}</dd></div>
                    <div><dt>Reason</dt><dd>{displayValue(pending.reason)}</dd></div>
                  </dl>
                ) : (
                  <p className="text-muted">적용 예정 AI 정책이 없습니다.</p>
                )}
              </article>
            </div>

            <h3>AI 모드 변경</h3>
            <div className="policy-form-grid">
              <div className="filter-item">
                <label htmlFor="ai-mode">AI Mode</label>
                <select
                  id="ai-mode"
                  value={mode}
                  onChange={(e) => {
                    draftDirty.current = true;
                    setMode(e.target.value);
                    setWriteError("");
                  }}
                  disabled={saving || !current || Boolean(pending)}
                >
                  <option value="">선택</option>
                  <option value="OFF">OFF</option>
                  <option value="OBSERVE">OBSERVE</option>
                </select>
                <small className="help-text">
                  OBSERVE는 관찰 모드입니다. ENFORCE는 Phase 9 범위 밖입니다.
                </small>
              </div>

              <div className="filter-item">
                <label>현재 Revision</label>
                <div className="readonly-value">
                  {revision ?? "-"}
                </div>
              </div>

              <div className="filter-item full-width">
                <label htmlFor="ai-reason">변경 사유</label>
                <textarea
                  id="ai-reason"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  disabled={saving || !current || Boolean(pending)}
                  placeholder="AI 정책 변경 사유를 입력해 주세요."
                />
              </div>

              <div className="filter-item full-width">
                <label htmlFor="ai-admin-key">Admin Key</label>
                <input
                  id="ai-admin-key"
                  type="password"
                  autoComplete="off"
                  value={adminKey}
                  onChange={(e) => setAdminKey(e.target.value)}
                  disabled={saving}
                  placeholder="관리자 Key 입력"
                />
                <small className="help-text">
                  인증키는 컴포넌트 메모리에만 보관하고 서버 요청 헤더로 전달합니다.
                </small>
              </div>
            </div>

            {registration !== "ACTIVE" && (
              <p className="text-muted">
                등록 상태: {registrationLabel(registration)}.
                실제 정책 변경 가능 여부는 서버 검증 결과를 따릅니다.
              </p>
            )}

            {pending && (
              <div className="verification-box verification-checking">
                <strong>적용 예정 AI 정책 존재</strong>
                <p>현재 변경의 적용 결과가 확인된 후 다음 변경을 진행하세요.</p>
              </div>
            )}

            {writeError && (
              <p className="inline-error" role="alert">{writeError}</p>
            )}

            {writeMessage && (
              <div
                className={
                  needsVerification
                    ? "verification-box verification-checking"
                    : "verification-box verification-checked"
                }
                role="status"
              >
                <strong>
                  {needsVerification ? "결과 확인 필요" : "AI 정책 결과"}
                </strong>
                <p>{writeMessage}</p>
              </div>
            )}

            <button
              type="button"
              className="button"
              disabled={
                saving ||
                loading ||
                !current ||
                Boolean(pending) ||
                needsVerification
              }
              onClick={saveAiPolicy}
            >
              {saving ? "AI 정책 저장 중..." : "AI 정책 변경 저장"}
            </button>
          </>
        )}
      </section>

      <section className="detail-section">
        <div className="section-heading">
          <div>
            <h3>AI 반복 경고</h3>
            <p>
              기기별 AI 관찰 결과입니다.
              Trust 감점 및 Firewall 격리 상태와 별개로 표시합니다.
            </p>
          </div>
          <button
            type="button"
            className="button button-ghost"
            onClick={() => refreshWarnings()}
            disabled={warningsLoading}
          >
            경고 새로고침
          </button>
        </div>

        {warningsLoading ? (
          <LoadingState title="AI 경고 조회 중" compact />
        ) : warningsError ? (
          <ErrorState
            title="AI 경고 조회 실패"
            message={warningsError}
            onRetry={() => refreshWarnings()}
            compact
          />
        ) : warnings.length === 0 ? (
          <EmptyState
            title="조회된 AI 경고가 없습니다."
            description="경고가 없다는 사실만으로 AI 추론이 정상 실행되었다고 판단하지 않습니다."
            compact
          />
        ) : (
          <div className="history-list">
            {warnings.map((warning, index) => (
              <article
                className="history-item"
                key={warning.id ?? `${warningOffset}-${index}`}
              >
                <div className="history-meta">
                  <StatusBadge
                    status="warning"
                    label={displayValue(
                      warning.detector ?? warning.detector_type ?? "AI"
                    )}
                    size="small"
                  />
                  <strong>
                    {displayValue(
                      warning.event_type ??
                      warning.warning_type ??
                      warning.status ??
                      "AI Warning"
                    )}
                  </strong>
                </div>

                <dl className="history-info">
                  <div>
                    <dt>횟수</dt>
                    <dd>{displayValue(
                      warning.count ?? warning.occurrence_count
                    )}</dd>
                  </div>
                  <div>
                    <dt>최초 시각</dt>
                    <dd>{formatKST(
                      warning.first_seen_at ??
                      warning.first_window_start
                    )}</dd>
                  </div>
                  <div>
                    <dt>최근 시각</dt>
                    <dd>{formatKST(
                      warning.last_seen_at ??
                      warning.last_window_start
                    )}</dd>
                  </div>
                  <div>
                    <dt>상태</dt>
                    <dd>{displayValue(warning.status)}</dd>
                  </div>
                  <div>
                    <dt>Alerted</dt>
                    <dd>{displayValue(warning.alerted)}</dd>
                  </div>
                  <div>
                    <dt>Suppressed</dt>
                    <dd>{displayValue(warning.suppressed)}</dd>
                  </div>
                </dl>
              </article>
            ))}
          </div>
        )}

        {warningTotal > LIMIT_WARNINGS && (
          <div className="page-warning-actions">
            <button
              type="button"
              className="button button-secondary"
              disabled={warningOffset === 0 || warningsLoading}
              onClick={() => setWarningOffset((n) =>
                Math.max(0, n - LIMIT_WARNINGS)
              )}
            >
              이전
            </button>

            <span>
              {warningOffset + 1}~
              {Math.min(warningOffset + LIMIT_WARNINGS, warningTotal)}
              {" / "}
              {warningTotal}
            </span>

            <button
              type="button"
              className="button button-secondary"
              disabled={
                warningsLoading ||
                warningOffset + LIMIT_WARNINGS >= warningTotal
              }
              onClick={() => setWarningOffset((n) => n + LIMIT_WARNINGS)}
            >
              다음
            </button>
          </div>
        )}
      </section>
    </>
  );
}

/* =========================================================
   Devices Main Page
========================================================= */

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [firewallRules, setFirewallRules] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [searchText, setSearchText] = useState("");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [pollWarning, setPollWarning] = useState("");
  const [lastUpdated, setLastUpdated] = useState("");

  const [selectedDevice, setSelectedDevice] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState("");
  const [trustHistory, setTrustHistory] = useState([]);
  const [trustLoading, setTrustLoading] = useState(false);
  const [trustError, setTrustError] = useState("");

  const [policyInfo, setPolicyInfo] = useState(EMPTY_POLICY);
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyError, setPolicyError] = useState("");
  const [policyDraft, setPolicyDraft] = useState(EMPTY_DRAFT);
  const [policyKey, setPolicyKey] = useState("");
  const [policySaving, setPolicySaving] = useState(false);
  const [policyWriteError, setPolicyWriteError] = useState("");
  const [policyMessage, setPolicyMessage] = useState("");
  const [policyVerify, setPolicyVerify] = useState(false);

  const [registrationOpen, setRegistrationOpen] = useState(false);
  const [registration, setRegistration] = useState(EMPTY_REGISTRATION);
  const [registrationKey, setRegistrationKey] = useState("");
  const [registrationSaving, setRegistrationSaving] = useState(false);
  const [registrationError, setRegistrationError] = useState("");
  const [registrationMessage, setRegistrationMessage] = useState("");
  const [registrationVerify, setRegistrationVerify] = useState(false);

  const hasDataRef = useRef(false);
  const listIdRef = useRef(0);
  const listControllerRef = useRef(null);
  const detailIdRef = useRef(0);
  const detailControllerRef = useRef(null);
  const policyDraftDirty = useRef(false);
  const registrationLock = useRef(false);
  const policyLock = useRef(false);

  const loadData = useCallback(async (manual = false) => {
    listControllerRef.current?.abort();
    const controller = new AbortController();
    listControllerRef.current = controller;
    const id = ++listIdRef.current;

    if (manual) setRefreshing(true);

    try {
      const [devicesResponse, firewallResponse] = await Promise.all([
        getDevices(
          {
            limit: LIMIT,
            offset,
            status: statusFilter || undefined,
          },
          { signal: controller.signal }
        ),
        getFirewallRules(
          { limit: 100, offset: 0 },
          { signal: controller.signal }
        ),
      ]);

      if (controller.signal.aborted || id !== listIdRef.current) return;

      const deviceItems = Array.isArray(devicesResponse?.items)
        ? devicesResponse.items : [];
      const ruleItems = Array.isArray(firewallResponse?.items)
        ? firewallResponse.items : [];

      setDevices(deviceItems);
      setFirewallRules(ruleItems);
      setTotal(
        Number.isFinite(Number(devicesResponse?.total))
          ? Number(devicesResponse.total)
          : deviceItems.length
      );
      setLastUpdated(new Date().toISOString());
      setError("");
      setPollWarning("");
      hasDataRef.current = true;
    } catch (err) {
      if (controller.signal.aborted || err?.isCanceled ||
          id !== listIdRef.current) return;

      const message = err?.message || "기기 목록 조회 실패";
      if (hasDataRef.current) setPollWarning(message);
      else setError(message);
    } finally {
      if (id === listIdRef.current) {
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, [offset, statusFilter]);

  useEffect(() => {
    loadData();
    const timer = window.setInterval(() => loadData(), POLLING_MS);
    return () => {
      window.clearInterval(timer);
      listControllerRef.current?.abort();
    };
  }, [loadData]);

  useEffect(() => {
    return () => detailControllerRef.current?.abort();
  }, []);

  const firewallMap = useMemo(
    () => getCurrentFirewallRuleMap(firewallRules),
    [firewallRules]
  );

  const rows = useMemo(() => devices.map((device) => {
    const rule = firewallMap.get(device.device_id);
    return {
      ...device,
      firewall_status: rule?.status ?? device.firewall_status ?? null,
      firewall_rule: rule ?? null,
    };
  }), [devices, firewallMap]);

  const filteredRows = useMemo(() => {
    const keyword = searchText.trim().toLowerCase();
    if (!keyword) return rows;
    return rows.filter((device) =>
      [
        device.device_id,
        device.ip_address,
        device.status,
        device.registration_state,
        device.firewall_status,
      ].some((value) =>
        String(value ?? "").toLowerCase().includes(keyword)
      )
    );
  }, [rows, searchText]);

  const summary = useMemo(() => {
    const result = {
      normal: 0, warning: 0, danger: 0, isolated: 0,
      registrationPending: 0, registrationActive: 0,
      registrationDisabled: 0, registrationUnknown: 0,
      firewallApplied: 0, firewallPending: 0, firewallFailed: 0,
    };

    rows.forEach((device) => {
      const trust = String(
        device.status || getTrustStatus(device.trust_score)
      ).toLowerCase();

      if (Object.hasOwn(result, trust)) result[trust] += 1;

      const registration = registrationState(device);
      if (registration === "PENDING") result.registrationPending++;
      else if (registration === "ACTIVE") result.registrationActive++;
      else if (registration === "DISABLED") result.registrationDisabled++;
      else result.registrationUnknown++;

      const firewall = String(device.firewall_status || "").toUpperCase();
      if (firewall === "APPLIED") result.firewallApplied++;
      else if (firewall === "PENDING") result.firewallPending++;
      else if (firewall === "FAILED") result.firewallFailed++;
    });

    return result;
  }, [rows]);

  const currentPolicy = policyInfo.current;
  const pendingPolicy = policyInfo.pending;
  const currentRegistration = registrationState(
    selectedDevice, currentPolicy
  );

  const refreshPolicy = useCallback(async (
    deviceId,
    preserveDraft = true
  ) => {
    setPolicyLoading(true);
    setPolicyError("");

    try {
      const [detailResult, policyResult] = await Promise.allSettled([
        getDeviceDetail(deviceId),
        getDevicePolicy(deviceId),
      ]);

      const latestDevice = detailResult.status === "fulfilled"
        ? detailResult.value?.item ?? detailResult.value
        : null;

      if (latestDevice) {
        setSelectedDevice((prev) =>
          prev?.device_id === deviceId
            ? { ...prev, ...latestDevice }
            : prev
        );
      }

      if (policyResult.status !== "fulfilled") {
        throw policyResult.reason;
      }

      const data = normalizePolicy(policyResult.value);
      setPolicyInfo(data);

      if (!preserveDraft || !policyDraftDirty.current) {
        setPolicyDraft(
          draftFromPolicy(data.current, latestDevice)
        );
        policyDraftDirty.current = false;
      }

      return data;
    } catch (err) {
      setPolicyError(err?.message || "Rule 정책 조회 실패");
      return null;
    } finally {
      setPolicyLoading(false);
    }
  }, []);

  async function openDetail(device) {
    if (!device?.device_id || policySaving) return;

    detailControllerRef.current?.abort();
    const controller = new AbortController();
    detailControllerRef.current = controller;
    const id = ++detailIdRef.current;
    const deviceId = device.device_id;

    setSelectedDevice(device);
    setDetailLoading(true);
    setDetailError("");
    setTrustHistory([]);
    setTrustLoading(true);
    setTrustError("");
    setPolicyInfo(EMPTY_POLICY);
    setPolicyLoading(true);
    setPolicyError("");
    setPolicyDraft(EMPTY_DRAFT);
    policyDraftDirty.current = false;
    setPolicyKey("");
    setPolicyWriteError("");
    setPolicyMessage("");
    setPolicyVerify(false);

    const results = await Promise.allSettled([
      getDeviceDetail(deviceId, { signal: controller.signal }),
      getFirewallRules(
        { device_id: deviceId, limit: 100, offset: 0 },
        { signal: controller.signal }
      ),
      getTrustScoreHistory(
        deviceId, { limit: 50, offset: 0 },
        { signal: controller.signal }
      ),
      getDevicePolicy(deviceId, { signal: controller.signal }),
    ]);

    if (controller.signal.aborted || id !== detailIdRef.current) {
      return;
    }

    const [detail, firewall, history, rulePolicy] = results;
    let latestDevice = device;

    if (detail.status === "fulfilled") {
      latestDevice = detail.value?.item ?? detail.value ?? device;
    } else {
      setDetailError(detail.reason?.message || "기기 상세 조회 실패");
    }

    if (firewall.status === "fulfilled") {
      const rules = Array.isArray(firewall.value?.items)
        ? firewall.value.items : [];
      const current = getCurrentFirewallRuleMap(rules).get(deviceId);
      latestDevice = {
        ...latestDevice,
        firewall_rule: current ?? null,
        firewall_status: current?.status ??
          latestDevice.firewall_status ?? null,
      };
    } else {
      setDetailError((prev) =>
        prev || firewall.reason?.message || "Firewall 조회 실패"
      );
    }

    setSelectedDevice(latestDevice);

    if (history.status === "fulfilled") {
      setTrustHistory(
        Array.isArray(history.value?.items) ? history.value.items : []
      );
    } else {
      setTrustError(history.reason?.message || "Trust 이력 조회 실패");
    }

    if (rulePolicy.status === "fulfilled") {
      const data = normalizePolicy(rulePolicy.value);
      setPolicyInfo(data);
      setPolicyDraft(draftFromPolicy(data.current, latestDevice));
    } else {
      setPolicyError(rulePolicy.reason?.message || "Rule 정책 조회 실패");
    }

    setDetailLoading(false);
    setTrustLoading(false);
    setPolicyLoading(false);
  }

  function closeDetail() {
    if (policySaving) return;
    detailIdRef.current++;
    detailControllerRef.current?.abort();
    setSelectedDevice(null);
    setPolicyKey("");
    setPolicyInfo(EMPTY_POLICY);
    setPolicyDraft(EMPTY_DRAFT);
    setPolicyWriteError("");
    setPolicyMessage("");
    setTrustHistory([]);
  }

  function registrationField(key, value) {
    setRegistration((prev) => ({ ...prev, [key]: value }));
  }

  function policyField(key, value) {
    policyDraftDirty.current = true;
    setPolicyDraft((prev) => ({ ...prev, [key]: value }));
    setPolicyWriteError("");
    setPolicyMessage("");
  }

  async function saveRegistration() {
    if (registrationLock.current) return;

    const errors = validatePolicyValues(registration);
    if (!/^[A-Za-z0-9._-]{1,64}$/.test(registration.device_id.trim())) {
      errors.push("Device ID는 64자 이하의 영문, 숫자, ., _, -만 가능합니다.");
    }
    if (!isPrivateIPv4(registration.ip_address)) {
      errors.push("고정 IP는 RFC1918 사설 IPv4여야 합니다.");
    }
    if (!DEVICE_TYPES.includes(registration.device_type)) {
      errors.push("Device Type을 확인해 주세요.");
    }
    if (!registration.mqtt_principal.trim()) {
      errors.push("MQTT Principal이 필요합니다.");
    }
    if (!registration.reason.trim() || !registrationKey.trim()) {
      errors.push("등록 사유와 관리자 Key가 필요합니다.");
    }

    if (errors.length) {
      setRegistrationError(errors.join(" "));
      return;
    }

    const payload = {
      device_id: registration.device_id.trim(),
      ip_address: registration.ip_address.trim(),
      device_type: registration.device_type,
      mqtt_principal: registration.mqtt_principal.trim(),
      reason: registration.reason.trim(),
      policy: {
        policy_profile: PROFILE,
        expected_publish_interval_seconds:
          Number(registration.expected_publish_interval),
        publish_count_max: Number(registration.publish_count_max),
        payload_size_max_bytes: Number(registration.payload_size_max),
        packet_rate_max_pps: Number(registration.packet_rate_max),
        byte_rate_max_bytes_per_second:
          Number(registration.byte_rate_max),
      },
    };

    registrationLock.current = true;
    setRegistrationSaving(true);
    setRegistrationError("");
    setRegistrationMessage("");
    setRegistrationVerify(false);

    try {
      await createDevice(payload, registrationKey);
      const checked = await Promise.allSettled([
        getDeviceDetail(payload.device_id),
        getDevicePolicy(payload.device_id),
      ]);
      const verified = checked.some((r) => r.status === "fulfilled");

      setRegistrationVerify(!verified);
      setRegistrationMessage(
        verified
          ? "기기 등록 후 서버 재조회까지 완료했습니다."
          : "등록 응답은 받았지만 서버 재조회에 실패했습니다."
      );
      setRegistrationKey("");
      await loadData(true);
    } catch (err) {
      if (uncertainError(err)) {
        setRegistrationVerify(true);
        setRegistrationMessage(
          "등록 결과가 불확실합니다. 자동 재전송하지 말고 서버 상태를 확인하세요."
        );
        await loadData(true);
      } else {
        setRegistrationError(err?.message || "기기 등록 실패");
      }
    } finally {
      registrationLock.current = false;
      setRegistrationSaving(false);
    }
  }

  async function saveRulePolicy() {
    if (policyLock.current || !selectedDevice?.device_id) return;

    const errors = validatePolicyValues(policyDraft);
    const revision = policyRevision(policyInfo);

    if (!policyDraft.registration_state) {
      errors.push("등록 상태가 필요합니다.");
    }
    if (!policyDraft.reason.trim() || !policyKey.trim()) {
      errors.push("변경 사유와 관리자 Key가 필요합니다.");
    }
    if (revision === null) errors.push("현재 Revision이 없습니다.");
    if (pendingPolicy) errors.push("적용 예정 정책이 존재합니다.");

    if (errors.length) {
      setPolicyWriteError(errors.join(" "));
      return;
    }

    const deviceId = selectedDevice.device_id;
    const payload = {
      expected_revision: revision,
      registration_state: policyDraft.registration_state,
      reason: policyDraft.reason.trim(),
      policy: {
        policy_profile:
          policyPayload(currentPolicy).policy_profile ?? PROFILE,
        expected_publish_interval_seconds:
          Number(policyDraft.expected_publish_interval),
        publish_count_max: Number(policyDraft.publish_count_max),
        payload_size_max_bytes: Number(policyDraft.payload_size_max),
        packet_rate_max_pps: Number(policyDraft.packet_rate_max),
        byte_rate_max_bytes_per_second:
          Number(policyDraft.byte_rate_max),
      },
    };

    policyLock.current = true;
    setPolicySaving(true);
    setPolicyWriteError("");
    setPolicyMessage("");
    setPolicyVerify(false);

    try {
      await createDevicePolicyRevision(deviceId, payload, policyKey);
      const checked = await refreshPolicy(deviceId, false);
      setPolicyVerify(!checked);
      setPolicyMessage(
        checked
          ? "Rule 정책 변경 요청을 저장하고 서버에서 재조회했습니다."
          : "변경 응답은 받았지만 서버 재조회에 실패했습니다."
      );
      setPolicyKey("");
      await loadData(true);
    } catch (err) {
      if (err?.status === 409) {
        setPolicyWriteError("Revision 충돌입니다. 서버 정책을 다시 조회했습니다.");
        await refreshPolicy(deviceId, true);
      } else if (uncertainError(err)) {
        setPolicyVerify(true);
        setPolicyMessage(
          "정책 변경 결과가 불확실합니다. 자동 재전송하지 않고 재조회합니다."
        );
        await refreshPolicy(deviceId, true);
      } else {
        setPolicyWriteError(err?.message || "Rule 정책 변경 실패");
      }
    } finally {
      policyLock.current = false;
      setPolicySaving(false);
    }
  }

  const pendingTime = effectiveFrom(pendingPolicy);

  useEffect(() => {
    if (!selectedDevice?.device_id || !pendingTime) return undefined;
    const time = Date.parse(pendingTime);
    if (!Number.isFinite(time)) return undefined;

    const timer = window.setTimeout(() => {
      refreshPolicy(selectedDevice.device_id, true);
      loadData(true);
    }, Math.max(250, time - Date.now() + 750));

    return () => window.clearTimeout(timer);
  }, [selectedDevice?.device_id, pendingTime, refreshPolicy, loadData]);

  const columns = [
    {
      key: "device_id",
      header: "Device ID",
      width: 150,
      render: (value) => (
        <strong className="device-id" title={value || ""}>
          {value || "-"}
        </strong>
      ),
    },
    {
      key: "ip_address",
      header: "IP Address",
      width: 140,
      render: (value) => value || "-",
    },
    {
      key: "registration_state",
      header: "등록 상태",
      width: 140,
      render: (value, device) => {
        const state = value || registrationState(device);
        return (
          <div className="registration-cell">
            <StatusBadge
              status={registrationTheme(state)}
              label={registrationLabel(state)}
              size="small"
            />
            <small>{automationLabel(state)}</small>
          </div>
        );
      },
    },
    {
      key: "status",
      header: "Trust 상태",
      width: 120,
      render: (value, device) => {
        const status = value || getTrustStatus(device.trust_score);
        return (
          <StatusBadge
            status={status}
            label={trustLabel(status)}
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
      render: (value) => (
        <div className="score-cell">
          <strong>{formatNumber(value)}</strong>
          <div className="score-bar">
            <div
              className={`score-fill score-${getTrustStatus(value)}`}
              style={{
                width: `${value == null
                  ? 0
                  : Math.min(100, Math.max(0, Number(value) || 0))}%`,
              }}
            />
          </div>
        </div>
      ),
    },
    {
      key: "firewall_status",
      header: "Firewall 상태",
      width: 140,
      render: (value) => (
        <StatusBadge
          status={firewallTheme(value)}
          label={firewallLabel(value)}
          size="small"
        />
      ),
    },
    {
      key: "last_seen_at",
      header: "마지막 통신",
      width: 190,
      render: (value) => {
        const state = lastSeenStatus(value);
        return (
          <div className="last-seen">
            <StatusBadge status={state.status} label={state.label} size="small" />
            <span>{elapsedLabel(value)}</span>
            <small>{formatKST(value)}</small>
          </div>
        );
      },
    },
  ];

  const page = Math.floor(offset / LIMIT) + 1;
  const pages = Math.max(1, Math.ceil(total / LIMIT));

  return (
    <div className="devices-page">
      <PageHeader
        title="Devices"
        description="기기 등록, Rule 정책, AI 관찰 정책, Trust Score 및 Firewall 상태를 분리해 관리합니다."
        updatedAt={lastUpdated ? formatKST(lastUpdated) : undefined}
        onRefresh={() => loadData(true)}
        refreshing={refreshing}
      />

      <section className="device-admin-bar">
        <div>
          <strong>Device Administration</strong>
          <p>
            신규 기기는 PENDING으로 등록됩니다.
            AI OBSERVE 경고는 단독으로 자동 감점·격리를 실행하지 않습니다.
          </p>
        </div>
        <button
          type="button"
          className="button"
          onClick={() => {
            setRegistration(EMPTY_REGISTRATION);
            setRegistrationKey("");
            setRegistrationError("");
            setRegistrationMessage("");
            setRegistrationVerify(false);
            setRegistrationOpen(true);
          }}
        >
          + 기기 등록
        </button>
      </section>

      {pollWarning && (
        <div className="page-warning-banner" role="alert">
          <div>
            <strong>최신 기기 상태 갱신 실패</strong>
            <p>{pollWarning} 이전 데이터를 표시하고 있습니다.</p>
          </div>
          <button
            type="button"
            className="button button-secondary"
            onClick={() => loadData(true)}
          >
            다시 시도
          </button>
        </div>
      )}

      {!loading && !error && rows.length > 0 && (
        <>
          <section className="summary-card-grid">
            <SummaryCard title="등록 준비" value={summary.registrationPending} description="PENDING" status="warning" />
            <SummaryCard title="등록 활성" value={summary.registrationActive} description="ACTIVE" status="normal" />
            <SummaryCard title="관리 비활성" value={summary.registrationDisabled} description="DISABLED" />
            <SummaryCard title="상태 확인 불가" value={summary.registrationUnknown} description="Migration/backfill 확인" />
          </section>
          <section className="summary-card-grid">
            <SummaryCard title="전체 기기" value={total} description="현재 필터 기준" />
            <SummaryCard title="정상" value={summary.normal} status="normal" />
            <SummaryCard title="주의" value={summary.warning} status="warning" />
            <SummaryCard title="위험" value={summary.danger} status="danger" />
            <SummaryCard title="격리" value={summary.isolated} status="isolated" />
            <SummaryCard title="Firewall 적용" value={summary.firewallApplied} status="normal" />
            <SummaryCard title="Firewall 대기" value={summary.firewallPending} status="warning" />
            <SummaryCard title="Firewall 실패" value={summary.firewallFailed} status="danger" />
          </section>
        </>
      )}

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>조회 조건</h2>
            <p className="panel-description">
              Trust 상태는 서버 필터, 검색어는 현재 페이지에 적용됩니다.
            </p>
          </div>
          <button
            type="button"
            className="button button-ghost"
            onClick={() => {
              setSearchText("");
              setStatusFilter("");
              setOffset(0);
            }}
          >
            필터 초기화
          </button>
        </div>
        <div className="filter-grid">
          <div className="filter-item">
            <label htmlFor="device-search">기기 또는 IP 검색</label>
            <input
              id="device-search"
              type="search"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Device ID, IP"
            />
          </div>
          <div className="filter-item">
            <label htmlFor="device-status">Trust 상태</label>
            <select
              id="device-status"
              value={statusFilter}
              onChange={(e) => {
                setLoading(true);
                setStatusFilter(e.target.value);
                setOffset(0);
              }}
            >
              <option value="">전체</option>
              <option value="normal">정상</option>
              <option value="warning">주의</option>
              <option value="danger">위험</option>
              <option value="isolated">격리</option>
            </select>
          </div>
        </div>
      </section>

      <section className="panel table-panel">
        <div className="panel-header">
          <div>
            <h2>등록 기기 목록</h2>
            <p className="panel-description">
              행을 선택하면 Rule/AI 정책 및 보안 상태를 확인합니다.
            </p>
          </div>
          <span className="data-count">{filteredRows.length}건 표시</span>
        </div>

        {loading && rows.length === 0 ? (
          <LoadingState title="기기 목록을 불러오는 중입니다." />
        ) : error && rows.length === 0 ? (
          <ErrorState
            title="기기 목록 조회 실패"
            message={error}
            onRetry={() => loadData(true)}
          />
        ) : (
          <div className="table-scroll">
            <DataTable
              columns={columns}
              rows={filteredRows}
              rowKey="device_id"
              minWidth={1260}
              tableLabel="등록 기기 목록"
              emptyTitle="등록된 기기가 없습니다."
              emptyDescription="등록 상태를 확인해 주세요."
              onRowClick={openDetail}
              rowClassName={(device) =>
                device.firewall_status === "FAILED"
                  ? "row-danger"
                  : device.status === "isolated"
                    ? "row-warning"
                    : ""
              }
            />
          </div>
        )}

        {!loading && !error && total > 0 && (
          <Pagination
            currentPage={page}
            totalPages={pages}
            total={total}
            pageSize={LIMIT}
            onPrevious={() => setOffset((n) => Math.max(0, n - LIMIT))}
            onNext={() => setOffset((n) => n + LIMIT)}
            disabled={refreshing}
          />
        )}
      </section>

      {/* Device Registration */}
      <DetailModal
        open={registrationOpen}
        title="신규 기기 등록"
        description="Application 등록만 수행하며 Broker 계정·비밀번호는 생성하지 않습니다."
        size="large"
        onClose={() => {
          if (registrationSaving) return;
          setRegistrationOpen(false);
          setRegistrationKey("");
        }}
        closeDisabled={registrationSaving}
        footer={
          <>
            <button
              type="button"
              className="button button-ghost"
              onClick={() => {
                if (!registrationSaving) {
                  setRegistrationOpen(false);
                  setRegistrationKey("");
                }
              }}
              disabled={registrationSaving}
            >
              닫기
            </button>
            <button
              type="button"
              className="button"
              onClick={saveRegistration}
              disabled={registrationSaving || registrationVerify}
            >
              {registrationSaving ? "등록 중..." : "PENDING으로 등록"}
            </button>
          </>
        }
      >
        <div className="detail">
          <section className="detail-section">
            <h3>기기 정보</h3>
            <div className="admin-form">
              {[
                ["device_id", "Device ID", "pico_01"],
                ["ip_address", "고정 IP", "192.168.0.50"],
                ["mqtt_principal", "MQTT Principal", "pico_01"],
                ["reason", "등록 사유", "신규 센서 등록"],
              ].map(([key, label, placeholder]) => (
                <div
                  className="filter-item"
                  key={key}
                >
                  <label htmlFor={`reg-${key}`}>{label}</label>
                  <input
                    id={`reg-${key}`}
                    value={registration[key]}
                    onChange={(e) => registrationField(key, e.target.value)}
                    disabled={registrationSaving}
                    placeholder={placeholder}
                  />
                </div>
              ))}

              <div className="filter-item">
                <label htmlFor="reg-type">Device Type</label>
                <select
                  id="reg-type"
                  value={registration.device_type}
                  onChange={(e) => registrationField("device_type", e.target.value)}
                  disabled={registrationSaving}
                >
                  {DEVICE_TYPES.map((type) => (
                    <option key={type}>{type}</option>
                  ))}
                </select>
              </div>

              <div className="filter-item">
                <label>자동 산출 Topic</label>
                <div className="readonly-value">
                  {registration.device_id
                    ? `iot/${registration.device_id}/sensor`
                    : "iot/{device_id}/sensor"}
                </div>
              </div>
            </div>
          </section>

          <section className="detail-section">
            <h3>기본 Rule 정책</h3>
            <div className="policy-form-grid">
              {[
                ["expected_publish_interval", "Expected Publish Interval", "seconds", "0.1"],
                ["publish_count_max", "Publish Count Max", "messages / 10s", "1"],
                ["payload_size_max", "Payload Size Max", "bytes", "1"],
                ["packet_rate_max", "Packet Rate Max", "packets/s", "0.1"],
                ["byte_rate_max", "Byte Rate Max", "bytes/s", "0.1"],
              ].map(([key, label, unit, step]) => (
                <div className="filter-item" key={key}>
                  <label htmlFor={`reg-${key}`}>{label}</label>
                  <div className="input-with-unit">
                    <input
                      id={`reg-${key}`}
                      type="number"
                      step={step}
                      min="0.000001"
                      value={registration[key]}
                      onChange={(e) => registrationField(key, e.target.value)}
                      disabled={registrationSaving}
                    />
                    <span>{unit}</span>
                  </div>
                </div>
              ))}
            </div>
          </section>

          <section className="detail-section">
            <h3>관리자 인증</h3>
            <div className="filter-item">
              <label htmlFor="register-admin">Admin Key</label>
              <input
                id="register-admin"
                type="password"
                autoComplete="off"
                value={registrationKey}
                onChange={(e) => setRegistrationKey(e.target.value)}
                disabled={registrationSaving}
                placeholder="관리자 Key"
              />
            </div>

            {registrationError && (
              <p className="inline-error" role="alert">{registrationError}</p>
            )}

            {registrationMessage && (
              <div
                className={
                  registrationVerify
                    ? "verification-box verification-checking"
                    : "verification-box verification-checked"
                }
              >
                <strong>{registrationVerify ? "결과 확인 필요" : "등록 결과"}</strong>
                <p>{registrationMessage}</p>
              </div>
            )}
          </section>
        </div>
      </DetailModal>

      {/* Device Detail */}
      <DetailModal
        open={Boolean(selectedDevice)}
        title={selectedDevice
          ? `${selectedDevice.device_id} 상세 상태`
          : "기기 상세 상태"}
        description={selectedDevice
          ? `${selectedDevice.ip_address || "IP 없음"} · Rule/AI/Trust/Firewall`
          : undefined}
        onClose={closeDetail}
        closeDisabled={policySaving}
        size="large"
        footer={
          <>
            <button
              type="button"
              className="button button-secondary"
              onClick={closeDetail}
              disabled={policySaving}
            >
              닫기
            </button>
            <button
              type="button"
              className="button"
              onClick={saveRulePolicy}
              disabled={
                policySaving ||
                policyLoading ||
                !currentPolicy ||
                Boolean(pendingPolicy) ||
                policyVerify
              }
            >
              {policySaving ? "Rule 정책 저장 중..." : "Rule 정책 변경 저장"}
            </button>
          </>
        }
      >
        {selectedDevice && (
          <div className="detail">
            {detailLoading && (
              <LoadingState title="최신 기기 상태 조회 중" compact />
            )}
            {detailError && (
              <ErrorState
                title="기기 상세 일부 조회 실패"
                message={detailError}
                onRetry={() => openDetail(selectedDevice)}
                compact
              />
            )}

            <section className="detail-grid">
              {[
                ["Device ID", selectedDevice.device_id],
                ["IP Address", selectedDevice.ip_address],
                ["Device Type", selectedDevice.device_type],
                ["MQTT Principal", selectedDevice.mqtt_principal],
                ["Topic", selectedDevice.mqtt_topic ??
                  `iot/${selectedDevice.device_id}/sensor`],
                ["등록 상태", registrationLabel(currentRegistration)],
                ["Trust 상태", trustLabel(
                  selectedDevice.status ??
                  getTrustStatus(selectedDevice.trust_score)
                )],
                ["Trust Score", formatNumber(selectedDevice.trust_score)],
                ["Firewall 상태", firewallLabel(selectedDevice.firewall_status)],
                ["마지막 통신", formatKST(selectedDevice.last_seen_at)],
              ].map(([label, value]) => (
                <div className="detail-item" key={label}>
                  <span>{label}</span>
                  <strong>{value || "-"}</strong>
                </div>
              ))}
            </section>

            {/* Existing Rule Policy */}
            <section className="detail-section">
              <div className="section-heading">
                <div>
                  <h3>현재 / 적용 예정 Rule 정책</h3>
                  <p>서버 재조회 기준으로 효력 적용 여부를 판단합니다.</p>
                </div>
                <button
                  type="button"
                  className="button button-ghost"
                  disabled={policyLoading || policySaving}
                  onClick={() => refreshPolicy(selectedDevice.device_id, true)}
                >
                  정책 새로고침
                </button>
              </div>

              {policyLoading ? (
                <LoadingState title="Rule 정책 조회 중" compact />
              ) : policyError ? (
                <ErrorState
                  title="Rule 정책 조회 실패"
                  message={policyError}
                  onRetry={() => refreshPolicy(selectedDevice.device_id, true)}
                  compact
                />
              ) : (
                <div className="policy-state-grid">
                  {[
                    ["현재 정책", currentPolicy, "normal"],
                    ["적용 예정 정책", pendingPolicy, "pending"],
                  ].map(([title, revision, status]) => (
                    <article className="policy-card" key={title}>
                      <div className="policy-card-header">
                        <strong>{title}</strong>
                        <StatusBadge
                          status={revision ? status : "unknown"}
                          label={revision ? (status === "normal" ? "CURRENT" : "PENDING") : "없음"}
                          size="small"
                        />
                      </div>
                      {revision ? (
                        <dl className="policy-list">
                          <div><dt>Revision</dt><dd>{displayValue(revision.revision)}</dd></div>
                          <div><dt>Registration</dt><dd>{registrationLabel(registrationState(selectedDevice, revision))}</dd></div>
                          <div><dt>Profile</dt><dd>{displayValue(policyPayload(revision).policy_profile)}</dd></div>
                          <div><dt>Expected Interval</dt><dd>{formatNumber(policyValue(revision, "expected_publish_interval"), 2)} s</dd></div>
                          <div><dt>Publish Count Max</dt><dd>{formatNumber(policyValue(revision, "publish_count_max"))} / 10s</dd></div>
                          <div><dt>Payload Size Max</dt><dd>{formatNumber(policyValue(revision, "payload_size_max"))} B</dd></div>
                          <div><dt>Packet Rate Max</dt><dd>{formatNumber(policyValue(revision, "packet_rate_max"), 2)} pps</dd></div>
                          <div><dt>Byte Rate Max</dt><dd>{formatNumber(policyValue(revision, "byte_rate_max"), 2)} B/s</dd></div>
                          <div><dt>Effective From</dt><dd>{formatKST(effectiveFrom(revision))}</dd></div>
                        </dl>
                      ) : (
                        <p className="text-muted">정책 정보가 없습니다.</p>
                      )}
                    </article>
                  ))}
                </div>
              )}
            </section>

            <section className="detail-section">
              <h3>기기별 Rule 정책 변경</h3>
              <p className="text-muted">
                Rule 정책과 Phase 9 AI 정책은 별개로 관리됩니다.
              </p>

              <div className="policy-form-grid">
                <div className="filter-item">
                  <label htmlFor="rule-registration">등록 상태</label>
                  <select
                    id="rule-registration"
                    value={policyDraft.registration_state}
                    onChange={(e) =>
                      policyField("registration_state", e.target.value)}
                    disabled={policySaving || Boolean(pendingPolicy)}
                  >
                    {!policyDraft.registration_state && (
                      <option value="">확인 불가</option>
                    )}
                    {availableRegistrationStates(currentRegistration).map((state) => (
                      <option key={state} value={state}>
                        {registrationLabel(state)}
                      </option>
                    ))}
                  </select>
                </div>

                {[
                  ["expected_publish_interval", "Expected Publish Interval", "seconds", "0.1"],
                  ["publish_count_max", "Publish Count Max", "messages / 10s", "1"],
                  ["payload_size_max", "Payload Size Max", "bytes", "1"],
                  ["packet_rate_max", "Packet Rate Max", "packets/s", "0.1"],
                  ["byte_rate_max", "Byte Rate Max", "bytes/s", "0.1"],
                ].map(([key, label, unit, step]) => (
                  <div className="filter-item" key={key}>
                    <label htmlFor={`rule-${key}`}>{label}</label>
                    <div className="input-with-unit">
                      <input
                        id={`rule-${key}`}
                        type="number"
                        min="0.000001"
                        step={step}
                        value={policyDraft[key]}
                        onChange={(e) => policyField(key, e.target.value)}
                        disabled={policySaving || Boolean(pendingPolicy)}
                      />
                      <span>{unit}</span>
                    </div>
                  </div>
                ))}

                <div className="filter-item full-width">
                  <label htmlFor="rule-reason">변경 사유</label>
                  <textarea
                    id="rule-reason"
                    value={policyDraft.reason}
                    onChange={(e) => policyField("reason", e.target.value)}
                    disabled={policySaving || Boolean(pendingPolicy)}
                    placeholder="Rule 정책 변경 사유"
                  />
                </div>

                <div className="filter-item full-width">
                  <label htmlFor="rule-key">Admin Key</label>
                  <input
                    id="rule-key"
                    type="password"
                    autoComplete="off"
                    value={policyKey}
                    onChange={(e) => setPolicyKey(e.target.value)}
                    disabled={policySaving}
                    placeholder="관리자 Key"
                  />
                </div>
              </div>

              {pendingPolicy && (
                <div className="verification-box verification-checking">
                  적용 예정 Rule 정책이 있어 새 변경이 제한됩니다.
                </div>
              )}
              {policyWriteError && (
                <p className="inline-error" role="alert">{policyWriteError}</p>
              )}
              {policyMessage && (
                <div className={
                  policyVerify
                    ? "verification-box verification-checking"
                    : "verification-box verification-checked"
                }>
                  <strong>{policyVerify ? "결과 확인 필요" : "Rule 정책 결과"}</strong>
                  <p>{policyMessage}</p>
                </div>
              )}
            </section>

            {/* Phase 9 - AI Policy / Warnings */}
            <DeviceAiManagement
              key={selectedDevice.device_id}
              deviceId={selectedDevice.device_id}
              registration={currentRegistration}
            />

            {/* Firewall */}
            {selectedDevice.firewall_rule && (
              <section className="detail-section">
                <h3>Firewall Rule</h3>
                <dl className="detail-list">
                  <div>
                    <dt>Source IP</dt>
                    <dd>{displayValue(selectedDevice.firewall_rule.source_ip)}</dd>
                  </div>
                  <FirewallTrafficFields
                    rule={selectedDevice.firewall_rule}
                  />
                  <div>
                    <dt>Action</dt>
                    <dd>{displayValue(selectedDevice.firewall_rule.action)}</dd>
                  </div>
                  <div>
                    <dt>Retry Count</dt>
                    <dd>{displayValue(selectedDevice.firewall_rule.retry_count)}</dd>
                  </div>
                  <div>
                    <dt>Last Error</dt>
                    <dd className="break-word">
                      {displayValue(selectedDevice.firewall_rule.last_error)}
                    </dd>
                  </div>
                </dl>
              </section>
            )}

            {/* Trust Score History */}
            <section className="detail-section">
              <div className="section-heading">
                <div>
                  <h3>Trust Score 이력</h3>
                  <p>서버가 계산한 실제 Score 변화값을 표시합니다.</p>
                </div>
              </div>

              {trustLoading ? (
                <LoadingState title="Trust 이력 조회 중" compact />
              ) : trustError ? (
                <ErrorState
                  message={trustError}
                  onRetry={() => openDetail(selectedDevice)}
                  compact
                />
              ) : trustHistory.length === 0 ? (
                <EmptyState
                  title="Trust Score 변화 이력이 없습니다."
                  compact
                />
              ) : (
                <div className="history-list">
                  {trustHistory.map((history, index) => (
                    <article
                      className="history-item"
                      key={history.id ?? index}
                    >
                      <div className="history-score">
                        <strong>{formatNumber(history.previous_score)}</strong>
                        <span>→</span>
                        <strong>{formatNumber(history.new_score)}</strong>
                      </div>
                      <div className="history-meta">
                        <StatusBadge
                          status={Number(history.actual_delta) < 0
                            ? "danger" : "normal"}
                          label={`실제 변화 ${formatDelta(history.actual_delta)}`}
                          size="small"
                        />
                        <span>{formatKST(history.analysis_window_start)}</span>
                        <span>~</span>
                        <span>{formatKST(history.analysis_window_end)}</span>
                      </div>
                      <dl className="history-info">
                        <div><dt>계산 Delta</dt><dd>{formatDelta(history.calculated_delta)}</dd></div>
                        <div><dt>상한 적용 Delta</dt><dd>{formatDelta(history.capped_delta)}</dd></div>
                        <div><dt>대표 Event</dt><dd>{Array.isArray(history.representative_event_ids) ? history.representative_event_ids.join(", ") : "-"}</dd></div>
                        <div><dt>Policy</dt><dd>{history.policy_version || "-"}</dd></div>
                      </dl>
                    </article>
                  ))}
                </div>
              )}
            </section>
          </div>
        )}
      </DetailModal>
    </div>
  );
}
