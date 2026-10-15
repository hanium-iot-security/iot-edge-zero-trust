import { useCallback, useEffect, useMemo, useRef, useState, } from "react";
import { createFirewallReleaseRequest, createFirewallScopeExtensionRequest, createPacketPairRecoveryPlan, getPacketPairRecoveryPlan, verifyPacketPairRecoveryPlan, getFirewallRuntimeStatus, executeRecovery, getDeviceDetail, getFirewallReleaseRequest, getFirewallRules, getIsolatedDevices, getIsolationHistory, getRecoveryHistory, recoveryPreflight, } from "../api/api";
import DataTable from "../components/DataTable";
import DetailModal from "../components/DetailModal";
import EmptyState from "../components/EmptyState";
import FirewallTrafficFields from "../components/FirewallTrafficFields";
import {
    canReleaseFirewallRule,
    findCurrentFirewallRuleByTriggerEvent,
    getCurrentFirewallRuleMap,
} from "../utils/firewallRuleSelection";
import PageHeader from "../components/PageHeader";
import Pagination from "../components/Pagination";
import StatusBadge from "../components/StatusBadge";
import SummaryCard from "../components/SummaryCard";
import "../styles/pages/Isolation.scss";
const DEFAULT_LIMIT = 20;
const POLLING_INTERVAL_MS = 10000;
const RELEASE_POLLING_INTERVAL_MS = 2000;
const RECOVERY_CONFIRMATION = "RESET-TO-NORMAL-100";
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
function formatNumber(value, maximumFractionDigits = 0) {
    if (value === null ||
        value === undefined ||
        value === "") {
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
    if (normalized ===
        "APPLIED") {
        return "applied";
    }
    if (normalized ===
        "PENDING") {
        return "pending";
    }
    if (normalized ===
        "FAILED") {
        return "failed";
    }
    if (normalized ===
        "REMOVED") {
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
    return (labels[normalized] ||
        status ||
        "Firewall 기록 없음");
}
function getFirewallReleaseConfirmation(ruleId) {
    if (ruleId === null ||
        ruleId === undefined ||
        ruleId === "") {
        return "";
    }
    return `RELEASE-FIREWALL-RULE-${ruleId}`;
}
/* =========================================================
   Isolation
   ========================================================= */
function getIsolationActionStatus(action) {
    const normalized = String(action || "")
        .trim()
        .toUpperCase();
    if (normalized ===
        "ISOLATED" ||
        normalized ===
            "ISOLATE") {
        return "isolated";
    }
    if (normalized ===
        "RELEASED" ||
        normalized ===
            "RELEASE" ||
        normalized ===
            "UNISOLATED") {
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
    return (labels[normalized] ||
        action ||
        "-");
}
function getTrustStatus(score) {
    if (score === null || score === undefined || score === "") return "unknown";
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
    return (labels[normalized] ||
        status ||
        "확인 불가");
}
function formatElapsedTime(dateString) {
    if (!dateString) {
        return "-";
    }
    const timestamp = new Date(dateString).getTime();
    if (Number.isNaN(timestamp)) {
        return "-";
    }
    const elapsedSeconds = Math.max(0, Math.floor((Date.now() -
        timestamp) /
        1000));
    if (elapsedSeconds < 60) {
        return `${elapsedSeconds}초 전`;
    }
    const elapsedMinutes = Math.floor(elapsedSeconds /
        60);
    if (elapsedMinutes < 60) {
        return `${elapsedMinutes}분 전`;
    }
    const elapsedHours = Math.floor(elapsedMinutes /
        60);
    if (elapsedHours < 24) {
        return `${elapsedHours}시간 전`;
    }
    return `${Math.floor(elapsedHours / 24)}일 전`;
}
/* =========================================================
   Release Request
   ========================================================= */
function normalizeReleaseRequestStatus(value) {
    return String(value || "")
        .trim()
        .toUpperCase();
}
function getReleaseRequestId(data) {
    return (data?.id ??
        data?.request_id ??
        data?.release_request_id ??
        null);
}
function getReleaseRequestTheme(status) {
    const normalized = normalizeReleaseRequestStatus(status);
    if (normalized ===
        "PENDING") {
        return "pending";
    }
    if (normalized ===
        "SUCCEEDED") {
        return "eligible";
    }
    if (normalized ===
        "FAILED") {
        return "failed";
    }
    return "unknown";
}
function getReleaseRequestLabel(status) {
    const normalized = normalizeReleaseRequestStatus(status);
    const labels = {
        PENDING: "처리 중",
        SUCCEEDED: "해제 성공",
        FAILED: "해제 실패",
    };
    return (labels[normalized] ||
        normalized ||
        "-");
}
/* =========================================================
   Recovery
   ========================================================= */
function getOperationId(data) {
    return (data?.operation_id ??
        data?.id ??
        null);
}
/*
 * 최신 API 계약:
 *
 * firewall_runtime_verification.status
 *
 * VERIFIED_RELEASED / UNAVAILABLE 등
 */
function getRuntimeReleaseStatus(data) {
    return String(data
        ?.firewall_runtime_verification
        ?.status ??
        "")
        .trim()
        .toUpperCase();
}
function getPreflightCanExecute(data) {
    return (data?.can_execute ===
        true);
}
/*
 * expected_trust_score는
 * Recovery 후 목표 Score 100이 아닙니다.
 *
 * Backend가 Preflight에서 비교하는 현재 Trust Score입니다.
 */
function getPreflightTrustScore(preflight, device) {
    const value = preflight
        ?.current_trust_score ??
        device
            ?.trust_score ??
        null;
    if (value === null || value === undefined || value === "") return null;
    const number = Number(value);
    return Number.isFinite(number)
        ? number
        : null;
}
function getRecoveryResult(data) {
    return String(data?.result || "")
        .trim()
        .toUpperCase();
}
function getRecoveryUiStatus(device, releaseRequest, preflight) {
    if (!device) {
        return {
            status: "unknown",
            label: "확인 불가",
            description: "기기 상태를 확인할 수 없습니다.",
        };
    }
    const firewallStatus = String(device.firewall_status ||
        "").toUpperCase();
    const releaseStatus = normalizeReleaseRequestStatus(releaseRequest
        ?.status);
    if (releaseStatus ===
        "PENDING") {
        return {
            status: "pending",
            label: "Firewall 해제 처리 중",
            description: "Firewall Worker가 Release Request를 처리하고 있습니다.",
        };
    }
    if (releaseStatus ===
        "FAILED") {
        return {
            status: "failed",
            label: "Firewall 해제 실패",
            description: "Release Request가 실패했습니다. 실패 사유와 현재 Firewall Rule 상태를 확인해 주세요.",
        };
    }
    if (firewallStatus ===
        "APPLIED") {
        return {
            status: "warning",
            label: "차단 해제 필요",
            description: "현재 Firewall Rule이 APPLIED 상태입니다. 관리자 승인형 Release Request가 먼저 필요합니다.",
        };
    }
    if (firewallStatus ===
        "PENDING") {
        return {
            status: "pending",
            label: "Firewall 적용 대기",
            description: "Firewall Rule 적용이 아직 완료되지 않았습니다.",
        };
    }
    if (firewallStatus ===
        "FAILED") {
        return {
            status: "failed",
            label: "Firewall 상태 확인 필요",
            description: "Firewall Rule 상태가 FAILED입니다. 남은 차단을 정확한 Rule ID의 해제 요청으로 정리한 뒤 Recovery를 진행해 주세요.",
        };
    }
    if (firewallStatus !==
        "REMOVED") {
        return {
            status: "unknown",
            label: "확인 필요",
            description: "Recovery 전 Firewall Rule 상태를 확인해야 합니다.",
        };
    }
    if (!preflight) {
        return {
            status: "pending",
            label: "Preflight 필요",
            description: "Firewall Rule이 REMOVED 상태입니다. Backend Preflight로 Runtime 상태와 나머지 안전 조건을 확인해 주세요.",
        };
    }
    const runtimeStatus = getRuntimeReleaseStatus(preflight);
    if (runtimeStatus !==
        "VERIFIED_RELEASED") {
        return {
            status: preflight?.result ===
                "HOLD"
                ? "warning"
                : "pending",
            label: runtimeStatus ===
                "UNAVAILABLE"
                ? "Runtime 검증 불가"
                : "Runtime 검증 대기",
            description: preflight
                ?.failure_reason ||
                "Runtime VERIFIED_RELEASED 상태가 확인되지 않았습니다.",
        };
    }
    if (!getPreflightCanExecute(preflight)) {
        return {
            status: "warning",
            label: "Preflight 차단",
            description: preflight
                ?.failure_reason ||
                "Backend Preflight가 Recovery 실행을 허용하지 않았습니다.",
        };
    }
    return {
        status: "eligible",
        label: "Recovery 가능",
        description: "Firewall REMOVED, Runtime VERIFIED_RELEASED 및 Backend Preflight 안전 조건을 통과했습니다.",
    };
}
function unwrapApiItem(data) {
    return data?.item ?? data;
}
function validateCommandResponse(data, { deviceId = null, requestId = null, firewallRuleId = null, } = {}) {
    const item = unwrapApiItem(data);
    if (!item || typeof item !== "object") {
        throw new Error("서버 응답 형식을 확인할 수 없습니다.");
    }
    if (deviceId &&
        item.device_id !== undefined &&
        item.device_id !== null &&
        String(item.device_id) !==
            String(deviceId)) {
        throw new Error("다른 기기의 응답이 도착해 결과를 반영하지 않았습니다.");
    }
    if (requestId !== null &&
        requestId !== undefined) {
        const responseRequestId = getReleaseRequestId(item);
        if (responseRequestId === null ||
            responseRequestId ===
                undefined) {
            throw new Error("Release Request ID가 없는 응답은 결과에 반영하지 않았습니다.");
        }
        if (String(responseRequestId) !==
            String(requestId)) {
            throw new Error("다른 Release Request 응답이 도착해 결과를 반영하지 않았습니다.");
        }
    }
    if (firewallRuleId !== null &&
        firewallRuleId !== undefined &&
        item.firewall_rule_id !==
            undefined &&
        item.firewall_rule_id !== null &&
        String(item.firewall_rule_id) !==
            String(firewallRuleId)) {
        throw new Error("다른 Firewall Rule의 응답이 도착해 결과를 반영하지 않았습니다.");
    }
    return item;
}
function isUncertainCommandError(error) {
    if (!error) {
        return true;
    }
    if (error.isCanceled) {
        return false;
    }
    if (error.code === "ERR_NETWORK" ||
        error.code === "ECONNABORTED" ||
        error.code === "ETIMEDOUT") {
        return true;
    }
    return (error.status === null ||
        error.status === undefined);
}
/* =========================================================
   Page
   ========================================================= */
/* =========================================================
   Phase 9 - Firewall Runtime / Scope Extension / Packet Pair
   Request bodies must match Swagger schema. The UI does not
   invent extension ranges, plan actions, or successful status.
   ========================================================= */
function Phase9RuntimePanel() {
  const [runtime, setRuntime] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [updatedAt, setUpdatedAt] = useState("");
  const seq = useRef(0);

  const refresh = useCallback(async (signal) => {
    const id = ++seq.current;
    setLoading(true);
    try {
      const response = await getFirewallRuntimeStatus({ signal });
      if (signal?.aborted || id !== seq.current) return;
      const value = unwrapApiItem(response);
      if (value == null || typeof value !== "object") {
        throw new Error("Firewall Runtime 응답 형식이 올바르지 않습니다.");
      }
      setRuntime(value);
      setUpdatedAt(new Date().toISOString());
      setError("");
    } catch (err) {
      if (!signal?.aborted && id === seq.current) {
        setError(err?.message || "Firewall Runtime 조회에 실패했습니다.");
      }
    } finally {
      if (id === seq.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    refresh(controller.signal);
    const timer = window.setInterval(() => refresh(controller.signal), POLLING_INTERVAL_MS);
    return () => {
      seq.current += 1;
      controller.abort();
      window.clearInterval(timer);
    };
  }, [refresh]);

  return (
    <section className="panel phase9-runtime-panel">
      <div className="panel-header">
        <div>
          <h2>Firewall Runtime Status (Phase 9)</h2>
          <p className="panel-description">DB Rule 상태는 실제 Firewall Runtime 검증을 대체하지 않습니다.</p>
        </div>
        <button type="button" className="button button-secondary" onClick={() => refresh()} disabled={loading}>
          {loading ? "조회 중..." : "Runtime 새로고침"}
        </button>
      </div>
      {error && <p className="inline-error" role="alert">{error}{runtime ? " · 이전 조회 데이터를 표시합니다." : ""}</p>}
      {runtime ? (
        <>
          <p className="text-muted">최근 조회: {formatKST(updatedAt)} {error ? "(최신 상태 아님)" : ""}</p>
          <details className="phase9-json-details" open>
            <summary>Firewall Runtime 원본 응답</summary>
            <pre>{JSON.stringify(runtime, null, 2)}</pre>
          </details>
        </>
      ) : <p className="text-muted">{loading ? "Runtime 정보 조회 중..." : "Runtime 상태를 확인할 수 없습니다."}</p>}
    </section>
  );
}

function parseAdminJson(raw, label) {
  const trimmed = String(raw || "").trim();
  if (!trimmed) throw new Error(`${label} JSON을 입력해 주세요.`);
  let value;
  try { value = JSON.parse(trimmed); }
  catch { throw new Error(`${label} JSON 형식이 올바르지 않습니다.`); }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label}는 JSON 객체여야 합니다.`);
  }
  return value;
}

function Phase9ScopeExtension({ rule, adminKey }) {
  const [payloadText, setPayloadText] = useState("");
  const [reason, setReason] = useState("");
  const [confirmId, setConfirmId] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [uncertain, setUncertain] = useState(false);
  const lock = useRef(false);
  const ruleId = rule?.id;

  async function submit() {
    if (lock.current || uncertain || !ruleId) return;
    setError("");
    let dispatched = false;
    try {
      if (!adminKey.trim()) throw new Error("관리자 Key를 입력해 주세요.");
      if (!reason.trim()) throw new Error("차단 범위 확대 사유를 입력해 주세요.");
      if (confirmId.trim() !== String(ruleId)) throw new Error("확인용 Rule ID가 다릅니다.");
      const payload = parseAdminJson(payloadText, "Scope Extension 요청 본문");
      if (typeof payload.reason === "string" && payload.reason.trim() !== reason.trim()) {
        throw new Error("입력한 사유와 요청 JSON의 reason이 다릅니다.");
      }
      if (payload.reason === undefined) {
        throw new Error("Swagger 규격에 따라 reason을 포함한 JSON을 입력해 주세요.");
      }
      lock.current = true;
      setBusy(true);
      setResult(null);
      dispatched = true;
      const value = await createFirewallScopeExtensionRequest(ruleId, payload, adminKey);
      setResult(unwrapApiItem(value));
    } catch (err) {
      const uncertainRequest = dispatched && isUncertainCommandError(err);
      if (uncertainRequest) setUncertain(true);
      setError(`${err?.message || "요청 실패"}${uncertainRequest ? " · 결과가 불확실하므로 자동 재요청하지 않습니다." : ""}`);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }

  return (
    <section className="detail-section phase9-admin-section">
      <h3>Phase 9 · Firewall Scope Extension</h3>
      <p className="text-muted">현재 Rule ID에 대해 관리자 승인형 범위 확대 요청을 보냅니다. 요청 자체를 실제 Firewall 적용으로 표시하지 않습니다. JSON 필드명·제약은 Swagger 스키마와 정확히 일치해야 합니다.</p>
      {!ruleId ? <p className="inline-error">선택된 Source Rule ID가 없어 요청할 수 없습니다.</p> : (
        <div className="recovery-form">
          <div className="filter-item"><label>Source Rule ID</label><div className="phase9-readonly">{ruleId}</div></div>
          <div className="filter-item"><label htmlFor="phase9-scope-reason">변경 사유 (JSON reason과 동일)</label><input id="phase9-scope-reason" value={reason} onChange={(e) => setReason(e.target.value)} disabled={busy || uncertain} /></div>
          <div className="filter-item"><label htmlFor="phase9-scope-json">Scope Extension 요청 JSON (Swagger 스키마 기준)</label><textarea id="phase9-scope-json" rows={6} value={payloadText} onChange={(e) => setPayloadText(e.target.value)} disabled={busy || uncertain} placeholder={'{\n  "reason": "..."\n}'} /></div>
          <div className="filter-item"><label htmlFor="phase9-scope-confirm">확인용 Rule ID 재입력</label><input id="phase9-scope-confirm" value={confirmId} onChange={(e) => setConfirmId(e.target.value)} disabled={busy || uncertain} /></div>
          <button type="button" className="button button-danger" disabled={busy || uncertain || !adminKey.trim()} onClick={submit}>{busy ? "요청 중..." : "Scope Extension 요청"}</button>
        </div>
      )}
      {uncertain && <p className="phase9-uncertain">결과 확인이 필요합니다. 서버의 변경 요청 상태를 직접 확인한 뒤 모달을 닫았다가 다시 열어 주세요.</p>}
      {error && <p className="inline-error" role="alert">{error}</p>}
      {result && <details className="phase9-json-details" open><summary>서버 요청 응답 (적용 완료 의미 아님)</summary><pre>{JSON.stringify(result, null, 2)}</pre></details>}
    </section>
  );
}

function Phase9PacketPairRecovery({ adminKey, deviceId }) {
  const [requestText, setRequestText] = useState("");
  const [planId, setPlanId] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [uncertain, setUncertain] = useState(false);
  const lock = useRef(false);

  async function run(kind) {
    if (lock.current || (kind !== "read" && uncertain)) return;
    setError("");
    if (!adminKey.trim()) { setError("관리자 Key를 입력해 주세요."); return; }
    lock.current = true;
    setBusy(true);
    let dispatched = false;
    try {
      let response;
      if (kind === "create") {
        const payload = parseAdminJson(requestText, "Packet Pair Plan 요청 본문");
        if (payload.device_id && String(payload.device_id) !== String(deviceId)) {
          throw new Error("다른 기기의 device_id로 복구 Plan을 생성할 수 없습니다.");
        }
        dispatched = true;
        response = await createPacketPairRecoveryPlan(payload, adminKey);
      } else {
        if (!planId.trim()) throw new Error("Plan ID를 입력해 주세요.");
        if (kind === "read") {
          response = await getPacketPairRecoveryPlan(planId.trim(), adminKey);
        } else {
          dispatched = true;
          response = await verifyPacketPairRecoveryPlan(planId.trim(), adminKey);
        }
      }
      const value = unwrapApiItem(response);
      setResult(value);
      const returnedId = value?.plan_id ?? value?.id;
      if (returnedId != null) setPlanId(String(returnedId));
    } catch (err) {
      const uncertainRequest = kind !== "read" && dispatched && isUncertainCommandError(err);
      if (uncertainRequest) setUncertain(true);
      setError(`${err?.message || "요청 실패"}${uncertainRequest ? " · 결과가 불확실하므로 자동 재시도하지 않습니다." : ""}`);
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }

  return (
    <section className="detail-section phase9-admin-section">
      <h3>Phase 9 · Packet Pair Recovery Plan</h3>
      <p className="text-muted">기존 Baseline Recovery와 별도 API입니다. Plan 생성/조회/검증만 다루며 성공 응답을 실제 복구 완료로 간주하지 않습니다. 요청 JSON은 Swagger 명세에 맞춰 입력하세요.</p>
      <div className="recovery-form">
        <div className="filter-item"><label htmlFor="phase9-plan-create">Plan 생성 요청 JSON</label><textarea id="phase9-plan-create" rows={6} value={requestText} disabled={busy || uncertain} onChange={(e) => setRequestText(e.target.value)} placeholder="Swagger에 정의된 Plan 생성 요청 JSON" /></div>
        <button type="button" className="button button-secondary" disabled={busy || uncertain || !adminKey.trim()} onClick={() => run("create")}>Plan 생성</button>
        <div className="filter-item"><label htmlFor="phase9-plan-id">Plan ID</label><input id="phase9-plan-id" value={planId} disabled={busy} onChange={(e) => setPlanId(e.target.value)} /></div>
        <button type="button" className="button button-secondary" disabled={busy || !planId.trim()} onClick={() => run("read")}>Plan 상태 재조회</button>
        <button type="button" className="button button-secondary" disabled={busy || uncertain || !planId.trim()} onClick={() => run("verify")}>Plan Verify 요청</button>
      </div>
      {uncertain && <p className="phase9-uncertain">POST 결과가 불확실합니다. 서버에서 Plan/요청 상태를 확인한 후에만 다시 수행하세요.</p>}
      {error && <p className="inline-error" role="alert">{error}</p>}
      {result && <details className="phase9-json-details" open><summary>최근 서버 응답</summary><pre>{JSON.stringify(result, null, 2)}</pre></details>}
    </section>
  );
}

export default function Isolation() {
    const [history, setHistory,] = useState([]);
    const [isolatedDevices, setIsolatedDevices,] = useState([]);
    const [firewallRules, setFirewallRules,] = useState([]);
    const [total, setTotal,] = useState(0);
    const [offset, setOffset,] = useState(0);
    const [searchText, setSearchText,] = useState("");
    const [actionFilter, setActionFilter,] = useState("");
    const [firewallFilter, setFirewallFilter,] = useState("");
    const [selectedHistory, setSelectedHistory,] = useState(null);
    const [selectedIsolatedDevice, setSelectedIsolatedDevice,] = useState(null);
    const [loading, setLoading,] = useState(true);
    const [refreshing, setRefreshing,] = useState(false);
    const [error, setError,] = useState("");
    const [pollWarning, setPollWarning,] = useState("");
    const [lastUpdated, setLastUpdated,] = useState("");
    /* =========================================================
       Admin Key
       ========================================================= */
    const [adminKey, setAdminKey,] = useState("");
    /* =========================================================
       Firewall Release
       ========================================================= */
    const [releaseReason, setReleaseReason,] = useState("");
    const [releaseConfirmation, setReleaseConfirmation,] = useState("");
    const [releaseRequest, setReleaseRequest,] = useState(null);
    const [releaseSubmitting, setReleaseSubmitting,] = useState(false);
    const [releaseError, setReleaseError,] = useState("");
    /* =========================================================
       Recovery Preflight
       ========================================================= */
    const [preflight, setPreflight,] = useState(null);
    const [preflightLoading, setPreflightLoading,] = useState(false);
    const [preflightError, setPreflightError,] = useState("");
    /* =========================================================
       Recovery Execute
       ========================================================= */
    const [recoveryReason, setRecoveryReason,] = useState("");
    const [recoveryConfirmation, setRecoveryConfirmation,] = useState("");
    const [recoveryExecuting, setRecoveryExecuting,] = useState(false);
    const [recoveryResult, setRecoveryResult,] = useState(null);
    const [recoveryError, setRecoveryError,] = useState("");
    const [recoveryHistory, setRecoveryHistory,] = useState([]);
    const [recoveryHistoryLoading, setRecoveryHistoryLoading,] = useState(false);
    const [recoveryHistoryError, setRecoveryHistoryError,] = useState("");
    const [outcomeVerification, setOutcomeVerification,] = useState(null);
    const [outcomeVerificationLoading, setOutcomeVerificationLoading,] = useState(false);
    const hasDataRef = useRef(false);
    const mainRequestRef = useRef({
        id: 0,
        controller: null,
        key: "",
    });
    const activeCriteriaRef = useRef("");
    const recoveryModalGenerationRef = useRef(0);
    /* =========================================================
       Main Data
       ========================================================= */
    const loadData = useCallback(async (isManualRefresh = false) => {
        const requestKey = `${offset}|${actionFilter}`;
        const previous = mainRequestRef.current;
        if (!isManualRefresh &&
            previous.controller &&
            previous.key === requestKey) {
            return;
        }
        previous.controller?.abort();
        const controller = new AbortController();
        const requestId = previous.id + 1;
        mainRequestRef.current = {
            id: requestId,
            controller,
            key: requestKey,
        };
        const criteriaChanged = activeCriteriaRef.current !==
            requestKey;
        activeCriteriaRef.current =
            requestKey;
        if (criteriaChanged) {
            setLoading(true);
        }
        if (isManualRefresh) {
            setRefreshing(true);
        }
        try {
            const [historyData, isolatedDeviceData, firewallData,] = await Promise.all([
                getIsolationHistory({
                    limit: DEFAULT_LIMIT,
                    offset,
                    action: actionFilter ||
                        undefined,
                }, {
                    signal: controller.signal,
                }),
                getIsolatedDevices({
                    limit: 100,
                    offset: 0,
                }, {
                    signal: controller.signal,
                }),
                getFirewallRules({
                    limit: 100,
                    offset: 0,
                }, {
                    signal: controller.signal,
                }),
            ]);
            if (mainRequestRef.current.id !==
                requestId ||
                controller.signal.aborted) {
                return;
            }
            const historyItems = Array.isArray(historyData?.items)
                ? historyData.items
                : [];
            const deviceItems = Array.isArray(isolatedDeviceData?.items)
                ? isolatedDeviceData.items
                : [];
            const firewallItems = Array.isArray(firewallData?.items)
                ? firewallData.items
                : [];
            const responseTotal = Number(historyData?.total);
            setHistory(historyItems);
            setIsolatedDevices(deviceItems);
            setFirewallRules(firewallItems);
            setTotal(Number.isFinite(responseTotal)
                ? responseTotal
                : historyItems.length);
            setLastUpdated(new Date().toISOString());
            hasDataRef.current = true;
            setError("");
            setPollWarning("");
        }
        catch (err) {
            if (controller.signal.aborted ||
                err?.isCanceled) {
                return;
            }
            if (mainRequestRef.current.id !==
                requestId) {
                return;
            }
            if (IS_DEV) {
                console.error("Isolation data load failed:", err);
            }
            const message = err instanceof Error
                ? err.message
                : "격리 데이터를 불러오지 못했습니다.";
            if (hasDataRef.current) {
                setPollWarning(message);
            }
            else {
                setError(message);
            }
        }
        finally {
            if (mainRequestRef.current.id ===
                requestId) {
                mainRequestRef.current.controller =
                    null;
                setLoading(false);
                setRefreshing(false);
            }
        }
    }, [
        offset,
        actionFilter,
    ]);
    useEffect(() => {
        loadData();
        const timer = window.setInterval(() => {
            loadData();
        }, POLLING_INTERVAL_MS);
        return () => {
            window.clearInterval(timer);
        };
    }, [loadData]);
    useEffect(() => () => {
        mainRequestRef.current.controller?.abort();
    }, []);
    /* =========================================================
       Current Firewall Mapping
       ========================================================= */
    const firewallRuleMap = useMemo(() => getCurrentFirewallRuleMap(firewallRules), [firewallRules]);
    const isolatedDevicesWithFirewall = useMemo(() => isolatedDevices.map((device) => {
        const firewallRule = firewallRuleMap.get(device.device_id) || null;
        return {
            ...device,
            firewall_status: firewallRule
                ?.status ??
                device
                    .firewall_status ??
                null,
            firewall_rule: firewallRule,
        };
    }), [
        isolatedDevices,
        firewallRuleMap,
    ]);
    /*
     * Release 처리 후 loadData가 최신 Firewall Rule을 받으면
     * 열려 있는 Recovery Modal의 Device 정보도 최신 상태로 맞춥니다.
     *
     * Recovery 성공 후 Device가 isolated 목록에서 사라진 경우에는
     * 성공 결과를 보여주기 위해 기존 selected 값을 유지합니다.
     */
    useEffect(() => {
        if (!selectedIsolatedDevice) {
            return;
        }
        const latest = isolatedDevicesWithFirewall.find((device) => device.device_id ===
            selectedIsolatedDevice.device_id);
        if (!latest) {
            return;
        }
        const currentFirewallStatus = String(selectedIsolatedDevice
            .firewall_status ||
            "");
        const latestFirewallStatus = String(latest
            .firewall_status ||
            "");
        const currentTrustScore = Number(selectedIsolatedDevice
            .trust_score);
        const latestTrustScore = Number(latest
            .trust_score);
        if (currentFirewallStatus ===
            latestFirewallStatus &&
            currentTrustScore ===
                latestTrustScore &&
            selectedIsolatedDevice
                .firewall_rule?.id ===
                latest
                    .firewall_rule?.id) {
            return;
        }
        setSelectedIsolatedDevice(latest);
    }, [
        isolatedDevicesWithFirewall,
        selectedIsolatedDevice,
    ]);
    /* =========================================================
     Release Request Polling
     ========================================================= */
    const activeReleaseRequestId = getReleaseRequestId(releaseRequest);
    const activeReleaseRequestStatus = normalizeReleaseRequestStatus(releaseRequest?.status);
    useEffect(() => {
        if (!selectedIsolatedDevice ||
            !activeReleaseRequestId ||
            activeReleaseRequestStatus !==
                "PENDING" ||
            !adminKey.trim()) {
            return undefined;
        }
        const controller = new AbortController();
        const expectedDeviceId = selectedIsolatedDevice.device_id;
        const expectedRuleId = releaseRequest?.firewall_rule_id ??
            selectedIsolatedDevice.firewall_rule?.id ??
            null;
        const generation = recoveryModalGenerationRef.current;
        const poll = async () => {
            try {
                const rawResponse = await getFirewallReleaseRequest(activeReleaseRequestId, adminKey, {
                    signal: controller.signal,
                });
                if (controller.signal.aborted ||
                    generation !==
                        recoveryModalGenerationRef.current) {
                    return;
                }
                const response = validateCommandResponse(rawResponse, {
                    deviceId: expectedDeviceId,
                    requestId: activeReleaseRequestId,
                    firewallRuleId: expectedRuleId,
                });
                setReleaseRequest(response);
                setReleaseError("");
                const nextStatus = normalizeReleaseRequestStatus(response?.status);
                if (nextStatus ===
                    "SUCCEEDED" ||
                    nextStatus ===
                        "FAILED") {
                    await loadData(true);
                }
            }
            catch (err) {
                if (controller.signal.aborted ||
                    err?.isCanceled) {
                    return;
                }
                if (generation !==
                    recoveryModalGenerationRef.current) {
                    return;
                }
                setReleaseError(err instanceof Error
                    ? err.message
                    : "Firewall 해제 요청 상태를 확인하지 못했습니다.");
            }
        };
        poll();
        const timer = window.setInterval(poll, RELEASE_POLLING_INTERVAL_MS);
        return () => {
            controller.abort();
            window.clearInterval(timer);
        };
    }, [
        activeReleaseRequestId,
        activeReleaseRequestStatus,
        releaseRequest?.firewall_rule_id,
        selectedIsolatedDevice,
        loadData,
        adminKey,
    ]);
    /* =========================================================
       Isolation History Mapping
       ========================================================= */
    const historyWithFirewall = useMemo(() => history.map((item) => {
        const firewallRule = findCurrentFirewallRuleByTriggerEvent(firewallRules, item.trigger_event_id);
        return {
            ...item,
            firewall_status: firewallRule
                ?.status ??
                null,
            firewall_rule: firewallRule,
        };
    }), [
        history,
        firewallRules,
    ]);
    const filteredHistory = useMemo(() => {
        const keyword = searchText
            .trim()
            .toLowerCase();
        return historyWithFirewall.filter((item) => {
            const matchesSearch = !keyword ||
                normalizeSearchValue(item.device_id).includes(keyword) ||
                normalizeSearchValue(item.reason).includes(keyword) ||
                normalizeSearchValue(item.action).includes(keyword) ||
                normalizeSearchValue(item.firewall_status).includes(keyword) ||
                normalizeSearchValue(item.trigger_event_id).includes(keyword);
            const matchesAction = !actionFilter ||
                String(item.action ||
                    "").toUpperCase() ===
                    actionFilter;
            const matchesFirewall = !firewallFilter ||
                String(item.firewall_status ||
                    "").toUpperCase() ===
                    firewallFilter;
            return (matchesSearch &&
                matchesAction &&
                matchesFirewall);
        });
    }, [
        historyWithFirewall,
        searchText,
        actionFilter,
        firewallFilter,
    ]);
    /* =========================================================
       Summary
       ========================================================= */
    const isolationSummary = useMemo(() => {
        let applied = 0;
        let pending = 0;
        let failed = 0;
        let missing = 0;
        isolatedDevicesWithFirewall.forEach((device) => {
            const status = String(device.firewall_status ||
                "").toUpperCase();
            if (status ===
                "APPLIED") {
                applied += 1;
            }
            else if (status ===
                "PENDING") {
                pending += 1;
            }
            else if (status ===
                "FAILED") {
                failed += 1;
            }
            else if (status !==
                "REMOVED") {
                missing += 1;
            }
        });
        return {
            isolated: isolatedDevicesWithFirewall.length,
            applied,
            pending,
            failed,
            missing,
        };
    }, [
        isolatedDevicesWithFirewall,
    ]);
    const currentPage = Math.floor(offset /
        DEFAULT_LIMIT) + 1;
    const totalPages = Math.max(1, Math.ceil(total /
        DEFAULT_LIMIT));
    /* =========================================================
       Actions
       ========================================================= */
    function handleRefresh() {
        loadData(true);
    }
    function handlePrevPage() {
        setOffset((currentOffset) => Math.max(0, currentOffset -
            DEFAULT_LIMIT));
    }
    function handleNextPage() {
        setOffset((currentOffset) => currentOffset +
            DEFAULT_LIMIT);
    }
    function handleActionChange(value) {
        setActionFilter(value);
        setOffset(0);
    }
    function handleFirewallChange(value) {
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
    function resetRecoveryFormState() {
        /*
         * Admin Key는 React Component Memory에만 보관하고
         * Modal을 닫을 때 폐기합니다.
         */
        setAdminKey("");
        setReleaseReason("");
        setReleaseConfirmation("");
        setReleaseRequest(null);
        setReleaseSubmitting(false);
        setReleaseError("");
        setPreflight(null);
        setPreflightLoading(false);
        setPreflightError("");
        setRecoveryReason("");
        setRecoveryConfirmation("");
        setRecoveryExecuting(false);
        setRecoveryResult(null);
        setRecoveryError("");
        setRecoveryHistory([]);
        setRecoveryHistoryLoading(false);
        setRecoveryHistoryError("");
        setOutcomeVerification(null);
        setOutcomeVerificationLoading(false);
    }
    function openRecoveryDetail(device) {
        recoveryModalGenerationRef.current += 1;
        resetRecoveryFormState();
        setSelectedIsolatedDevice(device);
    }
    function closeRecoveryDetail() {
        if (releaseSubmitting ||
            preflightLoading ||
            recoveryExecuting ||
            outcomeVerificationLoading) {
            return;
        }
        recoveryModalGenerationRef.current += 1;
        setSelectedIsolatedDevice(null);
        resetRecoveryFormState();
    }
    const verifyRecoveryTargetState = useCallback(async (deviceId, message) => {
        if (!deviceId) {
            return;
        }
        const generation = recoveryModalGenerationRef.current;
        setOutcomeVerificationLoading(true);
        setOutcomeVerification({
            status: "checking",
            message: message ||
                "요청 결과가 불명확하여 서버 상태를 다시 확인하고 있습니다.",
        });
        try {
            const [deviceResult, firewallResult,] = await Promise.allSettled([
                getDeviceDetail(deviceId),
                getFirewallRules({
                    device_id: deviceId,
                    limit: 100,
                    offset: 0,
                }),
            ]);
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            let nextDevice = null;
            if (deviceResult.status ===
                "fulfilled" &&
                deviceResult.value) {
                nextDevice =
                    unwrapApiItem(deviceResult.value);
            }
            const rules = firewallResult.status ===
                "fulfilled" &&
                Array.isArray(firewallResult.value?.items)
                ? firewallResult.value.items
                : [];
            const latestRule = getCurrentFirewallRuleMap(rules).get(deviceId) ??
                null;
            if (nextDevice &&
                String(nextDevice.device_id) === String(deviceId)) {
                setSelectedIsolatedDevice((current) => {
                    if (!current ||
                        String(current.device_id) !==
                            String(deviceId)) {
                        return current;
                    }
                    return {
                        ...current,
                        ...nextDevice,
                        firewall_status: latestRule?.status ??
                            nextDevice
                                .firewall_status ??
                            current
                                .firewall_status ??
                            null,
                        firewall_rule: latestRule ??
                            current.firewall_rule ??
                            null,
                    };
                });
            }
            await loadData(true);
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            const anyVerified = deviceResult.status ===
                "fulfilled" ||
                firewallResult.status ===
                    "fulfilled";
            setOutcomeVerification({
                status: anyVerified
                    ? "checked"
                    : "failed",
                message: anyVerified
                    ? "서버 상태를 다시 조회했습니다. 현재 Trust·Firewall 상태를 확인한 뒤 창을 닫고 다시 열어 다음 작업을 진행해 주세요."
                    : "서버 상태 재조회에도 실패했습니다. 결과를 단정하지 말고 잠시 후 다시 확인해 주세요.",
            });
        }
        catch (err) {
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            setOutcomeVerification({
                status: "failed",
                message: err instanceof Error
                    ? err.message
                    : "서버 상태 재조회에 실패했습니다.",
            });
        }
        finally {
            if (generation ===
                recoveryModalGenerationRef.current) {
                setOutcomeVerificationLoading(false);
            }
        }
    }, [loadData]);
    /* =========================================================
       Recovery History
       ========================================================= */
    const loadRecoveryHistory = useCallback(async (deviceId, currentAdminKey = "") => {
        if (!deviceId) {
            return;
        }
        const generation = recoveryModalGenerationRef.current;
        setRecoveryHistoryLoading(true);
        setRecoveryHistoryError("");
        try {
            const response = await getRecoveryHistory({
                device_id: deviceId,
                limit: 5,
                offset: 0,
            }, currentAdminKey);
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            const items = Array.isArray(response?.items)
                ? response.items
                : Array.isArray(response)
                    ? response
                    : [];
            const mismatchedItem = items.find((item) => item?.device_id &&
                String(item.device_id) !==
                    String(deviceId));
            if (mismatchedItem) {
                throw new Error("다른 기기의 Recovery History 응답이 포함되어 결과를 반영하지 않았습니다.");
            }
            setRecoveryHistory(items);
        }
        catch (err) {
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            setRecoveryHistory([]);
            setRecoveryHistoryError(err instanceof Error
                ? err.message
                : "Recovery History를 불러오지 못했습니다.");
        }
        finally {
            if (generation ===
                recoveryModalGenerationRef.current) {
                setRecoveryHistoryLoading(false);
            }
        }
    }, []);
    /*
     * Recovery History도 관리자 인증이 필요하므로
     * Admin Key 입력 전에는 요청하지 않습니다.
     *
     * 입력된 동일 Admin Key를 사용하되 입력 중 매 키 입력마다
     * 요청하지 않도록 짧게 지연한 뒤 최신 값만 조회합니다.
     */
    const selectedDeviceId = selectedIsolatedDevice?.device_id ??
        null;
    useEffect(() => {
        if (!selectedDeviceId ||
            !adminKey.trim()) {
            setRecoveryHistory([]);
            setRecoveryHistoryError("");
            return undefined;
        }
        const timer = window.setTimeout(() => {
            loadRecoveryHistory(selectedDeviceId, adminKey);
        }, 300);
        return () => {
            window.clearTimeout(timer);
        };
    }, [
        selectedDeviceId,
        adminKey,
        loadRecoveryHistory,
    ]);
    /* =========================================================
       Firewall Release Request
       ========================================================= */
    async function handleCreateReleaseRequest() {
        const device = selectedIsolatedDevice;
        const rule = device?.firewall_rule;
        if (!device?.device_id) {
            return;
        }
        if (!rule?.id) {
            setReleaseError("해제할 Firewall Rule ID를 확인할 수 없습니다.");
            return;
        }
        if (!canReleaseFirewallRule(rule)) {
            setReleaseError("APPLIED 또는 FAILED 상태의 Firewall Rule만 해제 요청할 수 있습니다.");
            return;
        }
        const reason = releaseReason.trim();
        if (!reason) {
            setReleaseError("Firewall 해제 사유를 입력해 주세요.");
            return;
        }
        const expectedConfirmation = getFirewallReleaseConfirmation(rule.id);
        if (releaseConfirmation.trim() !==
            expectedConfirmation) {
            setReleaseError(`확인 문구 ${expectedConfirmation}을 정확히 입력해 주세요.`);
            return;
        }
        if (!adminKey.trim()) {
            setReleaseError("관리자 Key를 입력해 주세요.");
            return;
        }
        const targetDeviceId = device.device_id;
        const targetRuleId = rule.id;
        const generation = recoveryModalGenerationRef.current;
        setReleaseSubmitting(true);
        setReleaseError("");
        setPreflight(null);
        setPreflightError("");
        setRecoveryResult(null);
        setRecoveryError("");
        setOutcomeVerification(null);
        try {
            const rawResponse = await createFirewallReleaseRequest(targetRuleId, {
                reason,
                confirmation: releaseConfirmation.trim(),
                adminKey,
            });
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            const response = validateCommandResponse(rawResponse, {
                deviceId: targetDeviceId,
                firewallRuleId: targetRuleId,
            });
            setReleaseRequest(response);
        }
        catch (err) {
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            const message = err instanceof Error
                ? err.message
                : "Firewall 해제 요청에 실패했습니다.";
            if (isUncertainCommandError(err)) {
                setReleaseError(`${message} 요청이 서버에 전달되었을 가능성이 있어 결과를 단정하지 않습니다.`);
                await verifyRecoveryTargetState(targetDeviceId, "Firewall 해제 요청의 응답이 불명확하여 서버 상태를 다시 확인하고 있습니다.");
            }
            else {
                setReleaseError(message);
            }
        }
        finally {
            if (generation ===
                recoveryModalGenerationRef.current) {
                setReleaseSubmitting(false);
            }
        }
    }
    /* =========================================================
       Recovery Preflight
       ========================================================= */
    async function handlePreflight() {
        const device = selectedIsolatedDevice;
        if (!device?.device_id) {
            return;
        }
        if (!adminKey.trim()) {
            setPreflightError("관리자 Key를 입력해 주세요.");
            return;
        }
        const currentTrustScore = Number(device.trust_score);
        if (!Number.isFinite(currentTrustScore)) {
            setPreflightError("현재 Trust Score를 확인할 수 없습니다.");
            return;
        }
        if (String(device.firewall_status ||
            "").toUpperCase() !==
            "REMOVED") {
            setPreflightError("Firewall Rule이 REMOVED 상태가 된 뒤 Preflight를 실행할 수 있습니다.");
            return;
        }
        const targetDeviceId = device.device_id;
        const generation = recoveryModalGenerationRef.current;
        setPreflightLoading(true);
        setPreflightError("");
        setPreflight(null);
        setRecoveryResult(null);
        setRecoveryError("");
        setOutcomeVerification(null);
        try {
            const rawResponse = await recoveryPreflight({
                device_id: targetDeviceId,
                /*
                 * 중요:
                 * 100이 아니라 현재 Trust Score입니다.
                 */
                expected_trust_score: currentTrustScore,
            }, adminKey);
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            const response = validateCommandResponse(rawResponse, {
                deviceId: targetDeviceId,
            });
            setPreflight(response);
        }
        catch (err) {
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            setPreflightError(err instanceof Error
                ? err.message
                : "Recovery Preflight에 실패했습니다.");
        }
        finally {
            if (generation ===
                recoveryModalGenerationRef.current) {
                setPreflightLoading(false);
            }
        }
    }
    /* =========================================================
       Recovery Execute
       ========================================================= */
    async function handleExecuteRecovery() {
        const device = selectedIsolatedDevice;
        if (!device?.device_id) {
            return;
        }
        if (!preflight ||
            !getPreflightCanExecute(preflight)) {
            setRecoveryError("먼저 Recovery Preflight를 통과해야 합니다.");
            return;
        }
        const runtimeStatus = getRuntimeReleaseStatus(preflight);
        if (runtimeStatus !==
            "VERIFIED_RELEASED") {
            setRecoveryError("Runtime VERIFIED_RELEASED 상태가 확인되지 않았습니다.");
            return;
        }
        const currentTrustScore = getPreflightTrustScore(preflight, device);
        if (currentTrustScore === null) {
            setRecoveryError("Recovery 직전 Trust Score를 확인할 수 없습니다.");
            return;
        }
        const reason = recoveryReason.trim();
        if (!reason) {
            setRecoveryError("Recovery 사유를 입력해 주세요.");
            return;
        }
        if (recoveryConfirmation.trim() !==
            RECOVERY_CONFIRMATION) {
            setRecoveryError(`${RECOVERY_CONFIRMATION}을 정확히 입력해 주세요.`);
            return;
        }
        if (!adminKey.trim()) {
            setRecoveryError("관리자 Key를 입력해 주세요.");
            return;
        }
        const targetDeviceId = device.device_id;
        const generation = recoveryModalGenerationRef.current;
        setRecoveryExecuting(true);
        setRecoveryError("");
        setOutcomeVerification(null);
        try {
            const rawResponse = await executeRecovery({
                device_id: targetDeviceId,
                expected_trust_score: currentTrustScore,
                reason,
                confirmation: recoveryConfirmation.trim(),
            }, adminKey);
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            const response = validateCommandResponse(rawResponse, {
                deviceId: targetDeviceId,
            });
            setRecoveryResult(response);
            await loadRecoveryHistory(targetDeviceId, adminKey);
            await loadData(true);
        }
        catch (err) {
            if (generation !==
                recoveryModalGenerationRef.current) {
                return;
            }
            const message = err instanceof Error
                ? err.message
                : "Recovery 실행에 실패했습니다.";
            if (isUncertainCommandError(err)) {
                setRecoveryError(`${message} 서버에서 실행되었을 가능성이 있어 성공/실패를 단정하지 않습니다.`);
                await verifyRecoveryTargetState(targetDeviceId, "Recovery 응답이 불명확하여 현재 Device·Firewall 상태를 다시 확인하고 있습니다.");
            }
            else {
                setRecoveryError(message);
            }
        }
        finally {
            if (generation ===
                recoveryModalGenerationRef.current) {
                setRecoveryExecuting(false);
            }
        }
    }
    /* =========================================================
       Current Isolation Table
       ========================================================= */
    const isolatedDeviceColumns = [
        {
            key: "device_id",
            header: "Device",
            width: 150,
            render: (value) => (<strong className="device-id" title={value ||
                    ""}>
            {value ||
                    "-"}
          </strong>),
        },
        {
            key: "ip_address",
            header: "IP Address",
            width: 140,
            render: (value) => value ||
                "-",
        },
        {
            key: "status",
            header: "Trust 상태",
            width: 120,
            render: (value, device) => {
                const status = String(value ||
                    getTrustStatus(device.trust_score)).toLowerCase();
                return (<StatusBadge status={status} label={getTrustStatusLabel(status)} size="small"/>);
            },
        },
        {
            key: "trust_score",
            header: "Trust Score",
            align: "center",
            width: 120,
            render: (value) => {
                const status = getTrustStatus(value);
                return (<div className="trust-score">
              <strong>
                {formatNumber(value)}
              </strong>
            </div>);
            },
        },
        {
            key: "firewall_status",
            header: "Firewall 상태",
            width: 140,
            render: (value) => (<StatusBadge status={getFirewallStatusTheme(value)} label={getFirewallStatusLabel(value)} size="small"/>),
        },
        {
            key: "last_seen_at",
            header: "마지막 통신",
            width: 190,
            render: (value) => (<div className="last-seen">
            <span>
              {formatElapsedTime(value)}
            </span>

            <small>
              {formatKST(value)}
            </small>
          </div>),
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
            render: (value) => (<strong className="device-id" title={value ||
                    ""}>
            {value ||
                    "-"}
          </strong>),
        },
        {
            key: "action",
            header: "격리 Action",
            width: 120,
            render: (value) => (<StatusBadge status={getIsolationActionStatus(value)} label={getIsolationActionLabel(value)} size="small"/>),
        },
        {
            key: "firewall_status",
            header: "Firewall 상태",
            width: 140,
            render: (value) => (<StatusBadge status={getFirewallStatusTheme(value)} label={getFirewallStatusLabel(value)} size="small"/>),
        },
        {
            key: "reason",
            header: "Reason",
            width: 280,
            render: (value) => (<span className="description" title={value ||
                    ""}>
            {value ||
                    "-"}
          </span>),
        },
        {
            key: "previous_score",
            header: "이전 Score",
            align: "right",
            width: 100,
            render: (value, item) => formatNumber(value ??
                item
                    .trust_score_before),
        },
        {
            key: "new_score",
            header: "변경 Score",
            align: "right",
            width: 100,
            render: (value, item) => formatNumber(value ??
                item
                    .trust_score),
        },
        {
            key: "trust_score_history_id",
            header: "Trust History",
            align: "right",
            width: 120,
            render: (value) => value ??
                "-",
        },
        {
            key: "trigger_event_id",
            header: "Trigger Event",
            align: "right",
            width: 120,
            render: (value) => value ??
                "-",
        },
        {
            key: "created_at",
            header: "Created At",
            width: 180,
            render: (value) => formatKST(value),
        },
    ];
    /* =========================================================
       Recovery Derived State
       ========================================================= */
    const selectedRecoveryStatus = getRecoveryUiStatus(selectedIsolatedDevice, releaseRequest, preflight);
    const releaseRequestStatus = normalizeReleaseRequestStatus(releaseRequest?.status);
    const selectedRule = selectedIsolatedDevice
        ?.firewall_rule ??
        null;
    const expectedReleaseConfirmation = getFirewallReleaseConfirmation(selectedRule?.id);
    const currentSelectedFirewallStatus = String(selectedIsolatedDevice
        ?.firewall_status ||
        "").toUpperCase();
    const isAdminOperationBusy = releaseSubmitting ||
        preflightLoading ||
        recoveryExecuting;
    const isReleasePolling = releaseRequestStatus ===
        "PENDING";
    const isRecoveryModalLocked = isAdminOperationBusy ||
        outcomeVerificationLoading;
    const hasUncertainOutcome = outcomeVerification?.status ===
        "checking" ||
        outcomeVerification?.status ===
            "failed" ||
        outcomeVerification?.status ===
            "checked";
    const canRequestRelease = canReleaseFirewallRule(selectedRule) &&
        !isReleasePolling &&
        !isAdminOperationBusy &&
        !hasUncertainOutcome;
    const runtimeReleaseStatus = getRuntimeReleaseStatus(preflight);
    const canRunRecovery = Boolean(preflight) &&
        getPreflightCanExecute(preflight) &&
        runtimeReleaseStatus ===
            "VERIFIED_RELEASED" &&
        currentSelectedFirewallStatus ===
            "REMOVED" &&
        !isAdminOperationBusy &&
        !hasUncertainOutcome;
    /* =========================================================
       Render
       ========================================================= */
    return (<div className="isolation-page">
      <PageHeader title="Isolation" description="Trust Score 기반 격리 판단과 실제 Firewall 차단 적용 상태를 함께 확인합니다." updatedAt={lastUpdated
            ? formatKST(lastUpdated)
            : undefined} onRefresh={handleRefresh} refreshing={refreshing}/>

      {pollWarning && (<div className="page-warning-banner" role="alert">
          <div>
            <strong>
              최신 격리 데이터 갱신 실패
            </strong>

            <p>
              {pollWarning} 이전에 조회한 격리 데이터를 계속 표시합니다.
            </p>
          </div>

          <div className="page-warning-actions">
            <span>
              {POLLING_INTERVAL_MS /
                1000}
              초마다 자동으로 다시 요청합니다.
            </span>

            <button type="button" className="button button-secondary" onClick={handleRefresh} disabled={refreshing}>
              지금 다시 시도
            </button>
          </div>
        </div>)}

      <Phase9RuntimePanel />

      {!loading &&
            !error && (<section className="summary-card-grid" aria-label="격리 상태 요약">
            <SummaryCard title="현재 격리" value={formatNumber(isolationSummary.isolated)} description="Trust 상태가 isolated인 기기" status={isolationSummary.isolated >
                0
                ? "isolated"
                : "default"}/>

            <SummaryCard title="Firewall 적용" value={formatNumber(isolationSummary.applied)} description="실제 네트워크 차단 완료" status="normal"/>

            <SummaryCard title="적용 대기" value={formatNumber(isolationSummary.pending)} description="격리 결정 후 차단 적용 대기" status={isolationSummary.pending >
                0
                ? "warning"
                : "default"}/>

            <SummaryCard title="Firewall 실패" value={formatNumber(isolationSummary.failed)} description="차단 규칙 적용 실패" status={isolationSummary.failed >
                0
                ? "danger"
                : "default"}/>

            <SummaryCard title="Firewall 미확인" value={formatNumber(isolationSummary.missing)} description="연결된 Firewall Rule 없음" status={isolationSummary.missing >
                0
                ? "warning"
                : "default"}/>

            <SummaryCard title="전체 격리 이력" value={formatNumber(total)} description="현재 조회 조건의 전체 기록"/>
          </section>)}

      {/* =====================================================
            Current Isolated Devices
            ===================================================== */}

      <section className="panel table-panel">
        <div className="panel-header">
          <div>
            <h2>
              현재 격리된 기기
            </h2>

            <p className="panel-description">
              행을 선택하면 Trust, Firewall 상태와 Recovery 준비 상태를 확인할 수 있습니다.
            </p>
          </div>

          <span className="data-count">
            {formatNumber(isolatedDevicesWithFirewall.length)}
            건
          </span>
        </div>

        <div className="table-scroll">
          <DataTable columns={isolatedDeviceColumns} rows={isolatedDevicesWithFirewall} loading={loading &&
            isolatedDevices.length ===
                0} error={isolatedDevices.length ===
            0
            ? error
            : ""} onRetry={handleRefresh} rowKey="device_id" minWidth={1000} tableLabel="현재 격리된 기기" emptyTitle="현재 격리된 기기가 없습니다." emptyDescription="Trust Score가 격리 기준 아래로 내려간 기기가 없습니다." rowClassName={(device) => {
            if (device.firewall_status ===
                "FAILED") {
                return "row-danger";
            }
            if (device.firewall_status ===
                "PENDING" ||
                !device.firewall_status) {
                return "row-warning";
            }
            return "";
        }} onRowClick={openRecoveryDetail}/>
        </div>
      </section>

      {/* =====================================================
            Isolation History
            ===================================================== */}

      <section className="panel table-panel">
        <div className="panel-header">
          <div>
            <h2>
              격리 이력
            </h2>

            <p className="panel-description">
              행을 선택하면 격리·해제 판단과 연결된 Trust Score History 및 Trigger Event를 확인할 수 있습니다.
            </p>
          </div>

          <button type="button" className="button button-ghost" onClick={handleResetFilters} disabled={loading ||
            refreshing}>
            필터 초기화
          </button>
        </div>

        <div className="filter-grid">
          <div className="filter-item">
            <label htmlFor="isolation-search">
              이력 검색
            </label>

            <input id="isolation-search" type="search" placeholder="device_id, reason, event ID" value={searchText} onChange={(event) => {
            setSearchText(event.target
                .value);
        }}/>
          </div>

          <div className="filter-item">
            <label htmlFor="isolation-action-filter">
              격리 Action
            </label>

            <select id="isolation-action-filter" value={actionFilter} onChange={(event) => {
            handleActionChange(event.target
                .value);
        }}>
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

            <select id="firewall-status-filter" value={firewallFilter} onChange={(event) => {
            handleFirewallChange(event.target
                .value);
        }}>
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
            history.length >
                0 &&
            filteredHistory.length ===
                0 ? (<EmptyState title="검색 조건에 맞는 격리 이력이 없습니다." description="다른 Device ID, 사유 또는 Trigger Event ID를 검색해 주세요." actionLabel="검색 초기화" onAction={() => setSearchText("")}/>) : (<div className="table-scroll">
            <DataTable columns={isolationHistoryColumns} rows={filteredHistory} loading={loading} error={error} onRetry={handleRefresh} rowKey="id" minWidth={1450} tableLabel="격리 이력" emptyTitle="표시할 격리 이력이 없습니다." emptyDescription="아직 격리 또는 격리 해제 기록이 생성되지 않았습니다." rowClassName={(item) => {
                if (item.firewall_status ===
                    "FAILED") {
                    return "row-danger";
                }
                if (item.firewall_status ===
                    "PENDING" ||
                    !item.firewall_status) {
                    return "row-warning";
                }
                return "";
            }} onRowClick={setSelectedHistory}/>
          </div>)}

        {!loading &&
            !error &&
            total > 0 && (<Pagination currentPage={currentPage} totalPages={totalPages} total={total} pageSize={DEFAULT_LIMIT} onPrevious={handlePrevPage} onNext={handleNextPage} disabled={refreshing}/>)}
      </section>

      {/* =====================================================
            Recovery Detail Modal
            ===================================================== */}

      <DetailModal open={Boolean(selectedIsolatedDevice)} title={selectedIsolatedDevice
            ? `${selectedIsolatedDevice.device_id} Recovery`
            : "Recovery"} description="Firewall Release → Runtime Verify → Preflight → Recovery 순서로 안전하게 정상 상태를 복구합니다." onClose={closeRecoveryDetail} closeDisabled={isRecoveryModalLocked} size="large" footer={<>
            <button type="button" className="button button-ghost" onClick={closeRecoveryDetail} disabled={isRecoveryModalLocked}>
              닫기
            </button>

            <button type="button" className="button" onClick={handleExecuteRecovery} disabled={!canRunRecovery}>
              {recoveryExecuting
                ? "Recovery 실행 중..."
                : "Recovery 실행"}
            </button>
          </>}>
        {selectedIsolatedDevice && (<div className="detail">
            {/* ===============================================
                Device Summary
                =============================================== */}

            <section className="detail-grid">
              <div className="detail-item">
                <span>
                  Device ID
                </span>

                <strong>
                  {selectedIsolatedDevice.device_id}
                </strong>
              </div>

              <div className="detail-item">
                <span>
                  IP Address
                </span>

                <strong>
                  {selectedIsolatedDevice.ip_address ||
                "-"}
                </strong>
              </div>

              <div className="detail-item">
                <span>
                  현재 Trust Score
                </span>

                <strong>
                  {formatNumber(selectedIsolatedDevice.trust_score)}
                </strong>
              </div>

              <div className="detail-item">
                <span>
                  Trust 상태
                </span>

                <StatusBadge status={selectedIsolatedDevice.status ||
                getTrustStatus(selectedIsolatedDevice.trust_score)} label={getTrustStatusLabel(selectedIsolatedDevice.status ||
                getTrustStatus(selectedIsolatedDevice.trust_score))}/>
              </div>

              <div className="detail-item">
                <span>
                  Firewall 상태
                </span>

                <StatusBadge status={getFirewallStatusTheme(selectedIsolatedDevice.firewall_status)} label={getFirewallStatusLabel(selectedIsolatedDevice.firewall_status)}/>
              </div>

              <div className="detail-item">
                <span>
                  마지막 통신
                </span>

                <strong>
                  {formatKST(selectedIsolatedDevice.last_seen_at)}
                </strong>
              </div>
            </section>

            {/* ===============================================
                Admin Authentication
                =============================================== */}

            <section className="detail-section">
              <h3>
                관리자 인증
              </h3>

              <div className="recovery-form">
                <div className="filter-item">
                  <label htmlFor="recovery-admin-key">
                    Admin Key
                  </label>

                  <input id="recovery-admin-key" type="password" autoComplete="off" value={adminKey} disabled={isRecoveryModalLocked ||
                isReleasePolling} onChange={(event) => setAdminKey(event
                .target
                .value)} placeholder="관리자 Key 입력"/>

                  <small className="help-text">
                    Admin Key는 이 Modal의 React 메모리에만 보관되며 닫기 또는 새로고침 시 폐기됩니다.
                  </small>
                </div>
              </div>
            </section>

            {/* ===============================================
                Recovery Status
                =============================================== */}

            <section className="detail-section">
              <h3>
                Recovery 준비 상태
              </h3>

              <div className="detail-list">
                <div>
                  <dt>
                    현재 단계
                  </dt>

                  <dd>
                    <StatusBadge status={selectedRecoveryStatus.status} label={selectedRecoveryStatus.label}/>
                  </dd>
                </div>

                <div>
                  <dt>
                    Release Request
                  </dt>

                  <dd>
                    {releaseRequestStatus ? (<StatusBadge status={getReleaseRequestTheme(releaseRequestStatus)} label={getReleaseRequestLabel(releaseRequestStatus)}/>) : ("-")}
                  </dd>
                </div>

                <div>
                  <dt>
                    Preflight
                  </dt>

                  <dd>
                    {preflightLoading
                ? "확인 중..."
                : preflight
                    ? getPreflightCanExecute(preflight)
                        ? "PASS"
                        : preflight.result ||
                            "BLOCKED"
                    : "미실행"}
                  </dd>
                </div>

                <div>
                  <dt>
                    Runtime
                  </dt>

                  <dd>
                    {preflight
                ? getRuntimeReleaseStatus(preflight) ||
                    "-"
                : "-"}
                  </dd>
                </div>

                <div>
                  <dt>
                    검증 Trust Score
                  </dt>

                  <dd>
                    {formatNumber(getPreflightTrustScore(preflight, selectedIsolatedDevice))}
                  </dd>
                </div>
              </div>

              <p className="text-muted">
                {selectedRecoveryStatus.description}
              </p>

              {outcomeVerification && (<div className={`verification-box verification-${outcomeVerification.status}`} role={outcomeVerification.status ===
                    "failed"
                    ? "alert"
                    : "status"}>
                  <strong>
                    {outcomeVerificationLoading
                    ? "결과 재확인 중"
                    : outcomeVerification.status ===
                        "failed"
                        ? "결과 확인 필요"
                        : "서버 상태 재확인 완료"}
                  </strong>
                  <p>
                    {outcomeVerification.message}
                  </p>
                </div>)}
            </section>

            {/* ===============================================
                Current Firewall Rule
                =============================================== */}

            {selectedRule && (<section className="detail-section">
                <h3>
                  현재 Firewall Rule
                </h3>

                <dl className="detail-list">
                  <div>
                    <dt>
                      Rule ID
                    </dt>

                    <dd>
                      {selectedRule.id ??
                    "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Source IP
                    </dt>

                    <dd>
                      {selectedRule.source_ip ||
                    "-"}
                    </dd>
                  </div>

                  <FirewallTrafficFields rule={selectedRule} />

                  <div>
                    <dt>
                      Action
                    </dt>

                    <dd>
                      {selectedRule.action ||
                    "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Status
                    </dt>

                    <dd>
                      <StatusBadge status={getFirewallStatusTheme(selectedRule.status)} label={getFirewallStatusLabel(selectedRule.status)}/>
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Retry Count
                    </dt>

                    <dd>
                      {selectedRule.retry_count ??
                    0}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Last Error
                    </dt>

                    <dd className="break-word">
                      {selectedRule.last_error ||
                    "-"}
                    </dd>
                  </div>
                </dl>
              </section>)}

            <Phase9ScopeExtension key={`${selectedIsolatedDevice.device_id}-${selectedRule?.id ?? "none"}`} rule={selectedRule} adminKey={adminKey} />

            {/* ===============================================
                Step 1 - Firewall Release
                =============================================== */}

            <section className="detail-section">
              <h3>
                1. Firewall 해제 요청
              </h3>

              <p className="text-muted">
                APPLIED 또는 FAILED Firewall Rule의 정확한 ID로 해제를 요청합니다. 실제 차단 해제는 Firewall Worker가 수행합니다. 다른 범위의 규칙이 남아 있으면 이어서 해당 규칙의 해제가 필요합니다.
              </p>

              <div className="recovery-form">
                <div className="filter-item">
                  <label htmlFor="firewall-release-reason">
                    Reason
                  </label>

                  <textarea id="firewall-release-reason" value={releaseReason} onChange={(event) => setReleaseReason(event
                .target
                .value)} placeholder="Firewall 해제 사유" disabled={isRecoveryModalLocked ||
                isReleasePolling ||
                hasUncertainOutcome}/>
                </div>

                <div className="filter-item">
                  <label htmlFor="firewall-release-confirmation">
                    Rule-bound Confirmation
                  </label>

                  <input id="firewall-release-confirmation" type="text" value={releaseConfirmation} onChange={(event) => setReleaseConfirmation(event
                .target
                .value)} placeholder={expectedReleaseConfirmation ||
                "RELEASE-FIREWALL-RULE-{rule_id}"} disabled={isRecoveryModalLocked ||
                isReleasePolling ||
                hasUncertainOutcome}/>

                  {expectedReleaseConfirmation && (<small className="help-text">
                      확인 문구:{" "}
                      <strong>
                        {expectedReleaseConfirmation}
                      </strong>
                    </small>)}
                </div>
              </div>

              <div className="action-row">
                <button type="button" className="button button-danger" onClick={handleCreateReleaseRequest} disabled={!canRequestRelease}>
                  {releaseSubmitting
                ? "해제 요청 중..."
                : releaseRequestStatus ===
                    "PENDING"
                    ? "Firewall Worker 처리 중..."
                    : "Firewall 해제 요청"}
                </button>
              </div>

              {releaseError && (<p className="inline-error" role="alert">
                  {releaseError}
                </p>)}

              {releaseRequest && (<dl className="detail-list result-list">
                  <div>
                    <dt>
                      Request ID
                    </dt>

                    <dd className="break-word">
                      {getReleaseRequestId(releaseRequest) ||
                    "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Status
                    </dt>

                    <dd>
                      <StatusBadge status={getReleaseRequestTheme(releaseRequestStatus)} label={getReleaseRequestLabel(releaseRequestStatus)}/>
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Requested By
                    </dt>

                    <dd>
                      {releaseRequest.requested_by ||
                    "-"}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Requested At
                    </dt>

                    <dd>
                      {formatKST(releaseRequest.requested_at)}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Processed At
                    </dt>

                    <dd>
                      {formatKST(releaseRequest.processed_at)}
                    </dd>
                  </div>

                  <div>
                    <dt>
                      Last Error
                    </dt>

                    <dd className="break-word">
                      {releaseRequest.last_error ||
                    "-"}
                    </dd>
                  </div>
                </dl>)}

              {isReleasePolling && (<p className="command-note">
                  Release Request는 서버에서 계속 처리됩니다. 이 창을 닫아도 서버 작업이 취소된 것으로 간주하지 않습니다.
                </p>)}
            </section>

            {/* ===============================================
                Step 2 - Recovery Preflight
                =============================================== */}

            <section className="detail-section">
              <h3>
                2. Recovery Preflight
              </h3>

              <p className="text-muted">
                Firewall Rule이 REMOVED 상태가 된 뒤 Backend가 Runtime Firewall, 미처리 Detection, Release Request 및 Backup 경로를 다시 검사합니다.
              </p>

              <div className="action-row">
                <button type="button" className="button button-secondary" onClick={handlePreflight} disabled={isAdminOperationBusy ||
                hasUncertainOutcome ||
                currentSelectedFirewallStatus !==
                    "REMOVED"}>
                  {preflightLoading
                ? "Preflight 확인 중..."
                : "Preflight 실행"}
                </button>
              </div>

              {preflightError && (<p className="inline-error" role="alert">
                  {preflightError}
                </p>)}

              {preflight && (<>
                  <dl className="detail-list result-list">
                    <div>
                      <dt>
                        Result
                      </dt>

                      <dd>
                        {preflight.result ||
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        can_execute
                      </dt>

                      <dd>
                        {getPreflightCanExecute(preflight)
                    ? "true"
                    : "false"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Current Status
                      </dt>

                      <dd>
                        {preflight.current_status ||
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Current Trust Score
                      </dt>

                      <dd>
                        {formatNumber(preflight.current_trust_score)}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Runtime
                      </dt>

                      <dd>
                        {getRuntimeReleaseStatus(preflight) ||
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Runtime Rule Count
                      </dt>

                      <dd>
                        {preflight
                    ?.firewall_runtime_verification
                    ?.rule_count ??
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Active Firewall Rules
                      </dt>

                      <dd>
                        {preflight
                    ?.firewall_db_state
                    ?.count ??
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Release Requests
                      </dt>

                      <dd>
                        {preflight
                    ?.firewall_release_request_state
                    ?.count ??
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Unprocessed Detection
                      </dt>

                      <dd>
                        {preflight.unprocessed_detection_count ??
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Backup Check
                      </dt>

                      <dd>
                        {preflight
                    ?.backup_check
                    ?.available ===
                    true
                    ? "AVAILABLE"
                    : preflight
                        ?.backup_check
                        ?.available ===
                        false
                        ? "UNAVAILABLE"
                        : "-"}
                      </dd>
                    </div>
                  </dl>

                  {!getPreflightCanExecute(preflight) && (<div className="page-warning-banner">
                        <div>
                          <strong>
                            Recovery 실행 불가
                          </strong>

                          <p>
                            {preflight.failure_reason ||
                        "Backend Preflight 안전 조건을 통과하지 못했습니다."}
                          </p>

                          {preflight.failure_code && (<p>
                              Failure Code:{" "}
                              <strong>
                                {preflight.failure_code}
                              </strong>
                            </p>)}
                        </div>
                      </div>)}
                </>)}
            </section>

            {/* ===============================================
                Step 3 - Recovery Execute
                =============================================== */}

            <section className="detail-section">
              <h3>
                3. Recovery 승인 및 실행
              </h3>

              <p className="text-muted">
                Preflight가 PASS이고 Runtime이 VERIFIED_RELEASED인 경우에만 Baseline Recovery를 실행할 수 있습니다.
              </p>

              <div className="recovery-form">
                <div className="filter-item">
                  <label htmlFor="recovery-reason">
                    Reason
                  </label>

                  <textarea id="recovery-reason" value={recoveryReason} onChange={(event) => setRecoveryReason(event
                .target
                .value)} placeholder="Recovery 수행 사유" disabled={!canRunRecovery}/>
                </div>

                <div className="filter-item">
                  <label htmlFor="recovery-confirmation">
                    Confirmation
                  </label>

                  <input id="recovery-confirmation" type="text" value={recoveryConfirmation} onChange={(event) => setRecoveryConfirmation(event
                .target
                .value)} placeholder={RECOVERY_CONFIRMATION} disabled={!canRunRecovery}/>

                  <small className="help-text">
                    확인 문구:{" "}
                    <strong>
                      {RECOVERY_CONFIRMATION}
                    </strong>
                  </small>
                </div>
              </div>

              {recoveryError && (<p className="inline-error" role="alert">
                  {recoveryError}
                </p>)}

              {recoveryResult && (<div className="success-box">
                  <strong>
                    {getRecoveryResult(recoveryResult) ===
                    "SUCCESS"
                    ? "Recovery 완료"
                    : `Recovery ${getRecoveryResult(recoveryResult)}`}
                  </strong>

                  <dl className="detail-list">
                    <div>
                      <dt>
                        Operation ID
                      </dt>

                      <dd className="break-word">
                        {getOperationId(recoveryResult) ||
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Result
                      </dt>

                      <dd>
                        {recoveryResult.result ||
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Before
                      </dt>

                      <dd>
                        {recoveryResult.before_status ||
                    "-"}
                        {" / "}
                        {formatNumber(recoveryResult.before_trust_score)}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        After
                      </dt>

                      <dd>
                        {recoveryResult.after_status ||
                    "-"}
                        {" / "}
                        {formatNumber(recoveryResult.after_trust_score)}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Firewall Release
                      </dt>

                      <dd>
                        {recoveryResult.firewall_release_status ||
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Backup Reference
                      </dt>

                      <dd className="break-word">
                        {recoveryResult.backup_reference ||
                    "-"}
                      </dd>
                    </div>

                    <div>
                      <dt>
                        Backup SHA256
                      </dt>

                      <dd className="break-word">
                        {recoveryResult.backup_sha256 ||
                    "-"}
                      </dd>
                    </div>
                  </dl>
                </div>)}
            </section>

            <Phase9PacketPairRecovery key={selectedIsolatedDevice.device_id} adminKey={adminKey} deviceId={selectedIsolatedDevice.device_id} />

            {/* ===============================================
                Recovery History
                =============================================== */}

            <section className="detail-section">
              <h3>
                Recovery History
              </h3>

              {recoveryHistoryLoading ? (<p className="text-muted">
                  Recovery History를 불러오는 중입니다.
                </p>) : recoveryHistoryError ? (<p className="inline-error" role="alert">
                  {recoveryHistoryError}
                </p>) : recoveryHistory.length ===
                0 ? (<p className="text-muted">
                  표시할 Recovery History가 없습니다.
                </p>) : (<div className="history-list">
                  {recoveryHistory.map((item, index) => (<article className="history-item" key={item.operation_id ??
                        item.id ??
                        index}>
                        <strong className="break-word">
                          {item.operation_id ??
                        item.id ??
                        "-"}
                        </strong>

                        <span>
                          {item.result ||
                        "-"}
                        </span>

                        <small>
                          {formatKST(item.requested_at ??
                        item.created_at ??
                        item.completed_at)}
                        </small>
                      </article>))}
                </div>)}
            </section>
          </div>)}
      </DetailModal>

      {/* =====================================================
            Isolation History Detail
            ===================================================== */}

      <DetailModal open={Boolean(selectedHistory)} title={selectedHistory
            ? `격리 이력 #${selectedHistory.id}`
            : "격리 이력 상세"} description={selectedHistory
            ? `${selectedHistory.device_id || "Device 없음"} · ${getIsolationActionLabel(selectedHistory.action)}`
            : undefined} onClose={closeHistoryDetail} size="large" footer={<button type="button" className="button button-secondary" onClick={closeHistoryDetail}>
            닫기
          </button>}>
        {selectedHistory && (<div className="detail">
            <section className="detail-grid">
              <div className="detail-item">
                <span>
                  Device
                </span>

                <strong>
                  {selectedHistory.device_id ||
                "-"}
                </strong>
              </div>

              <div className="detail-item">
                <span>
                  격리 Action
                </span>

                <StatusBadge status={getIsolationActionStatus(selectedHistory.action)} label={getIsolationActionLabel(selectedHistory.action)}/>
              </div>

              <div className="detail-item">
                <span>
                  Firewall 상태
                </span>

                <StatusBadge status={getFirewallStatusTheme(selectedHistory.firewall_status)} label={getFirewallStatusLabel(selectedHistory.firewall_status)}/>
              </div>

              <div className="detail-item">
                <span>
                  이전 Score
                </span>

                <strong>
                  {formatNumber(selectedHistory.previous_score ??
                selectedHistory.trust_score_before)}
                </strong>
              </div>

              <div className="detail-item">
                <span>
                  변경 Score
                </span>

                <strong>
                  {formatNumber(selectedHistory.new_score ??
                selectedHistory.trust_score)}
                </strong>
              </div>

              <div className="detail-item">
                <span>
                  Created At
                </span>

                <strong>
                  {formatKST(selectedHistory.created_at)}
                </strong>
              </div>
            </section>

            <section className="detail-section">
              <h3>
                격리 근거
              </h3>

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

            <section className="detail-section">
              <h3>
                Firewall Rule
              </h3>

              {selectedHistory.firewall_rule ? (<dl className="detail-list">
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

                  <FirewallTrafficFields rule={selectedHistory.firewall_rule} />

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
                </dl>) : (<EmptyState title="연결된 Firewall Rule이 없습니다." description="이 격리 이력의 Trigger Event ID와 일치하는 Firewall Rule이 없습니다. 다른 Device의 Rule을 임의로 연결하지 않습니다." compact/>)}
            </section>
          </div>)}
      </DetailModal>
    </div>);
}
