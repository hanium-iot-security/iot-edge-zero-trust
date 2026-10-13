import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  createDevice,
  createDevicePolicyRevision,
  getDeviceDetail,
  getDevicePolicy,
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

const DEFAULT_LIMIT = 20;
const POLLING_INTERVAL_MS = 10_000;
const IS_DEV = import.meta.env.DEV;
const POLICY_PROFILE = "periodic-sensor-v1";
const DEVICE_TYPES = ["SENSOR", "CAMERA", "ACTUATOR", "OTHER"];
const POLICY_LIMITS = {
  expected_publish_interval: 86_400,
  publish_count_max: 10_000,
  payload_size_max: 1_048_576,
  packet_rate_max: 100_000,
  byte_rate_max: 125_000_000,
};
const DEFAULT_POLICY = {
  expected_publish_interval: "5",
  publish_count_max: "15",
  payload_size_max: "5120",
  packet_rate_max: "10",
  byte_rate_max: "2500",
};
const EMPTY_REGISTRATION_FORM = {
  device_id: "",
  ip_address: "",
  device_type: "SENSOR",
  mqtt_principal: "",
  reason: "",
  ...DEFAULT_POLICY,
};
const EMPTY_POLICY_DRAFT = {
  expected_publish_interval: "",
  publish_count_max: "",
  payload_size_max: "",
  packet_rate_max: "",
  byte_rate_max: "",
  registration_state: "",
  reason: "",
};

function formatKST(value) {
  return formatMqttTimestampKST(value, LEGACY_KST_OPTIONS);
}

function formatNumber(value, maximumFractionDigits = 0) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "-";
  }
  return number.toLocaleString("ko-KR", { maximumFractionDigits });
}

function formatScoreDelta(value) {
  if (value === null || value === undefined || value === "") {
    return "-";
  }
  const number = Number(value);
  if (!Number.isFinite(number)) {
    return "-";
  }
  return number > 0 ? `+${number}` : String(number);
}

function normalizeSearchValue(value) {
  return String(value ?? "").trim().toLowerCase();
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
  return labels[String(status || "").toLowerCase()] || status || "확인 불가";
}

function getRegistrationState(device, policy) {
  return (
    policy?.registration_state ??
    device?.registration_state ??
    device?.registration_status ??
    null
  );
}

function getRegistrationStateLabel(state) {
  const labels = {
    PENDING: "등록 준비 중",
    ACTIVE: "등록 활성",
    DISABLED: "관리 비활성",
  };
  const normalized = String(state || "").toUpperCase();
  return labels[normalized] || "확인 불가";
}

function getRegistrationStateTheme(state) {
  const normalized = String(state || "").toUpperCase();
  if (normalized === "ACTIVE") {
    return "normal";
  }
  if (normalized === "PENDING") {
    return "pending";
  }
  if (normalized === "DISABLED") {
    return "removed";
  }
  return "unknown";
}

function getAutomationLabel(state) {
  const normalized = String(state || "").toUpperCase();
  if (normalized === "ACTIVE") {
    return "자동 대응 적용";
  }
  if (normalized === "PENDING") {
    return "자동 대응 미적용";
  }
  if (normalized === "DISABLED") {
    return "자동 대응 중지";
  }
  return "자동 대응 상태 확인 필요";
}

function getFirewallStatusLabel(status) {
  const labels = {
    PENDING: "적용 대기",
    APPLIED: "차단 적용",
    FAILED: "적용 실패",
    REMOVED: "차단 해제",
  };
  return labels[String(status || "").toUpperCase()] || status || "Firewall 기록 없음";
}

function getFirewallStatusTheme(status) {
  const normalized = String(status || "").toUpperCase();
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
    return { status: "unknown", label: "통신 정보 없음" };
  }
  const elapsedSeconds = elapsedSecondsFromMqttTimestamp(
    lastSeenAt,
    new Date(),
    LEGACY_KST_OPTIONS
  );
  if (elapsedSeconds === null) {
    return { status: "unknown", label: "시간 확인 불가" };
  }
  if (elapsedSeconds <= 30) {
    return { status: "online", label: "최근 통신" };
  }
  if (elapsedSeconds <= 120) {
    return { status: "stale", label: "통신 지연" };
  }
  return { status: "offline", label: "장기 미수신" };
}

function formatElapsedTime(dateString) {
  if (!dateString) {
    return "-";
  }
  const elapsedSeconds = elapsedSecondsFromMqttTimestamp(
    dateString,
    new Date(),
    LEGACY_KST_OPTIONS
  );
  if (elapsedSeconds === null) {
    return "-";
  }
  if (elapsedSeconds < 60) {
    return `${elapsedSeconds}초 전`;
  }
  const elapsedMinutes = Math.floor(elapsedSeconds / 60);
  if (elapsedMinutes < 60) {
    return `${elapsedMinutes}분 전`;
  }
  const elapsedHours = Math.floor(elapsedMinutes / 60);
  if (elapsedHours < 24) {
    return `${elapsedHours}시간 전`;
  }
  return `${Math.floor(elapsedHours / 24)}일 전`;
}

function pickLatestFirewallRule(items, deviceId) {
  const rules = Array.isArray(items) ? items : [];
  return getCurrentFirewallRuleMap(rules).get(deviceId) || null;
}

function normalizePolicyResponse(data) {
  const root = data?.item ?? data ?? {};
  return {
    current: root.current ?? null,
    pending: root.pending ?? null,
    serverTime: root.server_time ?? null,
    latestRevision:
      root.latest_revision === null || root.latest_revision === undefined
        ? null
        : Number(root.latest_revision),
  };
}

function getPolicyRevision(policyInfo) {
  const latest = Number(policyInfo?.latestRevision);
  if (Number.isInteger(latest) && latest >= 1) {
    return latest;
  }
  const current = Number(policyInfo?.current?.revision);
  return Number.isInteger(current) && current >= 1 ? current : null;
}

function getPolicyPayload(policyRevision) {
  if (!policyRevision) {
    return null;
  }
  return policyRevision.policy ?? policyRevision;
}

function policyValue(policyRevision, key) {
  const policy = getPolicyPayload(policyRevision);
  if (!policy) {
    return null;
  }
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
  for (const candidate of aliases[key] || [key]) {
    if (
      policy[candidate] !== null &&
      policy[candidate] !== undefined &&
      policy[candidate] !== ""
    ) {
      return policy[candidate];
    }
  }
  return null;
}

function draftFromPolicy(policy, device) {
  return {
    expected_publish_interval: String(
      policyValue(policy, "expected_publish_interval") ??
        device?.expected_publish_interval ??
        device?.expected_publish_interval_seconds ??
        ""
    ),
    publish_count_max: String(policyValue(policy, "publish_count_max") ?? ""),
    payload_size_max: String(policyValue(policy, "payload_size_max") ?? ""),
    packet_rate_max: String(policyValue(policy, "packet_rate_max") ?? ""),
    byte_rate_max: String(policyValue(policy, "byte_rate_max") ?? ""),
    registration_state: String(
      getRegistrationState(device, policy) || ""
    ).toUpperCase(),
    reason: "",
  };
}

function getPolicyEffectiveFrom(policy) {
  return policy?.effective_from ?? policy?.effective_at ?? null;
}

function getTopic(deviceId) {
  const value = String(deviceId || "").trim();
  return value ? `iot/${value}/sensor` : "iot/{device_id}/sensor";
}

function validateDeviceId(value) {
  const trimmed = value.trim();
  if (!trimmed) {
    return "Device ID를 입력해 주세요.";
  }
  if (trimmed.length > 64 || !/^[A-Za-z0-9._-]+$/.test(trimmed)) {
    return "Device ID는 64자 이하의 영문, 숫자, ., _, -만 사용할 수 있습니다.";
  }
  return "";
}

function isPrivateIpv4(value) {
  const parts = value.trim().split(".");
  if (parts.length !== 4) {
    return false;
  }
  const numbers = parts.map(Number);
  if (
    numbers.some(
      (part, index) =>
        !Number.isInteger(part) ||
        part < 0 ||
        part > 255 ||
        String(part) !== String(Number(parts[index]))
    )
  ) {
    return false;
  }
  const [a, b] = numbers;
  return (
    a === 10 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function validatePositiveNumber(
  value,
  label,
  { integer = false, max = null } = {}
) {
  if (value === "" || value === null || value === undefined) {
    return `${label}을(를) 입력해 주세요.`;
  }
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) {
    return `${label}은(는) 0보다 큰 유한한 숫자여야 합니다.`;
  }
  if (integer && !Number.isInteger(number)) {
    return `${label}은(는) 양의 정수여야 합니다.`;
  }
  if (max !== null && number > max) {
    return `${label}은(는) ${formatNumber(max)} 이하여야 합니다.`;
  }
  return "";
}

function validateRegistrationForm(form) {
  const errors = [];
  const deviceIdError = validateDeviceId(form.device_id);
  if (deviceIdError) {
    errors.push(deviceIdError);
  }
  if (!isPrivateIpv4(form.ip_address)) {
    errors.push("고정 IP는 RFC1918 사설 IPv4 주소여야 합니다.");
  }
  if (!DEVICE_TYPES.includes(form.device_type)) {
    errors.push("Device Type을 확인해 주세요.");
  }
  if (!form.mqtt_principal.trim()) {
    errors.push("MQTT Principal을 입력해 주세요.");
  }
  if (!form.reason.trim()) {
    errors.push("등록 사유를 입력해 주세요.");
  }
  errors.push(
    validatePositiveNumber(
      form.expected_publish_interval,
      "Expected Publish Interval",
      { max: POLICY_LIMITS.expected_publish_interval }
    ),
    validatePositiveNumber(
      form.publish_count_max,
      "Publish Count Max",
      { integer: true, max: POLICY_LIMITS.publish_count_max }
    ),
    validatePositiveNumber(
      form.payload_size_max,
      "Payload Size Max",
      { integer: true, max: POLICY_LIMITS.payload_size_max }
    ),
    validatePositiveNumber(
      form.packet_rate_max,
      "Packet Rate Max",
      { max: POLICY_LIMITS.packet_rate_max }
    ),
    validatePositiveNumber(
      form.byte_rate_max,
      "Byte Rate Max",
      { max: POLICY_LIMITS.byte_rate_max }
    )
  );
  return errors.filter(Boolean);
}

function validatePolicyDraft(draft) {
  const errors = [
    validatePositiveNumber(
      draft.expected_publish_interval,
      "Expected Publish Interval",
      { max: POLICY_LIMITS.expected_publish_interval }
    ),
    validatePositiveNumber(
      draft.publish_count_max,
      "Publish Count Max",
      { integer: true, max: POLICY_LIMITS.publish_count_max }
    ),
    validatePositiveNumber(
      draft.payload_size_max,
      "Payload Size Max",
      { integer: true, max: POLICY_LIMITS.payload_size_max }
    ),
    validatePositiveNumber(
      draft.packet_rate_max,
      "Packet Rate Max",
      { max: POLICY_LIMITS.packet_rate_max }
    ),
    validatePositiveNumber(
      draft.byte_rate_max,
      "Byte Rate Max",
      { max: POLICY_LIMITS.byte_rate_max }
    ),
  ].filter(Boolean);
  if (!draft.registration_state) {
    errors.push("등록 상태를 확인해 주세요.");
  }
  if (!draft.reason.trim()) {
    errors.push("정책 변경 사유를 입력해 주세요.");
  }
  return errors;
}

function isAmbiguousWriteError(error) {
  if (!error || error?.isCanceled) {
    return false;
  }
  return (
    !error.status ||
    error.code === "ERR_NETWORK" ||
    error.code === "ECONNABORTED" ||
    error.code === "ETIMEDOUT"
  );
}

function allowedRegistrationStates(currentState) {
  const normalized = String(currentState || "").toUpperCase();
  if (normalized === "PENDING") {
    return ["PENDING", "ACTIVE", "DISABLED"];
  }
  if (normalized === "ACTIVE") {
    return ["ACTIVE", "DISABLED"];
  }
  if (normalized === "DISABLED") {
    return ["DISABLED"];
  }
  return [normalized].filter(Boolean);
}

export default function Devices() {
  const [devices, setDevices] = useState([]);
  const [firewallRules, setFirewallRules] = useState([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [statusFilter, setStatusFilter] = useState("");
  const [searchText, setSearchText] = useState("");
  const [selectedDevice, setSelectedDevice] = useState(null);
  const [trustHistory, setTrustHistory] = useState([]);
  const [trustHistoryLoading, setTrustHistoryLoading] = useState(false);
  const [trustHistoryError, setTrustHistoryError] = useState("");
  const [policyInfo, setPolicyInfo] = useState({
    current: null,
    pending: null,
    serverTime: null,
    latestRevision: null,
  });
  const [policyLoading, setPolicyLoading] = useState(false);
  const [policyError, setPolicyError] = useState("");
  const [policyDraft, setPolicyDraft] = useState(EMPTY_POLICY_DRAFT);
  const [policyAdminKey, setPolicyAdminKey] = useState("");
  const [policySubmitting, setPolicySubmitting] = useState(false);
  const [policyWriteError, setPolicyWriteError] = useState("");
  const [policyWriteMessage, setPolicyWriteMessage] = useState("");
  const [policyNeedsVerification, setPolicyNeedsVerification] = useState(false);
  const [deviceDetailLoading, setDeviceDetailLoading] = useState(false);
  const [deviceDetailError, setDeviceDetailError] = useState("");
  const [registrationOpen, setRegistrationOpen] = useState(false);
  const [registrationForm, setRegistrationForm] = useState(EMPTY_REGISTRATION_FORM);
  const [registrationAdminKey, setRegistrationAdminKey] = useState("");
  const [registrationSubmitting, setRegistrationSubmitting] = useState(false);
  const [registrationError, setRegistrationError] = useState("");
  const [registrationMessage, setRegistrationMessage] = useState("");
  const [registrationNeedsVerification, setRegistrationNeedsVerification] =
    useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [pollWarning, setPollWarning] = useState("");
  const [lastUpdated, setLastUpdated] = useState("");
  const hasDataRef = useRef(false);
  const listRequestIdRef = useRef(0);
  const listRequestRef = useRef(null);
  const detailRequestIdRef = useRef(0);
  const detailAbortRef = useRef(null);
  const policyDraftInitializedRef = useRef(false);
  const policyDraftBaselineRef = useRef(null);

  const loadData = useCallback(
    async (isManualRefresh = false) => {
      const queryKey = `${offset}|${statusFilter}`;
      const activeRequest = listRequestRef.current;
      if (
        !isManualRefresh &&
        activeRequest?.controller &&
        !activeRequest.controller.signal.aborted &&
        activeRequest.queryKey === queryKey
      ) {
        return;
      }
      activeRequest?.controller?.abort();
      const controller = new AbortController();
      const requestId = ++listRequestIdRef.current;
      listRequestRef.current = { controller, queryKey, requestId };
      if (isManualRefresh) {
        setRefreshing(true);
      }
      try {
        const [deviceData, firewallData] = await Promise.all([
          getDevices(
            {
              limit: DEFAULT_LIMIT,
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
        if (
          controller.signal.aborted ||
          requestId !== listRequestIdRef.current
        ) {
          return;
        }
        const deviceItems = Array.isArray(deviceData?.items)
          ? deviceData.items
          : [];
        const firewallItems = Array.isArray(firewallData?.items)
          ? firewallData.items
          : [];
        const responseTotal = Number(deviceData?.total);
        setDevices(deviceItems);
        setFirewallRules(firewallItems);
        setTotal(
          Number.isFinite(responseTotal) ? responseTotal : deviceItems.length
        );
        setLastUpdated(new Date().toISOString());
        setSelectedDevice((currentDevice) => {
          if (!currentDevice?.device_id) {
            return currentDevice;
          }
          const freshDevice = deviceItems.find(
            (item) => item.device_id === currentDevice.device_id
          );
          if (!freshDevice) {
            return currentDevice;
          }
          const latestFirewallRule = pickLatestFirewallRule(
            firewallItems,
            currentDevice.device_id
          );
          return {
            ...currentDevice,
            ...freshDevice,
            firewall_status:
              latestFirewallRule?.status ??
              freshDevice.firewall_status ??
              currentDevice.firewall_status ??
              null,
            firewall_rule:
              latestFirewallRule ??
              freshDevice.firewall_rule ??
              currentDevice.firewall_rule ??
              null,
          };
        });
        hasDataRef.current = true;
        setError("");
        setPollWarning("");
      } catch (err) {
        if (
          controller.signal.aborted ||
          err?.isCanceled ||
          requestId !== listRequestIdRef.current
        ) {
          return;
        }
        if (IS_DEV) {
          console.error("Devices data load failed:", err);
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
        if (requestId === listRequestIdRef.current) {
          setLoading(false);
          setRefreshing(false);
          if (listRequestRef.current?.requestId === requestId) {
            listRequestRef.current = null;
          }
        }
      }
    },
    [offset, statusFilter]
  );

  useEffect(() => {
    loadData();
    const timer = window.setInterval(() => {
      loadData();
    }, POLLING_INTERVAL_MS);
    return () => {
      window.clearInterval(timer);
    };
  }, [loadData]);

  useEffect(() => {
    return () => {
      listRequestRef.current?.controller?.abort();
      listRequestRef.current = null;
      detailAbortRef.current?.abort();
    };
  }, []);

  const firewallRuleMap = useMemo(
    () => getCurrentFirewallRuleMap(firewallRules),
    [firewallRules]
  );

  const devicesWithFirewall = useMemo(
    () =>
      devices.map((device) => {
        const firewallRule = firewallRuleMap.get(device.device_id);
        return {
          ...device,
          firewall_status:
            firewallRule?.status ?? device.firewall_status ?? null,
          firewall_rule: firewallRule ?? null,
        };
      }),
    [devices, firewallRuleMap]
  );

  const filteredDevices = useMemo(() => {
    const keyword = searchText.trim().toLowerCase();
    if (!keyword) {
      return devicesWithFirewall;
    }
    return devicesWithFirewall.filter(
      (device) =>
        normalizeSearchValue(device.device_id).includes(keyword) ||
        normalizeSearchValue(device.ip_address).includes(keyword) ||
        normalizeSearchValue(device.status).includes(keyword) ||
        normalizeSearchValue(device.registration_state).includes(keyword) ||
        normalizeSearchValue(device.firewall_status).includes(keyword)
    );
  }, [devicesWithFirewall, searchText]);

  const deviceSummary = useMemo(() => {
    const summary = {
      normal: 0,
      warning: 0,
      danger: 0,
      isolated: 0,
      registrationPending: 0,
      registrationActive: 0,
      registrationDisabled: 0,
      registrationUnknown: 0,
      firewallApplied: 0,
      firewallPending: 0,
      firewallFailed: 0,
    };
    devicesWithFirewall.forEach((device) => {
      const trustStatus = String(
        device.status || getTrustStatusFromScore(device.trust_score)
      ).toLowerCase();
      if (
        ["normal", "warning", "danger", "isolated"].includes(trustStatus)
      ) {
        summary[trustStatus] += 1;
      }
      const registrationState = String(
        getRegistrationState(device) || ""
      ).toUpperCase();
      if (registrationState === "PENDING") {
        summary.registrationPending += 1;
      } else if (registrationState === "ACTIVE") {
        summary.registrationActive += 1;
      } else if (registrationState === "DISABLED") {
        summary.registrationDisabled += 1;
      } else {
        summary.registrationUnknown += 1;
      }
      const firewallStatus = String(
        device.firewall_status || ""
      ).toUpperCase();
      if (firewallStatus === "APPLIED") {
        summary.firewallApplied += 1;
      } else if (firewallStatus === "PENDING") {
        summary.firewallPending += 1;
      } else if (firewallStatus === "FAILED") {
        summary.firewallFailed += 1;
      }
    });
    return summary;
  }, [devicesWithFirewall]);

  const currentPage = Math.floor(offset / DEFAULT_LIMIT) + 1;
  const totalPages = Math.max(1, Math.ceil(total / DEFAULT_LIMIT));

  const applyPolicyResponse = useCallback(
    (rawPolicy, device, preserveDraft = false) => {
      const normalized = normalizePolicyResponse(rawPolicy);
      setPolicyInfo(normalized);
      setPolicyError("");
      const nextDraft = draftFromPolicy(normalized.current, device);
      const previousBaseline = policyDraftBaselineRef.current;
      if (!preserveDraft || !policyDraftInitializedRef.current) {
        setPolicyDraft(nextDraft);
        policyDraftInitializedRef.current = true;
      } else {
        setPolicyDraft((current) => {
          const next = { ...current };
          Object.keys(nextDraft).forEach((key) => {
            if (current[key] === previousBaseline?.[key]) {
              next[key] = nextDraft[key];
            }
          });
          return next;
        });
      }
      policyDraftBaselineRef.current = nextDraft;
      return normalized;
    },
    []
  );

  const refreshDetailAndPolicy = useCallback(
    async (deviceId, { preserveDraft = true } = {}) => {
      if (!deviceId) {
        return false;
      }
      const requestId = ++detailRequestIdRef.current;
      setPolicyLoading(true);
      try {
        const [detailResult, policyResult] = await Promise.allSettled([
          getDeviceDetail(deviceId),
          getDevicePolicy(deviceId),
        ]);
        if (requestId !== detailRequestIdRef.current) {
          return false;
        }
        const latestDevice =
          detailResult.status === "fulfilled"
            ? detailResult.value?.item ?? detailResult.value ?? null
            : null;
        if (latestDevice) {
          setSelectedDevice((current) =>
            current?.device_id === deviceId
              ? { ...current, ...latestDevice }
              : current
          );
        }
        if (policyResult.status === "fulfilled") {
          applyPolicyResponse(
            policyResult.value,
            latestDevice,
            preserveDraft
          );
        } else {
          setPolicyError(
            policyResult.reason instanceof Error
              ? policyResult.reason.message
              : "기기 정책을 다시 불러오지 못했습니다. 재시도해 주세요."
          );
        }
        return policyResult.status === "fulfilled";
      } catch (err) {
        if (requestId === detailRequestIdRef.current) {
          setPolicyError(
            err instanceof Error
              ? err.message
              : "기기 정책을 다시 불러오지 못했습니다. 재시도해 주세요."
          );
        }
        return false;
      } finally {
        if (requestId === detailRequestIdRef.current) {
          setPolicyLoading(false);
        }
      }
    },
    [applyPolicyResponse]
  );

  async function openDeviceDetail(device) {
    if (!device?.device_id || policySubmitting) {
      return;
    }
    const deviceId = device.device_id;
    detailAbortRef.current?.abort();
    const controller = new AbortController();
    const requestId = ++detailRequestIdRef.current;
    detailAbortRef.current = controller;
    policyDraftInitializedRef.current = false;
    setSelectedDevice(device);
    setDeviceDetailLoading(true);
    setDeviceDetailError("");
    setTrustHistory([]);
    setTrustHistoryError("");
    setTrustHistoryLoading(true);
    setPolicyInfo({
      current: null,
      pending: null,
      serverTime: null,
      latestRevision: null,
    });
    setPolicyLoading(true);
    setPolicyError("");
    setPolicyDraft(EMPTY_POLICY_DRAFT);
    setPolicyAdminKey("");
    setPolicyWriteError("");
    setPolicyWriteMessage("");
    setPolicyNeedsVerification(false);
    const [detailResult, firewallResult, historyResult, policyResult] =
      await Promise.allSettled([
        getDeviceDetail(deviceId, { signal: controller.signal }),
        getFirewallRules(
          { device_id: deviceId, limit: 100, offset: 0 },
          { signal: controller.signal }
        ),
        getTrustScoreHistory(
          deviceId,
          { limit: 50, offset: 0 },
          { signal: controller.signal }
        ),
        getDevicePolicy(deviceId, { signal: controller.signal }),
      ]);
    if (
      controller.signal.aborted ||
      requestId !== detailRequestIdRef.current
    ) {
      return;
    }
    let latestDevice = device;
    if (detailResult.status === "fulfilled") {
      latestDevice =
        detailResult.value?.item ?? detailResult.value ?? device;
      setSelectedDevice((current) =>
        current?.device_id === deviceId
          ? { ...current, ...latestDevice }
          : current
      );
    } else if (!detailResult.reason?.isCanceled) {
      setDeviceDetailError(
        detailResult.reason instanceof Error
          ? detailResult.reason.message
          : "최신 기기 상세 상태를 불러오지 못했습니다."
      );
    }
    if (firewallResult.status === "fulfilled") {
      const firewallItems = Array.isArray(firewallResult.value?.items)
        ? firewallResult.value.items
        : [];
      const latestFirewallRule = pickLatestFirewallRule(
        firewallItems,
        deviceId
      );
      setSelectedDevice((current) =>
        current?.device_id === deviceId
          ? {
              ...current,
              firewall_status:
                latestFirewallRule?.status ??
                current.firewall_status ??
                null,
              firewall_rule:
                latestFirewallRule ?? current.firewall_rule ?? null,
            }
          : current
      );
    } else if (!firewallResult.reason?.isCanceled) {
      setDeviceDetailError((current) =>
        current ||
        (firewallResult.reason instanceof Error
          ? firewallResult.reason.message
          : "최신 Firewall 상태를 불러오지 못했습니다.")
      );
    }
    if (historyResult.status === "fulfilled") {
      setTrustHistory(
        Array.isArray(historyResult.value?.items)
          ? historyResult.value.items
          : []
      );
      setTrustHistoryError("");
    } else if (!historyResult.reason?.isCanceled) {
      setTrustHistoryError(
        historyResult.reason instanceof Error
          ? historyResult.reason.message
          : "Trust Score 이력을 불러오지 못했습니다."
      );
    }
    if (policyResult.status === "fulfilled") {
      applyPolicyResponse(policyResult.value, latestDevice, false);
    } else if (!policyResult.reason?.isCanceled) {
      setPolicyError(
        policyResult.reason instanceof Error
          ? policyResult.reason.message
          : "기기 정책을 불러오지 못했습니다."
      );
    }
    if (requestId === detailRequestIdRef.current) {
      setDeviceDetailLoading(false);
      setTrustHistoryLoading(false);
      setPolicyLoading(false);
      if (detailAbortRef.current === controller) {
        detailAbortRef.current = null;
      }
    }
  }

  function closeDeviceDetail() {
    if (policySubmitting) {
      return;
    }
    detailRequestIdRef.current += 1;
    detailAbortRef.current?.abort();
    detailAbortRef.current = null;
    policyDraftInitializedRef.current = false;
    setSelectedDevice(null);
    setDeviceDetailLoading(false);
    setDeviceDetailError("");
    setTrustHistory([]);
    setTrustHistoryLoading(false);
    setTrustHistoryError("");
    setPolicyInfo({
      current: null,
      pending: null,
      serverTime: null,
      latestRevision: null,
    });
    setPolicyLoading(false);
    setPolicyError("");
    setPolicyDraft(EMPTY_POLICY_DRAFT);
    setPolicyAdminKey("");
    setPolicyWriteError("");
    setPolicyWriteMessage("");
    setPolicyNeedsVerification(false);
  }

  function openRegistration() {
    setRegistrationForm(EMPTY_REGISTRATION_FORM);
    setRegistrationAdminKey("");
    setRegistrationError("");
    setRegistrationMessage("");
    setRegistrationNeedsVerification(false);
    setRegistrationOpen(true);
  }

  function closeRegistration() {
    if (registrationSubmitting) {
      return;
    }
    setRegistrationOpen(false);
    setRegistrationForm(EMPTY_REGISTRATION_FORM);
    setRegistrationAdminKey("");
    setRegistrationError("");
    setRegistrationMessage("");
    setRegistrationNeedsVerification(false);
  }

  async function handleCreateDevice() {
    if (registrationSubmitting) {
      return;
    }
    const validationErrors = validateRegistrationForm(registrationForm);
    if (!registrationAdminKey.trim()) {
      validationErrors.push("관리자 Key를 입력해 주세요.");
    }
    if (validationErrors.length > 0) {
      setRegistrationError(validationErrors.join(" "));
      return;
    }
    const payload = {
      device_id: registrationForm.device_id.trim(),
      ip_address: registrationForm.ip_address.trim(),
      device_type: registrationForm.device_type,
      mqtt_principal: registrationForm.mqtt_principal.trim(),
      policy: {
        policy_profile: POLICY_PROFILE,
        expected_publish_interval_seconds: Number(
          registrationForm.expected_publish_interval
        ),
        publish_count_max: Number(registrationForm.publish_count_max),
        payload_size_max_bytes: Number(registrationForm.payload_size_max),
        packet_rate_max_pps: Number(registrationForm.packet_rate_max),
        byte_rate_max_bytes_per_second: Number(
          registrationForm.byte_rate_max
        ),
      },
      reason: registrationForm.reason.trim(),
    };
    setRegistrationSubmitting(true);
    setRegistrationError("");
    setRegistrationMessage("");
    setRegistrationNeedsVerification(false);
    try {
      const response = await createDevice(
        payload,
        registrationAdminKey
      );
      const createdDevice = response?.device ?? null;
      const createdDeviceId =
        createdDevice?.device_id ?? payload.device_id;
      const [detailResult, policyResult] = await Promise.allSettled([
        getDeviceDetail(createdDeviceId),
        getDevicePolicy(createdDeviceId),
      ]);
      const verified =
        detailResult.status === "fulfilled" ||
        policyResult.status === "fulfilled";
      setRegistrationMessage(
        verified
          ? `${createdDeviceId} 등록 후 서버 재조회까지 확인했습니다. 신규 기기는 PENDING 상태를 확인한 뒤 사용하세요.`
          : `${createdDeviceId} 등록 응답은 받았지만 재조회에 실패했습니다. 결과 확인이 필요합니다.`
      );
      setRegistrationNeedsVerification(!verified);
      await loadData(true);
    } catch (err) {
      if (isAmbiguousWriteError(err)) {
        setRegistrationNeedsVerification(true);
        setRegistrationMessage(
          "응답을 확정할 수 없어 등록 결과 확인이 필요합니다. 같은 요청을 자동 재전송하지 않고 서버를 재조회합니다."
        );
        try {
          const [detailResult, policyResult] = await Promise.allSettled([
            getDeviceDetail(payload.device_id),
            getDevicePolicy(payload.device_id),
          ]);
          if (
            detailResult.status === "fulfilled" ||
            policyResult.status === "fulfilled"
          ) {
            setRegistrationMessage(
              "응답은 유실되었지만 재조회에서 등록 결과가 확인되었습니다. 목록을 갱신했습니다."
            );
            setRegistrationNeedsVerification(false);
            await loadData(true);
          }
        } catch {
          setRegistrationNeedsVerification(true);
        }
      } else {
        setRegistrationError(
          err instanceof Error ? err.message : "기기 등록에 실패했습니다."
        );
        if (err?.status === 409) {
          await loadData(true);
        }
      }
    } finally {
      setRegistrationSubmitting(false);
    }
  }

  async function handleSavePolicy() {
    if (!selectedDevice?.device_id || policySubmitting) {
      return;
    }
    const validationErrors = validatePolicyDraft(policyDraft);
    if (!policyAdminKey.trim()) {
      validationErrors.push("관리자 Key를 입력해 주세요.");
    }
    const revision = getPolicyRevision(policyInfo);
    if (revision === null || revision === undefined) {
      validationErrors.push("현재 Policy Revision을 확인할 수 없습니다.");
    }
    if (policyInfo.pending) {
      validationErrors.push(
        "이미 적용 예정 정책이 있어 새 변경을 저장할 수 없습니다."
      );
    }
    if (validationErrors.length > 0) {
      setPolicyWriteError(validationErrors.join(" "));
      return;
    }
    const deviceId = selectedDevice.device_id;
    const payload = {
      expected_revision: revision,
      registration_state: policyDraft.registration_state,
      policy: {
        policy_profile:
          getPolicyPayload(currentPolicy)?.policy_profile ?? POLICY_PROFILE,
        expected_publish_interval_seconds: Number(
          policyDraft.expected_publish_interval
        ),
        publish_count_max: Number(policyDraft.publish_count_max),
        payload_size_max_bytes: Number(policyDraft.payload_size_max),
        packet_rate_max_pps: Number(policyDraft.packet_rate_max),
        byte_rate_max_bytes_per_second: Number(policyDraft.byte_rate_max),
      },
      reason: policyDraft.reason.trim(),
    };
    setPolicySubmitting(true);
    setPolicyWriteError("");
    setPolicyWriteMessage("");
    setPolicyNeedsVerification(false);
    try {
      await createDevicePolicyRevision(
        deviceId,
        payload,
        policyAdminKey
      );
      policyDraftInitializedRef.current = false;
      const verified = await refreshDetailAndPolicy(deviceId, {
        preserveDraft: false,
      });
      setPolicyWriteMessage(
        verified
          ? "정책 변경 요청이 저장되었습니다. 현재 정책과 적용 예정 정책을 서버에서 다시 조회했습니다."
          : "저장 응답은 받았지만 재조회에 실패했습니다. 결과 확인이 필요합니다."
      );
      setPolicyNeedsVerification(!verified);
      await loadData(true);
    } catch (err) {
      if (err?.status === 409) {
        setPolicyWriteError(
          `${err.message} 최신 revision과 적용 예정 정책을 다시 조회했습니다.`
        );
        await refreshDetailAndPolicy(deviceId, { preserveDraft: true });
      } else if (isAmbiguousWriteError(err)) {
        setPolicyNeedsVerification(true);
        setPolicyWriteMessage(
          "응답 유실 또는 타임아웃 가능성이 있어 결과 확인이 필요합니다. 자동 재전송하지 않고 상세/정책을 재조회합니다."
        );
        const verified = await refreshDetailAndPolicy(deviceId, {
          preserveDraft: true,
        });
        if (verified) {
          setPolicyWriteMessage(
            "정책 저장 응답은 확정할 수 없지만 서버 재조회는 완료했습니다. 현재/예정 revision을 확인한 뒤 추가 변경을 진행해 주세요."
          );
        }
      } else {
        setPolicyWriteError(
          err instanceof Error ? err.message : "정책 변경에 실패했습니다."
        );
      }
    } finally {
      setPolicySubmitting(false);
    }
  }

  const pendingEffectiveFromForRefresh =
    getPolicyEffectiveFrom(policyInfo.pending);
  const pendingRevisionForRefresh =
    policyInfo.pending?.revision ??
    policyInfo.pending?.policy_revision ??
    null;

  useEffect(() => {
    if (!selectedDevice?.device_id || !pendingEffectiveFromForRefresh) {
      return undefined;
    }
    const effectiveAt = new Date(pendingEffectiveFromForRefresh).getTime();
    if (!Number.isFinite(effectiveAt)) {
      return undefined;
    }
    const delay = Math.max(effectiveAt - Date.now() + 750, 250);
    const timer = window.setTimeout(() => {
      refreshDetailAndPolicy(selectedDevice.device_id, {
        preserveDraft: true,
      });
      loadData(true);
    }, delay);
    return () => window.clearTimeout(timer);
  }, [
    loadData,
    pendingEffectiveFromForRefresh,
    pendingRevisionForRefresh,
    refreshDetailAndPolicy,
    selectedDevice?.device_id,
  ]);

  function handleRefresh() {
    loadData(true);
  }

  function handleStatusChange(value) {
    setLoading(true);
    setStatusFilter(value);
    setOffset(0);
  }

  function handleResetFilters() {
    setLoading(true);
    setSearchText("");
    setStatusFilter("");
    setOffset(0);
  }

  function handleRegistrationField(key, value) {
    setRegistrationForm((current) => ({ ...current, [key]: value }));
  }

  function handlePolicyField(key, value) {
    setPolicyDraft((current) => ({ ...current, [key]: value }));
    setPolicyWriteError("");
    setPolicyWriteMessage("");
  }

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
        const state = value || getRegistrationState(device);
        return (
          <div className="registration-cell">
            <StatusBadge
              status={getRegistrationStateTheme(state)}
              label={getRegistrationStateLabel(state)}
              size="small"
            />
            <small>{getAutomationLabel(state)}</small>
          </div>
        );
      },
    },
    {
      key: "status",
      header: "Trust 상태",
      width: 120,
      render: (value, device) => {
        const trustStatus =
          value || getTrustStatusFromScore(device.trust_score);
        return (
          <StatusBadge
            status={trustStatus}
            label={getTrustStatusLabel(trustStatus)}
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
        const trustStatus = getTrustStatusFromScore(value);
        return (
          <div className="score-cell">
            <strong>{formatNumber(value, 0)}</strong>
            <div className="score-bar">
              <div
                className={`score-fill score-${trustStatus}`}
                style={{
                  width: `${Math.min(
                    Math.max(Number(value) || 0, 0),
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
          status={getFirewallStatusTheme(value)}
          label={getFirewallStatusLabel(value)}
          size="small"
        />
      ),
    },
    {
      key: "last_seen_at",
      header: "마지막 통신",
      width: 190,
      render: (value) => {
        const communicationStatus = getLastSeenStatus(value);
        return (
          <div className="last-seen">
            <StatusBadge
              status={communicationStatus.status}
              label={communicationStatus.label}
              size="small"
            />
            <span>{formatElapsedTime(value)}</span>
            <small>{formatKST(value)}</small>
          </div>
        );
      },
    },
  ];

  const currentPolicy = policyInfo.current;
  const pendingPolicy = policyInfo.pending;
  const currentRegistrationState = getRegistrationState(
    selectedDevice,
    currentPolicy
  );
  const stateOptions = allowedRegistrationStates(currentRegistrationState);

  return (
    <div className="devices-page">
      <PageHeader
        title="Devices"
        description="등록 상태, Trust Score, 정책 revision, 실제 Firewall 상태를 서로 분리해 확인합니다."
        updatedAt={lastUpdated ? formatKST(lastUpdated) : undefined}
        onRefresh={handleRefresh}
        refreshing={refreshing}
      />

      <section className="device-admin-bar">
        <div>
          <strong>Device Administration</strong>
          <p>
            신규 기기는 PENDING으로 등록되며 Broker 준비·수신 확인 전에는 자동 감점·차단이 적용되지 않습니다.
          </p>
        </div>
        <button
          type="button"
          className="button"
          onClick={openRegistration}
        >
          + 기기 등록
        </button>
      </section>

      {pollWarning && (
        <div className="page-warning-banner" role="alert">
          <div>
            <strong>최신 기기 상태 갱신 실패</strong>
            <p>{pollWarning} 이전 기기 데이터를 계속 표시합니다.</p>
          </div>
          <div className="page-warning-actions">
            <span>{POLLING_INTERVAL_MS / 1000}초마다 자동으로 다시 요청합니다.</span>
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

      {!loading && !error && devices.length > 0 && (
        <>
          <section className="summary-card-grid" aria-label="등록 상태 요약">
            <SummaryCard
              title="등록 준비"
              value={formatNumber(deviceSummary.registrationPending)}
              description="PENDING · 자동 대응 미적용"
              status={deviceSummary.registrationPending > 0 ? "warning" : "default"}
            />
            <SummaryCard
              title="등록 활성"
              value={formatNumber(deviceSummary.registrationActive)}
              description="ACTIVE · 정책에 따라 자동 대응"
              status="normal"
            />
            <SummaryCard
              title="관리 비활성"
              value={formatNumber(deviceSummary.registrationDisabled)}
              description="DISABLED · 새 자동 대응 중지"
              status={deviceSummary.registrationDisabled > 0 ? "warning" : "default"}
            />
            <SummaryCard
              title="등록 상태 확인 불가"
              value={formatNumber(deviceSummary.registrationUnknown)}
              description="Migration/backfill 또는 정책 상태 확인 필요"
              status={deviceSummary.registrationUnknown > 0 ? "warning" : "default"}
            />
          </section>
          <section className="summary-card-grid" aria-label="Trust 상태 요약">
            <SummaryCard
              title="전체 기기"
              value={formatNumber(total)}
              description="현재 조회 조건에 해당하는 등록 기기"
            />
            <SummaryCard
              title="점수 양호"
              value={formatNumber(deviceSummary.normal)}
              description="Trust Score 80 이상 · 등록 활성 여부와 별개"
              status="normal"
            />
            <SummaryCard
              title="주의"
              value={formatNumber(deviceSummary.warning)}
              description="Trust Score 60~79"
              status="warning"
            />
            <SummaryCard
              title="위험"
              value={formatNumber(deviceSummary.danger)}
              description="Trust Score 30~59"
              status="danger"
            />
            <SummaryCard
              title="격리"
              value={formatNumber(deviceSummary.isolated)}
              description="Trust Score 30 미만"
              status="isolated"
            />
            <SummaryCard
              title="Firewall 적용"
              value={formatNumber(deviceSummary.firewallApplied)}
              description="실제 차단 규칙 적용"
              status="normal"
            />
            <SummaryCard
              title="Firewall 대기"
              value={formatNumber(deviceSummary.firewallPending)}
              description="차단 적용 대기"
              status={deviceSummary.firewallPending > 0 ? "warning" : "default"}
            />
            <SummaryCard
              title="Firewall 실패"
              value={formatNumber(deviceSummary.firewallFailed)}
              description="차단 규칙 적용 실패"
              status={deviceSummary.firewallFailed > 0 ? "danger" : "default"}
            />
          </section>
        </>
      )}

      <section className="panel">
        <div className="panel-header">
          <div>
            <h2>조회 조건</h2>
            <p className="panel-description">
              Trust 상태 필터는 서버 조회에 적용되고 검색어는 현재 페이지 결과에 적용됩니다.
            </p>
          </div>
          <button
            type="button"
            className="button button-ghost"
            onClick={handleResetFilters}
            disabled={loading || refreshing}
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
              placeholder="device_id, IP, 등록 상태"
              value={searchText}
              onChange={(event) => setSearchText(event.target.value)}
            />
          </div>
          <div className="filter-item">
            <label htmlFor="device-status-filter">Trust 상태</label>
            <select
              id="device-status-filter"
              value={statusFilter}
              onChange={(event) => handleStatusChange(event.target.value)}
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
              등록 상태, Trust 상태, 실제 Firewall 상태를 서로 독립적으로 표시합니다.
            </p>
          </div>
          <span className="data-count">
            {formatNumber(filteredDevices.length)}건 표시
          </span>
        </div>
        {loading && devices.length === 0 ? (
          <LoadingState
            title="기기 목록을 불러오는 중입니다."
            description="등록 상태, Trust Score와 Firewall 상태를 함께 확인하고 있습니다."
          />
        ) : error && devices.length === 0 ? (
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
            description="다른 Device ID, IP Address 또는 등록 상태를 검색해 주세요."
            actionLabel="검색 초기화"
            onAction={() => setSearchText("")}
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
              minWidth={1260}
              tableLabel="등록 기기 목록"
              emptyTitle="표시할 등록 기기가 없습니다."
              emptyDescription="기기 등록 작업이 완료되었는지 확인해 주세요."
              rowClassName={(device) => {
                if (device.firewall_status === "FAILED") {
                  return "row-danger";
                }
                if (
                  device.status === "isolated" ||
                  getRegistrationState(device) === "PENDING"
                ) {
                  return "row-warning";
                }
                return "";
              }}
              onRowClick={openDeviceDetail}
            />
          </div>
        )}
        {!loading && !error && total > 0 && (
          <Pagination
            currentPage={currentPage}
            totalPages={totalPages}
            total={total}
            pageSize={DEFAULT_LIMIT}
            onPrevious={() =>
              setOffset((currentOffset) =>
                Math.max(0, currentOffset - DEFAULT_LIMIT)
              )
            }
            onNext={() =>
              setOffset((currentOffset) => currentOffset + DEFAULT_LIMIT)
            }
            disabled={refreshing}
          />
        )}
      </section>

      <DetailModal
        open={registrationOpen}
        title="신규 기기 등록"
        description="Application 등록만 수행합니다. Broker 계정 생성·비밀번호 저장은 포함하지 않습니다."
        onClose={closeRegistration}
        closeDisabled={registrationSubmitting}
        size="large"
        footer={
          <>
            <button
              type="button"
              className="button button-ghost"
              onClick={closeRegistration}
              disabled={registrationSubmitting}
            >
              닫기
            </button>
            <button
              type="button"
              className="button"
              onClick={handleCreateDevice}
              disabled={registrationSubmitting}
            >
              {registrationSubmitting ? "등록 중..." : "PENDING으로 등록"}
            </button>
          </>
        }
      >
        <div className="detail">
          <section className="detail-section">
            <h3>기기 정보</h3>
            <div className="admin-form">
              <div className="filter-item">
                <label htmlFor="register-device-id">Device ID</label>
                <input
                  id="register-device-id"
                  value={registrationForm.device_id}
                  onChange={(event) =>
                    handleRegistrationField("device_id", event.target.value)
                  }
                  disabled={registrationSubmitting}
                  placeholder="pico_01"
                />
              </div>
              <div className="filter-item">
                <label htmlFor="register-ip">고정 IP</label>
                <input
                  id="register-ip"
                  value={registrationForm.ip_address}
                  onChange={(event) =>
                    handleRegistrationField("ip_address", event.target.value)
                  }
                  disabled={registrationSubmitting}
                  placeholder="192.168.0.50"
                />
              </div>
              <div className="filter-item">
                <label htmlFor="register-device-type">Device Type</label>
                <select
                  id="register-device-type"
                  value={registrationForm.device_type}
                  onChange={(event) =>
                    handleRegistrationField("device_type", event.target.value)
                  }
                  disabled={registrationSubmitting}
                >
                  {DEVICE_TYPES.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
                <small className="help-text">
                  Backend 계약상 SENSOR/CAMERA/ACTUATOR/OTHER 중 하나를 사용합니다.
                </small>
              </div>
              <div className="filter-item">
                <label htmlFor="register-principal">MQTT Principal</label>
                <input
                  id="register-principal"
                  value={registrationForm.mqtt_principal}
                  onChange={(event) =>
                    handleRegistrationField("mqtt_principal", event.target.value)
                  }
                  disabled={registrationSubmitting}
                  placeholder="pico_01"
                />
              </div>
              <div className="filter-item full-width">
                <label htmlFor="register-reason">등록 사유</label>
                <input
                  id="register-reason"
                  value={registrationForm.reason}
                  onChange={(event) =>
                    handleRegistrationField("reason", event.target.value)
                  }
                  disabled={registrationSubmitting}
                  placeholder="예: Pico WH 신규 센서 등록"
                />
                <small className="help-text">
                  DeviceRegistrationRequest의 필수 reason 필드입니다.
                </small>
              </div>
              <div className="filter-item">
                <label htmlFor="register-interval">
                  Expected Publish Interval
                </label>
                <div className="input-with-unit">
                  <input
                    id="register-interval"
                    type="number"
                    min="0.000001"
                    max="86400"
                    step="0.1"
                    value={registrationForm.expected_publish_interval}
                    onChange={(event) =>
                      handleRegistrationField(
                        "expected_publish_interval",
                        event.target.value
                      )
                    }
                    disabled={registrationSubmitting}
                  />
                  <span>seconds</span>
                </div>
                <small className="help-text">
                  설명용 값입니다. 기존 30초/120초 미수신 기준을 변경하지 않습니다.
                </small>
              </div>
              <div className="filter-item">
                <label>자동 산출 Topic</label>
                <div className="readonly-value">
                  {getTopic(registrationForm.device_id)}
                </div>
                <small className="help-text">
                  Topic은 서버가 Device ID로 산출하며 비밀번호는 저장하지 않습니다.
                </small>
              </div>
            </div>
          </section>

          <section className="detail-section">
            <h3>기본 Rule 정책</h3>
            <div className="policy-form-grid">
              <div className="filter-item">
                <label htmlFor="register-publish-max">Publish Count Max</label>
                <div className="input-with-unit">
                  <input
                    id="register-publish-max"
                    type="number"
                    min="1"
                    max="10000"
                    step="1"
                    value={registrationForm.publish_count_max}
                    onChange={(event) =>
                      handleRegistrationField(
                        "publish_count_max",
                        event.target.value
                      )
                    }
                    disabled={registrationSubmitting}
                  />
                  <span>messages / 10s</span>
                </div>
              </div>
              <div className="filter-item">
                <label htmlFor="register-payload-max">Payload Size Max</label>
                <div className="input-with-unit">
                  <input
                    id="register-payload-max"
                    type="number"
                    min="1"
                    max="1048576"
                    step="1"
                    value={registrationForm.payload_size_max}
                    onChange={(event) =>
                      handleRegistrationField(
                        "payload_size_max",
                        event.target.value
                      )
                    }
                    disabled={registrationSubmitting}
                  />
                  <span>bytes</span>
                </div>
              </div>
              <div className="filter-item">
                <label htmlFor="register-packet-max">Packet Rate Max</label>
                <div className="input-with-unit">
                  <input
                    id="register-packet-max"
                    type="number"
                    min="0.000001"
                    max="100000"
                    step="0.1"
                    value={registrationForm.packet_rate_max}
                    onChange={(event) =>
                      handleRegistrationField(
                        "packet_rate_max",
                        event.target.value
                      )
                    }
                    disabled={registrationSubmitting}
                  />
                  <span>packets/s</span>
                </div>
              </div>
              <div className="filter-item">
                <label htmlFor="register-byte-max">Byte Rate Max</label>
                <div className="input-with-unit">
                  <input
                    id="register-byte-max"
                    type="number"
                    min="0.000001"
                    max="125000000"
                    step="0.1"
                    value={registrationForm.byte_rate_max}
                    onChange={(event) =>
                      handleRegistrationField(
                        "byte_rate_max",
                        event.target.value
                      )
                    }
                    disabled={registrationSubmitting}
                  />
                  <span>bytes/s</span>
                </div>
              </div>
            </div>
            <p className="policy-note">
              현재 코드 이관 기본값은 Publish 15/10초, Payload 5120B, Packet 10/s,
              Byte 2500B/s입니다. 운영 override가 있으면 Backend 기준값을 우선해야 합니다.
            </p>
          </section>

          <section className="detail-section">
            <h3>관리자 인증</h3>
            <div className="admin-form">
              <div className="filter-item full-width">
                <label htmlFor="register-admin-key">Admin Key</label>
                <input
                  id="register-admin-key"
                  type="password"
                  autoComplete="off"
                  value={registrationAdminKey}
                  onChange={(event) =>
                    setRegistrationAdminKey(event.target.value)
                  }
                  disabled={registrationSubmitting}
                  placeholder="관리자 Key 입력"
                />
                <small className="help-text">
                  이 Modal의 React 메모리에만 보관되며 닫기 또는 새로고침 시 폐기됩니다.
                </small>
              </div>
            </div>
          </section>

          {registrationError && (
            <p className="inline-error" role="alert">
              {registrationError}
            </p>
          )}
          {registrationMessage && (
            <div
              className={
                registrationNeedsVerification
                  ? "verification-box verification-checking"
                  : "verification-box verification-checked"
              }
              role="status"
            >
              <strong>
                {registrationNeedsVerification
                  ? "결과 확인 필요"
                  : "등록 결과 확인"}
              </strong>
              <p>{registrationMessage}</p>
            </div>
          )}
        </div>
      </DetailModal>

      <DetailModal
        open={Boolean(selectedDevice)}
        title={
          selectedDevice
            ? `${selectedDevice.device_id} 상세 상태`
            : "기기 상세 상태"
        }
        description={
          selectedDevice
            ? `${selectedDevice.ip_address || "IP 없음"} · 등록/Trust/Firewall 상태를 분리해 표시합니다.`
            : undefined
        }
        onClose={closeDeviceDetail}
        closeDisabled={policySubmitting}
        size="large"
        footer={
          <>
            <button
              type="button"
              className="button button-secondary"
              onClick={closeDeviceDetail}
              disabled={policySubmitting}
            >
              닫기
            </button>
            <button
              type="button"
              className="button"
              onClick={handleSavePolicy}
              disabled={
                policySubmitting ||
                policyLoading ||
                !currentPolicy ||
                Boolean(pendingPolicy)
              }
            >
              {policySubmitting ? "정책 저장 중..." : "정책 변경 저장"}
            </button>
          </>
        }
      >
        {selectedDevice && (
          <div className="detail">
            {deviceDetailLoading && (
              <LoadingState
                title="최신 기기 상태와 정책을 확인하는 중입니다."
                compact
              />
            )}
            {deviceDetailError && !deviceDetailLoading && (
              <ErrorState
                title="일부 최신 상태를 확인하지 못했습니다."
                message={deviceDetailError}
                onRetry={() => openDeviceDetail(selectedDevice)}
                compact
              />
            )}

            <section className="detail-grid">
              <div className="detail-item">
                <span>Device ID</span>
                <strong>{selectedDevice.device_id}</strong>
              </div>
              <div className="detail-item">
                <span>IP Address</span>
                <strong>{selectedDevice.ip_address || "-"}</strong>
              </div>
              <div className="detail-item">
                <span>Device Type</span>
                <strong>{selectedDevice.device_type || "-"}</strong>
              </div>
              <div className="detail-item">
                <span>MQTT Principal</span>
                <strong>{selectedDevice.mqtt_principal || "-"}</strong>
              </div>
              <div className="detail-item">
                <span>Topic</span>
                <strong>
                  {selectedDevice.mqtt_topic || getTopic(selectedDevice.device_id)}
                </strong>
              </div>
              <div className="detail-item">
                <span>등록 상태</span>
                <StatusBadge
                  status={getRegistrationStateTheme(currentRegistrationState)}
                  label={getRegistrationStateLabel(currentRegistrationState)}
                />
                <small className="detail-helper">
                  {getAutomationLabel(currentRegistrationState)}
                </small>
              </div>
              <div className="detail-item">
                <span>Trust 상태</span>
                <StatusBadge
                  status={
                    selectedDevice.status ||
                    getTrustStatusFromScore(selectedDevice.trust_score)
                  }
                  label={getTrustStatusLabel(
                    selectedDevice.status ||
                      getTrustStatusFromScore(selectedDevice.trust_score)
                  )}
                />
              </div>
              <div className="detail-item">
                <span>현재 Trust Score</span>
                <strong>{formatNumber(selectedDevice.trust_score)}</strong>
                {String(currentRegistrationState).toUpperCase() === "PENDING" &&
                  Number(selectedDevice.trust_score) === 100 && (
                    <small className="detail-helper">
                      초기 100점은 보안 검증 완료를 의미하지 않습니다.
                    </small>
                  )}
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
                <strong>{formatKST(selectedDevice.last_seen_at)}</strong>
              </div>
            </section>

            <section className="detail-section">
              <div className="section-heading">
                <div>
                  <h3>현재 / 적용 예정 정책</h3>
                  <p>
                    적용 완료 여부는 브라우저 시계가 아니라 서버의 정책 API 재조회 결과로 판단합니다.
                  </p>
                </div>
                <button
                  type="button"
                  className="button button-ghost"
                  onClick={() =>
                    refreshDetailAndPolicy(selectedDevice.device_id, {
                      preserveDraft: true,
                    })
                  }
                  disabled={policyLoading || policySubmitting}
                >
                  정책 새로고침
                </button>
              </div>
              {policyLoading ? (
                <LoadingState title="기기 정책을 불러오는 중입니다." compact />
              ) : policyError ? (
                <ErrorState
                  title="기기 정책을 불러오지 못했습니다."
                  message={policyError}
                  onRetry={() =>
                    refreshDetailAndPolicy(selectedDevice.device_id, {
                      preserveDraft: true,
                    })
                  }
                  compact
                />
              ) : (
                <div className="policy-state-grid">
                  <article className="policy-card">
                    <div className="policy-card-header">
                      <strong>현재 정책</strong>
                      <StatusBadge status="normal" label="CURRENT" size="small" />
                    </div>
                    {currentPolicy ? (
                      <dl className="policy-list">
                        <div>
                          <dt>Revision</dt>
                          <dd>{currentPolicy.revision ?? "-"}</dd>
                        </div>
                        <div>
                          <dt>Registration</dt>
                          <dd>{getRegistrationStateLabel(currentRegistrationState)}</dd>
                        </div>
                        <div>
                          <dt>Policy Profile</dt>
                          <dd>
                            {getPolicyPayload(currentPolicy)?.policy_profile || "-"}
                          </dd>
                        </div>
                        <div>
                          <dt>Expected Interval</dt>
                          <dd>{formatNumber(policyValue(currentPolicy, "expected_publish_interval"), 2)} s</dd>
                        </div>
                        <div>
                          <dt>Publish Count Max</dt>
                          <dd>{formatNumber(policyValue(currentPolicy, "publish_count_max"))} / 10s</dd>
                        </div>
                        <div>
                          <dt>Payload Size Max</dt>
                          <dd>{formatNumber(policyValue(currentPolicy, "payload_size_max"))} B</dd>
                        </div>
                        <div>
                          <dt>Packet Rate Max</dt>
                          <dd>{formatNumber(policyValue(currentPolicy, "packet_rate_max"), 2)} packets/s</dd>
                        </div>
                        <div>
                          <dt>Byte Rate Max</dt>
                          <dd>{formatNumber(policyValue(currentPolicy, "byte_rate_max"), 2)} B/s</dd>
                        </div>
                        <div>
                          <dt>Effective From</dt>
                          <dd>{formatKST(getPolicyEffectiveFrom(currentPolicy))}</dd>
                        </div>
                      </dl>
                    ) : (
                      <p className="text-muted">현재 정책을 확인할 수 없습니다.</p>
                    )}
                  </article>
                  <article className="policy-card">
                    <div className="policy-card-header">
                      <strong>적용 예정 정책</strong>
                      <StatusBadge
                        status={pendingPolicy ? "pending" : "unknown"}
                        label={pendingPolicy ? "PENDING" : "없음"}
                        size="small"
                      />
                    </div>
                    {pendingPolicy ? (
                      <dl className="policy-list">
                        <div>
                          <dt>Revision</dt>
                          <dd>
                            {pendingPolicy.revision ??
                              pendingPolicy.policy_revision ??
                              "-"}
                          </dd>
                        </div>
                        <div>
                          <dt>Registration</dt>
                          <dd>
                            {getRegistrationStateLabel(
                              getRegistrationState(selectedDevice, pendingPolicy)
                            )}
                          </dd>
                        </div>
                        <div>
                          <dt>Policy Profile</dt>
                          <dd>
                            {getPolicyPayload(pendingPolicy)?.policy_profile || "-"}
                          </dd>
                        </div>
                        <div>
                          <dt>Expected Interval</dt>
                          <dd>
                            {formatNumber(
                              policyValue(
                                pendingPolicy,
                                "expected_publish_interval"
                              ),
                              2
                            )}{" "}
                            s
                          </dd>
                        </div>
                        <div>
                          <dt>Publish Count Max</dt>
                          <dd>
                            {formatNumber(
                              policyValue(pendingPolicy, "publish_count_max")
                            )}{" "}
                            / 10s
                          </dd>
                        </div>
                        <div>
                          <dt>Payload Size Max</dt>
                          <dd>
                            {formatNumber(
                              policyValue(pendingPolicy, "payload_size_max")
                            )}{" "}
                            B
                          </dd>
                        </div>
                        <div>
                          <dt>Packet Rate Max</dt>
                          <dd>
                            {formatNumber(
                              policyValue(pendingPolicy, "packet_rate_max"),
                              2
                            )}{" "}
                            packets/s
                          </dd>
                        </div>
                        <div>
                          <dt>Byte Rate Max</dt>
                          <dd>
                            {formatNumber(
                              policyValue(pendingPolicy, "byte_rate_max"),
                              2
                            )}{" "}
                            B/s
                          </dd>
                        </div>
                        <div>
                          <dt>Effective From</dt>
                          <dd>{formatKST(getPolicyEffectiveFrom(pendingPolicy))}</dd>
                        </div>
                      </dl>
                    ) : (
                      <p className="text-muted">
                        적용 대기 중인 revision이 없습니다.
                      </p>
                    )}
                  </article>
                </div>
              )}
            </section>

            <section className="detail-section">
              <h3>기기별 Rule 정책 변경</h3>
              <p className="text-muted">
                편집 초안은 현재/예정 정책과 분리되어 자동 polling이 입력값을 덮어쓰지 않습니다.
              </p>
              <div className="policy-form-grid">
                <div className="filter-item">
                  <label htmlFor="policy-registration-state">등록 상태</label>
                  <select
                    id="policy-registration-state"
                    value={policyDraft.registration_state}
                    onChange={(event) =>
                      handlePolicyField(
                        "registration_state",
                        event.target.value
                      )
                    }
                    disabled={policySubmitting || Boolean(pendingPolicy)}
                  >
                    {stateOptions.length === 0 && (
                      <option value="">확인 불가</option>
                    )}
                    {stateOptions.map((state) => (
                      <option key={state} value={state}>
                        {getRegistrationStateLabel(state)}
                      </option>
                    ))}
                  </select>
                  <small className="help-text">
                    PENDING→ACTIVE, PENDING/ACTIVE→DISABLED만 지원하며 DISABLED 재활성화는 이번 범위에서 제외합니다.
                  </small>
                </div>
                <div className="filter-item">
                  <label htmlFor="policy-interval">
                    Expected Publish Interval
                  </label>
                  <div className="input-with-unit">
                    <input
                      id="policy-interval"
                      type="number"
                      min="0.000001"
                      max="86400"
                      step="0.1"
                      value={policyDraft.expected_publish_interval}
                      onChange={(event) =>
                        handlePolicyField(
                          "expected_publish_interval",
                          event.target.value
                        )
                      }
                      disabled={policySubmitting || Boolean(pendingPolicy)}
                    />
                    <span>seconds</span>
                  </div>
                </div>
                <div className="filter-item">
                  <label htmlFor="policy-publish-max">Publish Count Max</label>
                  <div className="input-with-unit">
                    <input
                      id="policy-publish-max"
                      type="number"
                      min="1"
                      max="10000"
                      step="1"
                      value={policyDraft.publish_count_max}
                      onChange={(event) =>
                        handlePolicyField(
                          "publish_count_max",
                          event.target.value
                        )
                      }
                      disabled={policySubmitting || Boolean(pendingPolicy)}
                    />
                    <span>messages / 10s</span>
                  </div>
                </div>
                <div className="filter-item">
                  <label htmlFor="policy-payload-max">Payload Size Max</label>
                  <div className="input-with-unit">
                    <input
                      id="policy-payload-max"
                      type="number"
                      min="1"
                      max="1048576"
                      step="1"
                      value={policyDraft.payload_size_max}
                      onChange={(event) =>
                        handlePolicyField(
                          "payload_size_max",
                          event.target.value
                        )
                      }
                      disabled={policySubmitting || Boolean(pendingPolicy)}
                    />
                    <span>bytes</span>
                  </div>
                </div>
                <div className="filter-item">
                  <label htmlFor="policy-packet-max">Packet Rate Max</label>
                  <div className="input-with-unit">
                    <input
                      id="policy-packet-max"
                      type="number"
                      min="0.000001"
                      max="100000"
                      step="0.1"
                      value={policyDraft.packet_rate_max}
                      onChange={(event) =>
                        handlePolicyField(
                          "packet_rate_max",
                          event.target.value
                        )
                      }
                      disabled={policySubmitting || Boolean(pendingPolicy)}
                    />
                    <span>packets/s</span>
                  </div>
                </div>
                <div className="filter-item">
                  <label htmlFor="policy-byte-max">Byte Rate Max</label>
                  <div className="input-with-unit">
                    <input
                      id="policy-byte-max"
                      type="number"
                      min="0.000001"
                      max="125000000"
                      step="0.1"
                      value={policyDraft.byte_rate_max}
                      onChange={(event) =>
                        handlePolicyField(
                          "byte_rate_max",
                          event.target.value
                        )
                      }
                      disabled={policySubmitting || Boolean(pendingPolicy)}
                    />
                    <span>bytes/s</span>
                  </div>
                </div>
                <div className="filter-item full-width">
                  <label htmlFor="policy-reason">변경 사유</label>
                  <textarea
                    id="policy-reason"
                    value={policyDraft.reason}
                    onChange={(event) =>
                      handlePolicyField("reason", event.target.value)
                    }
                    disabled={policySubmitting || Boolean(pendingPolicy)}
                    placeholder="정책 변경 사유"
                  />
                </div>
                <div className="filter-item full-width">
                  <label htmlFor="policy-admin-key">Admin Key</label>
                  <input
                    id="policy-admin-key"
                    type="password"
                    autoComplete="off"
                    value={policyAdminKey}
                    onChange={(event) =>
                      setPolicyAdminKey(event.target.value)
                    }
                    disabled={policySubmitting}
                    placeholder="관리자 Key 입력"
                  />
                  <small className="help-text">
                    메모리에만 보관하며 상세 창을 닫거나 다른 기기를 열면 폐기됩니다.
                  </small>
                </div>
              </div>
              {pendingPolicy && (
                <div className="verification-box verification-checking">
                  <strong>적용 예정 revision 존재</strong>
                  <p>
                    새 변경은 저장하지 않습니다. 서버의 다음 UTC 10초 효력 경계 이후 자동으로 정책을 재조회합니다.
                  </p>
                </div>
              )}
              {policyWriteError && (
                <p className="inline-error" role="alert">
                  {policyWriteError}
                </p>
              )}
              {policyWriteMessage && (
                <div
                  className={
                    policyNeedsVerification
                      ? "verification-box verification-checking"
                      : "verification-box verification-checked"
                  }
                  role="status"
                >
                  <strong>
                    {policyNeedsVerification ? "결과 확인 필요" : "정책 결과"}
                  </strong>
                  <p>{policyWriteMessage}</p>
                </div>
              )}
            </section>

            {selectedDevice.firewall_rule && (
              <section className="detail-section">
                <h3>Firewall Rule</h3>
                <dl className="detail-list">
                  <div>
                    <dt>Source IP</dt>
                    <dd>{selectedDevice.firewall_rule.source_ip || "-"}</dd>
                  </div>
                  <FirewallTrafficFields rule={selectedDevice.firewall_rule} />
                  <div>
                    <dt>Action</dt>
                    <dd>{selectedDevice.firewall_rule.action || "-"}</dd>
                  </div>
                  <div>
                    <dt>Retry Count</dt>
                    <dd>{selectedDevice.firewall_rule.retry_count ?? 0}</dd>
                  </div>
                  <div>
                    <dt>Last Error</dt>
                    <dd className="break-word">
                      {selectedDevice.firewall_rule.last_error || "-"}
                    </dd>
                  </div>
                </dl>
              </section>
            )}

            <section className="detail-section">
              <div className="section-heading">
                <div>
                  <h3>Trust Score 이력</h3>
                  <p>
                    Frontend에서 Event Delta를 다시 계산하지 않고 API의 실제 Score 변화값을 표시합니다.
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
                  message={trustHistoryError}
                  onRetry={() => openDeviceDetail(selectedDevice)}
                  compact
                />
              ) : trustHistory.length === 0 ? (
                <EmptyState
                  title="Trust Score 변화 이력이 없습니다."
                  description="현재 기기에 저장된 Trust Window 이력이 없습니다."
                  compact
                />
              ) : (
                <div className="history-list">
                  {trustHistory.map((history) => (
                    <article className="history-item" key={history.id}>
                      <div className="history-score">
                        <strong>
                          {formatNumber(history.previous_score)}
                        </strong>
                        <span>→</span>
                        <strong>{formatNumber(history.new_score)}</strong>
                      </div>
                      <div className="history-meta">
                        <StatusBadge
                          status={
                            Number(history.actual_delta) < 0
                              ? "danger"
                              : "normal"
                          }
                          label={`실제 변화 ${formatScoreDelta(
                            history.actual_delta
                          )}`}
                          size="small"
                        />
                        <span>{formatKST(history.analysis_window_start)}</span>
                        <span>~</span>
                        <span>{formatKST(history.analysis_window_end)}</span>
                      </div>
                      <dl className="history-info">
                        <div>
                          <dt>계산 Delta</dt>
                          <dd>
                            {formatScoreDelta(history.calculated_delta)}
                          </dd>
                        </div>
                        <div>
                          <dt>상한 적용 Delta</dt>
                          <dd>{formatScoreDelta(history.capped_delta)}</dd>
                        </div>
                        <div>
                          <dt>대표 Event</dt>
                          <dd>
                            {Array.isArray(history.representative_event_ids) &&
                            history.representative_event_ids.length > 0
                              ? history.representative_event_ids.join(", ")
                              : "-"}
                          </dd>
                        </div>
                        <div>
                          <dt>Policy</dt>
                          <dd>{history.policy_version || "-"}</dd>
                        </div>
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
