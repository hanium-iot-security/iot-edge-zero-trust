
import axios from "axios";

import {
  mockSummary,
  mockDevices,
  mockMqttLogs,
  mockFeatureLogs,
  mockEvents,
  mockIsolationHistory,
  mockTrustScoreSummary,
  mockTrustScoreHistories,
  mockPacketFeatureLogs,
  mockGatewayMetrics,
  mockFirewallRules,
  mockHealth,
} from "../mockData";

/* =========================================================
   API Environment
========================================================= */

const API_BASE_URL = (
  import.meta.env.VITE_API_BASE_URL ||
  "http://127.0.0.1:8001/api"
).replace(/\/+$/, "");

const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true";
const IS_DEV = import.meta.env.DEV;

if (IS_DEV) {
  console.log("[ENV CHECK]", {
    API_BASE_URL,
    USE_MOCK,
  });
}

/* =========================================================
   Common Helpers
========================================================= */

function removeEmptyParams(params = {}) {
  return Object.fromEntries(
    Object.entries(params).filter(
      ([, value]) =>
        value !== undefined &&
        value !== null &&
        value !== ""
    )
  );
}

function normalizePagination(
  params = {},
  { defaultLimit = 20, defaultOffset = 0 } = {}
) {
  const parsedLimit = Number(params.limit);
  const parsedOffset = Number(params.offset);

  return {
    limit:
      Number.isFinite(parsedLimit) && parsedLimit > 0
        ? parsedLimit
        : defaultLimit,
    offset:
      Number.isFinite(parsedOffset) && parsedOffset >= 0
        ? parsedOffset
        : defaultOffset,
  };
}

function paginateMockItems(
  items,
  params = {},
  defaultLimit = 20
) {
  const safeItems = Array.isArray(items) ? items : [];

  const { limit, offset } = normalizePagination(params, {
    defaultLimit,
  });

  return {
    items: safeItems.slice(offset, offset + limit),
    total: safeItems.length,
  };
}

function encodeId(id, label = "ID") {
  if (id === undefined || id === null || String(id) === "") {
    throw new Error(`${label}가 필요합니다.`);
  }

  return encodeURIComponent(String(id));
}

function requireAdminKey(adminKey) {
  if (!String(adminKey ?? "").trim()) {
    throw new Error("관리자 Key를 입력해 주세요.");
  }
}

function requireReason(reason) {
  const value = String(reason ?? "").trim();

  if (!value) {
    throw new Error("변경 사유를 입력해 주세요.");
  }

  return value;
}

function createApiErrorMessage(error) {
  if (axios.isCancel(error) || error.name === "CanceledError") {
    return "요청이 취소되었습니다.";
  }

  const status = error.response?.status;
  const body = error.response?.data;
  const detail = body?.detail;

  if (typeof detail === "string") {
    if (status === 401 && detail === "RECOVERY_ADMIN_UNAUTHORIZED") {
      return "관리자 인증에 실패했습니다. 입력한 관리자 인증키를 확인해 주세요.";
    }
    if (status === 503 && detail === "RECOVERY_ADMIN_NOT_CONFIGURED") {
      return "서버에 관리자 인증키가 설정되지 않아 관리자 기능을 사용할 수 없습니다. 서버 설정을 확인해 주세요.";
    }
    if (status === 404 && detail.trim() === "Not Found") {
      return "요청한 API 또는 자료를 찾을 수 없습니다. 서버 API 버전을 확인해 주세요. (404)";
    }
    return detail;
  }

  if (Array.isArray(detail)) {
    const message = detail
      .map((item) => item?.msg)
      .filter(Boolean)
      .join(", ");

    if (message) return message;
  }

  if (detail && typeof detail === "object") {
    const message = [
      detail.message,
      detail.reason,
      detail.error,
      detail.detail,
    ].find(
      (value) =>
        typeof value === "string" && value.trim()
    );

    if (message) return message.trim();
  }

  if (typeof body?.message === "string" && body.message.trim()) {
    return body.message.trim();
  }

  if (error.code === "ERR_NETWORK" || !error.response) {
    return "백엔드 서버에 연결할 수 없습니다.";
  }

  if (status === 401) {
    return "관리자 인증에 실패했습니다.";
  }

  if (status === 403) {
    return "요청을 수행할 권한이 없습니다.";
  }

  if (status === 404) {
    return "요청한 데이터를 찾을 수 없습니다.";
  }

  if (status === 409) {
    return "현재 상태에서는 요청을 수행할 수 없습니다.";
  }

  if (status === 422) {
    return "요청 조건을 확인해 주세요.";
  }

  if (status === 503) {
    return "관리자 기능을 사용할 수 없습니다.";
  }

  if (status >= 500) {
    return "서버에서 데이터를 처리하지 못했습니다.";
  }

  if (status) {
    return `API 요청에 실패했습니다. (${status})`;
  }

  return "API 요청에 실패했습니다.";
}

function toApiError(error) {
  const apiError = new Error(createApiErrorMessage(error));

  apiError.status = error.response?.status ?? null;
  apiError.code = error.code ?? null;
  apiError.responseData = error.response?.data ?? null;
  apiError.isCanceled =
    axios.isCancel(error) ||
    error.name === "CanceledError";

  return apiError;
}

/* =========================================================
   Common GET Request
========================================================= */

async function request(
  path,
  mockData,
  params = {},
  options = {}
) {
  const validParams = removeEmptyParams(params);

  if (USE_MOCK) {
    if (IS_DEV) {
      console.log("[MOCK]", path, validParams);
    }

    return mockData;
  }

  try {
    const response = await axios.get(
      `${API_BASE_URL}${path}`,
      {
        params: validParams,
        headers: {
          Accept: "application/json",
        },
        signal: options.signal,
        ...(options.timeout ? { timeout: options.timeout } : {}),
      }
    );

    if (IS_DEV) {
      console.log("[API]", path, validParams, response.data);
    }

    return response.data;
  } catch (error) {
    if (IS_DEV && !axios.isCancel(error)) {
      console.error("[API ERROR]", {
        path,
        params: validParams,
        status: error.response?.status,
        code: error.code,
      });
    }

    throw toApiError(error);
  }
}

/* =========================================================
   Common Admin Command Request

   Admin Key는 요청 헤더로만 전달합니다.
   요청 Body, 인증키, 확인 문자열은 로그에 출력하지 않습니다.
========================================================= */

async function commandRequest(
  method,
  path,
  {
    data = undefined,
    params = {},
    adminKey = "",
    signal,
    timeout,
    mockData = undefined,
  } = {}
) {
  const validParams = removeEmptyParams(params);

  if (USE_MOCK) {
    if (IS_DEV) {
      console.log("[MOCK COMMAND]", {
        method,
        path,
        // 관리자 파라미터 내용은 기록하지 않습니다.
      });
    }

    if (mockData !== undefined) {
      return mockData;
    }

    throw new Error(
      "Mock 모드에서는 실제 관리자 Write Command를 실행하지 않습니다."
    );
  }

  try {
    const response = await axios({
      method,
      url: `${API_BASE_URL}${path}`,
      data,
      params: validParams,
      headers: {
        Accept: "application/json",
        ...(data !== undefined
          ? { "Content-Type": "application/json" }
          : {}),
        ...(adminKey
          ? { "X-Recovery-Admin-Key": adminKey }
          : {}),
      },
      signal,
      ...(timeout ? { timeout } : {}),
    });

    if (IS_DEV) {
      console.log("[API COMMAND]", {
        method,
        path,
        status: response.status,
      });
    }

    return response.data;
  } catch (error) {
    if (IS_DEV && !axios.isCancel(error)) {
      console.error("[API COMMAND ERROR]", {
        method,
        path,
        status: error.response?.status,
        code: error.code,
      });
    }

    throw toApiError(error);
  }
}

/* =========================================================
   Dashboard
========================================================= */

export function getSummary(options = {}) {
  return request(
    "/dashboard/summary",
    mockSummary,
    {},
    options
  );
}

/* =========================================================
   Devices
========================================================= */

export function getDevices(params = {}, options = {}) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let items = Array.isArray(mockDevices.items)
    ? [...mockDevices.items]
    : [];

  if (queryParams.include_hidden !== true && queryParams.include_hidden !== "true") {
    items = items.filter((item) => !item.hidden_at);
  }

  if (queryParams.status) {
    items = items.filter(
      (item) => item.status === queryParams.status
    );
  }

  if (queryParams.device_id) {
    items = items.filter(
      (item) => item.device_id === queryParams.device_id
    );
  }

  return request(
    "/devices",
    paginateMockItems(items, queryParams),
    queryParams,
    options
  );
}

export function getDeviceDetail(deviceId, options = {}) {
  if (!deviceId) {
    return Promise.reject(
      new Error("조회할 Device ID가 필요합니다.")
    );
  }

  const mockDevice = Array.isArray(mockDevices.items)
    ? mockDevices.items.find(
        (item) => item.device_id === deviceId
      ) ?? null
    : null;

  return request(
    `/devices/${encodeId(deviceId, "Device ID")}`,
    mockDevice,
    {},
    options
  );
}

export async function createDevice(
  payload,
  adminKey,
  options = {}
) {
  if (!payload?.device_id) {
    throw new Error("Device ID가 필요합니다.");
  }

  requireAdminKey(adminKey);

  return commandRequest("POST", "/devices", {
    data: payload,
    adminKey,
    signal: options.signal,
    timeout: options.timeout ?? 15000,
  });
}

export function getDevicePolicy(deviceId, options = {}) {
  if (!deviceId) {
    return Promise.reject(
      new Error("정책을 조회할 Device ID가 필요합니다.")
    );
  }

  return request(
    `/devices/${encodeId(deviceId)}/policy`,
    null,
    {},
    options
  );
}

export function getDeviceManagement(deviceId, options = {}) {
  return request(
    `/devices/${encodeId(deviceId, "Device ID")}/management`,
    null,
    {},
    { ...options, timeout: options.timeout ?? 15000 }
  );
}

export async function executeDeviceManagement(deviceId, payload, adminKey, options = {}) {
  const id = encodeId(deviceId, "Device ID");
  if (!["DELETE_UNUSED", "HIDE", "RESTORE"].includes(payload?.action)) {
    throw new Error("기기 관리 작업을 선택해 주세요.");
  }
  if (![payload?.expected_revision, payload?.expected_ai_revision]
    .every((revision) => Number.isInteger(revision) && revision > 0) ||
      !(payload?.expected_instance_id === null || typeof payload?.expected_instance_id === "string") ||
      !(payload?.expected_hidden_at === null || typeof payload?.expected_hidden_at === "string") ||
      !(payload?.expected_management_operation_id === null || (typeof payload?.expected_management_operation_id === "string" &&
        payload.expected_management_operation_id.length > 0 && payload.expected_management_operation_id.length <= 128))) {
    throw new Error("기기 관리 상태를 먼저 조회해 주세요.");
  }
  requireAdminKey(adminKey);
  return commandRequest("POST", `/devices/${id}/management`, {
    data: payload,
    adminKey,
    signal: options.signal,
    timeout: options.timeout ?? 15000,
  });
}

export async function createDevicePolicyRevision(
  deviceId,
  payload,
  adminKey,
  options = {}
) {
  const id = encodeId(deviceId, "Device ID");

  if (
    payload?.expected_revision === null ||
    payload?.expected_revision === undefined ||
    payload?.expected_revision === ""
  ) {
    throw new Error(
      "현재 Policy Revision을 확인할 수 없습니다."
    );
  }

  requireReason(payload?.reason);
  requireAdminKey(adminKey);

  return commandRequest(
    "POST",
    `/devices/${id}/policy-revisions`,
    {
      data: payload,
      adminKey,
      signal: options.signal,
      timeout: options.timeout ?? 15000,
    }
  );
}

export function getIsolatedDevices(
  params = {},
  options = {}
) {
  return getDevices(
    {
      status: "isolated",
      include_hidden: true,
      ...params,
    },
    options
  );
}

/* =========================================================
   Phase 9 - Device AI Policy

   GET  /api/devices/{device_id}/ai-policy
   POST /api/devices/{device_id}/ai-policy-revisions

   Phase 9에서 허용하는 모드는 OFF / OBSERVE입니다.
   변경은 즉시 적용되지 않을 수 있습니다.
========================================================= */

export function getDeviceAiPolicy(
  deviceId,
  options = {}
) {
  if (!deviceId) {
    return Promise.reject(
      new Error("AI 정책을 조회할 Device ID가 필요합니다.")
    );
  }

  return request(
    `/devices/${encodeId(deviceId)}/ai-policy`,
    null,
    {},
    options
  );
}

export async function createDeviceAiPolicyRevision(
  deviceId,
  payload,
  adminKey,
  options = {}
) {
  const id = encodeId(deviceId, "Device ID");

  if (
    typeof payload?.expected_revision !== "number" ||
    !Number.isSafeInteger(payload.expected_revision) ||
    payload.expected_revision < 1
  ) {
    throw new Error(
      "올바른 AI Policy Revision을 입력해 주세요."
    );
  }

  if (!["OFF", "OBSERVE"].includes(payload?.mode)) {
    throw new Error(
      "AI 모드는 OFF 또는 OBSERVE만 선택할 수 있습니다."
    );
  }

  const reason = requireReason(payload?.reason);
  requireAdminKey(adminKey);

  return commandRequest(
    "POST",
    `/devices/${id}/ai-policy-revisions`,
    {
      data: {
        expected_revision: payload.expected_revision,
        ...(payload.expected_instance_id !== undefined
          ? { expected_instance_id: payload.expected_instance_id } : {}),
        mode: payload.mode,
        reason,
      },
      adminKey,
      signal: options.signal,
      timeout: options.timeout ?? 15000,
    }
  );
}

/* =========================================================
   MQTT Logs
========================================================= */

export function getMqttLogs(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 10,
    offset: 0,
    ...params,
  };

  return request(
    "/mqtt-logs",
    paginateMockItems(
      mockMqttLogs.items,
      queryParams,
      10
    ),
    queryParams,
    options
  );
}

/* =========================================================
   MQTT Feature Logs

   Phase 9:
   device_id, from, to, limit, offset를
   Backend 계약에 맞춰 전달합니다.
========================================================= */

export function getFeatureLogs(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 10,
    offset: 0,
    ...params,
  };

  return request(
    "/feature-logs",
    paginateMockItems(
      mockFeatureLogs.items,
      queryParams,
      10
    ),
    queryParams,
    options
  );
}

/* =========================================================
   Detection Events
========================================================= */

export function getEvents(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let items = Array.isArray(mockEvents.items)
    ? [...mockEvents.items]
    : [];

  if (queryParams.device_id) {
    items = items.filter(
      (item) => item.device_id === queryParams.device_id
    );
  }

  if (queryParams.event_type) {
    items = items.filter(
      (item) => item.event_type === queryParams.event_type
    );
  }

  if (queryParams.incident_family) {
    items = items.filter(
      (item) =>
        item.incident_family === queryParams.incident_family
    );
  }

  if (queryParams.severity) {
    items = items.filter(
      (item) => item.severity === queryParams.severity
    );
  }

  if (queryParams.applied_to_score !== undefined) {
    const appliedValue = [
      true,
      1,
      "1",
      "true",
    ].includes(queryParams.applied_to_score);

    items = items.filter(
      (item) =>
        Boolean(item.applied_to_score) === appliedValue
    );
  }

  return request(
    "/detection-events",
    paginateMockItems(items, queryParams),
    queryParams,
    options
  );
}

/* =========================================================
   Phase 9 - AI Warnings

   GET /api/ai-warnings

   Params:
   device_id, from, to, limit, offset

   AI 경고는 단독 Trust 감점이나 격리를 의미하지 않습니다.
========================================================= */

export function getAiWarnings(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  return request(
    "/ai-warnings",
    { items: [], total: 0 },
    queryParams,
    options
  );
}

/* =========================================================
   Isolation History
========================================================= */

export function getIsolationHistory(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let items = Array.isArray(mockIsolationHistory.items)
    ? [...mockIsolationHistory.items]
    : [];

  if (queryParams.device_id) {
    items = items.filter(
      (item) => item.device_id === queryParams.device_id
    );
  }

  return request(
    "/isolation/history",
    paginateMockItems(items, queryParams),
    queryParams,
    options
  );
}

/* =========================================================
   Trust Score
========================================================= */

export function getTrustScoreSummary(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 100,
    offset: 0,
    ...params,
  };

  return request(
    "/trust-score/summary",
    paginateMockItems(
      mockTrustScoreSummary.items,
      queryParams,
      100
    ),
    queryParams,
    options
  );
}

export function getTrustScoreCompensations(
  params = {},
  adminKey = "",
  options = {}
) {
  const queryParams = {
    limit: 100,
    offset: 0,
    ...params,
  };

  return commandRequest(
    "GET",
    "/trust-score/compensations",
    {
      params: queryParams,
      adminKey,
      signal: options.signal,
      mockData: {
        items: [],
        total: 0,
      },
    }
  );
}

export function getTrustScoreHistory(
  deviceId,
  params = {},
  options = {}
) {
  if (!deviceId) {
    return Promise.reject(
      new Error(
        "Trust Score 이력을 조회할 Device ID가 필요합니다."
      )
    );
  }

  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  const history = mockTrustScoreHistories[deviceId] || {
    device_id: deviceId,
    current_score: null,
    items: [],
    total: 0,
  };

  const pagedItems = paginateMockItems(
    history.items,
    queryParams
  );

  return request(
    `/trust-score/${encodeId(deviceId)}/history`,
    {
      ...history,
      items: pagedItems.items,
      total: pagedItems.total,
    },
    queryParams,
    options
  );
}

/* =========================================================
   Packet Feature Logs

   기존 API 유지
   Phase 9 그래프에서 필터 및 기간 조회에 사용
========================================================= */

export function getPacketFeatureLogs(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let items = Array.isArray(mockPacketFeatureLogs.items)
    ? [...mockPacketFeatureLogs.items]
    : [];

  if (queryParams.direction) {
    items = items.filter(
      (item) => item.direction === queryParams.direction
    );
  }

  if (queryParams.device_id) {
    items = items.filter(
      (item) => item.device_id === queryParams.device_id
    );
  }

  if (queryParams.capture_eligible !== undefined) {
    const eligibleValue = [
      true,
      1,
      "1",
      "true",
    ].includes(queryParams.capture_eligible);

    items = items.filter(
      (item) =>
        Boolean(item.capture_eligible) === eligibleValue
    );
  }

  // capture_eligible는 현재 Backend 지원 여부를
  // 확인한 뒤 화면에서 요청 파라미터로 전달해야 합니다.
  return request(
    "/packet-feature-logs",
    paginateMockItems(items, queryParams),
    queryParams,
    options
  );
}

/* =========================================================
   Phase 9 - Packet Capture Windows

   GET /api/packet-capture-windows

   Feature가 없는 구간의 Capture 상태를 확인합니다.
   실제 지원 필터는 Swagger Schema와 대조해야 합니다.
========================================================= */

export function getPacketCaptureWindows(
  params = {},
  options = {}
) {
  return request(
    "/packet-capture-windows",
    { items: [], total: 0 },
    params,
    options
  );
}

/* =========================================================
   Gateway Metrics
========================================================= */

export function getGatewayMetrics(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 1,
    offset: 0,
    ...params,
  };

  const refreshedItems = (
    mockGatewayMetrics.items || []
  ).map((item, index) =>
    index === 0
      ? {
          ...item,
          collected_at: new Date().toISOString(),
        }
      : item
  );

  return request(
    "/gateway-metrics",
    paginateMockItems(
      refreshedItems,
      queryParams,
      1
    ),
    queryParams,
    options
  );
}

/* =========================================================
   Phase 9 - Runtime Status

   GET /api/runtime-status

   설정값과 실제 실행 상태는 구분해야 합니다.
   조회 실패를 정상 상태로 대체하지 않습니다.
========================================================= */

export function getRuntimeStatus(options = {}) {
  return request(
    "/runtime-status",
    null,
    {},
    options
  );
}

/* =========================================================
   Phase 9 - Models

   GET /api/models
========================================================= */

export function getModels(options = {}) {
  return request(
    "/models",
    null,
    {},
    options
  );
}

/* =========================================================
   Firewall Rules
========================================================= */

export function getFirewallRules(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let items = Array.isArray(mockFirewallRules.items)
    ? [...mockFirewallRules.items]
    : [];

  if (queryParams.status) {
    items = items.filter(
      (item) => item.status === queryParams.status
    );
  }

  if (queryParams.device_id) {
    items = items.filter(
      (item) => item.device_id === queryParams.device_id
    );
  }

  if (queryParams.source_ip) {
    items = items.filter(
      (item) => item.source_ip === queryParams.source_ip
    );
  }

  return request(
    "/firewall-rules",
    paginateMockItems(items, queryParams),
    queryParams,
    options
  );
}

/* =========================================================
   Phase 9 - Firewall Runtime Status

   GET /api/firewall-runtime-status
========================================================= */

export function getFirewallRuntimeStatus(
  options = {}
) {
  return request(
    "/firewall-runtime-status",
    null,
    {},
    options
  );
}

/* =========================================================
   Phase 9 - Firewall Scope Extension

   POST
   /api/firewall-rules/{source_rule_id}/scope-extension-requests

   관리자 명령의 정확한 Body Schema는
   Swagger에서 확인해야 합니다.

   이 함수는 payload를 임의 변경하지 않습니다.
========================================================= */

export async function createFirewallScopeExtensionRequest(
  sourceRuleId,
  payload,
  adminKey,
  options = {}
) {
  const id = encodeId(
    sourceRuleId,
    "Source Firewall Rule ID"
  );

  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw new Error(
      "차단 범위 확대 요청 데이터가 필요합니다."
    );
  }

  requireAdminKey(adminKey);

  return commandRequest(
    "POST",
    `/firewall-rules/${id}/scope-extension-requests`,
    {
      data: payload,
      adminKey,
      signal: options.signal,
      timeout: options.timeout ?? 15000,
    }
  );
}

/* =========================================================
   Firewall Release Request
========================================================= */

export async function createFirewallReleaseRequest(
  ruleId,
  {
    reason,
    confirmation,
    adminKey,
  },
  options = {}
) {
  const id = encodeId(ruleId, "Firewall Rule ID");

  const trimmedReason = String(reason ?? "").trim();
  const trimmedConfirmation =
    String(confirmation ?? "").trim();

  if (!trimmedReason) {
    throw new Error(
      "Firewall 해제 사유를 입력해 주세요."
    );
  }

  const expectedConfirmation =
    `RELEASE-FIREWALL-RULE-${ruleId}`;

  if (trimmedConfirmation !== expectedConfirmation) {
    throw new Error(
      `확인 문구 ${expectedConfirmation}을 정확히 입력해 주세요.`
    );
  }

  requireAdminKey(adminKey);

  const response = await commandRequest(
    "POST",
    `/firewall-rules/${id}/release-requests`,
    {
      data: {
        reason: trimmedReason,
        confirm: trimmedConfirmation,
      },
      adminKey,
      signal: options.signal,
    }
  );

  return response?.item ?? response;
}

export function getFirewallReleaseRequest(
  requestId,
  adminKey = "",
  options = {}
) {
  if (!requestId) {
    return Promise.reject(
      new Error(
        "Firewall Release Request ID가 필요합니다."
      )
    );
  }

  return commandRequest(
    "GET",
    `/firewall-release-requests/${encodeId(requestId)}`,
    {
      adminKey,
      signal: options.signal,
    }
  );
}

/* =========================================================
   Recovery Preflight
========================================================= */

export function recoveryPreflight(
  { device_id, expected_trust_score },
  adminKey,
  options = {}
) {
  if (!device_id) {
    return Promise.reject(
      new Error("Recovery 대상 Device ID가 필요합니다.")
    );
  }

  const trustScore = Number(expected_trust_score);

  if (!Number.isFinite(trustScore)) {
    return Promise.reject(
      new Error(
        "현재 Trust Score를 확인할 수 없습니다."
      )
    );
  }

  if (!String(adminKey ?? "").trim()) {
    return Promise.reject(
      new Error("관리자 Key를 입력해 주세요.")
    );
  }

  return commandRequest(
    "POST",
    "/recovery/preflight",
    {
      data: {
        device_id,
        expected_trust_score: trustScore,
      },
      adminKey,
      signal: options.signal,
    }
  );
}

/* =========================================================
   Recovery Execute
========================================================= */

export function executeRecovery(
  {
    device_id,
    expected_trust_score,
    reason,
    confirmation,
  },
  adminKey,
  options = {}
) {
  if (!device_id) {
    return Promise.reject(
      new Error("Recovery 대상 Device ID가 필요합니다.")
    );
  }

  const trustScore = Number(expected_trust_score);

  if (!Number.isFinite(trustScore)) {
    return Promise.reject(
      new Error(
        "현재 Trust Score를 확인할 수 없습니다."
      )
    );
  }

  const trimmedReason = String(reason ?? "").trim();

  if (!trimmedReason) {
    return Promise.reject(
      new Error("Recovery 사유를 입력해 주세요.")
    );
  }

  const expectedConfirmation = "RESET-TO-NORMAL-100";

  if (String(confirmation ?? "").trim() !== expectedConfirmation) {
    return Promise.reject(
      new Error(
        `${expectedConfirmation}을 정확히 입력해 주세요.`
      )
    );
  }

  if (!String(adminKey ?? "").trim()) {
    return Promise.reject(
      new Error("관리자 Key를 입력해 주세요.")
    );
  }

  return commandRequest(
    "POST",
    "/recovery/execute",
    {
      data: {
        device_id,
        expected_trust_score: trustScore,
        reason: trimmedReason,
        confirm: expectedConfirmation,
      },
      adminKey,
      signal: options.signal,
    }
  );
}

/* =========================================================
   Recovery History
========================================================= */

export function getRecoveryHistory(
  params = {},
  adminKey = "",
  options = {}
) {
  return commandRequest(
    "GET",
    "/recovery/history",
    {
      params,
      adminKey,
      signal: options.signal,
    }
  );
}

export function getRecoveryHistoryDetail(
  operationId,
  adminKey = "",
  options = {}
) {
  if (!operationId) {
    return Promise.reject(
      new Error(
        "Recovery Operation ID가 필요합니다."
      )
    );
  }

  return commandRequest(
    "GET",
    `/recovery/history/${encodeId(operationId)}`,
    {
      adminKey,
      signal: options.signal,
    }
  );
}

/* =========================================================
   Phase 9 - Packet Pair Recovery

   POST /api/recovery/packet-pair/plans
   GET  /api/recovery/packet-pair/{plan_id}
   POST /api/recovery/packet-pair/{plan_id}/verify

   관리자 작업은 실제 적용/검증 범위를
   Swagger 요청 스키마와 대조해야 합니다.

   해당 함수는 API 호출 연결만 제공합니다.
   응답 실패 시 자동 재시도하지 않습니다.
========================================================= */

export async function createPacketPairRecoveryPlan(
  payload,
  adminKey,
  options = {}
) {
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload)
  ) {
    throw new Error(
      "Packet Pair Recovery Plan 데이터가 필요합니다."
    );
  }

  requireAdminKey(adminKey);

  return commandRequest(
    "POST",
    "/recovery/packet-pair/plans",
    {
      data: payload,
      adminKey,
      signal: options.signal,
      timeout: options.timeout ?? 15000,
    }
  );
}

export function getPacketPairRecoveryPlan(
  planId,
  adminKey = "",
  options = {}
) {
  if (!planId) {
    return Promise.reject(
      new Error("Recovery Plan ID가 필요합니다.")
    );
  }

  return commandRequest(
    "GET",
    `/recovery/packet-pair/${encodeId(planId)}`,
    {
      adminKey,
      signal: options.signal,
      timeout: options.timeout,
    }
  );
}

export async function verifyPacketPairRecoveryPlan(
  planId,
  adminKey,
  options = {}
) {
  const id = encodeId(planId, "Recovery Plan ID");

  requireAdminKey(adminKey);

  return commandRequest(
    "POST",
    `/recovery/packet-pair/${id}/verify`,
    {
      adminKey,
      signal: options.signal,
      timeout: options.timeout ?? 15000,
    }
  );
}

/* =========================================================
   Health
========================================================= */

export function getHealth(options = {}) {
  return request(
    "/health",
    mockHealth,
    {},
    options
  );
}

/* =========================================================
   Exports
========================================================= */

export {
  API_BASE_URL,
  USE_MOCK,
};
