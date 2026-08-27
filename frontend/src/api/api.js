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

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ||
  "http://localhost:8000/api";

const USE_MOCK =
  import.meta.env.VITE_USE_MOCK === "true";

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

/**
 * undefined, null, 빈 문자열인 Query Parameter를 제거합니다.
 * false와 0은 유효한 값이므로 유지합니다.
 */
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

/**
 * 숫자형 Pagination 값을 안전하게 변환합니다.
 */
function normalizePagination(
  params = {},
  {
    defaultLimit = 20,
    defaultOffset = 0,
  } = {}
) {
  const parsedLimit = Number(
    params.limit
  );

  const parsedOffset = Number(
    params.offset
  );

  return {
    limit:
      Number.isFinite(
        parsedLimit
      ) && parsedLimit > 0
        ? parsedLimit
        : defaultLimit,

    offset:
      Number.isFinite(
        parsedOffset
      ) && parsedOffset >= 0
        ? parsedOffset
        : defaultOffset,
  };
}

/**
 * 배열을 API의 items/total 구조로 Pagination합니다.
 */
function paginateMockItems(
  items,
  params = {},
  defaultLimit = 20
) {
  const safeItems =
    Array.isArray(items)
      ? items
      : [];

  const {
    limit,
    offset,
  } = normalizePagination(
    params,
    {
      defaultLimit,
    }
  );

  return {
    items: safeItems.slice(
      offset,
      offset + limit
    ),
    total: safeItems.length,
  };
}

/**
 * Axios 오류를 화면에 표시할 안전한 메시지로 변환합니다.
 */
function createApiErrorMessage(
  error
) {
  if (axios.isCancel(error)) {
    return "요청이 취소되었습니다.";
  }

  const status =
    error.response?.status;

  const detail =
    error.response?.data?.detail;

  if (
    typeof detail === "string"
  ) {
    return detail;
  }

  if (
    Array.isArray(detail)
  ) {
    const validationMessage =
      detail
        .map(
          (item) =>
            item?.msg
        )
        .filter(Boolean)
        .join(", ");

    if (validationMessage) {
      return validationMessage;
    }
  }

  if (
    error.code === "ERR_NETWORK" ||
    !error.response
  ) {
    return "백엔드 서버에 연결할 수 없습니다.";
  }

  if (status === 401) {
    return "관리자 인증에 실패했습니다.";
  }

  if (status === 404) {
    return "요청한 데이터를 찾을 수 없습니다.";
  }

  if (status === 409) {
    return (
      detail ||
      "현재 상태에서는 요청을 수행할 수 없습니다."
    );
  }

  if (status === 422) {
    return "요청 조건을 확인해 주세요.";
  }

  if (
    status &&
    status >= 500
  ) {
    return "서버에서 데이터를 처리하지 못했습니다.";
  }

  if (status) {
    return `API 요청에 실패했습니다. (${status})`;
  }

  return "API 요청에 실패했습니다.";
}

/* =========================================================
   Common GET Request
   ========================================================= */

/**
 * 공통 GET 요청 함수
 */
async function request(
  path,
  mockData,
  params = {},
  options = {}
) {
  const validParams =
    removeEmptyParams(params);

  if (USE_MOCK) {
    if (IS_DEV) {
      console.log(
        "[MOCK]",
        path,
        validParams
      );
    }

    return mockData;
  }

  try {
    const response =
      await axios.get(
        `${API_BASE_URL}${path}`,
        {
          params:
            validParams,

          headers: {
            Accept:
              "application/json",
          },

          signal:
            options.signal,
        }
      );

    if (IS_DEV) {
      console.log(
        "[API]",
        path,
        validParams,
        response.data
      );
    }

    return response.data;
  } catch (error) {
    const message =
      createApiErrorMessage(
        error
      );

    if (IS_DEV) {
      console.error(
        "[API ERROR]",
        {
          path,
          params:
            validParams,

          status:
            error.response
              ?.status,

          response:
            error.response
              ?.data,
        }
      );
    }

    const apiError =
      new Error(message);

    apiError.status =
      error.response?.status ??
      null;

    apiError.code =
      error.code ??
      null;

    apiError.responseData =
      error.response?.data ??
      null;

    apiError.isCanceled =
      axios.isCancel(
        error
      ) ||
      error.name ===
        "CanceledError";

    throw apiError;
  }
}

/* =========================================================
   Phase 6-B Command Request
   ========================================================= */

/**
 * 관리자 Command용 공통 요청 함수
 *
 * Admin Key는 요청 시점에만
 * X-Recovery-Admin-Key Header로 전달합니다.
 *
 * Admin Key / Reason / Confirm은
 * Console에 출력하지 않습니다.
 */
async function commandRequest(
  method,
  path,
  {
    data = undefined,
    params = {},
    adminKey = "",
    signal,
    mockData = undefined,
  } = {}
) {
  const validParams =
    removeEmptyParams(params);

  if (USE_MOCK) {
    if (IS_DEV) {
      console.log(
        "[MOCK COMMAND]",
        {
          method,
          path,
          params:
            validParams,
        }
      );
    }

    /**
     * Phase 6-B 계약:
     * Mock 화면을 실제 Release / Recovery 성공 증적으로
     * 사용하지 않습니다.
     *
     * 따라서 Mock에서는 호출자가 전달한 Fixture만 반환하고,
     * 실제 성공 상태를 임의 생성하지 않습니다.
     */
    if (
      mockData !== undefined
    ) {
      return mockData;
    }

    throw new Error(
      "Mock 모드에서는 실제 Firewall Release / Recovery Command를 실행하지 않습니다."
    );
  }

  try {
    const response =
      await axios({
        method,

        url:
          `${API_BASE_URL}${path}`,

        data,

        params:
          validParams,

        headers: {
          Accept:
            "application/json",

          ...(data !==
          undefined
            ? {
                "Content-Type":
                  "application/json",
              }
            : {}),

          ...(adminKey
            ? {
                "X-Recovery-Admin-Key":
                  adminKey,
              }
            : {}),
        },

        signal,
      });

    /**
     * Secret이나 Command Body를
     * Console에 출력하지 않습니다.
     */
    if (IS_DEV) {
      console.log(
        "[API COMMAND]",
        {
          method,
          path,
          status:
            response.status,
        }
      );
    }

    return response.data;
  } catch (error) {
    const message =
      createApiErrorMessage(
        error
      );

    /**
     * Admin Key, Request Body,
     * confirm 값은 Error Log에도 출력하지 않습니다.
     */
    if (IS_DEV) {
      console.error(
        "[API COMMAND ERROR]",
        {
          method,
          path,

          status:
            error.response
              ?.status,

          response:
            error.response
              ?.data,
        }
      );
    }

    const apiError =
      new Error(message);

    apiError.status =
      error.response?.status ??
      null;

    apiError.code =
      error.code ??
      null;

    apiError.responseData =
      error.response?.data ??
      null;

    apiError.isCanceled =
      axios.isCancel(
        error
      ) ||
      error.name ===
        "CanceledError";

    throw apiError;
  }
}

/* =========================================================
   Dashboard
   ========================================================= */

export function getSummary(
  options = {}
) {
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

export function getDevices(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let filteredItems =
    Array.isArray(
      mockDevices.items
    )
      ? [
          ...mockDevices.items,
        ]
      : [];

  if (
    queryParams.status
  ) {
    filteredItems =
      filteredItems.filter(
        (device) =>
          device.status ===
          queryParams.status
      );
  }

  if (
    queryParams.device_id
  ) {
    filteredItems =
      filteredItems.filter(
        (device) =>
          device.device_id ===
          queryParams.device_id
      );
  }

  const pagedMockData =
    paginateMockItems(
      filteredItems,
      queryParams
    );

  return request(
    "/devices",
    pagedMockData,
    queryParams,
    options
  );
}

export function getIsolatedDevices(
  params = {},
  options = {}
) {
  return getDevices(
    {
      status: "isolated",
      ...params,
    },
    options
  );
}

/* =========================================================
   MQTT
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

  const pagedMockData =
    paginateMockItems(
      mockMqttLogs.items,
      queryParams,
      10
    );

  return request(
    "/mqtt-logs",
    pagedMockData,
    queryParams,
    options
  );
}

/* =========================================================
   MQTT Feature Logs
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

  const pagedMockData =
    paginateMockItems(
      mockFeatureLogs.items,
      queryParams,
      10
    );

  return request(
    "/feature-logs",
    pagedMockData,
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

  let filteredItems =
    Array.isArray(
      mockEvents.items
    )
      ? [
          ...mockEvents.items,
        ]
      : [];

  if (
    queryParams.device_id
  ) {
    filteredItems =
      filteredItems.filter(
        (event) =>
          event.device_id ===
          queryParams.device_id
      );
  }

  if (
    queryParams.event_type
  ) {
    filteredItems =
      filteredItems.filter(
        (event) =>
          event.event_type ===
          queryParams.event_type
      );
  }

  if (
    queryParams.incident_family
  ) {
    filteredItems =
      filteredItems.filter(
        (event) =>
          event.incident_family ===
          queryParams.incident_family
      );
  }

  if (
    queryParams.severity
  ) {
    filteredItems =
      filteredItems.filter(
        (event) =>
          event.severity ===
          queryParams.severity
      );
  }

  if (
    queryParams.applied_to_score !==
    undefined
  ) {
    const appliedValue =
      queryParams.applied_to_score ===
        true ||
      queryParams.applied_to_score ===
        1 ||
      queryParams.applied_to_score ===
        "1" ||
      queryParams.applied_to_score ===
        "true";

    filteredItems =
      filteredItems.filter(
        (event) =>
          Boolean(
            event.applied_to_score
          ) ===
          appliedValue
      );
  }

  const pagedMockData =
    paginateMockItems(
      filteredItems,
      queryParams
    );

  return request(
    "/detection-events",
    pagedMockData,
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

  let filteredItems =
    Array.isArray(
      mockIsolationHistory.items
    )
      ? [
          ...mockIsolationHistory.items,
        ]
      : [];

  if (
    queryParams.device_id
  ) {
    filteredItems =
      filteredItems.filter(
        (item) =>
          item.device_id ===
          queryParams.device_id
      );
  }

  const pagedMockData =
    paginateMockItems(
      filteredItems,
      queryParams
    );

  return request(
    "/isolation/history",
    pagedMockData,
    queryParams,
    options
  );
}

/* =========================================================
   Trust Score
   ========================================================= */

export function getTrustScoreSummary(
  options = {}
) {
  return request(
    "/trust-score/summary",
    mockTrustScoreSummary,
    {},
    options
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
        "Trust Score 이력을 조회할 기기 ID가 필요합니다."
      )
    );
  }

  const encodedDeviceId =
    encodeURIComponent(
      deviceId
    );

  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  const history =
    mockTrustScoreHistories[
      deviceId
    ] || {
      device_id:
        deviceId,

      current_score:
        null,

      items: [],

      total: 0,
    };

  const pagedItems =
    paginateMockItems(
      history.items,
      queryParams
    );

  const pagedMockData = {
    ...history,

    items:
      pagedItems.items,

    total:
      pagedItems.total,
  };

  return request(
    `/trust-score/${encodedDeviceId}/history`,
    pagedMockData,
    queryParams,
    options
  );
}

/* =========================================================
   Packet Feature Logs
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

  let filteredItems =
    Array.isArray(
      mockPacketFeatureLogs.items
    )
      ? [
          ...mockPacketFeatureLogs.items,
        ]
      : [];

  if (
    queryParams.direction
  ) {
    filteredItems =
      filteredItems.filter(
        (item) =>
          item.direction ===
          queryParams.direction
      );
  }

  if (
    queryParams.device_id
  ) {
    filteredItems =
      filteredItems.filter(
        (item) =>
          item.device_id ===
          queryParams.device_id
      );
  }

  if (
    queryParams.capture_eligible !==
    undefined
  ) {
    const eligibleValue =
      queryParams.capture_eligible ===
        true ||
      queryParams.capture_eligible ===
        1 ||
      queryParams.capture_eligible ===
        "1" ||
      queryParams.capture_eligible ===
        "true";

    filteredItems =
      filteredItems.filter(
        (item) =>
          Boolean(
            item.capture_eligible
          ) ===
          eligibleValue
      );
  }

  const pagedMockData =
    paginateMockItems(
      filteredItems,
      queryParams
    );

  return request(
    "/packet-feature-logs",
    pagedMockData,
    queryParams,
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
    mockGatewayMetrics.items ||
    []
  ).map(
    (
      item,
      index
    ) =>
      index === 0
        ? {
            ...item,

            collected_at:
              new Date().toISOString(),
          }
        : item
  );

  const pagedMockData =
    paginateMockItems(
      refreshedItems,
      queryParams,
      1
    );

  return request(
    "/gateway-metrics",
    pagedMockData,
    queryParams,
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

  let filteredItems =
    Array.isArray(
      mockFirewallRules.items
    )
      ? [
          ...mockFirewallRules.items,
        ]
      : [];

  if (
    queryParams.status
  ) {
    filteredItems =
      filteredItems.filter(
        (rule) =>
          rule.status ===
          queryParams.status
      );
  }

  if (
    queryParams.device_id
  ) {
    filteredItems =
      filteredItems.filter(
        (rule) =>
          rule.device_id ===
          queryParams.device_id
      );
  }

  if (
    queryParams.source_ip
  ) {
    filteredItems =
      filteredItems.filter(
        (rule) =>
          rule.source_ip ===
          queryParams.source_ip
      );
  }

  const pagedMockData =
    paginateMockItems(
      filteredItems,
      queryParams
    );

  return request(
    "/firewall-rules",
    pagedMockData,
    queryParams,
    options
  );
}

/* =========================================================
   Phase 6-B Firewall Release Request
   ========================================================= */

/**
 * APPLIED Firewall Rule의 Release Request를 생성합니다.
 *
 * Backend는 Request만 저장하며
 * 실제 iptables Release는 Firewall Worker가 수행합니다.
 *
 * API 계약:
 *
 * POST /api/firewall-rules/{rule_id}/release-requests
 *
 * Body:
 * {
 *   reason,
 *   confirm
 * }
 *
 * confirm:
 * RELEASE-FIREWALL-RULE-{rule_id}
 */
export async function createFirewallReleaseRequest(
  ruleId,
  {
    reason,
    confirmation,
    adminKey,
  },
  options = {}
) {
  if (
    ruleId === null ||
    ruleId === undefined ||
    ruleId === ""
  ) {
    throw new Error(
      "Firewall Rule ID가 필요합니다."
    );
  }

  const trimmedReason =
    String(
      reason ?? ""
    ).trim();

  if (!trimmedReason) {
    throw new Error(
      "Firewall 해제 사유를 입력해 주세요."
    );
  }

  const trimmedConfirmation =
    String(
      confirmation ?? ""
    ).trim();

  if (
    !trimmedConfirmation
  ) {
    throw new Error(
      "Firewall 해제 확인 문구를 입력해 주세요."
    );
  }

  const expectedConfirmation =
    `RELEASE-FIREWALL-RULE-${ruleId}`;

  if (
    trimmedConfirmation !==
    expectedConfirmation
  ) {
    throw new Error(
      `확인 문구 ${expectedConfirmation}을 정확히 입력해 주세요.`
    );
  }

  if (
    !String(
      adminKey ?? ""
    ).trim()
  ) {
    throw new Error(
      "관리자 Key를 입력해 주세요."
    );
  }

  const encodedRuleId =
    encodeURIComponent(
      ruleId
    );

  const response =
    await commandRequest(
      "POST",

      `/firewall-rules/${encodedRuleId}/release-requests`,

      {
        data: {
          reason:
            trimmedReason,

          confirm:
            trimmedConfirmation,
        },

        adminKey,

        signal:
          options.signal,
      }
    );

  /**
   * Backend 201 Response:
   *
   * {
   *   item: {
   *     id,
   *     firewall_rule_id,
   *     status,
   *     ...
   *   }
   * }
   *
   * Frontend에서는 사용 편의를 위해
   * item 객체만 반환합니다.
   */
  return (
    response?.item ??
    response
  );
}

/**
 * Firewall Release Request 상태 단건 조회
 *
 * 반환 status:
 * - PENDING
 * - SUCCEEDED
 * - FAILED
 */
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

  const encodedRequestId =
    encodeURIComponent(
      requestId
    );

  return commandRequest(
    "GET",

    `/firewall-release-requests/${encodedRequestId}`,

    {
      adminKey,

      signal:
        options.signal,
    }
  );
}

/* =========================================================
   Phase 6-B Recovery
   ========================================================= */

/**
 * Recovery Preflight
 *
 * expected_trust_score는 Recovery 후 목표값 100이 아니라
 * 현재 Device의 Trust Score와 일치해야 합니다.
 *
 * 예:
 * 현재 esp32_02 trust_score = 25
 *
 * {
 *   device_id: "esp32_02",
 *   expected_trust_score: 25
 * }
 */
export function recoveryPreflight(
  {
    device_id,
    expected_trust_score,
  },
  adminKey,
  options = {}
) {
  if (!device_id) {
    return Promise.reject(
      new Error(
        "Recovery 대상 Device ID가 필요합니다."
      )
    );
  }

  const trustScore =
    Number(
      expected_trust_score
    );

  if (
    !Number.isFinite(
      trustScore
    )
  ) {
    return Promise.reject(
      new Error(
        "현재 Trust Score를 확인할 수 없습니다."
      )
    );
  }

  if (
    !String(
      adminKey ?? ""
    ).trim()
  ) {
    return Promise.reject(
      new Error(
        "관리자 Key를 입력해 주세요."
      )
    );
  }

  return commandRequest(
    "POST",

    "/recovery/preflight",

    {
      data: {
        device_id,

        expected_trust_score:
          trustScore,
      },

      adminKey,

      signal:
        options.signal,
    }
  );
}

/**
 * Recovery Execute
 *
 * confirm 값은 고정:
 * RESET-TO-NORMAL-100
 *
 * expected_trust_score 역시
 * Recovery 직전 현재 Trust Score입니다.
 */
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
      new Error(
        "Recovery 대상 Device ID가 필요합니다."
      )
    );
  }

  const trustScore =
    Number(
      expected_trust_score
    );

  if (
    !Number.isFinite(
      trustScore
    )
  ) {
    return Promise.reject(
      new Error(
        "현재 Trust Score를 확인할 수 없습니다."
      )
    );
  }

  const trimmedReason =
    String(
      reason ?? ""
    ).trim();

  if (!trimmedReason) {
    return Promise.reject(
      new Error(
        "Recovery 사유를 입력해 주세요."
      )
    );
  }

  const trimmedConfirmation =
    String(
      confirmation ?? ""
    ).trim();

  const expectedConfirmation =
    "RESET-TO-NORMAL-100";

  if (
    trimmedConfirmation !==
    expectedConfirmation
  ) {
    return Promise.reject(
      new Error(
        `${expectedConfirmation}을 정확히 입력해 주세요.`
      )
    );
  }

  if (
    !String(
      adminKey ?? ""
    ).trim()
  ) {
    return Promise.reject(
      new Error(
        "관리자 Key를 입력해 주세요."
      )
    );
  }

  return commandRequest(
    "POST",

    "/recovery/execute",

    {
      data: {
        device_id,

        expected_trust_score:
          trustScore,

        reason:
          trimmedReason,

        confirm:
          trimmedConfirmation,
      },

      adminKey,

      signal:
        options.signal,
    }
  );
}

/**
 * Recovery History
 *
 * Query:
 * - device_id
 * - result
 * - limit
 * - offset
 */
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

      signal:
        options.signal,
    }
  );
}

/**
 * Recovery History Detail
 */
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

  const encodedOperationId =
    encodeURIComponent(
      operationId
    );

  return commandRequest(
    "GET",

    `/recovery/history/${encodedOperationId}`,

    {
      adminKey,

      signal:
        options.signal,
    }
  );
}

/* =========================================================
   Health
   ========================================================= */

export function getHealth(
  options = {}
) {
  return request(
    "/health",
    mockHealth,
    {},
    options
  );
}

export {
  API_BASE_URL,
  USE_MOCK,
};