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
  const parsedLimit = Number(params.limit);
  const parsedOffset = Number(params.offset);

  return {
    limit:
      Number.isFinite(parsedLimit) &&
      parsedLimit > 0
        ? parsedLimit
        : defaultLimit,

    offset:
      Number.isFinite(parsedOffset) &&
      parsedOffset >= 0
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
  const safeItems = Array.isArray(items)
    ? items
    : [];

  const { limit, offset } =
    normalizePagination(params, {
      defaultLimit,
    });

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
function createApiErrorMessage(error) {
  if (axios.isCancel(error)) {
    return "요청이 취소되었습니다.";
  }

  const status =
    error.response?.status;

  const detail =
    error.response?.data?.detail;

  if (typeof detail === "string") {
    return detail;
  }

  if (Array.isArray(detail)) {
    const validationMessage = detail
      .map((item) => item?.msg)
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

  if (status === 404) {
    return "요청한 데이터를 찾을 수 없습니다.";
  }

  if (status === 422) {
    return "요청 조건을 확인해 주세요.";
  }

  if (status >= 500) {
    return "서버에서 데이터를 처리하지 못했습니다.";
  }

  if (status) {
    return `API 요청에 실패했습니다. (${status})`;
  }

  return "API 요청에 실패했습니다.";
}

/**
 * 공통 GET 요청 함수
 *
 * @param {string} path API 경로
 * @param {*} mockData Mock 모드에서 반환할 데이터
 * @param {object} params Query Parameter
 * @param {object} options Axios 요청 옵션
 * @param {AbortSignal} options.signal 요청 취소 Signal
 * @returns {Promise<*>}
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
    const response = await axios.get(
      `${API_BASE_URL}${path}`,
      {
        params: validParams,
        headers: {
          Accept: "application/json",
        },
        signal: options.signal,
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
      createApiErrorMessage(error);

    if (IS_DEV) {
      console.error("[API ERROR]", {
        path,
        params: validParams,
        status:
          error.response?.status,
        response:
          error.response?.data,
        error,
      });
    }

    const apiError = new Error(message);

    apiError.status =
      error.response?.status ?? null;

    apiError.code =
      error.code ?? null;

    apiError.isCanceled =
      axios.isCancel(error) ||
      error.name === "CanceledError";

    throw apiError;
  }
}

/**
 * Dashboard Summary
 */
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

/**
 * Device 목록
 */
export function getDevices(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let filteredItems = Array.isArray(
    mockDevices.items
  )
    ? [...mockDevices.items]
    : [];

  if (queryParams.status) {
    filteredItems = filteredItems.filter(
      (device) =>
        device.status ===
        queryParams.status
    );
  }

  if (queryParams.device_id) {
    filteredItems = filteredItems.filter(
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

/**
 * 격리 상태 Device 목록
 */
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

/**
 * MQTT Log 목록
 */
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

/**
 * MQTT Feature Log 목록
 */
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

/**
 * Detection Event 목록
 *
 * 지원 예정 Filter:
 * - device_id
 * - event_type
 * - incident_family
 * - severity
 * - applied_to_score
 * - from
 * - to
 * - limit
 * - offset
 */
export function getEvents(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let filteredItems = Array.isArray(
    mockEvents.items
  )
    ? [...mockEvents.items]
    : [];

  if (queryParams.device_id) {
    filteredItems = filteredItems.filter(
      (event) =>
        event.device_id ===
        queryParams.device_id
    );
  }

  if (queryParams.event_type) {
    filteredItems = filteredItems.filter(
      (event) =>
        event.event_type ===
        queryParams.event_type
    );
  }

  if (queryParams.incident_family) {
    filteredItems = filteredItems.filter(
      (event) =>
        event.incident_family ===
        queryParams.incident_family
    );
  }

  if (queryParams.severity) {
    filteredItems = filteredItems.filter(
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

    filteredItems = filteredItems.filter(
      (event) =>
        Boolean(event.applied_to_score) ===
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

/**
 * Isolation History
 *
 * Phase 4:
 * trust_score_history_id를 통해 격리 결정 Window와 연결합니다.
 */
export function getIsolationHistory(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let filteredItems = Array.isArray(
    mockIsolationHistory.items
  )
    ? [...mockIsolationHistory.items]
    : [];

  if (queryParams.device_id) {
    filteredItems = filteredItems.filter(
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

/**
 * Trust Score 요약
 */
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

/**
 * Device별 Trust Score Window 이력
 *
 * 주의:
 * Detection Event score_delta를 Frontend에서 다시 합산하지 않습니다.
 * API가 반환하는 actual_delta와 new_score를 그대로 사용합니다.
 */
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
    encodeURIComponent(deviceId);

  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  const history =
    mockTrustScoreHistories[
      deviceId
    ] || {
      device_id: deviceId,
      current_score: null,
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
    items: pagedItems.items,
    total: pagedItems.total,
  };

  return request(
    `/trust-score/${encodedDeviceId}/history`,
    pagedMockData,
    queryParams,
    options
  );
}

/**
 * Packet Feature Log
 *
 * Phase 4:
 * - nominal_*: 명목 10초 Window 기준
 * - effective_*: 실제 Capture Duration 기준
 * - captured_duration_seconds
 * - coverage_ratio
 * - capture_eligible
 * - capture_exclusion_reason
 */
export function getPacketFeatureLogs(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let filteredItems = Array.isArray(
    mockPacketFeatureLogs.items
  )
    ? [...mockPacketFeatureLogs.items]
    : [];

  if (queryParams.direction) {
    filteredItems = filteredItems.filter(
      (item) =>
        item.direction ===
        queryParams.direction
    );
  }

  if (queryParams.device_id) {
    filteredItems = filteredItems.filter(
      (item) =>
        item.device_id ===
        queryParams.device_id
    );
  }

  if (queryParams.capture_eligible !== undefined) {
    const eligibleValue =
      queryParams.capture_eligible ===
        true ||
      queryParams.capture_eligible ===
        1 ||
      queryParams.capture_eligible ===
        "1" ||
      queryParams.capture_eligible ===
        "true";

    filteredItems = filteredItems.filter(
      (item) =>
        Boolean(item.capture_eligible) ===
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

/**
 * Gateway Metric
 */
export function getGatewayMetrics(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 1,
    offset: 0,
    ...params,
  };

  /*
   * Mock 모드에서는 최신 Metric의 collected_at을
   * 요청 시점으로 갱신해 STALE 상태가 고정되는 것을 방지합니다.
   */
  const refreshedItems = (
    mockGatewayMetrics.items || []
  ).map((item, index) =>
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

/**
 * Firewall Rule 목록
 *
 * Filter:
 * - status: PENDING | APPLIED | FAILED | REMOVED
 * - device_id
 * - source_ip
 * - limit
 * - offset
 */
export function getFirewallRules(
  params = {},
  options = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  let filteredItems = Array.isArray(
    mockFirewallRules.items
  )
    ? [...mockFirewallRules.items]
    : [];

  if (queryParams.status) {
    filteredItems = filteredItems.filter(
      (rule) =>
        rule.status ===
        queryParams.status
    );
  }

  if (queryParams.device_id) {
    filteredItems = filteredItems.filter(
      (rule) =>
        rule.device_id ===
        queryParams.device_id
    );
  }

  if (queryParams.source_ip) {
    filteredItems = filteredItems.filter(
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

/**
 * FastAPI Process와 DB 연결 상태 확인
 */
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