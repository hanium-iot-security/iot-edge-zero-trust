import axios from "axios";
import {
  mockSummary,
  mockDevices,
  mockMqttLogs,
  mockFeatureLogs,
  mockEvents,
  mockIsolationHistory,
  mockTrustScoreSummary,
  mockPacketFeatureLogs,
  mockGatewayMetrics,
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

function createApiErrorMessage(error) {
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

  if (error.code === "ERR_NETWORK") {
    return "백엔드 서버에 연결할 수 없습니다.";
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
 * @param {object} params Query parameter
 * @returns {Promise<*>}
 */
async function request(
  path,
  mockData,
  params = {}
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

    /*
     * 운영 환경에서는 API 응답 원문이나
     * 오류 객체를 Console에 출력하지 않습니다.
     */
    if (IS_DEV) {
      console.error(
        "[API ERROR]",
        {
          path,
          params: validParams,
          status:
            error.response?.status,
          response:
            error.response?.data,
          error,
        }
      );
    }

    throw new Error(message);
  }
}

export function getSummary() {
  return request(
    "/dashboard/summary",
    mockSummary
  );
}

export function getDevices(
  params = {}
) {
  return request(
    "/devices",
    mockDevices,
    params
  );
}

export function getIsolatedDevices() {
  const isolatedDevices = (
    mockDevices.items || []
  ).filter(
    (device) =>
      device.status === "isolated"
  );

  return request(
    "/devices",
    {
      items: isolatedDevices,
      total: isolatedDevices.length,
    },
    {
      status: "isolated",
    }
  );
}

export function getMqttLogs(
  params = {}
) {
  return request(
    "/mqtt-logs",
    mockMqttLogs,
    {
      limit: 10,
      ...params,
    }
  );
}

export function getFeatureLogs(
  params = {}
) {
  return request(
    "/feature-logs",
    mockFeatureLogs,
    {
      limit: 10,
      ...params,
    }
  );
}

export function getEvents(
  params = {}
) {
  return request(
    "/detection-events",
    mockEvents,
    {
      limit: 10,
      ...params,
    }
  );
}

export function getIsolationHistory(
  params = {}
) {
  return request(
    "/isolation/history",
    mockIsolationHistory,
    params
  );
}

export function getTrustScoreSummary() {
  return request(
    "/trust-score/summary",
    mockTrustScoreSummary
  );
}

export function getTrustScoreHistory(
  deviceId,
  params = {}
) {
  const encodedDeviceId =
    encodeURIComponent(deviceId);

  return request(
    `/trust-score/${encodedDeviceId}/history`,
    {
      device_id: deviceId,
      current_score: null,
      items: [],
    },
    {
      limit: 50,
      ...params,
    }
  );
}

export function getPacketFeatureLogs(
  params = {}
) {
  const queryParams = {
    limit: 20,
    offset: 0,
    ...params,
  };

  /*
   * Mock 모드에서도 실제 API와 동일하게
   * Direction 필터와 limit·offset 페이지 이동을
   * 확인할 수 있도록 응답을 가공합니다.
   */
  const mockItems =
    Array.isArray(
      mockPacketFeatureLogs.items
    )
      ? mockPacketFeatureLogs.items
      : [];

  const filteredMockItems =
    queryParams.direction
      ? mockItems.filter(
          (item) =>
            item.direction ===
            queryParams.direction
        )
      : mockItems;

  const parsedLimit =
    Number(queryParams.limit);

  const parsedOffset =
    Number(queryParams.offset);

  const safeLimit =
    Number.isFinite(parsedLimit) &&
    parsedLimit > 0
      ? parsedLimit
      : 20;

  const safeOffset =
    Number.isFinite(parsedOffset) &&
    parsedOffset >= 0
      ? parsedOffset
      : 0;

  const pagedMockData = {
    items:
      filteredMockItems.slice(
        safeOffset,
        safeOffset + safeLimit
      ),
    total:
      filteredMockItems.length,
  };

  return request(
    "/packet-feature-logs",
    pagedMockData,
    queryParams
  );
}

export function getGatewayMetrics(
  params = {}
) {
  /*
   * Mock 데이터의 collected_at을 요청 시점마다
   * 갱신해 30초 후 STALE로 고정되는 문제를 방지합니다.
   */
  const refreshedMockGatewayMetrics = {
    ...mockGatewayMetrics,
    items: (
      mockGatewayMetrics.items || []
    ).map((item, index) =>
      index === 0
        ? {
            ...item,
            collected_at:
              new Date().toISOString(),
          }
        : item
    ),
  };

  return request(
    "/gateway-metrics",
    refreshedMockGatewayMetrics,
    {
      limit: 1,
      offset: 0,
      ...params,
    }
  );
}
