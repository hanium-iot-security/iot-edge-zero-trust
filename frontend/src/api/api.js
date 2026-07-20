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

console.log("[ENV CHECK]", {
  API_BASE_URL,
  USE_MOCK,
});


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
 * 공통 GET 요청 함수
 *
 * @param {string} path API 경로
 * @param {*} mockData Mock 모드에서 반환할 데이터
 * @param {object} params Query parameter
 */
async function request(
  path,
  mockData,
  params = {}
) {
  const validParams =
    removeEmptyParams(params);

  if (USE_MOCK) {
    console.log(
      "[MOCK]",
      path,
      validParams
    );

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

    console.log(
      "[API]",
      path,
      validParams,
      response.data
    );

    return response.data;
  } catch (error) {
    const status =
      error.response?.status;

    const detail =
      error.response?.data?.detail;

    let message =
      "API 요청에 실패했습니다.";

    if (typeof detail === "string") {
      message = detail;
    } else if (Array.isArray(detail)) {
      message = detail
        .map((item) => item.msg)
        .filter(Boolean)
        .join(", ");
    } else if (
      error.code === "ERR_NETWORK"
    ) {
      message =
        "백엔드 서버에 연결할 수 없습니다.";
    } else if (status) {
      message =
        `API 요청에 실패했습니다. (${status})`;
    }

    console.error(
      "[API ERROR]",
      {
        path,
        params: validParams,
        status,
        response:
          error.response?.data,
        error,
      }
    );

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
  return request(
    "/packet-feature-logs",
    mockPacketFeatureLogs,
    {
      limit: 100,
      offset: 0,
      ...params,
    }
  );
}


export function getGatewayMetrics(
  params = {}
) {

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