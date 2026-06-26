import axios from "axios";
import {
  mockSummary,
  mockDevices,
  mockMqttLogs,
  mockFeatureLogs,
  mockEvents,
  mockIsolationHistory,
  mockTrustScoreSummary,
} from "../mockData";

const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL || "http://localhost:8000/api";

const USE_MOCK = import.meta.env.VITE_USE_MOCK === "true";

async function request(path, mockData) {
  if (USE_MOCK) {
    console.log("[MOCK]", path);
    return mockData;
  }

  const res = await axios.get(`${API_BASE_URL}${path}`);
  console.log("[API]", path, res.data);
  return res.data;
}

export function getSummary() {
  return request("/dashboard/summary", mockSummary);
}

export function getDevices() {
  return request("/devices", mockDevices);
}

export function getIsolatedDevices() {
  return request("/devices?status=isolated", {
    items: mockDevices.items.filter((device) => device.status === "isolated"),
    total: mockDevices.items.filter((device) => device.status === "isolated").length,
  });
}

export function getMqttLogs() {
  return request("/mqtt-logs?limit=10", mockMqttLogs);
}

export function getFeatureLogs() {
  return request("/feature-logs?limit=10", mockFeatureLogs);
}

export function getEvents() {
  return request("/detection-events?limit=10", mockEvents);
}

export function getIsolationHistory() {
  return request("/isolation/history", mockIsolationHistory);
}

export function getTrustScoreSummary() {
  return request("/trust-score/summary", mockTrustScoreSummary);
}

export function getTrustScoreHistory(deviceId) {
  return request(`/trust-score/${deviceId}/history?limit=50`, {
    device_id: deviceId,
    current_score: null,
    items: [],
  });
}