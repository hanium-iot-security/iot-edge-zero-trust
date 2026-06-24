import axios from "axios";
import {
  mockSummary,
  mockDevices,
  mockMqttLogs,
  mockFeatureLogs,
  mockEvents,
  mockIsolationHistory,
} from "../mockData";

const API_BASE_URL = "http://192.168.0.20:8000";

// 백엔드 완성 전에는 true, 실제 FastAPI 연결할 때 false
const USE_MOCK = true;

export async function getSummary() {
  if (USE_MOCK) return mockSummary;
  const res = await axios.get(`${API_BASE_URL}/api/dashboard/summary`);
  return res.data;
}

export async function getDevices() {
  if (USE_MOCK) return mockDevices;
  const res = await axios.get(`${API_BASE_URL}/api/devices`);
  return res.data;
}

export async function getMqttLogs() {
  if (USE_MOCK) return mockMqttLogs;
  const res = await axios.get(`${API_BASE_URL}/api/mqtt-logs?limit=10`);
  return res.data;
}

export async function getFeatureLogs() {
  if (USE_MOCK) return mockFeatureLogs;
  const res = await axios.get(`${API_BASE_URL}/api/feature-logs?limit=10`);
  return res.data;
}

export async function getEvents() {
  if (USE_MOCK) return mockEvents;
  const res = await axios.get(`${API_BASE_URL}/api/detection-events?limit=10`);
  return res.data;
}

export async function getIsolationHistory() {
  if (USE_MOCK) return mockIsolationHistory;
  const res = await axios.get(`${API_BASE_URL}/api/isolation/history`);
  return res.data;
}