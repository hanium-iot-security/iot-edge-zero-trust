export const mockSummary = {
  total_devices: 2,
  normal_devices: 1,
  warning_devices: 0,
  danger_devices: 0,
  isolated_devices: 1,
  recent_events_count: 3,
  unknown_device_count: 1,
  last_updated: "2026-05-26 14:35:10",
};

export const mockDevices = {
  items: [
    {
      device_id: "esp32_01",
      ip_address: "192.168.0.4",
      status: "normal",
      trust_score: 100,
      last_seen_at: "2026-05-26 14:30:10",
    },
    {
      device_id: "esp32_02",
      ip_address: "192.168.0.5",
      status: "isolated",
      trust_score: 25,
      last_seen_at: "2026-05-26 14:29:50",
    },
  ],
  total: 2,
};

export const mockMqttLogs = {
  items: [
    {
      id: 1205,
      device_id: "esp32_01",
      topic: "iot/esp32_01/sensor",
      payload: "{\"device_id\":\"esp32_01\"}",
      payload_size: 24,
      received_at: "2026-05-26 14:30:01",
      is_json_valid: 1,
      is_topic_valid: 1,
      error_message: null,
    },
    {
      id: 1206,
      device_id: "unknown_01",
      topic: "iot/unknown_01/sensor",
      payload: "{\"device_id\":\"unknown_01\"}",
      payload_size: 28,
      received_at: "2026-05-26 14:30:05",
      is_json_valid: 1,
      is_topic_valid: 1,
      error_message: "Unknown device",
    },
  ],
  total: 2,
};

export const mockFeatureLogs = {
  items: [
    {
      id: 1,
      device_id: "esp32_01",
      window_start: "14:30:00",
      publish_count: 2,
      avg_payload_size: 57.5,
      max_payload_size: 82,
      avg_message_interval: 2.4,
      min_message_interval: 4.8,
    },
    {
      id: 2,
      device_id: "esp32_02",
      window_start: "14:30:10",
      publish_count: 18,
      avg_payload_size: 60,
      max_payload_size: 90,
      avg_message_interval: 0.8,
      min_message_interval: 0.5,
    },
  ],
  total: 2,
};

export const mockEvents = {
  items: [
    {
      id: 9,
      device_id: "esp32_02",
      detector_type: "RULE",
      event_type: "ABNORMAL_PUBLISH_RATE",
      severity: "high",
      score_delta: -20,
      applied_to_score: 1,
      description: "10초 동안 publish 15회 초과",
      detected_at: "2026-05-26 14:35:00",
    },
    {
      id: 10,
      device_id: "unknown_01",
      detector_type: "RULE",
      event_type: "UNKNOWN_DEVICE",
      severity: "high",
      score_delta: 0,
      applied_to_score: 0,
      description: "미등록 기기 접근",
      detected_at: "2026-05-26 14:35:05",
    },
    {
      id: 11,
      device_id: "esp32_02",
      detector_type: "AI",
      event_type: "AI_ANOMALY",
      severity: "high",
      score_delta: -15,
      applied_to_score: 1,
      description: "Isolation Forest 기반 이상 탐지",
      detected_at: "2026-05-26 14:35:08",
    },
  ],
  total: 3,
};

export const mockIsolationHistory = {
  items: [
    {
      id: 1,
      device_id: "esp32_02",
      action: "ISOLATED",
      reason: "Trust Score below threshold",
      trust_score: 25,
      trigger_event_id: 9,
      created_at: "2026-05-26 14:35:10",
    },
  ],
  total: 1,
};

export const mockTrustScoreSummary = {
  items: [
    {
      device_id: "esp32_01",
      trust_score: 100,
      status: "normal",
      last_seen_at: "2026-05-26 14:30:10",
    },
    {
      device_id: "esp32_02",
      trust_score: 25,
      status: "isolated",
      last_seen_at: "2026-05-26 14:29:50",
    },
  ],
};