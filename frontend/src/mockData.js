/*
 * 공통 Mock 시간
 *
 * 현재 시각을 기준으로 생성하기 때문에
 * Mock 화면에서 데이터가 지나치게 오래된 것으로
 * 표시되는 문제를 방지합니다.
 */
const MOCK_NOW = Date.now();

function secondsAgo(seconds) {
  return new Date(
    MOCK_NOW - seconds * 1000
  ).toISOString();
}

function minutesAgo(minutes) {
  return new Date(
    MOCK_NOW - minutes * 60 * 1000
  ).toISOString();
}

function createWindow(
  secondsBeforeNow,
  durationSeconds = 10
) {
  const startTime =
    MOCK_NOW -
    secondsBeforeNow * 1000;

  return {
    window_start:
      new Date(
        startTime
      ).toISOString(),

    window_end:
      new Date(
        startTime +
          durationSeconds * 1000
      ).toISOString(),
  };
}

const TRUST_WINDOW_1 =
  createWindow(90);

const TRUST_WINDOW_2 =
  createWindow(70);

const TRUST_WINDOW_3 =
  createWindow(50);

const CAPTURE_GAP_WINDOW =
  createWindow(30);

/*
 * Dashboard Summary
 */
export const mockSummary = {
  total_devices: 4,

  normal_devices: 1,
  warning_devices: 1,
  danger_devices: 1,
  isolated_devices: 1,

  recent_events_count: 6,
  unknown_device_count: 1,

  active_firewall_rules: 1,
  pending_firewall_rules: 1,
  failed_firewall_rules: 1,

  packet_capture_degraded: true,

  last_updated:
    secondsAgo(2),
};

/*
 * Device 목록
 *
 * firewall_status는 기존 Device API에 실제로
 * 포함되지 않을 수도 있습니다.
 *
 * 화면 Mock 확인을 위한 보조 필드이며,
 * 실제 구현에서는 firewall-rules 응답을
 * device_id 기준으로 연결할 수 있습니다.
 */
export const mockDevices = {
  items: [
    {
      device_id: "esp32_01",
      ip_address: "192.168.0.4",
      status: "normal",
      trust_score: 100,
      firewall_status: null,
      last_seen_at:
        secondsAgo(4),
    },
    {
      device_id: "esp32_02",
      ip_address: "192.168.0.5",
      status: "isolated",
      trust_score: 25,
      firewall_status: "APPLIED",
      last_seen_at:
        secondsAgo(12),
    },
    {
      device_id: "esp32_03",
      ip_address: "192.168.0.6",
      status: "danger",
      trust_score: 42,
      firewall_status: null,
      last_seen_at:
        secondsAgo(18),
    },
    {
      device_id: "esp32_04",
      ip_address: "192.168.0.7",
      status: "warning",
      trust_score: 67,
      firewall_status: "FAILED",
      last_seen_at:
        minutesAgo(2),
    },
  ],
  total: 4,
};

/*
 * MQTT Logs
 */
export const mockMqttLogs = {
  items: [
    {
      id: 1205,
      device_id: "esp32_01",
      topic:
        "iot/esp32_01/sensor",
      payload:
        "{\"device_id\":\"esp32_01\",\"temperature\":25.3}",
      payload_size: 47,
      received_at:
        secondsAgo(4),
      is_json_valid: 1,
      is_topic_valid: 1,
      error_message: null,
    },
    {
      id: 1206,
      device_id: "esp32_02",
      topic:
        "iot/esp32_02/sensor",
      payload:
        "{\"device_id\":\"esp32_02\",\"temperature\":27.8}",
      payload_size: 47,
      received_at:
        secondsAgo(14),
      is_json_valid: 1,
      is_topic_valid: 1,
      error_message: null,
    },
    {
      id: 1207,
      device_id: "unknown_01",
      topic:
        "iot/unknown_01/sensor",
      payload:
        "{\"device_id\":\"unknown_01\"}",
      payload_size: 28,
      received_at:
        secondsAgo(24),
      is_json_valid: 1,
      is_topic_valid: 1,
      error_message:
        "Unknown device",
    },
  ],
  total: 3,
};

/*
 * MQTT Feature Logs
 */
export const mockFeatureLogs = {
  items: [
    {
      id: 1,
      device_id: "esp32_01",

      window_start:
        TRUST_WINDOW_1.window_start,

      window_end:
        TRUST_WINDOW_1.window_end,

      publish_count: 2,
      avg_payload_size: 57.5,
      max_payload_size: 82,

      avg_message_interval: 2.4,
      min_message_interval: 4.8,

      malformed_count: 0,
      abnormal_topic_count: 0,

      created_at:
        TRUST_WINDOW_1.window_end,
    },
    {
      id: 2,
      device_id: "esp32_02",

      window_start:
        TRUST_WINDOW_2.window_start,

      window_end:
        TRUST_WINDOW_2.window_end,

      publish_count: 28,
      avg_payload_size: 60,
      max_payload_size: 90,

      avg_message_interval: 0.31,
      min_message_interval: 0.15,

      malformed_count: 0,
      abnormal_topic_count: 0,

      created_at:
        TRUST_WINDOW_2.window_end,
    },
  ],
  total: 2,
};

/*
 * Detection Events
 *
 * Phase 4 확인 항목:
 * - incident_family
 * - subject_ip
 * - analysis_window_start/end
 * - evidence
 * - evidence_schema_version
 * - processing_reason
 * - policy_version
 * - applied_to_score
 * - CAPTURE_GAP_UNSCORED
 */
export const mockEvents = {
  items: [
    /*
     * 첫 번째 BROKER_DOS 감점
     * 100 → 75
     */
    {
      id: 9,

      device_id: "esp32_02",
      subject_ip: "192.168.0.5",

      detector_name:
        "packet_rule",
      detector_type: "RULE",

      event_type:
        "BROKER_DOS_SUSPECTED",

      incident_family:
        "FLOODING",

      severity: "high",

      score_delta: -25,
      applied_to_score: 1,

      description:
        "MQTT Broker 대상 비정상 Packet Flood가 탐지되었습니다.",

      analysis_window_start:
        TRUST_WINDOW_1.window_start,

      analysis_window_end:
        TRUST_WINDOW_1.window_end,

      packet_feature_log_id: 101,
      feature_log_id: null,
      mqtt_log_id: null,

      processing_reason:
        "REPRESENTATIVE_RULE_EVENT",

      policy_version:
        "packet-rule-v1",

      dedupe_key:
        "packet_rule:packet_feature_logs:101:BROKER_DOS_SUSPECTED:packet-rule-v1",

      evidence_schema_version:
        "1.0",

      evidence: {
        source_type:
          "packet_feature_logs",

        source_id: 101,

        capture_session_id:
          "550e8400-e29b-41d4-a716-446655440001",

        packet_count: 360,
        total_bytes: 43800,

        captured_duration_seconds: 9.2,
        coverage_ratio: 0.92,

        nominal_packets_per_second: 36,

        effective_packets_per_second:
          39.13,

        nominal_bytes_per_second: 4380,

        effective_bytes_per_second:
          4760.87,

        mqtt_related_packet_count: 355,
        tcp_syn_count: 14,

        observed_value: 39.13,
        threshold: 25,

        comparison_operator: ">",

        capture_policy_version:
          "capture-policy-v1",

        cycle_cutoff:
          TRUST_WINDOW_1.window_end,
      },

      detected_at:
        TRUST_WINDOW_1.window_end,

      processed_at:
        secondsAgo(82),
    },

    /*
     * 동일 Window에서 AI도 탐지했지만
     * Rule이 존재하므로 보조 증거로만 저장
     */
    {
      id: 10,

      device_id: "esp32_02",
      subject_ip: "192.168.0.5",

      detector_name: "packet_if",
      detector_type: "AI",

      event_type:
        "AI_PACKET_ANOMALY",

      incident_family:
        "AI_ONLY",

      severity: "medium",

      score_delta: -15,
      applied_to_score: 0,

      description:
        "Packet Isolation Forest가 이상 트래픽을 탐지했습니다.",

      analysis_window_start:
        TRUST_WINDOW_1.window_start,

      analysis_window_end:
        TRUST_WINDOW_1.window_end,

      packet_feature_log_id: 101,
      feature_log_id: null,
      mqtt_log_id: null,

      processing_reason:
        "AI_SUPPORTING_EVIDENCE",

      policy_version:
        "packet-if-v1",

      dedupe_key:
        "packet_if:packet_feature_logs:101:AI_PACKET_ANOMALY:packet-if-v1",

      evidence_schema_version:
        "1.0",

      evidence: {
        source_type:
          "packet_feature_logs",

        source_id: 101,

        raw_decision_function:
          -0.184,

        anomaly_score: 0.184,

        threshold: 0.12,

        comparison_operator: ">",

        model_version:
          "packet-if-v1",

        captured_duration_seconds: 9.2,
        coverage_ratio: 0.92,

        normalized_packet_count:
          391.3,

        normalized_total_bytes:
          47608.7,
      },

      detected_at:
        TRUST_WINDOW_1.window_end,

      processed_at:
        secondsAgo(81),
    },

    /*
     * 두 번째 BROKER_DOS 감점
     * 75 → 50
     */
    {
      id: 11,

      device_id: "esp32_02",
      subject_ip: "192.168.0.5",

      detector_name:
        "packet_rule",
      detector_type: "RULE",

      event_type:
        "BROKER_DOS_SUSPECTED",

      incident_family:
        "FLOODING",

      severity: "high",

      score_delta: -25,
      applied_to_score: 1,

      description:
        "두 번째 완료 Window에서 MQTT Broker Flood가 탐지되었습니다.",

      analysis_window_start:
        TRUST_WINDOW_2.window_start,

      analysis_window_end:
        TRUST_WINDOW_2.window_end,

      packet_feature_log_id: 102,
      feature_log_id: null,
      mqtt_log_id: null,

      processing_reason:
        "REPRESENTATIVE_RULE_EVENT",

      policy_version:
        "packet-rule-v1",

      dedupe_key:
        "packet_rule:packet_feature_logs:102:BROKER_DOS_SUSPECTED:packet-rule-v1",

      evidence_schema_version:
        "1.0",

      evidence: {
        source_type:
          "packet_feature_logs",

        source_id: 102,

        packet_count: 410,
        total_bytes: 48700,

        captured_duration_seconds: 9.6,
        coverage_ratio: 0.96,

        nominal_packets_per_second: 41,

        effective_packets_per_second:
          42.71,

        nominal_bytes_per_second: 4870,

        effective_bytes_per_second:
          5072.92,

        mqtt_related_packet_count: 406,
        tcp_syn_count: 16,

        observed_value: 42.71,
        threshold: 25,

        comparison_operator: ">",

        capture_policy_version:
          "capture-policy-v1",
      },

      detected_at:
        TRUST_WINDOW_2.window_end,

      processed_at:
        secondsAgo(61),
    },

    /*
     * 세 번째 BROKER_DOS 감점
     * 50 → 25, 격리 진입
     */
    {
      id: 12,

      device_id: "esp32_02",
      subject_ip: "192.168.0.5",

      detector_name:
        "packet_rule",
      detector_type: "RULE",

      event_type:
        "BROKER_DOS_SUSPECTED",

      incident_family:
        "FLOODING",

      severity: "high",

      score_delta: -25,
      applied_to_score: 1,

      description:
        "세 번째 완료 Window에서 MQTT Broker Flood가 탐지되었습니다.",

      analysis_window_start:
        TRUST_WINDOW_3.window_start,

      analysis_window_end:
        TRUST_WINDOW_3.window_end,

      packet_feature_log_id: 103,
      feature_log_id: null,
      mqtt_log_id: null,

      processing_reason:
        "REPRESENTATIVE_RULE_EVENT",

      policy_version:
        "packet-rule-v1",

      dedupe_key:
        "packet_rule:packet_feature_logs:103:BROKER_DOS_SUSPECTED:packet-rule-v1",

      evidence_schema_version:
        "1.0",

      evidence: {
        source_type:
          "packet_feature_logs",

        source_id: 103,

        packet_count: 455,
        total_bytes: 53500,

        captured_duration_seconds: 9.4,
        coverage_ratio: 0.94,

        nominal_packets_per_second: 45.5,

        effective_packets_per_second:
          48.4,

        nominal_bytes_per_second: 5350,

        effective_bytes_per_second:
          5691.49,

        mqtt_related_packet_count: 450,
        tcp_syn_count: 18,

        observed_value: 48.4,
        threshold: 25,

        comparison_operator: ">",

        capture_policy_version:
          "capture-policy-v1",
      },

      detected_at:
        TRUST_WINDOW_3.window_end,

      processed_at:
        secondsAgo(41),
    },

    /*
     * 외부 IP Port Scan
     *
     * Device 매핑이 없으므로
     * Event는 저장하지만 Trust에는 미반영
     */
    {
      id: 13,

      device_id: null,
      subject_ip: "192.168.0.99",

      detector_name:
        "packet_rule",
      detector_type: "RULE",

      event_type: "PORT_SCAN",

      incident_family: "SCAN",

      severity: "high",

      score_delta: -20,
      applied_to_score: 0,

      description:
        "미매핑 IP에서 다수 목적지 Port에 대한 SYN 접근이 탐지되었습니다.",

      analysis_window_start:
        CAPTURE_GAP_WINDOW.window_start,

      analysis_window_end:
        CAPTURE_GAP_WINDOW.window_end,

      packet_feature_log_id: 105,
      feature_log_id: null,
      mqtt_log_id: null,

      processing_reason:
        "UNMAPPED_SUBJECT_IP",

      policy_version:
        "packet-rule-v1",

      dedupe_key:
        "packet_rule:packet_feature_logs:105:PORT_SCAN:packet-rule-v1",

      evidence_schema_version:
        "1.0",

      evidence: {
        source_type:
          "packet_feature_logs",

        source_id: 105,

        peer_ip:
          "192.168.0.99",

        distinct_dest_port_count: 18,
        tcp_syn_count: 21,

        threshold: 10,

        comparison_operator: ">",
      },

      detected_at:
        CAPTURE_GAP_WINDOW.window_end,

      processed_at:
        secondsAgo(21),
    },

    /*
     * Packet Capture Gap 구간 MQTT Event
     *
     * Event는 저장하지만 Trust 감점 없음
     */
    {
      id: 14,

      device_id: "esp32_03",
      subject_ip: "192.168.0.6",

      detector_name:
        "mqtt_feature_rule",

      detector_type: "RULE",

      event_type:
        "ABNORMAL_PUBLISH_RATE",

      incident_family:
        "FLOODING",

      severity: "medium",

      score_delta: -15,
      applied_to_score: 0,

      description:
        "Packet Capture Gap 구간에 발생한 MQTT 이상 증거입니다.",

      analysis_window_start:
        CAPTURE_GAP_WINDOW.window_start,

      analysis_window_end:
        CAPTURE_GAP_WINDOW.window_end,

      packet_feature_log_id: null,
      feature_log_id: 2,
      mqtt_log_id: null,

      processing_reason:
        "CAPTURE_GAP_UNSCORED",

      policy_version:
        "mqtt-feature-rule-v2",

      dedupe_key:
        "mqtt_feature_rule:feature_logs:2:ABNORMAL_PUBLISH_RATE:mqtt-feature-rule-v2",

      evidence_schema_version:
        "1.0",

      evidence: {
        source_type:
          "feature_logs",

        source_id: 2,

        publish_count: 23,
        threshold: 15,

        comparison_operator: ">",

        capture_gap: true,
        score_excluded: true,

        exclusion_reason:
          "PACKET_CAPTURE_GAP",
      },

      detected_at:
        CAPTURE_GAP_WINDOW.window_end,

      processed_at:
        secondsAgo(19),
    },
  ],
  total: 6,
};

/*
 * Trust Score Summary
 */
export const mockTrustScoreSummary = {
  items: [
    {
      device_id: "esp32_01",
      trust_score: 100,
      status: "normal",
      last_seen_at:
        secondsAgo(4),
    },
    {
      device_id: "esp32_02",
      trust_score: 25,
      status: "isolated",
      last_seen_at:
        secondsAgo(12),
    },
    {
      device_id: "esp32_03",
      trust_score: 42,
      status: "danger",
      last_seen_at:
        secondsAgo(18),
    },
    {
      device_id: "esp32_04",
      trust_score: 67,
      status: "warning",
      last_seen_at:
        minutesAgo(2),
    },
  ],
};

/*
 * Device별 Trust Score History
 *
 * api.js의 getTrustScoreHistory()에서
 * deviceId를 기준으로 조회합니다.
 *
 * 화면에서는 score_delta를 다시 더하지 않고
 * actual_delta와 new_score를 그대로 표시해야 합니다.
 */
export const mockTrustScoreHistories = {
  esp32_01: {
    device_id: "esp32_01",
    current_score: 100,
    items: [],
    total: 0,
  },

  esp32_02: {
    device_id: "esp32_02",
    current_score: 25,

    items: [
      {
        id: 703,
        device_id: "esp32_02",

        analysis_window_start:
          TRUST_WINDOW_3.window_start,

        analysis_window_end:
          TRUST_WINDOW_3.window_end,

        previous_score: 50,

        calculated_delta: -25,
        capped_delta: -25,
        actual_delta: -25,

        new_score: 25,

        representative_event_ids: [
          12,
        ],

        policy_version:
          "trust-policy-v2",

        created_at:
          secondsAgo(39),
      },
      {
        id: 702,
        device_id: "esp32_02",

        analysis_window_start:
          TRUST_WINDOW_2.window_start,

        analysis_window_end:
          TRUST_WINDOW_2.window_end,

        previous_score: 75,

        calculated_delta: -25,
        capped_delta: -25,
        actual_delta: -25,

        new_score: 50,

        representative_event_ids: [
          11,
        ],

        policy_version:
          "trust-policy-v2",

        created_at:
          secondsAgo(59),
      },
      {
        id: 701,
        device_id: "esp32_02",

        analysis_window_start:
          TRUST_WINDOW_1.window_start,

        analysis_window_end:
          TRUST_WINDOW_1.window_end,

        previous_score: 100,

        calculated_delta: -25,
        capped_delta: -25,
        actual_delta: -25,

        new_score: 75,

        representative_event_ids: [
          9,
        ],

        policy_version:
          "trust-policy-v2",

        created_at:
          secondsAgo(79),
      },
    ],

    total: 3,
  },

  esp32_03: {
    device_id: "esp32_03",
    current_score: 42,

    items: [
      {
        id: 704,
        device_id: "esp32_03",

        analysis_window_start:
          TRUST_WINDOW_2.window_start,

        analysis_window_end:
          TRUST_WINDOW_2.window_end,

        previous_score: 57,

        calculated_delta: -15,
        capped_delta: -15,
        actual_delta: -15,

        new_score: 42,

        representative_event_ids: [
          14,
        ],

        policy_version:
          "trust-policy-v2",

        created_at:
          secondsAgo(57),
      },
    ],

    total: 1,
  },

  esp32_04: {
    device_id: "esp32_04",
    current_score: 67,
    items: [],
    total: 0,
  },
};

/*
 * Isolation History
 *
 * trust_score_history_id를 통해
 * 어느 Trust Window에서 격리가 결정됐는지
 * 연결할 수 있습니다.
 */
export const mockIsolationHistory = {
  items: [
    {
      id: 1,

      device_id: "esp32_02",

      action: "ISOLATED",

      previous_status: "danger",
      new_status: "isolated",

      previous_score: 50,
      trust_score: 25,
      new_score: 25,

      reason:
        "Trust Score가 격리 기준인 30 미만으로 하락했습니다.",

      trigger_event_id: 12,

      trust_score_history_id: 703,

      created_at:
        secondsAgo(38),

      isolated_at:
        secondsAgo(38),

      released_at: null,
    },
  ],
  total: 1,
};

/*
 * Packet Traffic 테스트용 Mock 데이터
 *
 * 총 25건:
 * - 1페이지 20건
 * - 2페이지 5건
 *
 * Phase 4 확인 가능 항목:
 * - limit / offset Pagination
 * - INBOUND / OUTBOUND Filter
 * - 등록 Device / 미매핑 IP
 * - nominal Rate
 * - effective Rate
 * - Capture Duration
 * - Coverage
 * - Capture 적격 여부
 * - LATE_CAPTURE
 * - Legacy Timing Metadata 누락
 * - UTC → KST 변환
 */
const PACKET_FEATURE_COUNT = 25;

const PACKET_WINDOW_BASE_TIME =
  new Date(
    "2026-07-24T01:00:00Z"
  ).getTime();

const REGISTERED_DEVICE_IDS = [
  "esp32_01",
  "esp32_02",
  "esp32_03",
];

const REGISTERED_DEVICE_IPS = {
  esp32_01: "192.168.0.4",
  esp32_02: "192.168.0.5",
  esp32_03: "192.168.0.6",
};

const UNMAPPED_PEER_IPS = [
  "192.168.0.99",
  "192.168.0.100",
];

const packetFeatureItems =
  Array.from(
    {
      length: PACKET_FEATURE_COUNT,
    },
    (_, index) => {
      const id = 101 + index;

      const windowStartTime =
        PACKET_WINDOW_BASE_TIME +
        index * 10_000;

      const windowEndTime =
        windowStartTime + 10_000;

      /*
       * 5번째 Row는 미매핑 IP
       */
      const isUnmapped =
        (index + 1) % 5 === 0;

      /*
       * 12번째 Row는 LATE_CAPTURE 실패
       */
      const isLateCapture =
        index === 11;

      /*
       * 18번째 Row는 Legacy Timing Metadata 누락
       */
      const isLegacy =
        index === 17;

      const deviceId =
        isUnmapped
          ? null
          : REGISTERED_DEVICE_IDS[
              index %
                REGISTERED_DEVICE_IDS.length
            ];

      const peerIp =
        isUnmapped
          ? UNMAPPED_PEER_IPS[
              index %
                UNMAPPED_PEER_IPS.length
            ]
          : REGISTERED_DEVICE_IPS[
              deviceId
            ];

      const direction =
        index % 2 === 0
          ? "INBOUND"
          : "OUTBOUND";

      const packetCount =
        isLateCapture
          ? 0
          : isUnmapped
            ? 100 + index
            : 30 + index;

      const totalBytes =
        packetCount * 192;

      /*
       * 정상 Capture는 9.0~10.0초 사이
       */
      const capturedDuration =
        isLateCapture
          ? 0
          : isLegacy
            ? null
            : Number(
                (
                  9 +
                  (index % 10) * 0.1
                ).toFixed(1)
              );

      const coverageRatio =
        capturedDuration === null
          ? null
          : Number(
              (
                capturedDuration / 10
              ).toFixed(2)
            );

      const nominalPacketsPerSecond =
        packetCount / 10;

      const nominalBytesPerSecond =
        totalBytes / 10;

      const effectivePacketsPerSecond =
        capturedDuration &&
        capturedDuration > 0
          ? Number(
              (
                packetCount /
                capturedDuration
              ).toFixed(2)
            )
          : null;

      const effectiveBytesPerSecond =
        capturedDuration &&
        capturedDuration > 0
          ? Number(
              (
                totalBytes /
                capturedDuration
              ).toFixed(2)
            )
          : null;

      const captureEligible =
        !isLateCapture &&
        !isLegacy &&
        capturedDuration >= 9;

      const captureExclusionReason =
        isLateCapture
          ? "LATE_CAPTURE"
          : isLegacy
            ? "MISSING_TIMING_METADATA"
            : null;

      return {
        id,

        capture_segment_id:
          21 + index,

        capture_session_id:
          `550e8400-e29b-41d4-a716-${String(
            446655440000 + index
          )}`,

        /*
         * 기존 화면 호환용
         */
        session_id:
          `550e8400-e29b-41d4-a716-${String(
            446655440000 + index
          )}`,

        device_id: deviceId,
        peer_ip: peerIp,
        direction,

        window_start:
          new Date(
            windowStartTime
          ).toISOString(),

        window_end:
          new Date(
            windowEndTime
          ).toISOString(),

        packet_count:
          packetCount,

        total_bytes:
          totalBytes,

        avg_packet_size:
          packetCount > 0
            ? 192
            : null,

        max_packet_size:
          packetCount === 0
            ? null
            : isUnmapped
              ? 1024
              : 512,

        mean_inter_arrival_time:
          packetCount === 0
            ? null
            : isUnmapped
              ? 0.08
              : 0.23,

        distinct_dest_port_count:
          packetCount === 0
            ? null
            : isUnmapped
              ? 15
              : 1,

        tcp_syn_count:
          packetCount === 0
            ? null
            : isUnmapped
              ? 18
              : index % 7,

        mqtt_related_packet_count:
          packetCount === 0
            ? null
            : isUnmapped
              ? 0
              : packetCount,

        non_mqtt_tcp_udp_packet_count:
          packetCount === 0
            ? null
            : isUnmapped
              ? packetCount
              : 0,

        /*
         * 명목 10초 Window 기준 Rate
         */
        nominal_packets_per_second:
          nominalPacketsPerSecond,

        nominal_bytes_per_second:
          nominalBytesPerSecond,

        /*
         * Phase 3-B 호환 Alias
         *
         * 문서상 packets_per_second와
         * bytes_per_second는 전환 기간 동안
         * 명목값 Alias로 유지합니다.
         */
        packets_per_second:
          nominalPacketsPerSecond,

        bytes_per_second:
          nominalBytesPerSecond,

        /*
         * 실제 Capture Duration 기준 Rate
         *
         * Duration이 0이거나 Metadata가 없으면
         * null이며 명목값으로 대체하지 않습니다.
         */
        effective_packets_per_second:
          effectivePacketsPerSecond,

        effective_bytes_per_second:
          effectiveBytesPerSecond,

        captured_duration_seconds:
          capturedDuration,

        coverage_ratio:
          coverageRatio,

        capture_eligible:
          captureEligible,

        capture_exclusion_reason:
          captureExclusionReason,

        segment_status:
          isLateCapture
            ? "FAILED"
            : "PROCESSED",

        segment_error_code:
          isLateCapture
            ? "LATE_CAPTURE"
            : null,

        capture_policy_version:
          isLegacy
            ? null
            : "capture-policy-v1",

        capture_scope:
          "PI1_INTERNAL_LAN",

        created_at:
          new Date(
            windowEndTime + 1_000
          ).toISOString(),
      };
    }
  );

export const mockPacketFeatureLogs = {
  items: packetFeatureItems,

  total:
    packetFeatureItems.length,
};

/*
 * Gateway Status 테스트용 Mock 데이터
 *
 * 확인 가능 항목:
 * - Gateway ONLINE
 * - CPU / Memory / Disk / 온도
 * - Interface 정상
 * - Interface DOWN
 * - Interface 미인식
 * - Nullable Rate
 * - UTC → KST 변환
 * - 실제 수집 간격 10초
 */
export const mockGatewayMetrics = {
  items: [
    {
      id: 51,

      /*
       * api.js에서 요청할 때마다
       * 첫 번째 Item의 collected_at을
       * 현재 시각으로 갱신합니다.
       */
      collected_at:
        new Date().toISOString(),

      sample_interval_seconds:
        10.04,

      cpu_percent: 18.2,
      memory_percent: 41.5,
      disk_percent: 27.1,
      disk_used_mb: 8734.2,

      temperature_c: 48.6,

      interface_metrics: {
        /*
         * 정상 Interface
         */
        internal_lan: {
          interface_name: "eth0",

          exists: true,
          is_up: true,

          ip_address:
            "192.168.0.20",

          rx_bytes: 124000000,
          tx_bytes: 36000000,

          rx_bytes_per_second:
            1820.4,

          tx_bytes_per_second:
            940.2,

          /*
           * 기존 화면 호환 필드
           */
          rx_bytes_per_sec:
            1820.4,

          tx_bytes_per_sec:
            940.2,
        },

        /*
         * 존재하지만 DOWN 상태
         */
        wireless_lan: {
          interface_name: "wlan0",

          exists: true,
          is_up: false,

          ip_address: null,

          rx_bytes: 158000,
          tx_bytes: 92000,

          rx_bytes_per_second:
            null,

          tx_bytes_per_second:
            null,

          rx_bytes_per_sec: null,
          tx_bytes_per_sec: null,
        },

        /*
         * USB LAN 미인식
         */
        usb_lan: {
          interface_name: null,

          exists: false,
          is_up: null,

          ip_address: null,

          rx_bytes: null,
          tx_bytes: null,

          rx_bytes_per_second:
            null,

          tx_bytes_per_second:
            null,

          rx_bytes_per_sec: null,
          tx_bytes_per_sec: null,
        },
      },

      created_at:
        secondsAgo(2),
    },
  ],

  total: 1,
};

/*
 * Firewall Rules
 *
 * Trust의 격리 결정 상태와
 * 실제 Network 차단 상태를 구분하기 위한 Mock입니다.
 */
export const mockFirewallRules = {
  items: [
    /*
     * 실제 적용 완료
     */
    {
      id: 901,

      device_id: "esp32_02",
      source_ip: "192.168.0.5",

      protocol: "TCP",
      destination_port: 1883,
      action: "DROP",

      status: "APPLIED",

      reason:
        "Trust Score가 30 미만으로 하락하여 MQTT 통신 차단이 요청되었습니다.",

      retry_count: 0,

      last_error: null,

      last_attempted_at:
        secondsAgo(36),

      next_retry_at: null,

      applied_at:
        secondsAgo(35),

      released_at: null,

      created_at:
        secondsAgo(38),

      updated_at:
        secondsAgo(35),
    },

    /*
     * 격리 결정 후 적용 대기
     */
    {
      id: 902,

      device_id: "esp32_03",
      source_ip: "192.168.0.6",

      protocol: "TCP",
      destination_port: 1883,
      action: "DROP",

      status: "PENDING",

      reason:
        "Firewall Worker의 차단 적용을 기다리고 있습니다.",

      retry_count: 0,

      last_error: null,

      last_attempted_at: null,

      next_retry_at:
        new Date(
          MOCK_NOW + 10_000
        ).toISOString(),

      applied_at: null,
      released_at: null,

      created_at:
        secondsAgo(15),

      updated_at:
        secondsAgo(15),
    },

    /*
     * 최대 재시도 후 실패
     */
    {
      id: 903,

      device_id: "esp32_04",
      source_ip: "192.168.0.7",

      protocol: "TCP",
      destination_port: 1883,
      action: "DROP",

      status: "FAILED",

      reason:
        "Firewall Rule 적용에 실패했습니다.",

      retry_count: 3,

      last_error:
        "iptables 적용 후 동일한 Comment와 Rule Specification을 확인하지 못했습니다.",

      last_attempted_at:
        minutesAgo(1),

      next_retry_at: null,

      applied_at: null,
      released_at: null,

      created_at:
        minutesAgo(4),

      updated_at:
        minutesAgo(1),
    },

    /*
     * 기존 차단 해제
     */
    {
      id: 904,

      device_id: "esp32_01",
      source_ip: "192.168.0.4",

      protocol: "TCP",
      destination_port: 1883,
      action: "DROP",

      status: "REMOVED",

      reason:
        "관리자 확인 후 기존 Firewall Rule을 해제했습니다.",

      retry_count: 0,

      last_error: null,

      last_attempted_at:
        minutesAgo(8),

      next_retry_at: null,

      applied_at:
        minutesAgo(30),

      released_at:
        minutesAgo(8),

      created_at:
        minutesAgo(32),

      updated_at:
        minutesAgo(8),
    },
  ],

  total: 4,
};

/*
 * GET /api/health Mock
 *
 * 실제 API 응답에서도
 * DB 경로, Secret, Stack Trace 등은
 * 노출하지 않아야 합니다.
 */
export const mockHealth = {
  status: "ok",

  api: "available",

  database: "connected",

  checked_at:
    secondsAgo(1),
};