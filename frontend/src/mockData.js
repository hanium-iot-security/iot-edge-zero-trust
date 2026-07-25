export const mockSummary = {
  total_devices: 3,
  normal_devices: 2,
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
    {
      device_id: "esp32_03",
      ip_address: "192.168.0.6",
      status: "normal",
      trust_score: 92,
      last_seen_at: "2026-05-26 14:29:40",
    },
  ],
  total: 3,
};

export const mockMqttLogs = {
  items: [
    {
      id: 1205,
      device_id: "esp32_01",
      topic: "iot/esp32_01/sensor",
      payload:
        "{\"device_id\":\"esp32_01\"}",
      payload_size: 24,
      received_at:
        "2026-05-26 14:30:01",
      is_json_valid: 1,
      is_topic_valid: 1,
      error_message: null,
    },
    {
      id: 1206,
      device_id: "unknown_01",
      topic: "iot/unknown_01/sensor",
      payload:
        "{\"device_id\":\"unknown_01\"}",
      payload_size: 28,
      received_at:
        "2026-05-26 14:30:05",
      is_json_valid: 1,
      is_topic_valid: 1,
      error_message:
        "Unknown device",
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
      event_type:
        "ABNORMAL_PUBLISH_RATE",
      severity: "high",
      score_delta: -20,
      applied_to_score: 1,
      description:
        "10초 동안 publish 15회 초과",
      detected_at:
        "2026-05-26 14:35:00",
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
      detected_at:
        "2026-05-26 14:35:05",
    },
    {
      id: 11,
      device_id: "esp32_02",
      detector_type: "AI",
      event_type: "AI_ANOMALY",
      severity: "high",
      score_delta: -15,
      applied_to_score: 1,
      description:
        "Isolation Forest 기반 이상 탐지",
      detected_at:
        "2026-05-26 14:35:08",
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
      reason:
        "Trust Score below threshold",
      trust_score: 25,
      trigger_event_id: 9,
      created_at:
        "2026-05-26 14:35:10",
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
      last_seen_at:
        "2026-05-26 14:30:10",
    },
    {
      device_id: "esp32_02",
      trust_score: 25,
      status: "isolated",
      last_seen_at:
        "2026-05-26 14:29:50",
    },
    {
      device_id: "esp32_03",
      trust_score: 92,
      status: "normal",
      last_seen_at:
        "2026-05-26 14:29:40",
    },
  ],
};

/*
 * Packet Traffic 테스트용 Mock 데이터
 *
 * 총 25건:
 * - 1페이지 20건
 * - 2페이지 5건
 *
 * 확인 가능 항목:
 * - limit/offset 페이지 이동
 * - INBOUND/OUTBOUND 필터
 * - device_id 고유값 집계
 * - 미매핑 peer_ip 고유값 집계
 * - UTC → KST 변환
 */
const PACKET_FEATURE_COUNT = 25;

const PACKET_WINDOW_BASE_TIME =
  new Date(
    "2026-07-16T05:00:00Z"
  ).getTime();

const REGISTERED_DEVICE_IDS = [
  "esp32_01",
  "esp32_02",
  "esp32_03",
];

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
       * 5번째 Row마다 미매핑 데이터로 설정
       *
       * 미매핑 Row:
       * index 4, 9, 14, 19, 24
       *
       * peer_ip는 두 값을 반복해서 사용하므로
       * Row는 5건이어도 고유 미매핑 IP는 2개입니다.
       */
      const isUnmapped =
        (index + 1) % 5 === 0;

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
          : `192.168.0.${
              30 +
              (index %
                REGISTERED_DEVICE_IDS.length)
            }`;

      const direction =
        index % 2 === 0
          ? "INBOUND"
          : "OUTBOUND";

      const packetCount =
        isUnmapped
          ? 100 + index
          : 30 + index;

      const totalBytes =
        packetCount * 192;

      return {
        id,
        capture_segment_id:
          21 + index,
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
        avg_packet_size: 192,
        max_packet_size:
          isUnmapped ? 1024 : 512,
        mean_inter_arrival_time:
          isUnmapped ? 0.08 : 0.23,
        distinct_dest_port_count:
          isUnmapped ? 15 : 1,
        tcp_syn_count:
          isUnmapped ? 18 : 0,
        mqtt_related_packet_count:
          isUnmapped
            ? 0
            : packetCount,
        non_mqtt_tcp_udp_packet_count:
          isUnmapped
            ? packetCount
            : 0,
        packets_per_second:
          packetCount / 10,
        bytes_per_second:
          totalBytes / 10,
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
 * - 내부 LAN 연결됨
 * - USB LAN 미인식
 * - UTC → KST 변환
 * - 실제 수집 간격 10초
 */
export const mockGatewayMetrics = {
  items: [
    {
      id: 51,

      /*
       * api.js에서도 요청할 때마다
       * collected_at을 현재 시간으로 갱신합니다.
       * 따라서 Mock 모드에서는 ONLINE으로
       * 표시됩니다.
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
        internal_lan: {
          interface_name: "eth0",
          exists: true,
          is_up: true,
          ip_address:
            "192.168.0.20",
          rx_bytes: 124000000,
          tx_bytes: 36000000,
          rx_bytes_per_sec:
            1820.4,
          tx_bytes_per_sec:
            940.2,
        },

        /*
         * USB LAN 미인식 상태 검증용
         */
        usb_lan: {
          interface_name: null,
          exists: false,
          is_up: false,
          ip_address: null,
          rx_bytes: null,
          tx_bytes: null,
          rx_bytes_per_sec: null,
          tx_bytes_per_sec: null,
        },
      },
    },
  ],
  total: 1,
};