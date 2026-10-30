// Display labels only. API values, stored evidence and command payloads stay unchanged.
const labels = {
  UNKNOWN: "확인 불가", NO_DATA: "자료 없음", "NO DATA": "자료 없음", API_ERROR: "조회 실패",
  RESPONSE: "응답 수신", MATCH: "규칙 일치", MISMATCH: "규칙 불일치",
  PARTIAL: "부분 수집", UNINSPECTED: "미검사", EXCLUDED: "분석 제외",
  ONLINE: "최근 수신", OFFLINE: "장기 미수신", STALE: "정보 갱신 지연", FRESH: "최신",
  PENDING: "대기", APPLIED: "규칙 적용", REMOVED: "규칙 제거", FAILED: "실패",
  PROCESSED: "수집 처리 완료", CAPTURED: "수집 완료", COMPLETED: "완료",
  PROCESSING: "처리 중", EMPTY: "패킷 없음", MISSING: "수집 자료 누락",
  HIGH: "높음", MEDIUM: "보통", LOW: "낮음", CRITICAL: "매우 높음",
  DEGRADED: "품질 저하", DOWN: "비활성", CONNECTED: "연결됨",
  RULE: "규칙 기반", AI: "AI", INBOUND: "기기 → Pi", OUTBOUND: "Pi → 기기",
  CURRENT: "현재", HISTORICAL: "과거 관측", ENABLED: "사용", DISABLED: "사용 중지",
  RUNNING: "실행 중", ACTIVE: "활성", READY: "준비 완료", HEALTHY: "정상",
  STARTING: "시작 중", STOPPING: "종료 중", STOPPED: "중지", ERROR: "오류",
  UNHEALTHY: "상태 이상", CRASHED: "비정상 종료", OFF: "사용 안 함", OBSERVE: "관찰 모드",
  PASS: "통과", HOLD: "보류", SUCCESS: "성공", AVAILABLE: "사용 가능", UNAVAILABLE: "사용 불가",
  VERIFIED_RELEASED: "차단 해제 확인", VERIFIED_BLOCKED: "차단 확인",
  SUPPRESSED: "중복 알림 생략", NOTIFIED: "알림 전송", NOTIFY: "알림 전송", CLOSED: "마감",
  SENSOR: "센서", CAMERA: "카메라", ACTUATOR: "구동 장치", OTHER: "기타",
  IDENTITY: "기기 식별", MESSAGE_POLICY: "메시지 정책", FLOODING: "트래픽 폭주",
  NETWORK_POLICY: "네트워크 정책", SCAN: "포트 스캔", AI_ONLY: "AI 단독 이상징후",
  POLICY: "분석·설정 상태",
  AI_PACKET_ANOMALY: "AI 패킷 이상징후", AI_ANOMALY: "AI 메시지 이상징후",
  BROKER_DOS_SUSPECTED: "MQTT 브로커 과부하 의심", PORT_SCAN: "포트 스캔 의심",
  ABNORMAL_PUBLISH_RATE: "메시지 전송 빈도 이상", UNKNOWN_DEVICE: "미등록 기기 감지",
  PACKET_RATE_ANOMALY: "패킷 전송 빈도 이상", BYTE_RATE_ANOMALY: "데이터 전송량 이상",
  LARGE_PAYLOAD: "메시지 크기 초과", MALFORMED_PAYLOAD: "메시지 형식 오류",
  ABNORMAL_TOPIC: "허용 토픽 위반", DEVICE_ID_MISMATCH: "기기 식별정보 불일치",
  POLICY_UNAVAILABLE: "탐지 정책 확인 불가", BROKER_DOS_EVIDENCE_UNAVAILABLE: "브로커 탐지 근거 부족",
  NON_MQTT_TRAFFIC: "MQTT 외 통신",
  "UNKNOWN DEVICE": "미등록 기기 감지", INVALID_JSON: "JSON 형식 오류",
  INVALID_TOPIC: "토픽 형식 오류", PAYLOAD_TOO_LARGE: "메시지 크기 초과",
  LATE_CAPTURE: "수집 시작 지연", MISSING_TIMING_METADATA: "수집 시간 정보 없음",
};

export function uiLabel(value) {
  if (value === null || value === undefined || value === "") return "-";
  const text = String(value);
  return labels[text.trim().toUpperCase()] ?? text;
}

const evidenceLabels = {
  source_type: "원본 자료 유형", source_id: "원본 자료 ID", device_id: "기기 ID",
  candidate_device_id: "식별 후보 기기 ID", capture_coverage_ratio: "수집 시간 충족 비율",
  capture_policy: "수집 품질 기준", capture_segment_id: "수집 구간 ID",
  capture_session_id: "수집 세션 ID", cycle_range_start: "탐지 처리 범위 시작",
  cycle_cutoff: "탐지 처리 범위 종료", model: "모델 판정 정보",
  normalization: "입력값 보정 방식", normalized_values: "보정 입력값",
  observed_values: "실제 관측값", trust_decision: "신뢰점수 반영 근거",
  policy_version: "적용 정책 버전",
  detector_name: "탐지기", event_type: "탐지 유형", model_version: "모델 버전",
  raw_decision_function: "모델 원점수", anomaly_score: "이상 점수", threshold: "판정 기준값",
  comparison_operator: "판정 연산자", captured_duration_seconds: "실제 수집시간(초)",
  coverage_ratio: "수집 시간 충족률", normalized_packet_count: "보정 패킷 수",
  normalized_total_bytes: "보정 전송량", publish_count: "메시지 수",
  avg_payload_size: "평균 메시지 크기", max_payload_size: "최대 메시지 크기",
  packets_per_second: "초당 패킷 수", bytes_per_second: "초당 전송량",
  first_window: "최초 분석 구간", latest_window: "최근 분석 구간",
  bucket_start: "집계 시작", bucket_end: "집계 종료", count: "발생 횟수",
  occurrence_count: "발생 횟수", suppressed_count: "중복 알림 생략 횟수",
  last_decision: "최근 알림 처리", notified_at: "알림 시각", closed: "집계 마감 여부",
  window_start: "분석 시작", window_end: "분석 종료", inference_count: "추론 횟수",
  input_count: "입력 수", normal_count: "정상 판정 수", anomaly_count: "이상 판정 수",
};

export function evidenceLabel(key) {
  return Object.hasOwn(evidenceLabels, key) ? evidenceLabels[key] : key;
}
