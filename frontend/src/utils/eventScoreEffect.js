// Display server-projected effects without inferring them from nominal policy values.
export function formatScoreDelta(value) {

  if (

    value === null ||

    value === undefined ||

    value === ""

  ) {

    return "-";

  }

  const number = Number(value);

  if (!Number.isFinite(number)) {

    return "-";

  }

  if (number > 0) {

    return `+${number}`;

  }

  return String(number);

}

export function formatActualScoreDelta(event) {
  if (typeof event.actual_score_delta === "number" && Number.isFinite(event.actual_score_delta)) {
    return formatScoreDelta(event.actual_score_delta);
  }
  if (event.score_effect_reason === "PENDING") return "처리 대기";
  if (event.score_effect_reason === "GROUP_HISTORY") return "개별 배분 없음";
  return "확인 불가";
}

export function getScoreEffectDescription(event) {
  if (event.score_effect_reason === "NOT_APPLIED") {
    return `${getProcessingReasonLabel(event.processing_reason)} · 실제 점수 미반영`;
  }
  if (event.score_effect_reason === "PENDING") return "신뢰점수 처리 대기";
  if (event.score_effect_reason === "GROUP_HISTORY") {
    return "여러 대표 이벤트가 함께 반영된 이력입니다. 이벤트별 배분 근거 없음";
  }
  if (event.score_effect_reason === "EVENT_HISTORY") return "연결된 신뢰점수 이력으로 확인한 변화량";
  return "실제 점수 변화량을 확인할 수 있는 처리 기록이나 연결 이력이 없습니다.";
}

export function isAppliedToScore(value) {

  return (

    value === true ||

    value === 1 ||

    value === "1" ||

    value === "true"

  );

}

export function getAppliedStatus(event) {
  if (event.score_effect_reason === "PENDING") return { status: "unknown", label: "처리 대기" };


  if (

    event.processing_reason ===

    "CAPTURE_GAP_UNSCORED"

  ) {

    return {

      status: "degraded",

      label: "수집 공백 미반영",

    };

  }

  if (!isAppliedToScore(event.applied_to_score) && event.score_effect_reason !== "NOT_APPLIED") {
    return { status: "unknown", label: "반영 여부 확인 불가" };
  }

  if (isAppliedToScore(

    event.applied_to_score

  )) {

    return {

      status: "scored",

      label: "점수 반영",

    };

  }

  return {

    status: "unscored",

    label: "미반영",

  };

}

export function getProcessingReasonLabel(reason) {

  const labels = {
    APPLIED_TO_TRUST: "신뢰점수 반영",
    AI_OBSERVATION_ONLY: "AI 관찰 전용 · 감점 없음",
    ALREADY_ISOLATED: "이미 격리된 기기 · 추가 감점 없음",
    NOT_REPRESENTATIVE: "동일 구간의 대표 이벤트가 아님",
    LATE_EVENT: "이미 완료된 구간에 늦게 도착 · 미반영",
    UNMAPPED_DEVICE: "대상 기기 매핑 없음",
    UNMAPPED_EVENT_TYPE: "점수 정책에 없는 이벤트",
    INVALID_INCIDENT_FAMILY: "사건 분류 불일치",
    NO_SCORE_EVENT: "점수 반영 대상 아님",
    AI_OFF_AT_WINDOW: "분석 구간에서 AI 꺼짐",
    INVALID_AI_POLICY_EVIDENCE: "AI 정책 근거 불완전",
    PENDING_AT_WINDOW: "분석 구간에서 등록 승인 대기",
    DISABLED_AT_WINDOW: "분석 구간에서 비활성 기기",
    DISABLE_REQUESTED_OR_DISABLED: "비활성 요청 또는 비활성 기기",
    UNREGISTERED_AT_WINDOW: "분석 구간에서 미등록 기기",
    POLICY_UNAVAILABLE: "적용할 정책 없음",
    INVALID_POLICY_REVISION: "정책 이력 검증 실패",
    INVALID_REGISTRATION_REVISION: "등록 이력 검증 실패",
    LEGACY_MIGRATION: "이전 데이터 이관 · 실제 반영량 별도 확인",

    REPRESENTATIVE_RULE_EVENT:

      "대표 규칙 이벤트",

    AI_SUPPORTING_EVIDENCE:

      "AI 보조 증거",

    CAPTURE_GAP_UNSCORED:

      "수집 공백으로 미반영",

    UNMAPPED_SUBJECT_IP:

      "기기 매핑 없음",

    DUPLICATE_EVENT:

      "중복 이벤트",

    WINDOW_ALREADY_PROCESSED:

      "이미 처리된 분석 구간",

    SCORE_CAP_APPLIED:

      "분석 구간 감점 상한 적용",

  };

  return (

    labels[reason] ||

    reason ||

    "-"

  );

}
