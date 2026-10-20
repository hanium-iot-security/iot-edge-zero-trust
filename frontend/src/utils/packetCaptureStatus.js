import { uiLabel } from "./uiText.js";
export function getCaptureStatus(item) {
  if (item.segment_status === "FAILED") {
    return "failed";
  }

  if (item.capture_eligible === false) {
    return "excluded";
  }

  if (item.capture_eligible === true) {
    return "eligible";
  }

  return "unknown";
}


export function matchesCaptureStatusFilter(item, captureStatus) {
  if (!captureStatus) {
    return true;
  }

  return getCaptureStatus(item) === captureStatus;
}


export function getCaptureStatusLabel(item) {
  const status = getCaptureStatus(item);

  if (status === "failed") {
    return "수집 실패";
  }

  if (status === "excluded") {
    return "분석 제외";
  }

  if (status === "eligible") {
    return "분석 가능";
  }

  return "상태 미확인";
}


export function getExclusionLabel(reason) {
  const labels = {
    missing_timing_metadata: "수집 시간 정보 없음",
    non_finite_timing_metadata: "수집 시간 값 오류",
    negative_start_delay_seconds: "시작 지연 값 오류",
    captured_duration_out_of_range: "수집시간 범위 오류",
    start_delay_exceeds_policy: "수집 시작 지연 초과",
    captured_duration_below_policy: "수집시간 부족",
  };

  if (!reason) {
    return "-";
  }

  if (reason.startsWith("status_not_eligible:")) {
    return `분석 불가 상태 (${uiLabel(reason.slice("status_not_eligible:".length))})`;
  }

  if (reason.startsWith("error_code_present:")) {
    return `수집 오류 (${uiLabel(reason.slice("error_code_present:".length))})`;
  }

  return labels[String(reason).toLowerCase()] || uiLabel(reason);
}
