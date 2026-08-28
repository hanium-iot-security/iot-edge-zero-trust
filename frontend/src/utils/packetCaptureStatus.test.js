import assert from "node:assert/strict";
import test from "node:test";

import {
  getCaptureStatus,
  getCaptureStatusLabel,
  getExclusionLabel,
} from "./packetCaptureStatus.js";


test("FAILED segment takes priority over capture exclusion", () => {
  const item = {
    segment_status: "FAILED",
    capture_eligible: false,
  };

  assert.equal(getCaptureStatus(item), "failed");
  assert.equal(getCaptureStatusLabel(item), "수집 실패");
});


test("capture eligibility maps to dashboard status and label", () => {
  assert.equal(getCaptureStatus({ capture_eligible: true }), "eligible");
  assert.equal(
    getCaptureStatusLabel({ capture_eligible: true }),
    "분석 가능",
  );
  assert.equal(getCaptureStatus({ capture_eligible: false }), "excluded");
  assert.equal(
    getCaptureStatusLabel({ capture_eligible: false }),
    "분석 제외",
  );
});


test("common capture policy exclusion reasons have Korean labels", () => {
  assert.equal(getExclusionLabel("missing_timing_metadata"), "Timing 정보 없음");
  assert.equal(
    getExclusionLabel("captured_duration_below_policy"),
    "Capture 시간 부족",
  );
  assert.equal(
    getExclusionLabel("status_not_eligible:READY"),
    "분석 불가 상태 (READY)",
  );
  assert.equal(
    getExclusionLabel("error_code_present:LATE_CAPTURE"),
    "수집 오류 (LATE_CAPTURE)",
  );
});
