import assert from "node:assert/strict";
import test from "node:test";

import {
  LEGACY_KST_OPTIONS,
  elapsedSecondsFromMqttTimestamp,
  formatMqttTimestampKST,
  parseMqttTimestamp,
} from "./mqttTimestamp.js";


test("explicit UTC and offset timestamps resolve to the same instant", () => {
  const utc = parseMqttTimestamp("2026-07-31T10:00:01Z");
  const seoul = parseMqttTimestamp("2026-07-31T19:00:01+09:00");

  assert.equal(utc?.toISOString(), "2026-07-31T10:00:01.000Z");
  assert.equal(seoul?.toISOString(), utc?.toISOString());
});


test("legacy KST mode resolves subscriber local time to the same instant", () => {
  const utc = parseMqttTimestamp("2026-07-31T10:00:01Z");
  const legacy = parseMqttTimestamp(
    "2026-07-31 19:00:01",
    LEGACY_KST_OPTIONS,
  );

  assert.equal(legacy?.toISOString(), utc?.toISOString());
  assert.equal(
    formatMqttTimestampKST("2026-07-31T10:00:01Z"),
    formatMqttTimestampKST("2026-07-31 19:00:01", LEGACY_KST_OPTIONS),
  );
});


test("devices elapsed time uses the normalized instant", () => {
  const now = new Date("2026-07-31T10:00:11Z");

  assert.equal(
    elapsedSecondsFromMqttTimestamp(
      "2026-07-31 19:00:01",
      now,
      LEGACY_KST_OPTIONS,
    ),
    10,
  );
  assert.equal(
    elapsedSecondsFromMqttTimestamp("2026-07-31T10:00:01Z", now),
    10,
  );
});


test("ambiguous naive and invalid values are rejected safely", () => {
  assert.equal(parseMqttTimestamp("2026-07-31 19:00:01"), null);
  assert.equal(parseMqttTimestamp("not-a-timestamp"), null);
  assert.equal(parseMqttTimestamp(""), null);
  assert.equal(parseMqttTimestamp(null), null);
});
