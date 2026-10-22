import assert from "node:assert/strict";
import test from "node:test";
import { assertTrafficRowsMatchQuery, featureTime } from "./trafficQuery.js";

const params = {
  device_id: "esp32_02",
  from: "2026-10-19T15:00:00Z",
  to: "2026-10-19T16:00:00Z",
  direction: "INBOUND",
};
const row = {
  device_id: "esp32_02", direction: "INBOUND",
  window_start: params.from, window_end: "2026-10-19T15:00:10Z",
};

test("feature timestamps use UTC consistently for legacy and offset forms", () => {
  assert.equal(featureTime("2026-10-19 15:00:00"), featureTime(params.from));
  assert.equal(featureTime("2026-10-20T00:00:00+09:00"), featureTime(params.from));
  assert.ok(Number.isNaN(featureTime("invalid")));
  assert.ok(Number.isNaN(featureTime(null)));
});
test("accepts exact lower/upper boundaries and empty responses", () => {
  assert.doesNotThrow(() => assertTrafficRowsMatchQuery([row], params));
  assert.doesNotThrow(() => assertTrafficRowsMatchQuery([
    {...row, window_start: "2026-10-19T15:59:50Z", window_end: params.to},
  ], params));
  assert.doesNotThrow(() => assertTrafficRowsMatchQuery([], params));
});
test("rejects the old server response that ignores the selected date range", () => {
  assert.throws(() => assertTrafficRowsMatchQuery([
    {...row, window_start: "2026-10-14T15:00:00Z", window_end: "2026-10-14T15:00:10Z"},
  ], params), /Backend API/);
});
test("rejects wrong devices/directions, crossing windows, and missing dates", () => {
  for (const patch of [
    {device_id:"pico_01"}, {direction:"OUTBOUND"},
    {window_start:"2026-10-19T14:59:59Z"},
    {window_end:"2026-10-19T16:00:01Z"},
    {window_end:row.window_start}, {window_start:null},
  ]) assert.throws(() => assertTrafficRowsMatchQuery([{...row,...patch}], params));
});
test("MQTT rows do not require a packet direction", () => {
  const {direction: _direction, ...mqttParams} = params;
  const {direction: _rowDirection, ...mqttRow} = row;
  assert.doesNotThrow(() => assertTrafficRowsMatchQuery([mqttRow], mqttParams));
});
