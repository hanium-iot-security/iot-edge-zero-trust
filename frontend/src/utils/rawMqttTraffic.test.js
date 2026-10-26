import assert from "node:assert/strict";
import test from "node:test";
import { loadRawMqttLogs, rawMqttChartRows, mqttTimestampMicros } from "./rawMqttTraffic.js";

const params = { device_id: "raw_a", from: "2026-10-01T00:00:00Z", to: "2026-10-01T00:01:00Z" };
const row = (id, at, payload_size = 128) => ({ id, device_id: "raw_a", received_at: at, payload_size, is_json_valid: 0 });
const rows = [row(3, "2026-10-01T00:00:10.000003Z"), row(2, "2026-10-01T09:00:05.000001+09:00", 0), row(1, "2026-10-01T00:00:00Z", null)];
const page = (items, offset, total = 3, extra = {}) => ({ items, total, snapshot_max_id: 3, offset, limit: 2, has_more: offset + items.length < total, timestamp_unavailable_count: 0, source_span_count: offset ? null : total, source_span_count_scope: "selected_source_ids_first_page", interval_predecessor_policy: "within_range_only", timestamp_unavailable_count_scope: "device_snapshot_first_page", ...extra });

test("raw chart uses each stored byte size and exact consecutive receive differences", () => {
  const original = JSON.stringify(rows);
  const chart = rawMqttChartRows({ rows, total: 3, sourceSpanCount: 3, incomplete: false, timestampUnavailableCount: 0 });
  assert.deepEqual(chart.map(r => r.payload_size), [null, 0, 128]);
  assert.deepEqual(chart.map(r => r.message_interval_seconds), [null, 5.000001, 5.000002]);
  assert.equal(JSON.stringify(rows), original);
  assert.equal(mqttTimestampMicros("2026-10-01 00:00:00"), null);
  assert.equal(mqttTimestampMicros("bad"), null);
});

test("unknown size stays null, simultaneous arrivals preserve zero, and invalid times break predecessors", () => {
  const chart = rawMqttChartRows({ rows: [row(1, params.from, ""), row(2, params.from, -1), row(3, "bad"), row(4, "2026-10-01T00:00:10Z")], total: 4, sourceSpanCount: 4, incomplete: false });
  assert.deepEqual(chart.map(r => r.payload_size), [null, null, null, 128]);
  assert.deepEqual(chart.map(r => r.message_interval_seconds), [null, 0, null, null]);
});

test("partial pages and unproven source continuity never imply known consecutive intervals", () => {
  for (const extra of [{ incomplete: true }, { sourceSpanCount: null }]) {
    assert.ok(rawMqttChartRows({ rows, total: 3, sourceSpanCount: 3, ...extra }).every(r => r.message_interval_seconds === null));
  }
});

test("bounded raw paging holds snapshot, period and device across pages", async () => {
  const calls = [];
  const result = await loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, request: async p => {
    calls.push(p);
    return p.offset === 0 ? page(rows.slice(0, 2), 0) : page(rows.slice(2), 2);
  }});
  assert.equal(result.incomplete, false);
  assert.equal(result.rows.length, 3);
  assert.equal(result.sourceSpanCount, 3);
  assert.equal(calls[1].snapshot_max_id, 3);
  assert.equal(calls[1].from, params.from);
  assert.equal(calls[1].device_id, params.device_id);
});

test("missing, shifted, duplicated, unordered or changed pages fail closed", async () => {
  for (const second of [page([], 2), page(rows.slice(2), 1), page([rows[1]], 2), page(rows.slice(2), 2, 4), page(rows.slice(2), 2, 3, { snapshot_max_id: 4 })]) {
    const result = await loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, request: async p => p.offset === 0 ? page(rows.slice(0, 2), 0) : second });
    assert.equal(result.incomplete, true);
    assert.equal(result.rows.length, 2);
    assert.ok(rawMqttChartRows(result).every(r => r.message_interval_seconds === null));
  }
});

test("old API, wrong device/range, request failure and safety cap are visible", async () => {
  for (const response of [{ items: rows, total: 3 }, page([row(1, params.to)], 0, 1), page([{ ...rows[0], device_id: "other" }], 0, 1)]) {
    await assert.rejects(loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, request: async () => response }));
  }
  const failed = await loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, request: async p => { if (p.offset) throw new Error("offline"); return page(rows.slice(0, 2), 0); } });
  assert.equal(failed.incomplete, true);
  assert.match(failed.warning, /offline/);
  const capped = await loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, maxRows: 2, request: async () => page(rows.slice(0, 2), 0) });
  assert.equal(capped.incomplete, true);
});

test("impossible calendar days, rolled hours and invalid offsets are unknown", () => {
  for (const value of ["2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z", "0000-01-01T00:00:00Z", "0000-12-31T23:00:00-01:00", "2026-01-01T00:00:00+09:60"]) {
    assert.equal(mqttTimestampMicros(value), null, value);
  }
  assert.equal(mqttTimestampMicros("2024-02-29T00:00:00Z"), mqttTimestampMicros("2024-02-29T09:00:00+09:00"));
});


test("older unknown timestamps do not hide intervals with exact source continuity evidence", () => {
  const chart = rawMqttChartRows({ rows, total: 3, sourceSpanCount: 3, timestampUnavailableCount: 799 });
  assert.deepEqual(chart.map(r => r.message_interval_seconds), [null, 5.000001, 5.000002]);
});

test("missing source-continuity evidence, interleaved rows and reordered receipts keep intervals unknown", () => {
  for (const extra of [{ sourceSpanCount: null }, { sourceSpanCount: 4 }, { rows: [rows[0], { ...rows[1], id: 4 }, rows[2]] }]) {
    const chart = rawMqttChartRows({ rows, total: 3, sourceSpanCount: 3, ...extra });
    assert.ok(chart.every(r => r.message_interval_seconds === null));
  }
});


test("source continuity metadata is required, snapshot stable and independent of historical unknown timestamps", async () => {
  for (const extra of [{ source_span_count: undefined }, { source_span_count: null }, { source_span_count: 2 }, { source_span_count: "3" }, { source_span_count_scope: "not_evaluated" }]) {
    await assert.rejects(loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, request: async () => page(rows.slice(0, 2), 0, 3, extra) }));
  }
  const result = await loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, request: async p =>
    p.offset === 0 ? page(rows.slice(0, 2), 0, 3, { timestamp_unavailable_count: 799 }) : page(rows.slice(2), 2, 3, { timestamp_unavailable_count: null }) });
  assert.equal(result.sourceSpanCount, 3);
  assert.equal(result.timestampUnavailableCount, 799);
  assert.match(result.warning, /799/);
  assert.doesNotMatch(result.warning, /간격은 표시하지 않습니다/);
  assert.deepEqual(rawMqttChartRows(result).map(r => r.message_interval_seconds), [null, 5.000001, 5.000002]);
  const changed = await loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, request: async p =>
    p.offset === 0 ? page(rows.slice(0, 2), 0) : page(rows.slice(2), 2, 3, { source_span_count: 4 }) });
  assert.equal(changed.incomplete, true);
});

test("intervening source records and nonmonotonic receipt IDs keep sizes but explicitly hide intervals", async () => {
  for (const extra of [{ source_span_count: 4 }, {}]) {
    const selected = extra.source_span_count ? rows : [{ ...rows[0], id: 2 }, { ...rows[1], id: 3 }, rows[2]];
    const result = await loadRawMqttLogs({ params, signal: new AbortController().signal, pageSize: 2, request: async p =>
      p.offset === 0 ? page(selected.slice(0, 2), 0, 3, extra) : page(selected.slice(2), 2) });
    assert.equal(result.incomplete, false);
    assert.match(result.warning, /간격은 표시하지 않습니다/);
    const chart = rawMqttChartRows(result);
    assert.ok(chart.every(r => r.message_interval_seconds === null));
    assert.deepEqual(chart.map(r => r.payload_size), [null, 0, 128]);
  }
});
