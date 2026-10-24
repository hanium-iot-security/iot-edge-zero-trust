import * as uiText from "../utils/uiText.js";
import * as runtimeStatus from "../utils/runtimeStatus.js";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { transformWithOxc } from "vite";
import * as mqttTimestamp from "../utils/mqttTimestamp.js";
import { featureTime } from "../utils/trafficQuery.js";

// Render the production JSX and field readers with fixed API response fixtures.
async function page(name, exports, states = {}, directory = "pages") {
  const source = await readFile(new URL(`../${directory}/${name}.jsx`, import.meta.url), "utf8");
  const importedNames = [...source.matchAll(/^import\s+(?:\{([\s\S]*?)\}|(\w+))\s+from\s+["'][^"']+["'];/gm)]
    .flatMap((match) => match[1] ? match[1].split(",").map((name) => name.trim()).filter(Boolean) : [match[2]]);
  const { code } = await transformWithOxc(source.replace(/^import\b[\s\S]*?;\r?\n/gm, ""), `${name}.jsx`, {
    jsx: { runtime: "classic", pragma: "jsx", pragmaFrag: "Fragment" },
    define: { "import.meta.env.DEV": "false" },
  });
  let state = 0;
  const scope = {
    ...Object.fromEntries(importedNames.map((name) => [name, name])),
    ...mqttTimestamp,
    ...uiText,
    ...runtimeStatus,
    featureTime,
    useSearchParams: () => [new URLSearchParams()],
    useState: (initial) => [Object.hasOwn(states, state) ? states[state++] : (state++, typeof initial === "function" ? initial() : initial), () => {}],
    useRef: (initial) => ({ current: initial }),
    useMemo: (callback) => callback(),
    useCallback: (callback) => callback,
    useEffect: () => {},
    jsx: (type, props, ...children) => ({ type, props: props || {}, children }),
    Fragment: "Fragment", Date, console, AbortController,
  };
  runInNewContext(code.replace(`export default function ${name}`, `function ${name}`) +
    `\nglobalThis.subject = {${exports.join(",")}};`, scope);
  return scope.subject;
}

function* nodes(node) {
  if (Array.isArray(node)) { for (const child of node) yield* nodes(child); }
  else if (node && typeof node === "object") { yield node; yield* nodes(node.children); }
}
function text(node) {
  if (Array.isArray(node)) return node.map(text).join(" ").replace(/\s+/g, " ");
  if (node && typeof node === "object") return text(node.children);
  return node == null || typeof node === "boolean" ? "" : String(node);
}

const observedAt = "2026-10-15T07:00:00Z";
const runtime = {
  status: "FAILED", last_observation_status: "FAILED", freshness: "FRESH", observed_at: observedAt,
  max_age_seconds: 30, error_code: "MODEL_LOAD_FAILED", reason_code: null,
  stages: [{ name: "packet_if", enabled: true, required: true, status: "FAILED", model_version: "packet-v2", error_code: "MODEL_LOAD_FAILED" }], completions: [],
};

test("runtime cards preserve actual failure and stage evidence, not policy guesses", async () => {
  const subject = await page("GatewayStatus", ["extractRuntimeItems", "getRuntimeField", "RuntimeCard"]);
  const items = subject.extractRuntimeItems(runtime, Date.parse(observedAt));
  assert.equal(subject.getRuntimeField(items[0], "actual"), "FAILED");
  const stage = items.find((item) => item.name === "packet_if");
  assert.ok(stage, "declared stages must be rendered");
  const card = subject.RuntimeCard({ item: stage, index: 1 });
  assert.match(text(card), /packet-v2/);
  assert.match(text(card), /MODEL_LOAD_FAILED/);
  assert.ok([...nodes(card)].some((node) => node.type === "StatusBadge" && node.props.label === "실패"));
});

test("stale and expired observations do not advertise current runtime execution", async () => {
  const subject = await page("GatewayStatus", ["extractRuntimeItems", "getRuntimeField"]);
  for (const [data, now] of [[{ ...runtime, freshness: "STALE" }, Date.parse(observedAt)], [runtime, Date.parse(observedAt) + 31_000]]) {
    const items = subject.extractRuntimeItems(data, now);
    assert.ok(items.every((item) => subject.getRuntimeField(item, "actual") === "UNKNOWN"));
    assert.equal(items[0].last_observation_status, "FAILED");
  }
});

test("completion evidence retains its historical identity and inference counts", async () => {
  const { CompletionCard } = await page("GatewayStatus", ["CompletionCard"]);
  const card = CompletionCard({ item: {
    detector_name: "packet_if", evidence_status: "HISTORICAL", freshness: "STALE", device_id: "pico_01",
    completed_window_end: observedAt, model_version: "packet-v1", inference_count: 2, input_count: 3,
    normal_count: 1, anomaly_count: 1, exclusion_counts: { CAPTURE_GAP: 1 },
  } });
  const badge = [...nodes(card)].find((node) => node.type === "StatusBadge");
  assert.equal(badge.props.label, "과거 관측 / 정보 갱신 지연");
  assert.notEqual(badge.props.status, "normal");
  for (const value of ["pico_01", "packet-v1", "2 / 3", "CAPTURE_GAP"]) assert.ok(text(card).includes(value));
});

test("cached completion evidence expires with its snapshot and marks failed refreshes", async () => {
  const { extractCompletionItems } = await page("GatewayStatus", ["extractCompletionItems"]);
  const completion = {
    observed_at: observedAt, evidence_status: "CURRENT", freshness: "FRESH",
    inference_count: 2, normal_count: 1, anomaly_count: 1,
  };
  const data = { ...runtime, completions: [completion] };
  const now = Date.parse(observedAt);
  const current = extractCompletionItems(data, "FRESH", now)[0];
  assert.equal(current.evidence_status, "CURRENT");
  assert.equal(current.freshness, "FRESH");
  const expired = extractCompletionItems(data, "STALE", now + 31_000)[0];
  assert.equal(expired.evidence_status, "HISTORICAL");
  assert.equal(expired.freshness, "STALE");
  const snapshotExpired = extractCompletionItems(data, "STALE", now)[0];
  assert.equal(snapshotExpired.evidence_status, "HISTORICAL");
  const failedPoll = extractCompletionItems(data, "API_ERROR", now)[0];
  assert.equal(failedPoll.evidence_status, "HISTORICAL");
  assert.equal(failedPoll.freshness, "API_ERROR");
  assert.equal(failedPoll.inference_count, 2);
  assert.equal(completion.evidence_status, "CURRENT", "raw server response stays unchanged");
  assert.equal(completion.freshness, "FRESH");
});

const warning = {
  id: 1, device_id: "pico_01", detector_name: "packet_if", event_type: "AI_PACKET_ANOMALY",
  model_version: "packet-v2", bucket_start: observedAt, bucket_end: "2026-10-15T07:10:00Z",
  first_window: observedAt, latest_window: "2026-10-15T07:00:20Z", count: 3,
  notified_at: "2026-10-15T07:00:30Z", suppressed_count: 2, closed: true, last_decision: "SUPPRESSED",
};

test("warning table renders published window, model and decision fields", async () => {
  const { Events, warningTimestamp } = await page("Events", ["Events", "warningTimestamp"]);
  assert.equal(warningTimestamp(warning), warning.latest_window);
  const table = [...nodes(Events())].find((node) => node.type === "DataTable" && node.props.tableLabel === "AI 경고 목록");
  assert.ok(table);
  const cells = table.props.columns.map((column) => column.render?.(warning[column.key], warning));
  for (const value of ["packet_if", "packet-v2", "중복 알림 생략", "2"]) assert.ok(text(cells).includes(value));
  assert.ok(!table.props.columns.some((column) => column.key === "severity"));
});

test("device warning cards show first/latest windows and notification evidence", async () => {
  const { DeviceAiManagement } = await page("Devices", ["DeviceAiManagement"], { 1: false, 10: [warning], 13: false });
  const card = DeviceAiManagement({ deviceId: "pico_01", registration: "ACTIVE" });
  for (const value of ["중복 알림 생략", "packet-v2", "16:00:00", "16:00:20", "16:00:30", "2"]) assert.ok(text(card).includes(value), `missing ${value}`);
});


test("display localization preserves identifiers that happen to match status words", async () => {
  for (const name of ["Devices", "GatewayStatus"]) {
    const subject = await page(name, ["displayValue"]);
    for (const value of ["OFF", "PENDING", "RAW_MODEL_01"]) {
      assert.equal(subject.displayValue(value), value);
    }
  }
  const events = await page("Events", ["warningText"]);
  assert.equal(events.warningText("PENDING"), "PENDING");
});


test("evidence labels leave original values and nested JSON intact; MQTT keys stay raw", async () => {
  const { JsonViewer } = await page("JsonViewer", ["JsonViewer"], {}, "components");
  const evidence = {
    candidate_device_id: "PENDING", capture_coverage_ratio: 0.9922034999999999,
    model: { model_version: "packet-if-v2-calib-002-p99-py310", raw_decision_score: -0.22475799838643418, threshold_operator: ">" },
    observed_values: { packet_count: 7, total_bytes: 650 },
    constructor: "original-field", future_evidence_field: "OFF",
  };
  const original = JSON.stringify(evidence);
  Object.freeze(evidence.model);
  Object.freeze(evidence.observed_values);
  Object.freeze(evidence);
  const rendered = [...nodes(JsonViewer({ data: evidence, translateKeys: true }))];
  const keys = rendered.filter((node) => node.type === "dt").map(text);
  assert.deepEqual(keys, ["식별 후보 기기 ID", "수집 시간 충족 비율", "모델 판정 정보", "실제 관측값", "constructor", "future_evidence_field"]);
  const values = rendered.filter((node) => node.type === "dd").map(text);
  assert.equal(values[0], "PENDING");
  assert.equal(values[1], "0.9922034999999999");
  assert.equal(values[5], "OFF");
  const jsonBlocks = rendered.filter((node) => node.type === "pre");
  assert.equal(jsonBlocks[0].children[0], JSON.stringify(evidence.model, null, 2));
  assert.equal(jsonBlocks[1].children[0], JSON.stringify(evidence.observed_values, null, 2));
  assert.equal(JSON.stringify(evidence), original);

  const mqtt = { device_id: "esp32_02", sequence: 2345, uptime_s: 11729 };
  const mqttRendered = [...nodes(JsonViewer({ data: mqtt }))];
  assert.deepEqual(mqttRendered.filter((node) => node.type === "dt").map(text), Object.keys(mqtt));
  assert.deepEqual(mqttRendered.filter((node) => node.type === "dd").map(text), ["esp32_02", "2345", "11729"]);
});


test("summary status labels are Korean while numbers and unknown identifiers remain intact", async () => {
  const { SummaryCard } = await page("SummaryCard", ["SummaryCard"], {}, "components");
  for (const [value, label] of [["RUNNING", "실행 중"], ["RESPONSE", "응답 수신"], ["ONLINE", "최근 수신"], [0, "0"], ["model-v2", "model-v2"]]) {
    const card = SummaryCard({ title: "상태", value });
    const displayed = [...nodes(card)].find((node) => node.props.className === "card-value");
    assert.equal(text(displayed), label);
  }
});

test("dashboard summaries require fresh observations, not successful API responses or observe settings", () => {
  const data = { status: "RUNNING", freshness: "FRESH", observed_at: observedAt, max_age_seconds: 45, trust_ai_mode: "OBSERVE" };
  const now = Date.parse(observedAt);
  assert.equal(runtimeStatus.observationState(data, { now }).status, "RUNNING");
  for (const [patch, options] of [
    [{ freshness: "STALE" }, {}], [{ observed_at: null }, {}], [{ max_age_seconds: null }, {}],
    [{ observed_at: "invalid" }, {}], [{}, { failed: true }], [{}, { now: now + 46_000 }], [{}, { now: now - 1 }],
  ]) {
    assert.equal(runtimeStatus.observationState({ ...data, ...patch }, { now, ...options }).status, "UNKNOWN");
  }
  assert.equal(data.status, "RUNNING");
  assert.equal(data.freshness, "FRESH");
  const firewall = { status: "MATCH", observed_at: observedAt, max_age_seconds: 15 };
  assert.equal(runtimeStatus.observationState(firewall, { now, requireFreshness: false }).status, "MATCH");
  assert.equal(runtimeStatus.observationState(firewall, { now: now + 16_000, requireFreshness: false }).status, "UNKNOWN");
});

test("capture evidence labels distinguish processed, missing and unknown API observations", async () => {
  const { CaptureEvidence } = await page("DeviceTrafficTrends", ["CaptureEvidence"], {}, "components");
  const items = [{ observation: "PROCESSED" }, { observation: "MISSING" }, { segment_status: "EMPTY" }, { segment_status: "READY" }, { observation: "FAILED" }, {}];
  const rendered = text(CaptureEvidence({ data: { items } }));
  assert.match(rendered, /처리 완료 1/);
  assert.match(rendered, /수집 자료 누락 1/);
  assert.match(rendered, /패킷 없음 1/);
  assert.match(rendered, /수집 실패 1/);
  assert.match(rendered, /대기 1/);
  assert.match(rendered, /미확인 1/);
});

test("Packet trend request includes only complete 10-second windows at the period end", async () => {
  const { packetTrendRequestParams } = await page("DeviceTrafficTrends", ["packetTrendRequestParams"], {}, "components");
  const query = { device_id: "esp32_01", direction: "INBOUND", from: "2026-10-24T00:52:00Z", to: "2026-10-24T01:52:00Z", limit: 500, offset: 0 };
  const actual = packetTrendRequestParams(query);
  assert.equal(actual.to, "2026-10-24T01:51:50.000Z");
  assert.equal(Date.parse(actual.to) + 10_000, Date.parse(query.to));
  for (const key of ["device_id", "direction", "from", "limit", "offset"]) assert.equal(actual[key], query[key]);
  assert.equal(query.to, "2026-10-24T01:52:00Z", "display period and capture evidence retain the original end");
});

test("MQTT summary never converts missing counts or empty observations to zero", async () => {
  const { mqttMessageTotal } = await page("DeviceTrafficTrends", ["mqttMessageTotal"], {}, "components");
  assert.equal(mqttMessageTotal([{ publish_count: 0 }]), 0);
  assert.equal(mqttMessageTotal([{ publish_count: 3 }, { publish_count: 2 }]), 5);
  for (const rows of [[], [{}], [{ publish_count: null }], [{ publish_count: "" }], [{ publish_count: -1 }], [{ publish_count: 3 }, {}]]) {
    assert.equal(mqttMessageTotal(rows), null);
  }
});


test("MQTT charts distinguish coincident series without moving values", async () => {
  const rows = ["2026-10-24T00:00:00Z", "2026-10-24T00:00:10Z"].map((window_start) => ({
    device_id: "esp32_02", window_start, publish_count: 2,
    avg_payload_size: 128, max_payload_size: 128, avg_message_interval: 5, min_message_interval: 5,
  }));
  const original = JSON.stringify(rows);
  const criteria = { device_id: "esp32_02", from: rows[0].window_start, to: "2026-10-24T00:00:20Z" };
  const subject = await page("DeviceTrafficTrends", ["DeviceTrafficTrends", "MetricsChart"], {
    0: ["esp32_02"], 2: "esp32_02", 10: { kind: "mqtt", rows, total: 2, criteria },
  }, "components");
  const charts = [...nodes(subject.DeviceTrafficTrends())].filter((node) => node.type === subject.MetricsChart);
  assert.equal(charts.length, 3);
  for (const [index, keys] of [[1, ["avg_payload_size", "max_payload_size"]], [2, ["avg_message_interval", "min_message_interval"]]]) {
    const rendered = subject.MetricsChart(charts[index].props);
    const series = [...nodes(rendered)].filter((node) => node.type === "Line");
    assert.deepEqual(series.map((node) => node.props.dataKey), keys);
    assert.equal(series[0].props.strokeDasharray, "none", "average remains solid underneath");
    assert.equal(series[1].props.strokeDasharray, "6 4", "top series exposes the coincident average through its gaps");
    assert.ok(series.every((node) => node.props.legendType === "plainline"), "legend must show the actual dash pattern");
    const plot = [...nodes(rendered)].find((node) => node.type === "LineChart").props.data;
    for (const row of plot) {
      assert.equal(row[keys[0]], row[keys[1]], "equal measurements must stay equal");
      assert.equal(row[keys[0]], rows[0][keys[0]]);
    }
    assert.match(text(rendered), /평균은 실선/);
    assert.match(text(rendered), /값이 같으면 같은 위치/);
  }
  assert.doesNotMatch(text(subject.MetricsChart(charts[0].props)), /평균은 실선/);
  assert.equal(JSON.stringify(rows), original, "chart presentation must not mutate API measurements");
});

test("MQTT chart data preserves nulls, zeroes and gaps between observed windows", async () => {
  const { chartRows, MetricsChart } = await page("DeviceTrafficTrends", ["chartRows", "MetricsChart"], {}, "components");
  const rows = [
    { window_start: "2026-10-24T00:00:00Z", avg_payload_size: 0, max_payload_size: 0, avg_message_interval: 0, min_message_interval: 0 },
    { window_start: "2026-10-24T00:00:10Z", avg_payload_size: null, max_payload_size: 128, avg_message_interval: "" },
    { window_start: "2026-10-24T00:00:40Z", avg_payload_size: 100, max_payload_size: 120, avg_message_interval: 5, min_message_interval: 4.98 },
  ];
  const plot = chartRows(rows, "mqtt");
  assert.equal(plot.length, 4);
  for (const key of ["avg_payload_size", "max_payload_size", "avg_message_interval", "min_message_interval"]) assert.equal(plot[0][key], 0);
  assert.equal(plot[1].avg_payload_size, null);
  assert.equal(plot[1].avg_message_interval, null);
  assert.equal(plot[1].min_message_interval, null);
  assert.equal(plot[1].max_payload_size, 128);
  assert.equal(plot[2].__gap, true);
  assert.equal(plot[2].window_start, null);
  assert.equal(plot[3].avg_payload_size, 100);
  assert.equal(plot[3].max_payload_size, 120);
  assert.equal(plot[3].avg_message_interval, 5);
  assert.equal(plot[3].min_message_interval, 4.98);
  const rendered = MetricsChart({ data: plot, lines: [{ key: "avg_payload_size", label: "평균" }, { key: "max_payload_size", label: "최대" }] });
  assert.ok([...nodes(rendered)].filter((node) => node.type === "Line").every((node) => node.props.connectNulls === false));
});

test("compact runtime overview keeps latest device results and retains all evidence in closed details", async () => {
  const { RuntimeOverview, latestCompletionRows } = await page("GatewayStatus", ["RuntimeOverview", "latestCompletionRows"]);
  const old = { device_id: "esp32_01", detector_name: "packet_if", completed_window_end: observedAt, evidence_status: "HISTORICAL", freshness: "STALE", inference_count: 0, input_count: 0 };
  const latest = { ...old, completed_window_end: "2026-10-15T07:00:10Z", evidence_status: "CURRENT", freshness: "FRESH", inference_count: 1, input_count: 2, normal_count: 1, anomaly_count: 0 };
  const globalHistory = { ...old, device_id: null };
  const second = { ...latest, device_id: "pico_01", inference_count: null, normal_count: null };
  const completions = [old, latest, globalHistory, second];
  const original = JSON.stringify(completions);
  const rows = latestCompletionRows(completions);
  assert.equal(rows.length, 2);
  assert.equal(rows[0], latest);
  const view = RuntimeOverview({ runtimeItems: [{ name: "AI Runtime", status: "RUNNING", freshness: "FRESH", observed_at: observedAt }], completionItems: completions, runtimeData: { completions }, runtimeUpdatedAt: observedAt, now: Date.parse(observedAt) });
  const table = [...nodes(view)].find((node) => node.type === "table");
  const body = [...nodes(table)].find((node) => node.type === "tbody");
  const renderedRows = [...nodes(body)].filter((node) => node.type === "tr");
  assert.equal(renderedRows.length, 2);
  assert.match(text(renderedRows[0]), /esp32_01.*패킷 AI.*1 \/ 2/);
  assert.match(text(renderedRows[1]), /측정 불가 \/ 2/);
  const details = [...nodes(view)].filter((node) => node.type === "details");
  assert.ok(details.every((node) => !node.props.open));
  const diagnosis = details.find((node) => node.props.className?.includes("diagnostics"));
  assert.equal([...nodes(diagnosis)].filter((node) => node.type?.name === "CompletionCard").length, completions.length);
  assert.equal([...nodes(diagnosis)].find((node) => node.type === "pre").children[0], JSON.stringify({ completions }, null, 2));
  assert.equal(JSON.stringify(completions), original);
});

test("collapsing runtime detail never hides current stage failures, stopped engines or stale evidence", async () => {
  const { RuntimeOverview, runtimeIssues } = await page("GatewayStatus", ["RuntimeOverview", "runtimeIssues"]);
  function* visible(node) {
    if (Array.isArray(node)) { for (const child of node) yield* visible(child); }
    else if (node && typeof node === "object") {
      yield node;
      yield* visible(node.type === "details" && !node.props.open ? node.children[0] : node.children);
    }
  }
  const engine = { name: "AI Runtime", status: "RUNNING", freshness: "FRESH" };
  const failure = { name: "packet_if", status: "FAILED", freshness: "FRESH", enabled: true, error_code: "MODEL_LOAD_FAILED" };
  const disabled = { name: "mqtt_if", status: "DISABLED", freshness: "FRESH", enabled: false };
  assert.equal(runtimeIssues([engine, disabled]).length, 0, "intentionally disabled stages are not failures");
  for (const items of [[engine, failure, disabled], [{ ...engine, status: "STOPPED" }], [{ ...engine, status: "UNKNOWN", freshness: "STALE" }]]) {
    const view = RuntimeOverview({ runtimeItems: items, completionItems: [], runtimeData: {}, runtimeUpdatedAt: observedAt, now: Date.parse(observedAt) });
    assert.ok([...visible(view)].some((node) => node.props.role === "alert"), "attention state must remain outside collapsed details");
  }
  const view = RuntimeOverview({ runtimeItems: [engine, failure], completionItems: [], runtimeData: {}, runtimeUpdatedAt: observedAt, now: Date.parse(observedAt) });
  const alert = [...visible(view)].find((node) => node.props.role === "alert");
  assert.match(text(alert), /패킷 AI.*실패.*MODEL_LOAD_FAILED/);
});
