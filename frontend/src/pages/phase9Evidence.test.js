import * as uiText from "../utils/uiText.js";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { transformWithOxc } from "vite";
import * as mqttTimestamp from "../utils/mqttTimestamp.js";

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
