import * as eventScoreEffect from "../utils/eventScoreEffect.js";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import * as uiText from "../utils/uiText.js";
import * as runtimeStatus from "../utils/runtimeStatus.js";

// The optional path lets an isolated worktree use an existing dependency tree.
const { transformWithOxc } = await import(process.env.VITE_TEST_MODULE || "vite");

async function render(event, name = "Events") {
  const source = await readFile(new URL(`./${name}.jsx`, import.meta.url), "utf8");
  const { code } = await transformWithOxc(source.replace(/^import\b[\s\S]*?;\r?\n/gm, ""), `${name}.jsx`, {
    jsx: { runtime: "classic", pragma: "jsx", pragmaFrag: "Fragment" },
    define: { "import.meta.env.DEV": "false" },
  });
  let index = 0;
  const states = name === "Dashboard"
    ? { 3: [event], 14: false, 19: { events: { status: "success", lastSuccessAt: "2026-10-26T00:00:00Z" } } }
    : { 0: [event], 1: 1, 3: event, 9: false };
  const importedNames = [...source.matchAll(/^import\s+(?:\{([\s\S]*?)\}|(\w+))\s+from\s+["'][^"']+["'];/gm)]
    .flatMap((match) => match[1] ? match[1].split(",").map((name) => name.trim()).filter(Boolean) : [match[2]]);
  const scope = {
    ...Object.fromEntries(importedNames.map((name) => [name, name])),
    ...uiText, ...runtimeStatus, ...eventScoreEffect, Date, console, AbortController, Fragment: "Fragment",
    ...Object.fromEntries(["DataTable", "DetailModal", "EmptyState", "JsonViewer", "PageHeader",
      "Pagination", "StatusBadge", "SummaryCard"].map((name) => [name, name])),
    useState: (initial) => [Object.hasOwn(states, index) ? states[index++] : (index++, typeof initial === "function" ? initial() : initial), () => {}],
    useRef: (current) => ({ current }), useMemo: (fn) => fn(), useCallback: (fn) => fn, useEffect: () => {},
    jsx: (type, props, ...children) => ({ type, props: props || {}, children }),
  };
  runInNewContext(code.replace(`export default function ${name}`, `function ${name}`) +
    `\nglobalThis.tree = ${name}();`, scope);
  return scope.tree;
}

function* nodes(node) {
  if (Array.isArray(node)) { for (const child of node) yield* nodes(child); }
  else if (node && typeof node === "object") { yield node; yield* nodes(node.children); }
}
function text(node) {
  if (Array.isArray(node)) return node.map(text).join(" ").replace(/\s+/g, " ").trim();
  if (node && typeof node === "object") return text(node.children);
  return node == null || typeof node === "boolean" ? "" : String(node);
}
function eventTable(tree) {
  return [...nodes(tree)].find((node) => node.type === "DataTable" && node.props.tableLabel === "탐지 이벤트 목록");
}
const base = { id: 1, device_id: "esp32_01", detector_type: "AI", event_type: "AI_ANOMALY",
  score_delta: -15, policy_score_delta: -15, applied_to_score: 0,
  processed_at: "2026-10-02T00:00:10Z", evidence: { anomaly_score: -0.72, threshold: -0.51 } };

for (const reason of ["ALREADY_ISOLATED", "AI_OBSERVATION_ONLY", "LATE_EVENT", "NOT_REPRESENTATIVE"]) {
  test(`completed ${reason} displays actual zero separately from the candidate`, async () => {
    const event = { ...base, actual_score_delta: 0, score_effect_reason: "NOT_APPLIED", processing_reason: reason };
    const tree = await render(event);
    const columns = eventTable(tree).props.columns;
    const actual = columns.find((column) => column.key === "actual_score_delta");
    assert.ok(actual, "actual score column exists");
    assert.equal(text(actual.render(0, event)), "0");
    const detail = [...nodes(tree)].find((node) => node.type === "DetailModal");
    assert.match(text(detail), /실제 점수 변화량 0/);
    assert.match(text(detail), /정책상 점수 변화량 -15/);
    const evidence = [...nodes(detail)].find((node) => node.type === "JsonViewer");
    assert.deepEqual(evidence.props.data, event.evidence);
  });
}

test("pending, unknown, old API and group effects never become fake zero or raw -15", async () => {
  for (const extra of [{ score_effect_reason: "PENDING", processed_at: null }, {},
    { score_effect_reason: "GROUP_HISTORY", applied_to_score: 1, window_actual_delta: -10, trust_score_history_id: 1 }]) {
    const event = { ...base, ...extra };
    const tree = await render(event);
    const actual = eventTable(tree).props.columns.find((column) => column.key === "actual_score_delta");
    assert.ok(actual);
    assert.ok(!["0", "-15"].includes(text(actual.render(undefined, event))));
    if (extra.score_effect_reason === "GROUP_HISTORY") {
      assert.match(text(tree), /분석 구간 전체 변화량 -10/);
      assert.match(text(tree), /이벤트별 배분 근거 없음/);
    }
  }
});

test("applied single-event history displays its actual floor-limited effect", async () => {
  const event = { ...base, actual_score_delta: -10, score_effect_reason: "EVENT_HISTORY", applied_to_score: 1 };
  const tree = await render(event);
  const actual = eventTable(tree).props.columns.find((column) => column.key === "actual_score_delta");
  assert.ok(actual);
  assert.equal(text(actual.render(-10, event)), "-10");
  assert.match(text(tree), /실제 점수 변화량 -10/);
});


function dashboardTable(tree) {
  return [...nodes(tree)].find(node => node.type === "DataTable" && node.props.tableLabel === "최근 탐지 이벤트");
}
for (const reason of ["AI_OBSERVATION_ONLY", "ALREADY_ISOLATED"]) {
  test(`Dashboard ${reason} displays actual zero, the cause and original policy candidate`, async () => {
    const event = { ...base, actual_score_delta: 0, score_effect_reason: "NOT_APPLIED", processing_reason: reason };
    const columns = dashboardTable(await render(event, "Dashboard")).props.columns;
    const actual = columns.find(column => column.key === "actual_score_delta");
    assert.ok(actual, "homepage uses the server's actual effect");
    const cell = actual.render(0, event);
    assert.equal(text(cell), "0");
    assert.match(cell.props.title, /정책상 점수 변화량 -15/);
    const result = columns.find(column => column.key === "processing_reason");
    assert.match(cell.props.title, /실제 점수 미반영/);
    assert.match(text(result.render(reason, event)), reason === "ALREADY_ISOLATED" ? /이미 격리/ : /AI 관찰 전용/);
  });
}

test("Dashboard preserves applied Rule and historical enforced AI changes", async () => {
  for (const [detector_type, delta] of [["RULE", -20], ["AI", -15]]) {
    const event = { ...base, detector_type, actual_score_delta: delta, score_effect_reason: "EVENT_HISTORY", applied_to_score: 1 };
    const columns = dashboardTable(await render(event, "Dashboard")).props.columns;
    const actual = columns.find(column => column.key === "actual_score_delta");
    assert.ok(actual);
    assert.equal(text(actual.render(delta, event)), String(delta));
    assert.match(columns.find(column => column.key === "applied_to_score").render(1, event).props.label, /점수 반영/);
  }
});

test("Dashboard pending, unknown and grouped effects do not imply zero or nominal deduction", async () => {
  for (const extra of [{ score_effect_reason: "PENDING", processed_at: null }, {}, { score_effect_reason: "GROUP_HISTORY", applied_to_score: 1, window_actual_delta: -10 }]) {
    const event = { ...base, ...extra };
    const columns = dashboardTable(await render(event, "Dashboard")).props.columns;
    const actual = columns.find(column => column.key === "actual_score_delta");
    assert.ok(actual);
    assert.ok(!["0", "-15"].includes(text(actual.render(undefined, event))));
    if (extra.score_effect_reason === "PENDING") assert.match(columns.find(column => column.key === "applied_to_score").render(0, event).props.label, /처리 대기/);
    if (extra.score_effect_reason === "GROUP_HISTORY") assert.equal(text(actual.render(undefined, event)), "개별 배분 없음");
  }
});


test("Dashboard and Events render identical processing results for the same event", async () => {
  const cases = [
    { processing_reason: "AI_OBSERVATION_ONLY", score_effect_reason: "NOT_APPLIED", actual_score_delta: 0 },
    { processing_reason: "ALREADY_ISOLATED", score_effect_reason: "NOT_APPLIED", actual_score_delta: 0 },
    { detector_type: "RULE", processing_reason: "APPLIED_TO_TRUST", score_effect_reason: "EVENT_HISTORY", actual_score_delta: -20, applied_to_score: 1 },
    { processing_reason: "APPLIED_TO_TRUST", score_effect_reason: "EVENT_HISTORY", actual_score_delta: -15, applied_to_score: 1 },
    { processing_reason: null, score_effect_reason: "PENDING", processed_at: null },
    { processing_reason: "FUTURE_REASON", score_effect_reason: "UNKNOWN" },
    { processing_reason: "REPRESENTATIVE_RULE_EVENT", score_effect_reason: "GROUP_HISTORY", applied_to_score: 1 },
    { processing_reason: "CAPTURE_GAP_UNSCORED", score_effect_reason: "NOT_APPLIED", actual_score_delta: 0 },
  ];
  for (const extra of cases) {
    const event = { ...base, ...extra };
    const dashboard = dashboardTable(await render(event, "Dashboard")).props.columns.find(column => column.key === "processing_reason");
    const events = eventTable(await render(event)).props.columns.find(column => column.key === "processing_reason");
    const homepage = dashboard.render(event.processing_reason, event);
    const list = events.render(event.processing_reason, event);
    assert.equal(text(homepage), text(list), `${extra.processing_reason ?? "pending"}: same processing label`);
    assert.equal(homepage.props.title, list.props.title, "raw processing reason is preserved");
  }
});

const approvedEventLabels = [
  ["ABNORMAL_PUBLISH_RATE", "메시지 전송 빈도 이상"],
  ["PACKET_RATE_ANOMALY", "패킷 전송 빈도 이상"],
  ["BYTE_RATE_ANOMALY", "데이터 전송량 이상"],
  ["LARGE_PAYLOAD", "메시지 크기 초과"],
  ["MALFORMED_PAYLOAD", "메시지 형식 오류"],
  ["ABNORMAL_TOPIC", "허용 토픽 위반"],
  ["DEVICE_ID_MISMATCH", "기기 식별정보 불일치"],
  ["UNKNOWN_DEVICE", "미등록 기기 감지"],
  ["PORT_SCAN", "포트 스캔 의심"],
  ["BROKER_DOS_SUSPECTED", "MQTT 브로커 과부하 의심"],
  ["POLICY_UNAVAILABLE", "탐지 정책 확인 불가"],
  ["BROKER_DOS_EVIDENCE_UNAVAILABLE", "브로커 탐지 근거 부족"],
  ["NON_MQTT_TRAFFIC", "MQTT 외 통신"],
];

test("approved Korean event names are shared by Events and Dashboard without changing raw codes", async () => {
  const event = { ...base, event_type: "PACKET_RATE_ANOMALY", severity: "high" };
  for (const [pageName, getTable] of [["Events", eventTable], ["Dashboard", dashboardTable]]) {
    const columns = getTable(await render(event, pageName)).props.columns;
    const column = columns.find((item) => item.key === "event_type");
    for (const [code, label] of approvedEventLabels) {
      assert.equal(uiText.uiLabel(code), label);
      const cell = column.render(code);
      assert.equal(text(cell), label, `${pageName}: ${code}`);
      assert.equal(cell.props.title, code, "the original code remains available in the list");
    }
    assert.equal(text(column.render("FUTURE_EVENT_TYPE")), "FUTURE_EVENT_TYPE");
  }
});

test("event details show the Korean event name and the original English event_type separately", async () => {
  const event = { ...base, event_type: "PACKET_RATE_ANOMALY", severity: "high" };
  const tree = await render(event);
  const detail = [...nodes(tree)].find((node) => node.type === "DetailModal" && node.props.open);
  assert.match(detail.props.description, /패킷 전송 빈도 이상/);
  const fields = [...nodes(detail)].filter((node) => node.props.className === "detail-item");
  assert.ok(fields.some((field) => text(field) === "탐지 유형 패킷 전송 빈도 이상"));
  assert.ok(fields.some((field) => text(field) === "원본 이벤트 코드 PACKET_RATE_ANOMALY"));
  assert.equal(event.event_type, "PACKET_RATE_ANOMALY");
});

test("Events and Dashboard preserve stored severities for old AI and rule events", async () => {
  const cases = [
    { event_type: "AI_ANOMALY", detector_type: "AI", processing_reason: "AI_OBSERVATION_ONLY", severity: "high" },
    { event_type: "AI_PACKET_ANOMALY", detector_type: "AI", processing_reason: "AI_OBSERVATION_ONLY", severity: "low" },
    { event_type: "PACKET_RATE_ANOMALY", detector_type: "RULE", severity: "medium" },
    { event_type: "PACKET_RATE_ANOMALY", detector_type: "RULE", severity: "high" },
    { event_type: "BYTE_RATE_ANOMALY", detector_type: "RULE", severity: "medium" },
    { event_type: "BYTE_RATE_ANOMALY", detector_type: "RULE", severity: "high" },
  ];
  for (const extra of cases) {
    const event = Object.freeze({ ...base, ...extra });
    for (const [pageName, getTable] of [["Events", eventTable], ["Dashboard", dashboardTable]]) {
      const tree = await render(event, pageName);
      const column = getTable(tree).props.columns.find((item) => item.key === "severity");
      const badge = column.render(event.severity, event);
      assert.equal(badge.props.status, event.severity);
      assert.equal(badge.props.label, event.severity.toUpperCase());
      if (pageName === "Events") {
        const detail = [...nodes(tree)].find((node) => node.type === "DetailModal" && node.props.open);
        const field = [...nodes(detail)].find((node) => node.props.className === "detail-item" && text(node).trim() === "심각도");
        const detailBadge = [...nodes(field)].find((node) => node.type === "StatusBadge");
        assert.equal(detailBadge.props.status, event.severity);
        assert.equal(detailBadge.props.label, event.severity.toUpperCase());
      }
    }
  }
});

test("policy evidence states retain the analysis/config family in list and detail", async () => {
  for (const event_type of ["POLICY_UNAVAILABLE", "BROKER_DOS_EVIDENCE_UNAVAILABLE"]) {
    const event = Object.freeze({ ...base, event_type, incident_family: "POLICY", detector_type: "RULE", severity: "low" });
    const tree = await render(event);
    const column = eventTable(tree).props.columns.find((item) => item.key === "incident_family");
    assert.equal(column.render("POLICY", event).props.label, "분석·설정 상태");
    const detail = [...nodes(tree)].find((node) => node.type === "DetailModal" && node.props.open);
    assert.match(text(detail), /사건 분류 분석·설정 상태/);
    assert.equal(event.incident_family, "POLICY");
  }
});
