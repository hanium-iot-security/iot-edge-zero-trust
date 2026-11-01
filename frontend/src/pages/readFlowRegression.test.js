import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { transformWithOxc } from "vite";
import * as uiText from "../utils/uiText.js";
import * as eventScoreEffect from "../utils/eventScoreEffect.js";
import * as runtimePresentation from "../utils/runtimeStatus.js";
import * as packetCaptureStatus from "../utils/packetCaptureStatus.js";
import * as mqttTimestamp from "../utils/mqttTimestamp.js";
import * as firewallRuleSelection from "../utils/firewallRuleSelection.js";

// Like devicePolicyPolling.test.js, execute the complete production component.
// Substitute only imports, hooks/JSX, transport and time; never copy its handlers.
const compiled = new Map();
async function pageCode(name) {
  if (!compiled.has(name)) {
    const source = await readFile(new URL(`./${name}.jsx`, import.meta.url), "utf8");
    const imported = [...source.matchAll(/^import\s+(?:\{([\s\S]*?)\}|(\w+))\s+from\s+["'][^"']+["'];/gm)]
      .flatMap((match) => match[1] ? match[1].split(",").map((s) => s.trim()).filter(Boolean) : [match[2]]);
    const stripped = source.replace(/^import\s+["'][^"']+["'];?\r?\n/gm, "")
      .replace(/^import\b[\s\S]*?;\r?\n/gm, "");
    const result = await transformWithOxc(stripped, `${name}.jsx`, {
      jsx: { runtime: "classic", pragma: "jsx", pragmaFrag: "Fragment" },
      define: { "import.meta.env.DEV": "false" },
    });
    compiled.set(name, { imported, code: result.code
      .replace(`export default function ${name}`, `function ${name}`)
      .replace(/\bexport\s*\{[^}]*\};?/g, "") + `\nglobalThis.Component = ${name};` });
  }
  return compiled.get(name);
}

function clock() {
  let now = Date.parse("2026-11-01T06:00:00Z"), nextId = 0;
  const timers = new Map();
  class ControlledDate extends Date {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return now; }
  }
  return {
    Date: ControlledDate,
    get now() { return now; },
    window: {
      setInterval(callback, delay) { const id = ++nextId; timers.set(id, { callback, delay, at: now + delay }); return id; },
      clearInterval(id) { timers.delete(id); },
      setTimeout(callback, delay) { const id = ++nextId; timers.set(id, { callback, delay: 0, at: now + delay }); return id; },
      clearTimeout(id) { timers.delete(id); },
    },
    async advance(milliseconds, settle) {
      const target = now + milliseconds;
      for (;;) {
        const entry = [...timers.entries()].filter(([, t]) => t.at <= target).sort((a, b) => a[1].at - b[1].at)[0];
        const next = entry?.[1];
        if (!next) break;
        now = next.at;
        if (next.delay) next.at += next.delay; else timers.delete(entry[0]);
        next.callback(); await settle();
      }
      now = target; await settle();
    },
  };
}

async function mount(name, api, time = clock()) {
  const { imported, code } = await pageCode(name);
  const slots = [];
  let cursor = 0, dirty = false, root, effects = [];
  const same = (a, b) => a && b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));
  const hooks = {
    useState(initial) {
      const i = cursor++;
      slots[i] ??= { value: typeof initial === "function" ? initial() : initial };
      return [slots[i].value, (update) => {
        const value = typeof update === "function" ? update(slots[i].value) : update;
        if (!Object.is(value, slots[i].value)) { slots[i].value = value; dirty = true; }
      }];
    },
    useRef(initial) { const i = cursor++; return slots[i] ??= { current: initial }; },
    useMemo(callback, deps) {
      const i = cursor++;
      if (!slots[i] || !same(slots[i].deps, deps)) slots[i] = { deps, value: callback() };
      return slots[i].value;
    },
    useCallback(callback, deps) { return hooks.useMemo(() => callback, deps); },
    useEffect(callback, deps) {
      const i = cursor++;
      if (!slots[i] || !same(slots[i].deps, deps)) {
        const cleanup = slots[i]?.cleanup;
        slots[i] = { deps };
        effects.push(() => { cleanup?.(); slots[i].cleanup = callback(); });
      }
    },
  };
  const scope = {
    ...Object.fromEntries(imported.map((n) => [n, /^get/.test(n) ? async () => ({ items: [], total: 0 }) : n])),
    ...uiText, ...eventScoreEffect, ...runtimePresentation, ...packetCaptureStatus,
    ...mqttTimestamp, ...firewallRuleSelection,
    ...api, ...hooks, Error, AbortController, console, Date: time.Date, window: time.window,
    Fragment: "Fragment", jsx: (type, props, ...children) => ({ type, props: props || {}, children }),
  };
  runInNewContext(code, scope, { filename: `${name}.jsx` });
  function render() { cursor = 0; dirty = false; effects = []; root = scope.Component(); effects.forEach((f) => f()); }
  async function settle() {
    for (let i = 0; i < 40; i++) { await Promise.resolve(); if (dirty) render(); }
    assert.equal(dirty, false, "effects must settle");
  }
  function* walk(node) {
    if (Array.isArray(node)) { for (const child of node) yield* walk(child); }
    else if (node && typeof node === "object") { yield node; yield* walk(node.children); }
  }
  const nodes = () => [...walk(root)];
  const find = (predicate) => { const node = nodes().find(predicate); assert.ok(node, `missing ${name} UI node`); return node; };
  async function act(action) { action(); await settle(); }
  const app = { time, settle, nodes, find, act,
    change: (id, value) => act(() => find((n) => n.props.id === id).props.onChange({ target: { value } })),
    advance: (ms) => time.advance(ms, settle),
    cleanup: () => slots.forEach((slot) => slot?.cleanup?.()),
  };
  render(); await settle(); return app;
}

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const packet = (id, overrides = {}) => ({ id, device_id: "esp32_01", peer_ip: "192.0.2.10",
  direction: "INBOUND", capture_session_id: "fixture-session", capture_segment_id: id,
  window_start: "2026-11-01T05:59:50Z", window_end: "2026-11-01T06:00:00Z",
  segment_status: "PROCESSED", capture_eligible: true, effective_packets_per_second: 0.4, ...overrides });
const packetTable = (app) => app.find((n) => n.type === "DataTable" && n.props.tableLabel === "패킷 분석 지표 목록");
const packetIds = (app) => Array.from(packetTable(app).props.rows, (r) => r.id);

test("Dashboard retained gateway metric expires after 30 seconds when subsequent API reads fail", async () => {
  const time = clock(); let calls = 0;
  const app = await mount("Dashboard", { getGatewayMetrics: async () => {
    if (++calls > 1) throw new Error("controlled gateway read failure");
    return { items: [{ collected_at: new Date(time.now).toISOString(), cpu_percent: 10 }] };
  } }, time);
  const gatewayBadge = () => app.find((n) => n.type === "StatusBadge" && ["ONLINE", "STALE"].includes(n.props.label));
  try {
    assert.equal(gatewayBadge().props.label, "ONLINE");
    await app.advance(31_000);
    assert.ok(calls >= 4, "real polling effects attempted subsequent reads");
    const cpu = app.find((n) => n.type === "MetricCard" && n.props.label === "CPU");
    assert.equal(cpu.props.stale, true, "API failure reached the rendered source state");
    assert.equal(gatewayBadge().props.label, "STALE", "retained metric age must expire independently of object identity");
  } finally { app.cleanup(); }
});

for (const transition of ["direction", "page"]) {
  test(`PacketTraffic ${transition} failure must not display prior-query rows under the new query`, async () => {
    const pending = deferred(), queries = [];
    const app = await mount("PacketTraffic", { getPacketFeatureLogs: (query) => {
      queries.push(query);
      return queries.length === 1 ? Promise.resolve({ items: [packet(101)], total: 41 }) : pending.promise;
    } });
    try {
      assert.deepEqual(packetIds(app), [101]);
      if (transition === "direction") await app.change("direction-filter", "OUTBOUND");
      else await app.act(() => app.find((n) => n.type === "Pagination").props.onNext());
      assert.equal(queries.length, 2);
      if (transition === "direction") assert.equal(queries[1].direction, "OUTBOUND");
      else assert.equal(queries[1].offset, 20);
      pending.reject(new Error("controlled changed-query failure"));
      await app.settle();
      assert.ok(!packetIds(app).includes(101), "old INBOUND/page-1 row must not be attributed to the newly selected query");
    } finally { app.cleanup(); }
  });
}

for (const [label, values, expected] of [["all missing", [null, null], "계산 불가"], ["mixed", [null, 2], "2"]]) {
  test(`PacketTraffic actual PPS average excludes unknown rates: ${label}`, async () => {
    const app = await mount("PacketTraffic", { getPacketFeatureLogs: async () => ({
      items: values.map((value, i) => packet(i + 1, { effective_packets_per_second: value })), total: values.length,
    }) });
    try {
      const card = app.find((n) => n.type === "SummaryCard" && n.props.title === "평균 실제 PPS");
      assert.equal(card.props.value, expected, "unknown duration/rate is not measured zero traffic");
    } finally { app.cleanup(); }
  });
}

test("PacketTraffic preserves prior successful rows on same-query polling failure", async () => {
  let calls = 0;
  const app = await mount("PacketTraffic", { getPacketFeatureLogs: async () => {
    if (++calls > 1) throw new Error("controlled same-query failure");
    return { items: [packet(101)], total: 1 };
  } });
  try {
    await app.advance(10_000);
    assert.equal(calls, 2);
    assert.deepEqual(packetIds(app), [101], "same-query stale evidence remains useful");
    assert.ok(app.nodes().some((n) => n.props.role === "alert"), "retained results must carry a failure notice");
  } finally { app.cleanup(); }
});

test("PacketTraffic actual PPS average includes measured zero", async () => {
  const app = await mount("PacketTraffic", { getPacketFeatureLogs: async () => ({
    items: [packet(1, { effective_packets_per_second: 0 }), packet(2, { effective_packets_per_second: 2 })], total: 2,
  }) });
  try {
    assert.equal(app.find((n) => n.type === "SummaryCard" && n.props.title === "평균 실제 PPS").props.value, "1");
  } finally { app.cleanup(); }
});

test("PacketTraffic client-filter empty result explains the filter and resets it without refetching", async () => {
  let calls = 0;
  const app = await mount("PacketTraffic", { getPacketFeatureLogs: async () => {
    calls++; return { items: [packet(101)], total: 1 };
  } });
  try {
    await app.change("capture-status-filter", "excluded");
    const empty = app.nodes().find((n) => n.type === "EmptyState");
    assert.ok(empty, "client filter must have its own empty state instead of suggesting capture service failure");
    assert.match(empty.props.description, /현재 페이지.*(검색|조건|상태)/);
    assert.equal(empty.props.actionLabel, "필터 초기화");
    await app.act(() => empty.props.onAction());
    assert.deepEqual(packetIds(app), [101]);
    assert.equal(calls, 1, "clearing client-only filters must not change the server query");
  } finally { app.cleanup(); }
});

test("PacketTraffic page-2 capture filter and local reset preserve direction and offset without requests", async () => {
  const queries = [];
  const app = await mount("PacketTraffic", { getPacketFeatureLogs: async (query) => {
    queries.push(query);
    return { items: [packet(101 + query.offset, { direction: query.direction || "INBOUND" })], total: 41 };
  } });
  const pagination = () => app.find((n) => n.type === "Pagination");
  const direction = () => app.find((n) => n.props.id === "direction-filter").props.value;
  try {
    await app.change("direction-filter", "OUTBOUND");
    await app.act(() => pagination().props.onNext());
    assert.equal(queries.at(-1).offset, 20);
    assert.equal(queries.at(-1).direction, "OUTBOUND");
    assert.equal(pagination().props.currentPage, 2);
    assert.deepEqual(packetIds(app), [121]);
    const initialCalls = queries.length;
    await app.change("capture-status-filter", "excluded");
    assert.equal(queries.length, initialCalls, "current-page capture filtering must not issue a server query");
    assert.equal(pagination().props.currentPage, 2, "client filtering preserves offset 20");
    assert.equal(direction(), "OUTBOUND");
    const empty = app.find((n) => n.type === "EmptyState");
    assert.equal(empty.props.actionLabel, "필터 초기화");
    await app.act(() => empty.props.onAction());
    assert.equal(queries.length, initialCalls, "local empty-state reset must not issue a server query");
    assert.equal(pagination().props.currentPage, 2, "local reset preserves offset 20");
    assert.equal(direction(), "OUTBOUND");
    assert.equal(app.find((n) => n.props.id === "capture-status-filter").props.value, "");
    assert.deepEqual(packetIds(app), [121]);
  } finally { app.cleanup(); }
});

test("PacketTraffic server-empty result retains the collection and extraction service guidance", async () => {
  const app = await mount("PacketTraffic", { getPacketFeatureLogs: async () => ({ items: [], total: 0 }) });
  try {
    const table = packetTable(app);
    assert.equal(table.props.rows.length, 0);
    assert.equal(table.props.emptyTitle, "표시할 패킷 분석 지표가 없습니다.");
    assert.equal(table.props.emptyDescription, "패킷 수집과 특징 추출 서비스가 정상적으로 실행 중인지 확인해 주세요.");
    assert.equal(app.nodes().some((n) => n.type === "Pagination"), false);
  } finally { app.cleanup(); }
});

const device = Object.freeze({ device_id: "fixture_sensor", ip_address: "192.0.2.10",
  status: "normal", registration_state: "ACTIVE", trust_score: 100 });
const deviceIds = (app) => app.nodes().filter((n) => n.type === "DataTable" && n.props.tableLabel === "등록 기기 목록")
  .flatMap((table) => Array.from(table.props.rows, (row) => row.device_id));

for (const state of ["pending", "failed"]) {
  test(`Devices must not show normal rows beneath newly selected isolated filter: ${state}`, async () => {
    const pending = deferred(), queries = [];
    const app = await mount("Devices", { getDevices: (query) => {
      queries.push(query);
      return queries.length === 1 ? Promise.resolve({ items: [device], total: 1 }) : pending.promise;
    } });
    try {
      assert.deepEqual(deviceIds(app), [device.device_id]);
      await app.change("device-status", "isolated");
      assert.equal(queries.length, 2);
      assert.equal(queries[1].status, "isolated");
      if (state === "failed") { pending.reject(new Error("controlled isolated-query failure")); await app.settle(); }
      assert.deepEqual(deviceIds(app), [], "new isolated query must not attribute previous normal devices to its results");
    } finally { app.cleanup(); }
  });
}

test("Devices 12-second reads complete despite the 10-second automatic polling interval", async (t) => {
  const time = clock(), calls = [];
  const app = await mount("Devices", { getDevices: (_query, { signal }) => new Promise((resolve, reject) => {
    calls.push({ signal });
    const timer = time.window.setTimeout(() => resolve({ items: [device], total: 1 }), 12_000);
    signal.addEventListener("abort", () => {
      time.window.clearTimeout(timer);
      reject(Object.assign(new Error("controlled canceled slow request"), { isCanceled: true }));
    }, { once: true });
  }) }, time);
  try {
    await app.advance(32_000);
    t.diagnostic(`controlled elapsed=32000ms, calls=${calls.length}, aborted=${calls.filter((c) => c.signal.aborted).length}`);
    assert.deepEqual(deviceIds(app), [device.device_id], "automatic polling must allow an in-flight slow read to finish");
  } finally { app.cleanup(); }
});

test("Devices retains prior successful rows with a notice on same-query polling failure", async () => {
  let calls = 0;
  const app = await mount("Devices", { getDevices: async () => {
    if (++calls > 1) throw new Error("controlled same-query failure");
    return { items: [device], total: 1 };
  } });
  try {
    await app.advance(10_000);
    assert.equal(calls, 2);
    assert.deepEqual(deviceIds(app), [device.device_id]);
    assert.ok(app.nodes().some((n) => n.props.role === "alert"));
  } finally { app.cleanup(); }
});

test("Devices manual refresh supersedes in-flight read and ignores its late result", async () => {
  const calls = [];
  const app = await mount("Devices", { getDevices: (_query, { signal }) => {
    const request = { ...deferred(), signal }; calls.push(request); return request.promise;
  } });
  try {
    await app.act(() => app.find((n) => n.type === "PageHeader").props.onRefresh());
    assert.equal(calls.length, 2);
    assert.equal(calls[0].signal.aborted, true);
    calls[1].resolve({ items: [device], total: 1 }); await app.settle();
    calls[0].resolve({ items: [{ ...device, device_id: "obsolete" }], total: 99 }); await app.settle();
    assert.deepEqual(deviceIds(app), [device.device_id]);
    assert.equal(app.find((n) => n.type === "Pagination").props.total, 1);
  } finally { app.cleanup(); }
});

test("Devices query change cancels pending read and does not accept its late failure", async () => {
  const calls = [];
  const app = await mount("Devices", { getDevices: (query, { signal }) => {
    const request = { ...deferred(), query, signal }; calls.push(request); return request.promise;
  } });
  try {
    await app.change("device-status", "isolated");
    assert.equal(calls.length, 2);
    assert.equal(calls[0].signal.aborted, true);
    assert.equal(calls[1].query.status, "isolated");
    calls[1].resolve({ items: [{ ...device, status: "isolated", trust_score: 0 }], total: 1 }); await app.settle();
    calls[0].reject(new Error("obsolete initial query failure")); await app.settle();
    assert.deepEqual(deviceIds(app), [device.device_id]);
    assert.equal(app.nodes().some((n) => n.props.role === "alert"), false);
  } finally { app.cleanup(); }
});
