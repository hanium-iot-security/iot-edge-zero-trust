import * as eventScoreEffect from "../utils/eventScoreEffect.js";
import * as uiText from "../utils/uiText.js";
import * as runtimePresentation from "../utils/runtimeStatus.js";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { fileURLToPath } from "node:url";
import { transformWithOxc } from "vite";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import FirewallTrafficFields from "../components/FirewallTrafficFields.js";
import * as mqttTimestamp from "../utils/mqttTimestamp.js";
import * as firewallRuleSelection from "../utils/firewallRuleSelection.js";

// Execute the complete production component. Only its imports, React hook runtime,
// JSX renderer, API transport and clock are replaced; handlers are never copied.
// FRONTEND_REGRESSION_REF=<commit> runs these assertions against historical source.
const repository = fileURLToPath(new URL("../../../", import.meta.url));
const compiledPages = new Map();
async function pageCode(name, folder = "pages") {
  const revision = process.env.FRONTEND_REGRESSION_REF;
  const key = `${revision || "working-tree"}:${folder}:${name}`;
  if (!compiledPages.has(key)) {
    const source = revision
      ? execFileSync("git", ["show", `${revision}:frontend/src/${folder}/${name}.jsx`], {
          cwd: repository,
          encoding: "utf8",
        })
      : await readFile(new URL(`../${folder}/${name}.jsx`, import.meta.url), "utf8");
    const importedNames = [];
    for (const match of source.matchAll(
      /^import\s+(?:\{([\s\S]*?)\}|(\w+))\s+from\s+["'][^"']+["'];/gm,
    )) {
      if (match[1]) importedNames.push(...match[1].split(",").map((item) => item.trim()).filter(Boolean));
      if (match[2]) importedNames.push(match[2]);
    }
    const result = await transformWithOxc(
      source.replace(/^import\b[\s\S]*?;\r?\n/gm, ""),
      `${name}.jsx`,
      {
        jsx: { runtime: "classic", pragma: "jsx", pragmaFrag: "Fragment" },
        define: { "import.meta.env.DEV": "false" },
      },
    );
    compiledPages.set(key, {
      importedNames,
      code: result.code.replace(`export default function ${name}`, `function ${name}`).replace(/\bexport\s*\{[^}]*\};?/g, "") +
        `\nglobalThis.Component = ${name};`,
    });
  }
  return compiledPages.get(key);
}

function createClock() {
  let now = Date.parse("2026-10-12T00:00:00Z");
  let nextId = 0;
  const timers = new Map();
  class ControlledDate extends Date {
    constructor(...args) { super(...(args.length ? args : [now])); }
    static now() { return now; }
  }
  const add = (callback, delay, interval = 0) => {
    const id = ++nextId;
    timers.set(id, { callback, at: now + Number(delay), interval });
    return id;
  };
  return {
    Date: ControlledDate,
    get now() { return now; },
    window: {
      setTimeout: (callback, delay) => add(callback, delay),
      clearTimeout: (id) => timers.delete(id),
      setInterval: (callback, delay) => add(callback, delay, Number(delay)),
      clearInterval: (id) => timers.delete(id),
    },
    async advance(milliseconds, settle) {
      const target = now + milliseconds;
      for (;;) {
        const next = [...timers.entries()]
          .filter(([, timer]) => timer.at <= target)
          .sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
        if (!next) break;
        const [id, timer] = next;
        now = timer.at;
        if (timer.interval) timer.at += timer.interval;
        else timers.delete(id);
        timer.callback();
        await settle();
      }
      now = target;
      await settle();
    },
  };
}

async function componentHarness(name, api, clock = createClock()) {
  const { importedNames, code } = await pageCode(name);
  const slots = [];
  let cursor = 0;
  let dirty = false;
  let root;
  let effects = [];
  const actionErrors = [];
  const same = (a, b) => a && b && a.length === b.length && a.every((value, i) => Object.is(value, b[i]));
  const hooks = {
    useState(initial) {
      const i = cursor++;
      if (!(i in slots)) slots[i] = { value: typeof initial === "function" ? initial() : initial };
      return [slots[i].value, (update) => {
        const value = typeof update === "function" ? update(slots[i].value) : update;
        if (!Object.is(value, slots[i].value)) { slots[i].value = value; dirty = true; }
      }];
    },
    useRef(initial) { const i = cursor++; return slots[i] ??= { current: initial }; },
    useMemo(callback, dependencies) {
      const i = cursor++;
      if (!slots[i] || !same(slots[i].dependencies, dependencies)) {
        slots[i] = { dependencies, value: callback() };
      }
      return slots[i].value;
    },
    useCallback(callback, dependencies) { return hooks.useMemo(() => callback, dependencies); },
    useEffect(callback, dependencies) {
      const i = cursor++;
      if (!slots[i] || !same(slots[i].dependencies, dependencies)) {
        const cleanup = slots[i]?.cleanup;
        slots[i] = { dependencies, effect: callback };
        effects.push(() => { cleanup?.(); slots[i].cleanup = callback(); });
      }
    },
  };
  const scope = {
    ...Object.fromEntries(importedNames.map((importedName) => [importedName,
      /^(get|create|execute|recovery)/.test(importedName) ? async () => ({ items: [] }) : importedName])),
    ...mqttTimestamp,
    ...uiText,
    ...eventScoreEffect,
    ...runtimePresentation,
    ...firewallRuleSelection,
    ...api,
    ...hooks,
    Error,
    AbortController,
    console,
    Date: clock.Date,
    window: clock.window,
    Fragment: "Fragment",
    jsx: (type, properties, ...children) => ({ type, props: properties || {}, children }),
  };
  runInNewContext(code, scope, { filename: `${name}.jsx` });
  function render() {
    cursor = 0;
    dirty = false;
    effects = [];
    root = scope.Component();
    effects.forEach((effect) => effect());
  }
  async function settle() {
    for (let i = 0; i < 40; i++) {
      await Promise.resolve();
      if (dirty) render();
    }
    assert.equal(actionErrors.length, 0, actionErrors[0]?.stack);
    assert.equal(dirty, false, "component must settle without an effect render loop");
  }
  function* walk(node) {
    if (Array.isArray(node)) { for (const child of node) yield* walk(child); }
    else if (node && typeof node === "object") {
      yield node;
      yield* walk(node.children);
      yield* walk(node.props?.footer);
      yield* walk(node.props?.actions);
    }
  }
  const nodes = () => [...walk(root)];
  const find = (predicate) => {
    const node = nodes().find(predicate);
    assert.ok(node, `missing ${name} UI node`);
    return node;
  };
  const textContent = (node) => {
    if (Array.isArray(node)) return node.map(textContent).join("");
    if (node && typeof node === "object") return textContent(node.children);
    return typeof node === "string" || typeof node === "number" ? String(node) : "";
  };
  async function act(callback) {
    const result = callback();
    result?.catch?.((error) => actionErrors.push(error));
    await settle();
  }
  const input = (id) => find((node) => node.props.id === id);
  const button = (label) => find((node) => node.type === "button" && textContent(node).trim() === label);
  const harness = {
    clock, settle, find, nodes, input, button, textContent,
    act,
    change: (id, value) => act(() => input(id).props.onChange({ target: { value } })),
    click: (label) => act(() => {
      const target = button(label);
      assert.equal(Boolean(target.props.disabled), false, `${label} must be enabled`);
      return target.props.onClick();
    }),
    advance: (milliseconds) => clock.advance(milliseconds, settle),
    async strictReplay() {
      const activeEffects = slots.filter((slot) => slot?.effect);
      activeEffects.forEach((slot) => slot.cleanup?.());
      activeEffects.forEach((slot) => { slot.cleanup = slot.effect(); });
      await settle();
    },
    cleanup() { slots.filter((slot) => slot?.effect).forEach((slot) => slot.cleanup?.()); },
  };
  render();
  await settle();
  return harness;
}

const sensor = { device_id: "sensor_01", ip_address: "192.168.1.30", registration_state: "ACTIVE", trust_score: 100 };
function policy(revision, payload = 5120, overrides = {}) {
  return {
    revision, registration_state: "ACTIVE",
    policy: {
      policy_profile: "periodic-sensor-v1", expected_publish_interval_seconds: 5,
      publish_count_max: 15, payload_size_max_bytes: payload,
      packet_rate_max_pps: 10, byte_rate_max_bytes_per_second: 2500, ...overrides,
    },
  };
}
function deviceServer(clock) {
  let current = policy(1);
  let pending = null;
  let failure = null;
  const writes = [];
  const server = {
    writes,
    setCurrent(value) { current = value; },
    setPending(value) { pending = value; },
    failNextPolicy(error) { failure = error; },
    api: {
      getDevices: async () => ({ items: [sensor], total: 1 }),
      getFirewallRules: async () => ({ items: [] }),
      getDeviceDetail: async () => sensor,
      getTrustScoreHistory: async () => ({ items: [], total: 0 }),
      getDevicePolicy: async () => {
        if (failure) { const error = failure; failure = null; throw error; }
        if (pending && Date.parse(pending.effective_from) <= clock.now) { current = pending; pending = null; }
        return { current, pending, latest_revision: pending?.revision ?? current.revision };
      },
      createDevicePolicyRevision: async (deviceId, payload) => {
        writes.push({ deviceId, payload });
        pending = {
          revision: current.revision + 1,
          registration_state: payload.registration_state,
          policy: payload.policy,
          effective_from: new Date(clock.now + 10_000).toISOString(),
        };
      },
    },
  };
  return server;
}
async function openSensor(app) {
  const table = app.find((node) => node.type === "DataTable" && node.props.onRowClick);
  await app.act(() => table.props.onRowClick(table.props.rows[0]));
}

// The saved change first remains pending; the timer must load the applied policy
// into unchanged draft fields so the next unrelated save cannot revert it.
test("saved pending policy resyncs 5120 to 6000 and next publish-count save retains 6000", async () => {
  const clock = createClock();
  const server = deviceServer(clock);
  const app = await componentHarness("Devices", server.api, clock);
  await openSensor(app);
  await app.change("rule-key", "test-admin");
  await app.change("rule-payload_size_max", "6000");
  await app.change("rule-reason", "raise payload limit");
  await app.click("규칙 정책 변경 저장");
  assert.equal(server.writes.length, 1);
  assert.equal(app.input("rule-key").props.value, "", "successful save clears the administrator key");
  assert.equal(app.input("rule-payload_size_max").props.value, "5120");
  assert.equal(app.input("rule-payload_size_max").props.disabled, true);
  await app.advance(10_750);
  assert.equal(app.input("rule-payload_size_max").props.value, "6000");
  assert.equal(app.input("rule-payload_size_max").props.disabled, false);
  await app.change("rule-key", "test-admin");
  await app.change("rule-publish_count_max", "20");
  await app.change("rule-reason", "raise publish count");
  await app.click("규칙 정책 변경 저장");
  assert.equal(server.writes.length, 2);
  assert.equal(server.writes[1].payload.expected_revision, 2);
  assert.equal(server.writes[1].payload.policy.payload_size_max_bytes, 6000);
  assert.equal(server.writes[1].payload.policy.publish_count_max, 20);
  app.cleanup();
});

test("409 refresh and later scheduled callback preserve edited fields and update untouched fields", async () => {
  const clock = createClock();
  const server = deviceServer(clock);
  server.api.createDevicePolicyRevision = async () => {
    server.setPending({ ...policy(2, 7000, { byte_rate_max_bytes_per_second: 3100 }), effective_from: new Date(clock.now + 10_000).toISOString() });
    throw Object.assign(new Error("revision conflict"), { status: 409 });
  };
  const app = await componentHarness("Devices", server.api, clock);
  await openSensor(app);
  await app.change("rule-key", "test-admin");
  await app.change("rule-payload_size_max", "6200");
  await app.change("rule-publish_count_max", "21");
  await app.change("rule-reason", "keep my draft");
  await app.click("규칙 정책 변경 저장");
  assert.equal(app.input("rule-payload_size_max").props.value, "6200");
  assert.equal(app.input("rule-reason").props.value, "keep my draft");
  await app.advance(10_750);
  assert.equal(app.input("rule-payload_size_max").props.value, "6200");
  assert.equal(app.input("rule-publish_count_max").props.value, "21");
  assert.equal(app.input("rule-reason").props.value, "keep my draft");
  assert.equal(app.input("rule-byte_rate_max").props.value, "3100");
  app.cleanup();
});

for (const recovery of ["ErrorState retry", "manual policy refresh"]) {
  test(`scheduled policy refresh failure exposes error and ${recovery} unlocks save`, async () => {
    const clock = createClock();
    const server = deviceServer(clock);
    server.setPending({ ...policy(2, 6000), effective_from: new Date(clock.now + 10_000).toISOString() });
    const app = await componentHarness("Devices", server.api, clock);
    await openSensor(app);
    await app.change("rule-key", "test-admin");
    server.failNextPolicy(new Error("temporary policy outage"));
    await app.advance(10_750);
    const error = app.find((node) => node.type === "ErrorState" && node.props.message === "temporary policy outage");
    assert.equal(app.button("규칙 정책 변경 저장").props.disabled, true);
    if (recovery === "ErrorState retry") await app.act(() => error.props.onRetry());
    else await app.click("정책 새로고침");
    assert.equal(app.nodes().some((node) => node.type === "ErrorState" && node.props.message === "temporary policy outage"), false);
    assert.equal(app.input("rule-payload_size_max").props.value, "6000");
    assert.equal(app.button("규칙 정책 변경 저장").props.disabled, false);
    app.cleanup();
  });
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

async function openDevice(app, deviceId) {
  const table = app.find((node) => node.type === "DataTable" && node.props.onRowClick);
  await app.act(() => table.props.onRowClick(table.props.rows.find((row) => row.device_id === deviceId)));
}

function selectedDetail(app) {
  return app.find((node) => node.type === "DetailModal" && node.props.open && node.props.title.endsWith("상세 상태"));
}

test("delayed policy refresh for device A cannot overwrite device B draft or next write", async () => {
  const a = { ...sensor, device_id: "sensor_A" };
  const b = { ...sensor, device_id: "sensor_B" };
  const stale = deferred();
  const writes = [];
  let delayA = false;
  const app = await componentHarness("Devices", {
    getDevices: async () => ({ items: [a, b], total: 2 }),
    getFirewallRules: async () => ({ items: [] }),
    getDeviceDetail: async (id) => id === a.device_id ? a : b,
    getTrustScoreHistory: async () => ({ items: [], total: 0 }),
    getDevicePolicy: async (id) => id === a.device_id && delayA
      ? stale.promise
      : { current: policy(1, id === a.device_id ? 5120 : 9100), latest_revision: 1 },
    createDevicePolicyRevision: async (deviceId, payload) => { writes.push({ deviceId, payload }); },
  });
  await openDevice(app, a.device_id);
  delayA = true;
  await app.click("정책 새로고침");
  await app.act(() => selectedDetail(app).props.onClose());
  await openDevice(app, b.device_id);
  stale.resolve({ current: policy(1, 5120), latest_revision: 1 });
  await app.settle();
  assert.equal(selectedDetail(app).props.title, "sensor_B 상세 상태");
  assert.equal(app.input("rule-payload_size_max").props.value, "9100");
  await app.change("rule-publish_count_max", "22");
  await app.change("rule-key", "test-admin");
  await app.change("rule-reason", "change device B publish count");
  await app.click("규칙 정책 변경 저장");
  assert.equal(writes.length, 1);
  assert.equal(writes[0].deviceId, b.device_id);
  assert.equal(writes[0].payload.policy.payload_size_max_bytes, 9100);
  assert.equal(writes[0].payload.policy.publish_count_max, 22);
  app.cleanup();
});

test("closed device A refresh error cannot clear device B loading state or show a stale error", async () => {
  const a = { ...sensor, device_id: "sensor_A" };
  const b = { ...sensor, device_id: "sensor_B" };
  const stale = deferred();
  const current = deferred();
  let delayA = false;
  const app = await componentHarness("Devices", {
    getDevices: async () => ({ items: [a, b], total: 2 }),
    getFirewallRules: async () => ({ items: [] }),
    getDeviceDetail: async (id) => id === a.device_id ? a : b,
    getTrustScoreHistory: async () => ({ items: [], total: 0 }),
    getDevicePolicy: async (id) => id === b.device_id ? current.promise
      : delayA ? stale.promise : { current: policy(1), latest_revision: 1 },
  });
  await openDevice(app, a.device_id);
  delayA = true;
  await app.click("정책 새로고침");
  await app.act(() => selectedDetail(app).props.onClose());
  await openDevice(app, b.device_id);
  stale.reject(new Error("old device A refresh failed"));
  await app.settle();
  assert.equal(app.nodes().some((node) => node.type === "ErrorState" && node.props.message === "old device A refresh failed"), false);
  assert.equal(app.nodes().some((node) => node.type === "LoadingState" && node.props.title === "규칙 정책 조회 중"), true);
  assert.equal(app.button("규칙 정책 변경 저장").props.disabled, true);
  current.resolve({ current: policy(1, 9100), latest_revision: 1 });
  await app.settle();
  assert.equal(app.input("rule-payload_size_max").props.value, "9100");
  assert.equal(app.button("규칙 정책 변경 저장").props.disabled, false);
  app.cleanup();
});

function dashboardApi(gateway) {
  return {
    getSummary: async () => ({ device_count: 1 }),
    getDevices: async () => ({ items: [sensor] }),
    getHealth: async () => ({ status: "ok", database: "ok", db_connected: true }),
    getGatewayMetrics: gateway,
  };
}
function gatewayCard(app) { return app.find((node) => node.type === "MetricCard" && node.props.label === "CPU"); }

test("slow Dashboard gateway completes at 12 seconds without 10-second poll abort starvation", async () => {
  const clock = createClock();
  const calls = [];
  const api = dashboardApi((_params, { signal }) => new Promise((resolve, reject) => {
    const call = { signal, index: calls.length + 1 };
    calls.push(call);
    const timer = clock.window.setTimeout(() => resolve({ items: [{ cpu_percent: call.index * 10, collected_at: new Date(clock.now).toISOString() }] }), 12_000);
    signal.addEventListener("abort", () => {
      clock.window.clearTimeout(timer);
      reject(Object.assign(new Error("canceled"), { isCanceled: true }));
    }, { once: true });
  }));
  const app = await componentHarness("Dashboard", api, clock);
  await app.advance(10_000);
  assert.equal(calls.length, 1, "automatic poll must leave in-flight request running");
  assert.equal(calls[0].signal.aborted, false);
  await app.advance(2_000);
  assert.equal(Number(gatewayCard(app).props.value), 10);
  assert.ok(gatewayCard(app).props.updatedAt);
  await app.advance(8_000);
  assert.equal(calls.length, 2, "polling must resume after the request settles");
  await app.advance(12_000);
  assert.equal(Number(gatewayCard(app).props.value), 20);
  assert.equal(calls[1].signal.aborted, false);
  app.cleanup();
});

test("Dashboard StrictMode effect cleanup remount starts fresh request and discards old response", async () => {
  const requests = [];
  const app = await componentHarness("Dashboard", dashboardApi((_params, { signal }) => new Promise((resolve) => requests.push({ signal, resolve }))));
  assert.equal(requests.length, 1);
  await app.strictReplay();
  assert.equal(requests[0].signal.aborted, true);
  assert.equal(requests.length, 2);
  requests[1].resolve({ items: [{ cpu_percent: 77, collected_at: "2026-10-12T00:00:00Z" }] });
  await app.settle();
  assert.equal(Number(gatewayCard(app).props.value), 77);
  requests[0].resolve({ items: [{ cpu_percent: 11, collected_at: "2026-10-11T00:00:00Z" }] });
  await app.settle();
  assert.equal(Number(gatewayCard(app).props.value), 77, "aborted first mount cannot overwrite remounted data");
  await app.advance(10_000);
  assert.equal(requests.length, 3);
  app.cleanup();
  assert.equal(requests[2].signal.aborted, true);
});

// Replay the actual mount cleanup/setup while transport is still pending.
// The fake clock measures the unwanted polling delay without sleeping.
for (const settlement of ["cancellation", "late response"]) {
  test("Isolation StrictMode restarts canceled initial history at 0 ms: " + settlement, async () => {
    const clock = createClock();
    const startedAt = clock.now;
    const requests = [];
    const api = {
      getIsolationHistory: (_params, { signal }) => new Promise((resolve, reject) => {
        requests.push({ signal, resolve, reject });
      }),
      getIsolatedDevices: async () => ({ items: [] }),
      getFirewallRules: async () => ({ items: [] }),
    };
    const app = await componentHarness("Isolation", api, clock);
    const table = () => app.find((node) => node.type === "DataTable" && node.props.tableLabel === "격리 이력");
    const result = (id) => ({
      items: [{ id, device_id: sensor.device_id, action: "ISOLATE", trust_score: 20,
        reason: "test isolation", created_at: "2026-10-12T00:00:00Z" }],
      total: 1,
    });
    try {
      assert.equal(requests.length, 1);
      await app.strictReplay();
      assert.equal(requests[0].signal.aborted, true);
      // On the broken component, let its next poll run to expose the 10,000 ms baseline.
      if (requests.length === 1) await app.advance(10_000);
      assert.equal(clock.now - startedAt, 0, "initial history must restart immediately, without waiting for a 10,000 ms poll");
      assert.equal(requests.length, 2);
      assert.equal(requests[1].signal.aborted, false);
      if (settlement === "cancellation") {
        requests[0].reject(Object.assign(new Error("canceled"), { isCanceled: true }));
        await app.settle();
        assert.equal(table().props.loading, true, "old cancellation must not clear the new request's loading state");
        assert.equal(table().props.error, "");
      }
      requests[1].resolve(result(22));
      await app.settle();
      assert.equal(table().props.rows[0].id, 22);
      assert.equal(table().props.loading, false);
      if (settlement === "late response") {
        requests[0].resolve(result(11));
        await app.settle();
        assert.equal(table().props.rows[0].id, 22, "old transport response cannot overwrite remounted history");
      }
      await app.advance(10_000);
      assert.equal(requests.length, 3, "normal polling must continue after initial history loads");
    } finally {
      app.cleanup();
    }
    assert.equal(requests.at(-1).signal.aborted, true, "unmount must cancel the current request");
  });
}

test("Isolation leaves a slow live history request running across the 10-second poll", async () => {
  const clock = createClock();
  const requests = [];
  const app = await componentHarness("Isolation", {
    getIsolationHistory: (_params, { signal }) => new Promise((resolve) => {
      requests.push({ signal });
      clock.window.setTimeout(() => resolve({
        items: [{ id: 22, device_id: sensor.device_id, action: "ISOLATE" }], total: 1,
      }), 12_000);
    }),
    getIsolatedDevices: async () => ({ items: [] }),
    getFirewallRules: async () => ({ items: [] }),
  }, clock);
  try {
    await app.advance(10_000);
    assert.equal(requests.length, 1, "a poll must not duplicate a live request");
    assert.equal(requests[0].signal.aborted, false);
    await app.advance(2_000);
    const table = app.find((node) => node.type === "DataTable" && node.props.tableLabel === "격리 이력");
    assert.equal(table.props.rows[0].id, 22);
    assert.equal(table.props.loading, false);
    await app.advance(8_000);
    assert.equal(requests.length, 2, "polling resumes after the live request finishes");
  } finally {
    app.cleanup();
  }
  assert.equal(requests.at(-1).signal.aborted, true);
});

test("Isolation history modal shows MQTT parent and null-trigger IPv4 child with separate scopes and statuses", async () => {
  const history = { id: 27, device_id: sensor.device_id, trigger_event_id: 45, action: "ISOLATE" };
  let rules = [
    { id: 30, device_id: sensor.device_id, source_ip: sensor.ip_address, trigger_event_id: null,
      source_rule_id: 29, status: "APPLIED", scope: "PI_INPUT_IPV4_ALL", protocol: null, dest_port: null,
      updated_at: "2026-10-12T00:00:00Z" },
    { id: 29, device_id: sensor.device_id, source_ip: sensor.ip_address, trigger_event_id: 45,
      status: "REMOVED", scope: "MQTT_IPV4_TCP_1883", protocol: "tcp", dest_port: 1883,
      updated_at: "2026-10-12T00:01:00Z" },
  ];
  const app = await componentHarness("Isolation", {
    getIsolationHistory: async () => ({ items: [history], total: 1 }),
    getIsolatedDevices: async () => ({ items: [] }),
    getFirewallRules: async () => ({ items: rules }),
  });
  try {
    const table = app.find((node) => node.type === "DataTable" && node.props.tableLabel === "격리 이력");
    const row = table.props.rows[0];
    assert.equal(row.firewall_status, "APPLIED", "a removed MQTT parent must not hide its applied IPv4 child");
    assert.equal(row.firewall_rule.id, 30, "representative compatibility follows unresolved precedence");
    assert.deepEqual(Array.from(row.firewall_rules, (rule) => rule.id), [29, 30]);
    await app.act(() => table.props.onRowClick(row));
    const modal = app.find((node) => node.type === "DetailModal" && node.props.open && node.props.title === "격리 이력 #27");
    const cards = treeNodes(modal).filter((node) => node.type === "article" && node.props.className === "history-item");
    assert.equal(cards.length, 2);
    assert.match(app.textContent(cards[0]), /MQTT IPv4/);
    assert.match(app.textContent(cards[1]), /전체 IPv4/);
    assert.deepEqual(cards.map((card) => treeNodes(card).find((node) => node.type === "StatusBadge").props.label), ["차단 해제", "차단 적용"]);
    assert.deepEqual(cards.map((card) => treeNodes(card).find((node) => node.type === "FirewallTrafficFields").props.rule.id), [29, 30]);
    const traffic = cards.map((card) => renderToStaticMarkup(createElement(FirewallTrafficFields,
      treeNodes(card).find((node) => node.type === "FirewallTrafficFields").props)));
    assert.match(traffic[0], /tcp.*1883/);
    assert.match(traffic[1], /전체 IPv4.*모든 포트/);
    assert.doesNotMatch(traffic[1], /1883/);
    assert.equal(treeNodes(modal).filter((node) => node.type === "button").length, 0, "history rule cards add no management actions");
    rules = rules.map((rule) => ({ ...rule, status: "REMOVED" }));
    await app.act(() => app.find((node) => node.type === "PageHeader").props.onRefresh());
    const refreshedTable = app.find((node) => node.type === "DataTable" && node.props.tableLabel === "격리 이력");
    assert.equal(refreshedTable.props.rows[0].firewall_status, "REMOVED", "all scopes removed means the history badge is removed");
    const refreshedModal = app.find((node) => node.type === "DetailModal" && node.props.open && node.props.title === "격리 이력 #27");
    const refreshedCards = treeNodes(refreshedModal).filter((node) => node.type === "article" && node.props.className === "history-item");
    assert.deepEqual(refreshedCards.map((card) => treeNodes(card).find((node) => node.type === "StatusBadge").props.label), ["차단 해제", "차단 해제"]);
  } finally { app.cleanup(); }
});

for (const [label, rule, expectedTraffic] of [
  ["direct all-IPv4", { scope: "PI_INPUT_IPV4_ALL", protocol: null, dest_port: null }, /전체 IPv4.*모든 포트/],
  ["legacy MQTT-only", { protocol: "tcp", dest_port: 1883 }, /tcp.*1883/],
]) {
  test(`Isolation history modal preserves a single ${label} rule`, async () => {
    const app = await componentHarness("Isolation", {
      getIsolationHistory: async () => ({ items: [{ id: 27, device_id: sensor.device_id, trigger_event_id: 45 }], total: 1 }),
      getIsolatedDevices: async () => ({ items: [] }),
      getFirewallRules: async () => ({ items: [{ ...rule, id: 30, device_id: sensor.device_id, source_ip: sensor.ip_address,
        trigger_event_id: 45, source_rule_id: null, status: "APPLIED" }] }),
    });
    try {
      const table = app.find((node) => node.type === "DataTable" && node.props.tableLabel === "격리 이력");
      assert.equal(table.props.rows[0].firewall_rules.length, 1);
      await app.act(() => table.props.onRowClick(table.props.rows[0]));
      const modal = app.find((node) => node.type === "DetailModal" && node.props.open && node.props.title === "격리 이력 #27");
      const cards = treeNodes(modal).filter((node) => node.type === "article" && node.props.className === "history-item");
      assert.equal(cards.length, 1);
      const fields = treeNodes(cards[0]).find((node) => node.type === "FirewallTrafficFields");
      const traffic = renderToStaticMarkup(createElement(FirewallTrafficFields, fields.props));
      assert.match(traffic, expectedTraffic);
      if (label === "direct all-IPv4") assert.doesNotMatch(traffic, /1883/);
    } finally { app.cleanup(); }
  });
}

test("Isolation refresh preserves release target ID then sequentially releases wide and FAILED MQTT scopes", async () => {
  const clock = createClock();
  const device = { ...sensor, trust_score: 20, status: "isolated" };
  let rules = [
    { id: 20, device_id: sensor.device_id, status: "FAILED", scope: "MQTT_IPV4_TCP_1883", protocol: "tcp", dest_port: 1883, updated_at: "2026-10-11T00:00:00Z" },
    { id: 21, device_id: sensor.device_id, status: "APPLIED", scope: "PI_INPUT_IPV4_ALL", protocol: null, dest_port: null, updated_at: "2026-10-12T00:00:00Z" },
  ];
  const releases = [];
  let requestStatus = "PENDING";
  let runtimeStatus = "UNAVAILABLE";
  const preflightCalls = [];
  const recoveryCalls = [];
  const api = {
    getIsolationHistory: async () => ({ items: [], total: 0 }),
    getIsolatedDevices: async () => ({ items: [device] }),
    getFirewallRules: async () => ({ items: rules }),
    getDeviceDetail: async () => device,
    getRecoveryHistory: async () => ({ items: [] }),
    createFirewallReleaseRequest: async (ruleId, options) => {
      releases.push({ ruleId, options });
      return { id: 100 + ruleId, device_id: sensor.device_id, firewall_rule_id: ruleId, status: "PENDING" };
    },
    getFirewallReleaseRequest: async (requestId) => ({ id: requestId, device_id: sensor.device_id, firewall_rule_id: requestId - 100, status: requestStatus }),
    recoveryPreflight: async (payload) => {
      preflightCalls.push(payload);
      return { device_id: sensor.device_id, can_execute: true, firewall_runtime_verification: { status: runtimeStatus } };
    },
    executeRecovery: async (payload) => { recoveryCalls.push(payload); },
  };
  const app = await componentHarness("Isolation", api, clock);
  const table = app.find((node) => node.type === "DataTable" && node.props.tableLabel === "현재 격리된 기기");
  assert.equal(table.props.rows[0].firewall_rule.id, 21);
  await app.act(() => table.props.onRowClick(table.props.rows[0]));
  await app.change("recovery-admin-key", "test-admin");
  await app.change("firewall-release-reason", "release exact wide rule");
  await app.change("firewall-release-confirmation", "RELEASE-FIREWALL-RULE-20");
  await app.click("방화벽 해제 요청");
  assert.equal(releases.length, 0, "confirmation for another scope must not dispatch");
  await app.change("firewall-release-confirmation", "RELEASE-FIREWALL-RULE-21");
  await app.click("방화벽 해제 요청");
  assert.equal(releases[0].ruleId, 21);
  assert.equal(app.input("recovery-reason").props.value, "release exact wide rule");
  assert.equal(app.input("recovery-confirmation").props.value, "");
  assert.equal(preflightCalls.length, 0, "copying the reason must not run preflight");
  assert.equal(recoveryCalls.length, 0, "copying the reason must not execute Recovery");
  rules = rules.map((rule) => rule.id === 21 ? { ...rule, status: "REMOVED", updated_at: "2026-10-12T00:00:01Z" } : rule);
  await app.act(() => app.find((node) => node.type === "PageHeader").props.onRefresh());
  assert.equal(app.find((node) => node.type === "FirewallTrafficFields").props.rule.id, 20);
  requestStatus = "SUCCEEDED";
  await app.advance(2_000);
  assert.equal(app.button("방화벽 해제 요청").props.disabled, false, "completed request 21 must remain matched to rule 21 after selection changes to rule 20");
  assert.equal(app.button("사전 점검 실행").props.disabled, true, "remaining MQTT scope still blocks Recovery");
  await app.change("firewall-release-reason", "release exact failed MQTT rule");
  await app.change("firewall-release-confirmation", "RELEASE-FIREWALL-RULE-20");
  requestStatus = "PENDING";
  await app.click("방화벽 해제 요청");
  assert.deepEqual(releases.map((item) => item.ruleId), [21, 20]);
  assert.equal(releases[1].options.confirmation, "RELEASE-FIREWALL-RULE-20");
  assert.equal(app.input("recovery-reason").props.value, "release exact wide rule");
  rules = rules.map((rule) => ({ ...rule, status: "REMOVED" }));
  requestStatus = "SUCCEEDED";
  await app.advance(2_000);
  await app.click("사전 점검 실행");
  assert.equal(preflightCalls[0].expected_trust_score, 20);
  assert.equal(app.button("복구 실행").props.disabled, true, "can_execute alone cannot bypass runtime verification");
  runtimeStatus = "VERIFIED_RELEASED";
  await app.click("사전 점검 실행");
  assert.equal(app.button("복구 실행").props.disabled, false);
  app.cleanup();
});


for (const [label, draft, expected] of [
  ["whitespace", " \t\n ", "release after new block"],
  ["edited", "  operator-specific recovery justification  ", "  operator-specific recovery justification  "],
]) {
  test(`Isolation ${label} Recovery reason survives a new block and resets for another device`, async () => {
    const device = { ...sensor, status: "isolated", trust_score: 20 };
    const otherDevice = { ...device, device_id: "sensor_02", ip_address: "192.168.1.31" };
    let rules = [{ id: 21, device_id: device.device_id, status: "REMOVED", scope: "PI_INPUT_IPV4_ALL" }];
    const releases = [];
    const preflights = [];
    const recoveries = [];
    const app = await componentHarness("Isolation", {
      getIsolationHistory: async () => ({ items: [], total: 0 }),
      getIsolatedDevices: async () => ({ items: [device, otherDevice] }),
      getFirewallRules: async () => ({ items: rules }),
      getRecoveryHistory: async () => ({ items: [] }),
      createFirewallReleaseRequest: async (ruleId, options) => {
        releases.push({ ruleId, options });
        return { id: 100 + ruleId, device_id: device.device_id, firewall_rule_id: ruleId, status: "PENDING" };
      },
      getFirewallReleaseRequest: async () => ({ id: 122, device_id: device.device_id, firewall_rule_id: 22, status: "PENDING" }),
      recoveryPreflight: async (payload) => {
        preflights.push(payload);
        return { device_id: device.device_id, can_execute: true, current_trust_score: 20, firewall_runtime_verification: { status: "VERIFIED_RELEASED" } };
      },
      executeRecovery: async (payload) => { recoveries.push(payload); },
    });
    await openDevice(app, device.device_id);
    await app.change("recovery-admin-key", "test-admin");
    await app.click("사전 점검 실행");
    assert.equal(app.input("recovery-reason").props.disabled, false);
    await app.change("recovery-reason", draft);

    rules = [...rules, { id: 22, device_id: device.device_id, status: "APPLIED", scope: "PI_INPUT_IPV4_ALL" }];
    await app.act(() => app.find((node) => node.type === "PageHeader").props.onRefresh());
    assert.equal(app.input("recovery-reason").props.disabled, true);
    await app.change("firewall-release-reason", "  release after new block  ");
    await app.change("firewall-release-confirmation", "RELEASE-FIREWALL-RULE-22");
    await app.click("방화벽 해제 요청");

    assert.equal(app.input("recovery-reason").props.value, expected);
    assert.equal(releases.length, 1);
    assert.equal(releases[0].ruleId, 22);
    assert.equal(releases[0].options.reason, "release after new block");
    assert.equal(releases[0].options.confirmation, "RELEASE-FIREWALL-RULE-22");
    assert.equal(preflights.length, 1, "only the manual preflight should run");
    assert.equal(recoveries.length, 0);
    assert.equal(app.input("recovery-confirmation").props.value, "");
    assert.equal(app.button("복구 실행").props.disabled, true);

    const modal = app.find((node) => node.type === "DetailModal" && node.props.open && node.props.title === `${device.device_id} 복구`);
    assert.equal(modal.props.closeDisabled, false, "the HTTP release response has settled");
    await app.act(() => modal.props.onClose());
    await openDevice(app, otherDevice.device_id);
    for (const id of ["recovery-admin-key", "firewall-release-reason", "firewall-release-confirmation", "recovery-reason", "recovery-confirmation"]) {
      assert.equal(app.input(id).props.value, "", `${id} must reset for the other device`);
    }
    app.cleanup();
  });
}

function packetQualityBadge(app) {
  const panel = app.find((node) => node.type === "article" && app.textContent(node).includes("패킷 수집 상태"));
  const header = panel.children.find((node) => node?.props?.className === "panel-header");
  return header.children.find((node) => node?.type === "StatusBadge").props;
}

test("empty capture results and a failed refresh never advertise healthy collection; cached counts remain", async () => {
  let items = [];
  let failure = false;
  const app = await componentHarness("Dashboard", {
    ...dashboardApi(async () => ({ items: [] })),
    getPacketFeatureLogs: async () => {
      if (failure) throw new Error("packet refresh failed");
      return { items };
    },
  });
  assert.equal(packetQualityBadge(app).label, "자료 없음");
  assert.notEqual(packetQualityBadge(app).status, "normal");
  items = [{ capture_eligible: true, segment_status: "PROCESSED", coverage_ratio: 0.997 }];
  await app.advance(10_000);
  assert.equal(packetQualityBadge(app).label, "수집 양호");
  failure = true;
  await app.advance(10_000);
  assert.equal(packetQualityBadge(app).label, "확인 불가");
  assert.notEqual(packetQualityBadge(app).status, "normal");
  const count = app.find((node) => node.type === "SummaryCard" && node.props.title === "분석 가능");
  assert.equal(Number(count.props.value), 1, "failed refresh preserves the prior successful count");
  assert.equal(count.props.stale, true);
  app.cleanup();
});

test("unknown capture eligibility stays unconfirmed while failed or excluded rows indicate degraded quality", async () => {
  let items = [{ segment_status: "PROCESSED" }];
  const app = await componentHarness("Dashboard", {
    ...dashboardApi(async () => ({ items: [] })),
    getPacketFeatureLogs: async () => ({ items }),
  });
  assert.equal(packetQualityBadge(app).label, "확인 불가");
  assert.notEqual(packetQualityBadge(app).status, "normal");
  for (const row of [{ capture_eligible: false }, { segment_status: "FAILED", capture_eligible: true }]) {
    items = [row];
    await app.advance(10_000);
    assert.equal(packetQualityBadge(app).label, "수집 품질 저하");
    assert.equal(packetQualityBadge(app).status, "degraded");
  }
  app.cleanup();
});


function trustRows(total, deviceId = sensor.device_id) {
  return Array.from({ length: total }, (_, index) => ({
    id: total - index, device_id: deviceId, previous_score: 80, new_score: 60,
    actual_delta: -20, calculated_delta: -20, capped_delta: -20,
    representative_event_ids: [total - index], policy_version: `history-${total - index}`,
  }));
}
function trustPager(app) {
  return app.find((node) => node.type === "Pagination" && node.props.ariaLabel === "신뢰점수 이력 페이지 이동");
}
function trustItems(app) {
  return app.nodes().filter((node) => node.type === "article" && node.props.className === "history-item");
}
function historyServer(total) {
  const server = deviceServer(createClock());
  const calls = [];
  const otherCalls = [];
  for (const name of ["getDeviceDetail", "getDevicePolicy", "getFirewallRules"]) {
    const original = server.api[name];
    server.api[name] = (...args) => { otherCalls.push(name); return original(...args); };
  }
  server.api.getTrustScoreHistory = async (deviceId, params, options) => {
    calls.push({ deviceId, ...params, signal: options?.signal });
    return { device_id: deviceId, items: trustRows(total, deviceId).slice(params.offset, params.offset + params.limit), total };
  };
  return { ...server, calls, otherCalls };
}

test("trust history uses server pages of five and preserves policy inputs without detail refetches", async () => {
  const server = historyServer(12);
  const app = await componentHarness("Devices", server.api);
  try {
    await openSensor(app);
    assert.equal(server.calls[0].limit, 5);
    assert.equal(trustItems(app).length, 5);
    assert.equal(trustPager(app).props.total, 12);
    assert.equal(trustPager(app).props.totalPages, 3);
    await app.change("rule-key", "retain-key");
    await app.change("rule-payload_size_max", "6200");
    await app.change("rule-reason", "retain unsaved reason");
    const otherCalls = server.otherCalls.length;
    await app.act(() => trustPager(app).props.onPageChange(2));
    assert.equal(trustItems(app).length, 5);
    assert.equal(trustPager(app).props.currentPage, 2);
    await app.act(() => trustPager(app).props.onNext());
    assert.equal(trustItems(app).length, 2);
    assert.equal(trustPager(app).props.currentPage, 3);
    assert.deepEqual(server.calls.map(({ limit, offset }) => [limit, offset]), [[5, 0], [5, 5], [5, 10]]);
    assert.equal(server.otherCalls.length, otherCalls);
    assert.equal(app.input("rule-key").props.value, "retain-key");
    assert.equal(app.input("rule-payload_size_max").props.value, "6200");
    assert.equal(app.input("rule-reason").props.value, "retain unsaved reason");
    await app.act(() => selectedDetail(app).props.onClose());
    await openSensor(app);
    assert.equal(server.calls.at(-1).offset, 0);
    assert.equal(trustPager(app).props.currentPage, 1);
  } finally { app.cleanup(); }
});

test("trust history reaches beyond fifty records and retries only the failed page without stale rows", async () => {
  const server = historyServer(57);
  const original = server.api.getTrustScoreHistory;
  let fail = true;
  server.api.getTrustScoreHistory = async (...args) => {
    const result = await original(...args);
    if (args[1].offset === 55 && fail) { fail = false; throw new Error("history page unavailable"); }
    return result;
  };
  const app = await componentHarness("Devices", server.api);
  try {
    await openSensor(app);
    await app.change("rule-key", "retain-on-retry");
    const otherCalls = server.otherCalls.length;
    await app.act(() => trustPager(app).props.onPageChange(12));
    assert.equal(trustItems(app).length, 0, "failed page must not display previous page rows");
    const error = app.find((node) => node.type === "ErrorState" && node.props.message === "history page unavailable");
    await app.act(() => error.props.onRetry());
    assert.equal(trustItems(app).length, 2);
    assert.equal(trustPager(app).props.total, 57);
    assert.equal(trustPager(app).props.currentPage, 12);
    assert.deepEqual(server.calls.map(({ offset }) => offset), [0, 55, 55]);
    assert.equal(server.otherCalls.length, otherCalls);
    assert.equal(app.input("rule-key").props.value, "retain-on-retry");
  } finally { app.cleanup(); }
});

test("trust history cancels a pending page on close and discards it after another device opens", async () => {
  const server = historyServer(12);
  const second = { ...sensor, device_id: "sensor_B" };
  server.api.getDevices = async () => ({ items: [sensor, second], total: 2 });
  server.api.getDeviceDetail = async (id) => id === second.device_id ? second : sensor;
  const stale = deferred();
  const original = server.api.getTrustScoreHistory;
  server.api.getTrustScoreHistory = async (...args) => {
    const result = await original(...args);
    return args[0] === sensor.device_id && args[1].offset === 5 ? stale.promise : result;
  };
  const app = await componentHarness("Devices", server.api);
  try {
    await openSensor(app);
    await app.act(() => trustPager(app).props.onPageChange(2));
    assert.equal(trustItems(app).length, 0, "pending page cannot relabel old rows");
    const oldRequest = server.calls.at(-1);
    await app.act(() => selectedDetail(app).props.onClose());
    assert.equal(oldRequest.signal.aborted, true);
    await openDevice(app, second.device_id);
    stale.resolve({ device_id: sensor.device_id, items: trustRows(5), total: 999 });
    await app.settle();
    assert.equal(trustPager(app).props.total, 12);
    assert.equal(trustPager(app).props.currentPage, 1);
    assert.equal(trustItems(app).length, 5);
    assert.equal(selectedDetail(app).props.title, "sensor_B 상세 상태");
  } finally { app.cleanup(); }
});

test("trust history ignores a late previous page for the same device", async () => {
  const server = historyServer(12);
  const stale = deferred();
  const original = server.api.getTrustScoreHistory;
  server.api.getTrustScoreHistory = async (...args) => {
    const result = await original(...args);
    return args[1].offset === 5 ? stale.promise : result;
  };
  const app = await componentHarness("Devices", server.api);
  try {
    await openSensor(app);
    const changePage = trustPager(app).props.onPageChange;
    await app.act(() => changePage(2));
    const previousRequest = server.calls.at(-1);
    await app.act(() => changePage(3));
    assert.equal(previousRequest.signal.aborted, true);
    assert.equal(trustPager(app).props.currentPage, 3);
    assert.equal(trustItems(app).length, 2);
    stale.resolve({ device_id: sensor.device_id, items: trustRows(5), total: 999 });
    await app.settle();
    assert.equal(trustPager(app).props.currentPage, 3);
    assert.equal(trustPager(app).props.total, 12);
    assert.equal(trustItems(app).length, 2);
  } finally { app.cleanup(); }
});

test("trust history empty response shows no pager and rejects a mismatched device payload", async () => {
  const server = historyServer(0);
  const app = await componentHarness("Devices", server.api);
  try {
    await openSensor(app);
    assert.equal(trustItems(app).length, 0);
    assert.equal(app.nodes().some((node) => node.type === "Pagination" && node.props.ariaLabel === "신뢰점수 이력 페이지 이동"), false);
    assert.ok(app.nodes().some((node) => node.type === "EmptyState" && node.props.title === "신뢰점수 변화 이력이 없습니다."));
    await app.act(() => selectedDetail(app).props.onClose());
    server.api.getTrustScoreHistory = async () => ({ device_id: "another-device", items: trustRows(1), total: 1 });
    // The harness captures API bindings, so reopen with a separate component for changed transport.
  } finally { app.cleanup(); }
  const mismatched = await componentHarness("Devices", server.api);
  try {
    await openSensor(mismatched);
    assert.equal(trustItems(mismatched).length, 0);
    assert.ok(mismatched.nodes().some((node) => node.type === "ErrorState" && node.props.message.includes("이력")));
  } finally { mismatched.cleanup(); }
});

async function paginationTree(props) {
  const { code } = await pageCode("Pagination", "components");
  const scope = { jsx: (type, properties, ...children) => ({ type, props: properties || {}, children }) };
  runInNewContext(code, scope);
  return scope.Component(props);
}
function treeNodes(root) {
  if (Array.isArray(root)) return root.flatMap(treeNodes);
  if (!root || typeof root !== "object") return [];
  return [root, ...treeNodes(root.children)];
}

test("numbered pagination renders a bounded window, current-page semantics, and unchanged default controls", async () => {
  const visited = [];
  const props = { currentPage: 12, totalPages: 12, total: 57, pageSize: 5,
    onPrevious() {}, onNext() {}, onPageChange: (page) => visited.push(page), ariaLabel: "신뢰점수 이력 페이지 이동" };
  const root = await paginationTree(props);
  assert.equal(root.props["aria-label"], props.ariaLabel);
  const numbers = treeNodes(root).filter((node) => node.type === "button" && node.props["aria-label"]?.endsWith("페이지"));
  assert.deepEqual(Array.from(numbers, (node) => Number(node.children[0])), [8, 9, 10, 11, 12]);
  assert.equal(numbers.at(-1).props["aria-current"], "page");
  numbers[0].props.onClick();
  assert.deepEqual(visited, [8]);
  const defaultRoot = await paginationTree({ ...props, currentPage: 1, onPageChange: undefined, ariaLabel: undefined });
  const defaultButtons = treeNodes(defaultRoot).filter((node) => node.type === "button");
  assert.equal(defaultRoot.props["aria-label"], "페이지 이동");
  assert.equal(defaultButtons.length, 2);
  assert.equal(defaultButtons[0].props.disabled, true);
  assert.equal(defaultButtons[1].props.disabled, false);
  const disabledRoot = await paginationTree({ ...props, disabled: true });
  assert.ok(treeNodes(disabledRoot).filter((node) => node.type === "button").every((node) => node.props.disabled));
});


test("trust history settles after same-device first-page detail error retry", async () => {
  const server = historyServer(12);
  let failDetail = true;
  server.api.getDeviceDetail = async () => {
    if (failDetail) { failDetail = false; throw new Error("temporary detail outage"); }
    return sensor;
  };
  const app = await componentHarness("Devices", server.api);
  try {
    await openSensor(app);
    assert.equal(trustItems(app).length, 5);
    assert.equal(server.calls.length, 1);
    const error = app.find((node) => node.type === "ErrorState" && node.props.message === "temporary detail outage");
    await app.act(() => error.props.onRetry());
    assert.equal(trustItems(app).length, 5, "detail retry must finish reloading the first history page");
    assert.equal(server.calls.length, 2);
    assert.deepEqual(server.calls.map(({ limit, offset }) => [limit, offset]), [[5, 0], [5, 0]]);
    assert.equal(trustPager(app).props.currentPage, 1);
    assert.equal(app.nodes().some((node) => node.type === "LoadingState" && node.props.title === "Trust 이력 조회 중"), false);
    assert.equal(app.nodes().some((node) => node.type === "ErrorState" && node.props.message === "temporary detail outage"), false);
  } finally { app.cleanup(); }
});
