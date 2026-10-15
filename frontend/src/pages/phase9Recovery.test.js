import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { transformWithOxc } from "vite";

const stripImports = (source) => source.replace(/^import\b[\s\S]*?;\r?\n/gm, "");
const [pageSource, apiSource] = await Promise.all([
  readFile(new URL("./Isolation.jsx", import.meta.url), "utf8"),
  readFile(new URL("../api/api.js", import.meta.url), "utf8"),
]);
const page = await transformWithOxc(stripImports(pageSource), "Isolation.jsx", {
  jsx: { runtime: "classic", pragma: "jsx", pragmaFrag: "Fragment" },
  define: { "import.meta.env": "{}" },
});
const api = await transformWithOxc(stripImports(apiSource), "api.js", {
  define: { "import.meta.env": "{}" },
});

// Execute the production components and API helpers through a captured HTTP
// boundary. This small renderer exposes real inputs and handlers without copying
// their validation, uncertainty decisions, or request construction into tests.
function recoveryHarness(component, respond = async () => ({ status: 200, data: {} })) {
  const requests = [];
  const axios = async (request) => { requests.push(request); return respond(request); };
  axios.isCancel = () => false;
  const scope = { axios, AbortController, console, Fragment: "Fragment" };
  runInNewContext("(function () {" + api.code.replace(/\bexport\s*\{[^}]*\};?/g, "").replace(/\bexport\s+/g, "") +
    "\nglobalThis.recoveryApi = { createFirewallScopeExtensionRequest, createPacketPairRecoveryPlan, getPacketPairRecoveryPlan, verifyPacketPairRecoveryPlan }; })();", scope);
  const slots = [];
  let cursor = 0;
  let dirty = false;
  let tree;
  Object.assign(scope, scope.recoveryApi, {
    useState(initial) {
      const index = cursor++;
      if (!(index in slots)) slots[index] = initial;
      return [slots[index], (value) => {
        slots[index] = typeof value === "function" ? value(slots[index]) : value;
        dirty = true;
      }];
    },
    useRef(initial) { const index = cursor++; return slots[index] ??= { current: initial }; },
    jsx: (type, props, ...children) => ({ type, props: props || {}, children }),
  });
  runInNewContext(page.code.replace("export default function Isolation", "function Isolation") +
    `\nglobalThis.Component = ${component};`, scope);
  const render = () => { cursor = 0; dirty = false; tree = scope.Component({ rule: { id: 12 }, adminKey: "test-admin", deviceId: "sensor_01" }); };
  const walk = (node) => Array.isArray(node) ? node.flatMap(walk)
    : node && typeof node === "object" ? [node, ...walk(node.children)] : [];
  const text = (node) => Array.isArray(node) ? node.map(text).join("")
    : node && typeof node === "object" ? text(node.children) : node == null ? "" : String(node);
  const find = (predicate) => { const node = walk(tree).find(predicate); assert.ok(node, "expected recovery UI control"); return node; };
  const input = (id) => find((node) => node.props.id === id);
  const button = (label) => find((node) => node.type === "button" && text(node) === label);
  const settle = async () => { for (let i = 0; i < 30; i++) { await Promise.resolve(); if (dirty) render(); } };
  const act = async (action) => { await action(); await settle(); };
  render();
  return {
    requests, api: scope.recoveryApi, input, button, settle,
    text: () => text(tree),
    change: (id, value) => act(() => input(id).props.onChange({ target: { value } })),
    click: (label) => act(() => {
      const target = button(label);
      assert.equal(Boolean(target.props.disabled), false, `${label} must be enabled`);
      return target.props.onClick();
    }),
  };
}

async function fillScope(app, { reason = "approved expansion", confirmation = "12", json = '{"reason":"approved expansion"}' } = {}) {
  await app.change("phase9-scope-reason", reason);
  await app.change("phase9-scope-confirm", confirmation);
  await app.change("phase9-scope-json", json);
}

for (const [name, invalid] of [
  ["missing reason", { reason: "" }],
  ["wrong confirmation", { confirmation: "13" }],
  ["malformed JSON", { json: "{" }],
]) {
  test(`Scope Extension ${name} stays editable and corrected input sends once`, async () => {
    const app = recoveryHarness("Phase9ScopeExtension");
    await fillScope(app, invalid);
    await app.click("Scope Extension 요청");
    assert.equal(app.requests.length, 0, "local validation must not send HTTP");
    assert.equal(app.input("phase9-scope-json").props.disabled, false);
    assert.equal(app.text().includes("결과가 불확실"), false);
    await fillScope(app);
    await app.click("Scope Extension 요청");
    assert.equal(app.requests.length, 1);
    assert.equal(app.requests[0].headers["X-Recovery-Admin-Key"], "test-admin");
    assert.equal(app.requests[0].data.reason, "approved expansion");
  });
}

test("Scope Extension uncertain POST keeps its write lock after request completion", async () => {
  const app = recoveryHarness("Phase9ScopeExtension", async () => {
    throw Object.assign(new Error("request timed out"), { code: "ETIMEDOUT" });
  });
  await fillScope(app);
  await app.click("Scope Extension 요청");
  assert.equal(app.requests.length, 1);
  assert.equal(app.input("phase9-scope-json").props.disabled, true);
  assert.equal(app.button("Scope Extension 요청").props.disabled, true);
  await app.button("Scope Extension 요청").props.onClick();
  await app.settle();
  assert.equal(app.requests.length, 1, "handler also guards against a duplicate write");
});
test("Packet Pair malformed JSON can be corrected without remounting", async () => {
  const app = recoveryHarness("Phase9PacketPairRecovery");
  await app.change("phase9-plan-create", "{");
  await app.click("Plan 생성");
  assert.equal(app.requests.length, 0);
  assert.equal(app.input("phase9-plan-create").props.disabled, false);
  await app.change("phase9-plan-create", '{"source_session_id":1,"target_session_id":2,"reason":"approved recovery"}');
  await app.click("Plan 생성");
  assert.equal(app.requests.length, 1);
});

test("Packet Pair uncertain POST blocks another write but permits authoritative GET", async () => {
  const app = recoveryHarness("Phase9PacketPairRecovery", async (request) => {
    if (request.method === "POST") throw Object.assign(new Error("connection lost"), { code: "ERR_NETWORK" });
    return { status: 200, data: { plan_id: "plan-01", status: "UNKNOWN" } };
  });
  await app.change("phase9-plan-id", "plan-01");
  await app.click("Plan Verify 요청");
  assert.equal(app.requests.length, 1);
  assert.equal(app.button("Plan Verify 요청").props.disabled, true);
  assert.equal(app.button("Plan 생성").props.disabled, true);
  await app.click("Plan 상태 재조회");
  assert.equal(app.requests.length, 2, "uncertainty must not suppress the GET handler");
  assert.equal(app.requests[1].method, "GET");
  assert.equal(app.requests[1].url.endsWith("/packet-pair/plan-01"), true);
  assert.equal(app.button("Plan Verify 요청").props.disabled, true, "read response alone must not unlock duplicate writes");
});

test("Packet Pair HTTP rejection remains correctable instead of uncertain", async () => {
  const app = recoveryHarness("Phase9PacketPairRecovery", async () => {
    throw Object.assign(new Error("forbidden"), { response: { status: 403, data: { detail: "forbidden" } } });
  });
  await app.change("phase9-plan-id", "plan-01");
  await app.click("Plan Verify 요청");
  assert.equal(app.requests.length, 1);
  assert.equal(app.button("Plan Verify 요청").props.disabled, false);
  assert.equal(app.text().includes("결과가 불확실"), false);
});

test("Packet Pair Verify UI uses bodyless API and exact admin header", async () => {
  const app = recoveryHarness("Phase9PacketPairRecovery");
  await app.change("phase9-plan-id", "plan-01");
  await app.click("Plan Verify 요청");
  assert.equal(app.requests.length, 1);
  assert.equal(app.requests[0].method, "POST");
  assert.equal(app.requests[0].headers["X-Recovery-Admin-Key"], "test-admin");
  assert.equal(app.requests[0].data, undefined, "Verify endpoint has no request body");
  assert.equal(app.text().includes("Verify 본문 JSON"), false);
});

test("Packet Pair Verify helper keeps cancellation and timeout in request options", async () => {
  const app = recoveryHarness("Phase9PacketPairRecovery");
  const controller = new AbortController();
  await app.api.verifyPacketPairRecoveryPlan("plan/01", "test-admin", { signal: controller.signal, timeout: 4321 });
  assert.equal(app.requests[0].url.endsWith("/packet-pair/plan%2F01/verify"), true);
  assert.equal(app.requests[0].headers["X-Recovery-Admin-Key"], "test-admin");
  assert.equal(app.requests[0].data, undefined);
  assert.equal(app.requests[0].signal, controller.signal);
  assert.equal(app.requests[0].timeout, 4321);
});
