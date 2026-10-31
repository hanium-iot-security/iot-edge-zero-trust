import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import test from "node:test";

// Reuse the existing actual-page renderer and fake clock without changing its
// test file or copying its implementation. Only API response timing is adapted.
const harnessUrl = new URL("./recoveryWorkflow.test.js", import.meta.url);
let harness = await readFile(harnessUrl, "utf8");
const boundary = harness.indexOf('test("ordinary recovery');
assert.ok(boundary > 0, "existing workflow harness boundary must be present");
harness = harness.slice(0, boundary);
function adapt(before, after) {
  assert.equal(harness.split(before).length, 2, "fixture adaptation must match exactly once");
  harness = harness.replace(before, after);
}
adapt('recoveryEvidence = {', 'historyResponder = null, preflightResponder = null, recoveryEvidence = {');
adapt('async getRecoveryHistory(params, key) { remember("history", { params, key });',
  'async getRecoveryHistory(params, key, options) { remember("history", { params, key }); if (historyResponder) return historyResponder(params, key, options);');
adapt('remember("preflight", { body, key });',
  'remember("preflight", { body, key }); if (preflightResponder) return preflightResponder(body, key);');
harness = harness.replaceAll('new URL("./Isolation.jsx", import.meta.url)',
  'new URL(' + JSON.stringify(new URL("./Isolation.jsx", import.meta.url).href) + ')');
harness = harness.replace(/from "(\.\.\/[^"]+)"/g,
  (_, path) => "from " + JSON.stringify(new URL(path, harnessUrl).href));
harness = harness.replace('from "vite"',
  "from " + JSON.stringify(pathToFileURL(createRequire(import.meta.url).resolve("vite")).href));
harness += "\nexport { opened, releaseAll };";
const { opened, releaseAll } = await import("data:text/javascript;base64," + Buffer.from(harness).toString("base64"));

function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
function history(operationId) {
  return { items: [{ operation_id: operationId, device_id: "esp32_02", result: "SUCCESS" }], total: 1 };
}
async function historyRace() {
  const requests = [];
  const app = await opened({ historyResponder: (params, key, options) => {
    const request = { ...deferred(), key, options };
    requests.push(request);
    return request.promise; // Deliberately allow completion even after cancellation.
  } });
  await app.change("recovery-admin-key", "old-fixture-key");
  await app.tick(300);
  assert.equal(requests.length, 1);
  return { app, requests };
}
async function replaceKey(app) {
  await app.change("recovery-admin-key", "new-fixture-key");
  await app.tick(300);
}
const loadingHistory = (app) => app.text().includes("복구 이력을 불러오는 중입니다.");

for (const outcome of ["success", "error"]) {
  test(`history ignores old ${outcome} after a newer key succeeds`, async () => {
    const { app, requests } = await historyRace();
    await replaceKey(app);
    requests[1].resolve(history("CURRENT-HISTORY"));
    await app.settle();
    if (outcome === "success") requests[0].resolve(history("STALE-HISTORY"));
    else requests[0].reject(new Error("STALE-AUTH-ERROR"));
    await app.settle();
    assert.ok(app.text().includes("CURRENT-HISTORY"));
    assert.ok(!app.text().includes("STALE-HISTORY"));
    assert.ok(!app.text().includes("STALE-AUTH-ERROR"));
  });

  test(`clearing the key rejects delayed history ${outcome}`, async () => {
    const { app, requests } = await historyRace();
    await app.change("recovery-admin-key", "");
    if (outcome === "success") requests[0].resolve(history("STALE-HISTORY"));
    else requests[0].reject(new Error("STALE-AUTH-ERROR"));
    await app.settle();
    assert.equal(app.input("recovery-admin-key").props.value, "");
    assert.ok(!app.text().includes("STALE-HISTORY"));
    assert.ok(!app.text().includes("STALE-AUTH-ERROR"));
    assert.equal(loadingHistory(app), false);
  });
}

test("old request completion cannot hide a newer history loading state", async () => {
  const { app, requests } = await historyRace();
  await replaceKey(app);
  requests[0].resolve(history("STALE-HISTORY"));
  await app.settle();
  assert.equal(loadingHistory(app), true);
  requests[1].resolve(history("CURRENT-HISTORY"));
  await app.settle();
  assert.equal(loadingHistory(app), false);
  assert.ok(app.text().includes("CURRENT-HISTORY"));
});

test("clearing a key immediately clears history loading and cancels its request", async () => {
  const { app, requests } = await historyRace();
  assert.equal(loadingHistory(app), true);
  await app.change("recovery-admin-key", "");
  assert.equal(loadingHistory(app), false);
  assert.equal(requests[0].options?.signal?.aborted, true);
  requests[0].resolve(history("STALE-HISTORY"));
  await app.settle();
});

test("closing and reopening a modal rejects the previous history response", async () => {
  const { app, requests } = await historyRace();
  app.modal().props.onClose();
  await app.settle();
  await app.open();
  requests[0].resolve(history("CLOSED-MODAL-HISTORY"));
  await app.settle();
  assert.equal(app.input("recovery-admin-key").props.value, "");
  assert.ok(!app.text().includes("CLOSED-MODAL-HISTORY"));
  assert.equal(loadingHistory(app), false);
});

async function ready() {
  const app = await opened();
  await releaseAll(app);
  await app.click("사전 점검 실행");
  await app.change("recovery-reason", "controlled fixture recovery");
  await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
  return app;
}

test("an unchanged poll preserves a successful preflight", async () => {
  const app = await ready();
  await app.tick(10000);
  assert.equal(app.button("복구 실행").props.disabled, false);
  assert.equal(app.calls.filter((call) => call.kind === "preflight").length, 1);
});

test("a changed score requires a new preflight and sends the refreshed score", async () => {
  const app = await ready();
  app.device.trust_score = 19;
  await app.tick(10000);
  assert.equal(app.button("복구 실행").props.disabled, true);
  await app.button("복구 실행").props.onClick();
  await app.settle();
  assert.equal(app.calls.filter((call) => call.kind === "execute").length, 0);
  await app.click("사전 점검 실행");
  await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
  await app.click("복구 실행");
  assert.equal(app.calls.find((call) => call.kind === "execute").body.expected_trust_score, 19);
});

test("a changed firewall state cannot revive old preflight when it returns to REMOVED", async () => {
  const app = await ready();
  app.rules[1].status = "APPLIED";
  await app.tick(10000);
  assert.equal(app.button("복구 실행").props.disabled, true);
  app.rules[1].status = "REMOVED";
  await app.tick(10000);
  assert.equal(app.button("복구 실행").props.disabled, true);
});

test("changing the checked device address invalidates runtime preflight", async () => {
  const app = await ready();
  app.device.ip_address = "192.168.0.77";
  await app.tick(10000);
  assert.equal(app.button("복구 실행").props.disabled, true);
});

test("a preflight response cannot authorize a state changed during its request", async () => {
  const pending = deferred();
  const app = await opened({ preflightResponder: () => pending.promise });
  await releaseAll(app);
  const click = app.click("사전 점검 실행");
  await app.settle();
  app.device.trust_score = 19;
  await app.tick(10000);
  pending.resolve({ device_id: "esp32_02", current_status: "isolated", current_trust_score: 20,
    can_execute: true, result: "SUCCESS", firewall_runtime_verification: { status: "VERIFIED_RELEASED" } });
  await click;
  assert.equal(app.button("복구 실행").props.disabled, true);
});

for (const [label, change] of [
  ["external recovery removes the selected device from isolation", (app) => {
    app.device.status = "normal";
    app.device.trust_score = 100;
  }],
  ["the isolation response no longer contains the selected device ID", (app) => {
    app.device.device_id = "another-isolated-device";
  }],
]) {
  test(label + " invalidates its previous preflight", async () => {
    const app = await ready();
    change(app);
    await app.tick(10000);
    assert.equal(app.button("복구 실행").props.disabled, true);
    assert.equal(app.button("사전 점검 실행").props.disabled, true);
    const preflightCount = app.calls.filter((call) => call.kind === "preflight").length;
    await app.button("사전 점검 실행").props.onClick();
    await app.settle();
    assert.equal(app.calls.filter((call) => call.kind === "preflight").length, preflightCount);
    await app.button("복구 실행").props.onClick();
    await app.settle();
    assert.equal(app.calls.filter((call) => call.kind === "execute").length, 0);
  });
}

test("a delayed preflight cannot survive the selected device disappearing and returning", async () => {
  const pending = deferred();
  const app = await opened({ preflightResponder: () => pending.promise });
  await releaseAll(app);
  const click = app.click("사전 점검 실행");
  await app.settle();
  app.device.status = "normal";
  await app.tick(10000);
  app.device.status = "isolated";
  await app.tick(10000);
  pending.resolve({ device_id: "esp32_02", current_status: "isolated", current_trust_score: 20,
    can_execute: true, result: "SUCCESS", firewall_runtime_verification: { status: "VERIFIED_RELEASED" } });
  await click;
  assert.equal(app.button("복구 실행").props.disabled, true);
  assert.equal(app.button("사전 점검 실행").props.disabled, false);
});

test("unchanged absent-device polling preserves the delayed preflight explanation", async () => {
  const pending = deferred();
  const app = await opened({ preflightResponder: () => pending.promise });
  await releaseAll(app);
  const click = app.click("사전 점검 실행");
  await app.settle();
  app.device.status = "normal";
  await app.tick(10000);
  pending.resolve({ device_id: "esp32_02", current_status: "isolated", current_trust_score: 20,
    can_execute: true, result: "SUCCESS", firewall_runtime_verification: { status: "VERIFIED_RELEASED" } });
  await click;
  const explanation = "기기 상태가 변경되어 사전 점검을 다시 실행해 주세요.";
  assert.ok(app.text().includes(explanation));
  await app.tick(10000);
  assert.ok(app.text().includes(explanation));
  assert.equal(app.button("사전 점검 실행").props.disabled, true);
  assert.equal(app.button("복구 실행").props.disabled, true);
});
