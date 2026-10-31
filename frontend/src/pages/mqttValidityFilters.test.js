import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import test from "node:test";

// Reuse the existing production-page renderer and clock; no copied hook runtime.
const harnessUrl = new URL("./devicePolicyPolling.test.js", import.meta.url);
let harness = await readFile(harnessUrl, "utf8");
const boundary = harness.indexOf("\nconst sensor =");
assert.ok(boundary > 0, "existing component harness boundary must be present");
harness = harness.slice(0, boundary);
// Logs has a semicolon-free style import. Remove that import before the existing
// renderer's normal import stripping, without consuming its next JS declaration.
const stripImports = 'source.replace(/^import\\b[\\s\\S]*?;\\r?\\n/gm, "")';
assert.ok(harness.includes(stripImports));
harness = harness.replace(stripImports,
  'source.replace(/^import\\s+["\'][^"\']+["\'];?\\r?\\n/gm, "").replace(/^import\\b[\\s\\S]*?;\\r?\\n/gm, "")');
harness = harness.replaceAll("import.meta.url", JSON.stringify(harnessUrl.href));
const require = createRequire(import.meta.url);
harness = harness.replace(/from "([^"]+)"/g, (match, specifier) => {
  if (specifier.startsWith("node:")) return match;
  const url = specifier.startsWith(".") ? new URL(specifier, harnessUrl)
    : pathToFileURL(require.resolve(specifier));
  return "from " + JSON.stringify(url.href);
});
harness += "\nexport { componentHarness };";
const { componentHarness } = await import("data:text/javascript;base64," + Buffer.from(harness).toString("base64"));

const unsupported = "현재 연결된 서버가 JSON·토픽 유효성 필터를 지원하지 않습니다. 서버 API를 업데이트한 뒤 다시 조회해 주세요.";
const normal = { id: 1, device_id: "fixture-device", topic: "fixture/data", payload: "{}", is_json_valid: true, is_topic_valid: true };
const invalid = { ...normal, id: 2, payload: "invalid-json", is_json_valid: false };
const table = (app) => app.find((node) => node.type === "DataTable" && node.props.tableLabel === "MQTT 로그 목록");
const summary = (app) => app.nodes().filter((node) => node.type === "SummaryCard");
const pagination = (app) => app.nodes().find((node) => node.type === "Pagination");
const legacy = () => ({ items: [normal], total: 41 });
const metadata = (json = null, topic = null, validOnly = false) => ({ is_json_valid: json, is_topic_valid: topic, valid_only: validOnly });
function response(applied, items = [invalid], total = 21) {
  return { items, total, ...(applied === undefined ? {} : { applied_validity_filters: applied }) };
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}

test("unfiltered legacy servers remain usable and keep the server total", async () => {
  const app = await componentHarness("Logs", { getMqttLogs: async () => legacy() });
  try {
    assert.equal(table(app).props.error, "");
    assert.deepEqual(Array.from(table(app).props.rows, (row) => row.id), [1]);
    assert.equal(pagination(app).props.total, 41);
  } finally { app.cleanup(); }
});

for (const filter of ["json-validity-filter", "topic-validity-filter"]) {
  for (const value of ["valid", "invalid"]) {
    test(`${filter} ${value} rejects a legacy response and clears old unfiltered rows/counts`, async () => {
      const queries = [];
      const app = await componentHarness("Logs", { getMqttLogs: async (params) => { queries.push(params); return legacy(); } });
      try {
        await app.change(filter, value);
        const flag = filter.startsWith("json") ? "is_json_valid" : "is_topic_valid";
        assert.equal(queries.at(-1)[flag], value === "valid");
        assert.equal(table(app).props.error, unsupported);
        assert.equal(table(app).props.rows.length, 0);
        assert.equal(summary(app).length, 0);
        assert.equal(pagination(app), undefined);
        assert.equal(app.nodes().some((node) => node.props.className === "page-warning-banner"), false);
      } finally { app.cleanup(); }
    });
  }
}

test("false JSON flags, combined filters and pagination use exact server metadata and total", async () => {
  const queries = [];
  const replies = [legacy(), response(metadata(false)), response(metadata(false, true)), response(metadata(false, true), [], 21)];
  const app = await componentHarness("Logs", { getMqttLogs: async (params) => { queries.push(params); return replies.shift(); } });
  try {
    await app.change("json-validity-filter", "invalid");
    assert.equal(queries.at(-1).is_json_valid, false);
    assert.equal(table(app).props.error, "");
    assert.equal(table(app).props.rows[0].id, 2);
    assert.equal(pagination(app).props.total, 21, "server count must not become current-page row count");
    await app.change("topic-validity-filter", "valid");
    assert.equal(queries.at(-1).is_json_valid, false);
    assert.equal(queries.at(-1).is_topic_valid, true);
    await app.act(() => pagination(app).props.onNext());
    assert.equal(queries.at(-1).offset, 20);
    assert.equal(queries.at(-1).is_json_valid, false);
    assert.equal(queries.at(-1).is_topic_valid, true);
    assert.equal(table(app).props.error, "");
    assert.equal(pagination(app).props.total, 21);
  } finally { app.cleanup(); }
});

test("missing, mistyped, conflicting or extra hidden validity filters are rejected even on empty pages", async () => {
  for (const applied of [undefined, {}, metadata(true), metadata("false"), metadata(false, false), metadata(false, null, true), { is_json_valid: false, is_topic_valid: null }]) {
    let calls = 0;
    const app = await componentHarness("Logs", { getMqttLogs: async () => ++calls === 1 ? legacy() : response(applied, [], 0) });
    try {
      await app.change("json-validity-filter", "invalid");
      assert.equal(table(app).props.error, unsupported);
      assert.equal(table(app).props.rows.length, 0);
      assert.equal(pagination(app), undefined);
    } finally { app.cleanup(); }
  }
});

test("resetting unsupported filters restores the legacy unfiltered view", async () => {
  const queries = [];
  const app = await componentHarness("Logs", { getMqttLogs: async (params) => { queries.push(params); return legacy(); } });
  try {
    await app.change("json-validity-filter", "invalid");
    assert.equal(table(app).props.error, unsupported);
    await app.click("필터 초기화");
    assert.equal(Object.hasOwn(queries.at(-1), "is_json_valid"), false);
    assert.equal(Object.hasOwn(queries.at(-1), "is_topic_valid"), false);
    assert.equal(table(app).props.error, "");
    assert.equal(table(app).props.rows[0].id, 1);
    assert.equal(pagination(app).props.total, 41);
  } finally { app.cleanup(); }
});

test("a later contract mismatch clears previously verified filtered results", async () => {
  const replies = [legacy(), response(metadata(false)), response(metadata(true))];
  const app = await componentHarness("Logs", { getMqttLogs: async () => replies.shift() });
  try {
    await app.change("json-validity-filter", "invalid");
    assert.equal(table(app).props.rows[0].id, 2);
    await app.advance(10_000);
    assert.equal(table(app).props.error, unsupported);
    assert.equal(table(app).props.rows.length, 0);
    assert.equal(summary(app).length, 0);
    assert.equal(pagination(app), undefined);
  } finally { app.cleanup(); }
});

test("a transient network failure preserves the last verified same-filter results and warning", async () => {
  let calls = 0;
  const app = await componentHarness("Logs", { getMqttLogs: async () => {
    calls += 1;
    if (calls === 1) return legacy();
    if (calls === 2) return response(metadata(false));
    throw new Error("temporary fixture outage");
  } });
  try {
    await app.change("json-validity-filter", "invalid");
    await app.advance(10_000);
    assert.equal(table(app).props.error, "");
    assert.equal(table(app).props.rows[0].id, 2);
    assert.ok(app.nodes().some((node) => node.props.className === "page-warning-banner"));
  } finally { app.cleanup(); }
});

for (const staleOutcome of ["success", "error"]) {
  test(`changing validity criteria replaces a pending request and ignores its stale ${staleOutcome}`, async () => {
    const requests = [];
    const app = await componentHarness("Logs", { getMqttLogs: (params, options) => {
      const request = { ...deferred(), params, signal: options?.signal };
      requests.push(request); return request.promise;
    } });
    try {
      assert.equal(requests.length, 1);
      await app.change("json-validity-filter", "invalid");
      assert.equal(requests.length, 2, "changed criteria must start a replacement query immediately");
      assert.equal(requests[0].signal.aborted, true);
      assert.equal(requests[1].params.is_json_valid, false);
      requests[1].resolve(response(metadata(false)));
      await app.settle();
      assert.equal(table(app).props.rows[0].id, 2);
      if (staleOutcome === "success") requests[0].resolve(legacy());
      else requests[0].reject(new Error("old unfiltered request failed"));
      await app.settle();
      assert.equal(table(app).props.error, "");
      assert.equal(table(app).props.rows[0].id, 2);
      assert.equal(pagination(app).props.total, 21);
      assert.equal(app.nodes().some((node) => node.props.className === "page-warning-banner"), false);
    } finally { app.cleanup(); }
  });
}

test("stale completion cannot unlock or clear the replacement request's loading state", async () => {
  const requests = [];
  const app = await componentHarness("Logs", { getMqttLogs: (params, options) => {
    const request = { ...deferred(), params, signal: options?.signal };
    requests.push(request); return request.promise;
  } });
  try {
    await app.change("topic-validity-filter", "invalid");
    assert.equal(requests.length, 2);
    requests[0].resolve(legacy());
    await app.settle();
    assert.equal(table(app).props.loading, true);
    assert.equal(table(app).props.rows.length, 0);
    await app.advance(10_000);
    assert.equal(requests.length, 2, "same-criteria polls must not duplicate a slow replacement");
    requests[1].resolve(response(metadata(null, false), [{ ...invalid, is_topic_valid: false }]));
    await app.settle();
    assert.equal(table(app).props.loading, false);
    assert.equal(table(app).props.rows[0].is_topic_valid, false);
    await app.advance(10_000);
    assert.equal(requests.length, 3, "polling resumes after the live replacement settles");
  } finally { app.cleanup(); }
  assert.equal(requests.at(-1).signal.aborted, true, "unmount cancels pending polling");
});
