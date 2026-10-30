import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { transformWithOxc } from "vite";
import * as uiText from "../utils/uiText.js";
import * as runtimeStatus from "../utils/runtimeStatus.js";
import * as firewallRules from "../utils/firewallRuleSelection.js";

const source = await readFile(new URL("./Isolation.jsx", import.meta.url), "utf8");
const imported = [...source.matchAll(/^import\s+(?:\{([\s\S]*?)\}|(\w+))\s+from\s+["'][^"']+["'];/gm)]
  .flatMap((m) => m[1] ? m[1].split(",").map((v) => v.trim()).filter(Boolean) : [m[2]]);
const { code } = await transformWithOxc(source.replace(/^import\b[\s\S]*?;\r?\n/gm, ""), "Isolation.jsx", {
  jsx: { runtime: "classic", pragma: "jsx", pragmaFrag: "Fragment" },
  define: { "import.meta.env.DEV": "false" },
});
const walk = (node) => Array.isArray(node) ? node.flatMap(walk)
  : node && typeof node === "object" ? [node, ...walk(node.children), ...walk(node.props?.footer)] : [];
const text = (node) => Array.isArray(node) ? node.map(text).join(" ").replace(/\s+/g, " ")
  : node && typeof node === "object" ? text(node.children) : node == null || typeof node === "boolean" ? "" : String(node);
const detailValue = (node, label) => {
  const row = walk(node).find((n) => n.type === "div" && n.children.some((child) => child?.type === "dt" && text(child).trim() === label));
  assert.ok(row, `expected detail row: ${label}`);
  return text(row.children.find((child) => child?.type === "dd")).trim();
};

// Render actual page hooks and handlers; only external API/timers are fixtures.
function workflow({ runtimeStatus: runtime = "VERIFIED_RELEASED", uncertainExecute = false, executeError = null, executeCommitted = true, detailFailure = false, truncatedRules = false, unknownRuleTotal, wrongDeviceDetail = false,
  auditCheck = { available: true, storage: "database", failure_reason: null }, legacyPreflight = false,
  backupCheck = { required: false, available: null, status: "NOT_REQUIRED" }, priorRecoveries = [],
  recoveryEvidence = { audit_reference: "device_recovery_audits:recovery-01", backup_reference: null, backup_sha256: null } } = {}) {
  const slots = [], effects = new Set(), timers = new Map(), calls = [];
  let cursor = 0, dirty = false, tree, nextTimer = 1;
  const device = { device_id: "esp32_02", ip_address: "192.168.0.5", status: "isolated", trust_score: 20 };
  const rules = [11, 12].map((id) => ({ id, device_id: device.device_id, source_ip: device.ip_address,
    scope: id === 12 ? "PI_INPUT_IPV4_ALL" : "MQTT_IPV4_TCP_1883", status: "APPLIED", action: "DROP",
    created_at: `2026-10-26T01:00:${id}Z`, updated_at: `2026-10-26T01:00:${id}Z` }));
  const releases = new Map();
  const history = [...priorRecoveries];
  const remember = (kind, value) => { calls.push({ kind, ...value }); };
  const api = {
    async getIsolationHistory() { return { items: [], total: 0 }; },
    async getIsolatedDevices() { return { items: device.status === "isolated" ? [{ ...device }] : [], total: device.status === "isolated" ? 1 : 0 }; },
    async getFirewallRules() { remember("rules", {}); return { items: device.status === "normal" && unknownRuleTotal !== undefined ? [] : rules.map((r) => ({ ...r })), total: device.status === "normal" && unknownRuleTotal !== undefined ? unknownRuleTotal : truncatedRules && device.status === "normal" ? rules.length + 1 : rules.length }; },
    async getDeviceDetail() { remember("detail", {}); if (detailFailure) throw new Error("detail unavailable"); return { ...device, device_id: wrongDeviceDetail ? "other_sensor" : device.device_id }; },
    async getRecoveryHistory(params, key) { remember("history", { params, key }); return { items: [...history], total: history.length }; },
    async createFirewallReleaseRequest(ruleId, body) {
      remember("release", { ruleId, body });
      const request = { id: 100 + ruleId, firewall_rule_id: ruleId, device_id: device.device_id, status: "PENDING" };
      releases.set(request.id, request); return { ...request };
    },
    async getFirewallReleaseRequest(id) {
      const request = releases.get(id); request.status = "SUCCEEDED";
      rules.find((r) => r.id === request.firewall_rule_id).status = "REMOVED";
      return { ...request };
    },
    async recoveryPreflight(body, key) {
      remember("preflight", { body, key });
      return { device_id: device.device_id, current_status: device.status, current_trust_score: device.trust_score,
        can_execute: true, result: "SUCCESS", firewall_runtime_verification: { available: true, passed: runtime === "VERIFIED_RELEASED", status: runtime },
        firewall_db_state: { passed: true, count: 0 }, firewall_release_request_state: { passed: true, count: 0 },
        ...(legacyPreflight ? {} : { audit_check: auditCheck }), backup_check: backupCheck };
    },
    async executeRecovery(body, key) {
      remember("execute", { body, key });
      if (executeError && !executeCommitted) throw executeError;
      device.status = "normal"; device.trust_score = 100;
      const item = { operation_id: "recovery-01", device_id: device.device_id, result: "SUCCESS", before_status: "isolated",
        before_trust_score: 20, after_status: "normal", after_trust_score: 100, firewall_release_status: "VERIFIED_RELEASED", ...recoveryEvidence };
      history.push(item);
      if (uncertainExecute) throw Object.assign(new Error("network lost"), { code: "ERR_NETWORK" });
      if (executeError) throw executeError;
      return item;
    },
  };
  const same = (a, b) => Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((x, i) => Object.is(x, b[i]));
  const scope = { ...Object.fromEntries(imported.map((v) => [v, v])), ...uiText, ...runtimeStatus, ...firewallRules, ...api,
    console, Date, Error, AbortController, Fragment: "Fragment",
    window: {
      setInterval(fn, ms) { const id = nextTimer++; timers.set(id, { fn, ms }); return id; },
      clearInterval(id) { timers.delete(id); },
      setTimeout(fn, ms) { const id = nextTimer++; timers.set(id, { fn, ms, once: true }); return id; },
      clearTimeout(id) { timers.delete(id); },
    },
    useState(initial) {
      const index = cursor++;
      if (!(index in slots)) slots[index] = { value: typeof initial === "function" ? initial() : initial };
      return [slots[index].value, (value) => { const next = typeof value === "function" ? value(slots[index].value) : value;
        if (!Object.is(next, slots[index].value)) { slots[index].value = next; dirty = true; } }];
    },
    useRef(initial) { const index = cursor++; return slots[index] ??= { current: initial }; },
    useMemo(fn, deps) { const index = cursor++; if (!slots[index] || !same(slots[index].deps, deps)) slots[index] = { deps, value: fn() }; return slots[index].value; },
    useCallback(fn, deps) { return scope.useMemo(() => fn, deps); },
    useEffect(fn, deps) { const index = cursor++; const prior = slots[index]; if (!prior || !same(prior.deps, deps)) {
      prior?.cleanup?.(); slots[index] = { deps, fn }; effects.add(index); } },
    jsx: (type, props, ...children) => ({ type, props: props || {}, children }),
  };
  runInNewContext(code.replace("export default function Isolation", "function Isolation").replace(/\bexport\s*\{[^}]*\};?/g, "") + "\nglobalThis.Page = Isolation;", scope);
  const render = () => { cursor = 0; dirty = false; tree = scope.Page(); };
  const settle = async () => {
    for (let i = 0; i < 60; i++) {
      if (dirty) render();
      for (const index of [...effects]) { effects.delete(index); slots[index].cleanup = slots[index].fn(); }
      await new Promise((resolve) => setImmediate(resolve));
      if (!dirty && effects.size === 0) return;
    }
    throw new Error("page did not settle");
  };
  const nodes = () => walk(tree);
  const find = (predicate) => { const result = nodes().find(predicate); assert.ok(result, "expected page control"); return result; };
  const input = (id) => find((n) => n.props.id === id);
  const button = (label) => find((n) => n.type === "button" && text(n).trim() === label);
  const act = async (fn) => { await fn(); await settle(); };
  render();
  return { calls, device, rules, nodes, input, button, settle, text: () => text(tree),
    modal: () => find((n) => n.type === "DetailModal" && n.props.open && n.props.title.includes("복구")),
    open: () => act(() => find((n) => n.type === "DataTable" && n.props.tableLabel === "현재 격리된 기기").props.onRowClick({ ...device, firewall_rule: rules[1], firewall_status: rules[1].status })),
    change: (id, value) => act(() => input(id).props.onChange({ target: { value } })),
    click: (label) => act(() => { const n = button(label); assert.equal(Boolean(n.props.disabled), false, `${label} must be enabled`); return n.props.onClick(); }),
    tick: (ms) => act(async () => { for (const [id, timer] of [...timers]) if (timer.ms === ms) { if (timer.once) timers.delete(id); await timer.fn(); } }),
  };
}

async function opened(options) { const app = workflow(options); await app.settle(); await app.open(); return app; }
async function releaseAll(app) {
  await app.change("recovery-admin-key", "test-admin");
  await app.change("firewall-release-reason", "controlled recovery");
  assert.equal(app.button("사전 점검 실행").props.disabled, true);
  for (const id of [12, 11]) {
    await app.change("firewall-release-confirmation", `RELEASE-FIREWALL-RULE-${id}`);
    await app.click("방화벽 해제 요청");
    await app.tick(2000);
    if (id === 12) assert.equal(app.button("사전 점검 실행").props.disabled, true, "another applied scope remains");
  }
}

test("ordinary recovery excludes internal tools and keeps its history collapsed last", async () => {
  const app = await opened();
  const nodes = walk(app.modal().children);
  assert.ok(!nodes.some((n) => typeof n.type === "function" && ["Phase9ScopeExtension", "Phase9PacketPairRecovery"].includes(n.type.name)));
  assert.equal(app.input("recovery-admin-key").props.type, "password");
  const history = nodes.find((n) => n.type === "details" && text(n).includes("복구 이력"));
  assert.ok(history, "history uses native expandable control");
  assert.ok(!history.props.open, "default is collapsed");
  const sections = nodes.filter((n) => ["section", "details"].includes(n.type));
  assert.equal(sections.at(-1), history);
});

test("two exact releases precede runtime preflight and successful recovery refreshes normal100", async () => {
  const app = await opened();
  await releaseAll(app);
  await app.click("사전 점검 실행");
  await app.change("recovery-reason", "controlled recovery");
  await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
  await app.click("복구 실행");
  assert.deepEqual(app.calls.filter((x) => x.kind === "release").map((x) => x.ruleId), [12, 11]);
  const commands = app.calls.filter((x) => x.kind === "execute");
  assert.equal(commands.length, 1); assert.equal(commands[0].body.expected_trust_score, 20); assert.equal(commands[0].key, "test-admin");
  const summary = walk(app.modal().children).find((n) => n.props.className === "detail-grid");
  assert.match(text(summary), /100/); assert.ok(walk(summary).some((n) => n.type === "StatusBadge" && n.props.label === "정상"));
  assert.equal(app.button("복구 실행").props.disabled, true, "completed command cannot be repeated from stale preflight");
  assert.ok(app.text().includes("recovery-01"));
  assert.ok(app.nodes().some((n) => n.type === "StatusBadge" && n.props.label === "복구 완료"));
});

test("current preflight reports database audit readiness rather than a required backup", async () => {
  const app = await opened(); await releaseAll(app); await app.click("사전 점검 실행");
  assert.equal(detailValue(app.modal().children, "감사 기록 저장"), "준비됨 (데이터베이스)");
  assert.ok(!app.text().includes("백업 확인"));
  assert.ok(!app.text().includes("백업 경로를 다시 검사"));
});

test("an unavailable database audit does not fall back to an available legacy backup", async () => {
  const app = await opened({ auditCheck: { available: false, storage: "database", failure_reason: "감사 저장소 점검 실패" },
    backupCheck: { available: true } });
  await releaseAll(app); await app.click("사전 점검 실행");
  assert.match(detailValue(app.modal().children, "감사 기록 저장"), /저장 불가.*감사 저장소 점검 실패/);
  assert.ok(!app.text().includes("백업 확인"));
});

test("a present but unreadable audit check does not claim legacy backup readiness", async () => {
  const app = await opened({ auditCheck: null, backupCheck: { available: true } });
  await releaseAll(app); await app.click("사전 점검 실행");
  assert.equal(detailValue(app.modal().children, "감사 기록 저장"), "확인 불가");
  assert.ok(!app.text().includes("백업 확인"));
});

for (const [available, label] of [[true, "사용 가능"], [false, "사용 불가"]]) {
  test(`legacy preflight without an audit field retains backup status ${available}`, async () => {
    const app = await opened({ legacyPreflight: true, backupCheck: { available } });
    await releaseAll(app); await app.click("사전 점검 실행");
    assert.equal(detailValue(app.modal().children, "백업 확인 (구형 응답)"), label);
    assert.ok(!walk(app.modal().children).some((n) => n.type === "dt" && text(n).trim() === "감사 기록 저장"));
  });
}

test("recovery results and history show the audit reference and explicitly explain absent backups", async () => {
  const app = await opened(); await releaseAll(app); await app.click("사전 점검 실행");
  await app.change("recovery-reason", "controlled recovery"); await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
  await app.click("복구 실행");
  const result = app.nodes().find((n) => n.props.className === "success-box");
  const history = app.nodes().find((n) => n.type === "details" && text(n).includes("복구 이력"));
  for (const node of [result, history]) {
    assert.equal(detailValue(node, "감사 기록"), "device_recovery_audits:recovery-01");
    assert.equal(detailValue(node, "백업 위치"), "생성 안 함(필요 시 별도 백업)");
  }
});

test("older recovery evidence retains its actual backup reference and digest", async () => {
  const evidence = { backup_reference: "backups/legacy-recovery.sqlite3", backup_sha256: "a".repeat(64) };
  const app = await opened({ priorRecoveries: [{ operation_id: "legacy-recovery", result: "SUCCESS", ...evidence }], recoveryEvidence: evidence });
  await releaseAll(app); await app.click("사전 점검 실행");
  await app.change("recovery-reason", "controlled recovery"); await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
  await app.click("복구 실행");
  const result = app.nodes().find((n) => n.props.className === "success-box");
  const oldHistory = app.nodes().find((n) => n.type === "article" && text(n).includes("legacy-recovery"));
  for (const node of [result, oldHistory]) {
    assert.equal(detailValue(node, "백업 위치"), evidence.backup_reference);
    assert.equal(detailValue(node, "백업 SHA256"), evidence.backup_sha256);
  }
});

test("preflight success without actual runtime release cannot enable recovery", async () => {
  const app = await opened({ runtimeStatus: "UNVERIFIED" });
  await releaseAll(app); await app.click("사전 점검 실행");
  assert.equal(app.button("복구 실행").props.disabled, true);
  assert.equal(app.calls.filter((x) => x.kind === "execute").length, 0);
});


test("ordinary release still requires administrator authentication", async () => {
  const app = await opened();
  await app.change("firewall-release-reason", "controlled recovery");
  await app.change("firewall-release-confirmation", "RELEASE-FIREWALL-RULE-12");
  await app.click("방화벽 해제 요청");
  assert.equal(app.calls.filter((x) => x.kind === "release").length, 0);
  assert.match(app.text(), /관리자 인증키를 입력/);
});

for (const [label, options] of [["failed device read", { detailFailure: true }], ["incomplete rule list", { truncatedRules: true }], ["unknown null total", { unknownRuleTotal: null }], ["unknown empty total", { unknownRuleTotal: "" }], ["wrong device detail", { wrongDeviceDetail: true }]]) {
  test(`successful reset with ${label} does not claim final verification`, async () => {
    const app = await opened(options); await releaseAll(app); await app.click("사전 점검 실행");
    await app.change("recovery-reason", "controlled recovery"); await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
    await app.click("복구 실행");
    assert.match(app.text(), /복구 성공 응답은 받았지만/);
    assert.ok(!app.text().includes("서버에서 정상·100점과 남은 차단 규칙이 없음을 확인했습니다."));
    assert.equal(app.button("복구 실행").props.disabled, true);
    await app.button("복구 실행").props.onClick(); await app.settle();
    assert.equal(app.calls.filter((x) => x.kind === "execute").length, 1);
  });
}

test("uncertain reset reconciles state without permitting another write", async () => {
  const app = await opened({ uncertainExecute: true }); await releaseAll(app); await app.click("사전 점검 실행");
  await app.change("recovery-reason", "controlled recovery"); await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
  await app.click("복구 실행");
  assert.match(app.text(), /실행되었을 가능성/);
  assert.equal(app.button("복구 실행").props.disabled, true);
  await app.button("복구 실행").props.onClick(); await app.settle();
  assert.equal(app.calls.filter((x) => x.kind === "execute").length, 1);
  assert.ok(app.calls.some((x) => x.kind === "detail"));
});

test("a committed recovery with an HTTP500 unverified receipt reconciles without another write", async () => {
  const executeError = Object.assign(new Error("복구 저장 후 결과 조회에 실패했습니다."), { status: 500, responseData: { detail: {
    operation_id: "recovery-01", device_id: "esp32_02", result: "HOLD", failure_code: "BASELINE_RECOVERY_COMMITTED_UNVERIFIED",
    after_status: null, after_trust_score: null,
  } } });
  const app = await opened({ executeError }); await releaseAll(app); await app.click("사전 점검 실행");
  await app.change("recovery-reason", "controlled recovery"); await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
  const beforeExecute = app.calls.length;
  await app.click("복구 실행");
  assert.match(app.text(), /실행되었을 가능성/);
  const reconciliation = app.calls.slice(beforeExecute);
  assert.ok(reconciliation.some((x) => x.kind === "detail"), "query the actual device after the uncertain receipt");
  assert.ok(reconciliation.some((x) => x.kind === "rules"), "query remaining firewall rules after the uncertain receipt");
  assert.equal(app.button("복구 실행").props.disabled, true);
  await app.button("복구 실행").props.onClick(); await app.settle();
  await app.button("복구 실행").props.onClick(); await app.settle();
  assert.equal(app.calls.filter((x) => x.kind === "execute").length, 1);
});

test("an ordinary HTTP500 error keeps its known failure behavior", async () => {
  const executeError = Object.assign(new Error("감사 기록 저장에 실패했습니다."), { status: 500, responseData: { detail: {
    failure_code: "RECOVERY_AUDIT_WRITE_FAILED",
  } } });
  const app = await opened({ executeError, executeCommitted: false }); await releaseAll(app); await app.click("사전 점검 실행");
  await app.change("recovery-reason", "controlled recovery"); await app.change("recovery-confirmation", "RESET-TO-NORMAL-100");
  const beforeExecute = app.calls.length;
  await app.click("복구 실행");
  assert.match(app.text(), /감사 기록 저장에 실패했습니다/);
  assert.ok(!app.text().includes("실행되었을 가능성"));
  assert.ok(!app.calls.slice(beforeExecute).some((x) => x.kind === "detail" || x.kind === "rules"));
  assert.equal(app.button("복구 실행").props.disabled, false);
  assert.equal(app.calls.filter((x) => x.kind === "execute").length, 1);
});

test("closing and reopening discards the administrator key", async () => {
  const app = await opened(); await app.change("recovery-admin-key", "test-admin");
  app.modal().props.onClose(); await app.settle(); await app.open();
  assert.equal(app.input("recovery-admin-key").props.value, "");
  const history = walk(app.modal().children).find((n) => n.type === "details" && text(n).includes("복구 이력"));
  assert.ok(history && !history.props.open);
});
