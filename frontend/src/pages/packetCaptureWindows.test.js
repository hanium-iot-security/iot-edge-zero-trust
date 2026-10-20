import * as uiText from "../utils/uiText.js";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { transformWithOxc } from "vite";

// Run the production capture component and its helpers; only hooks, JSX and API
// transport are substituted so pagination tests exercise the actual UI handlers.
async function captureHarness(response) {
  const source = await readFile(new URL("./PacketTraffic.jsx", import.meta.url), "utf8");
  const captureSource = source.slice(source.indexOf("function formatKST"), source.indexOf("export default function PacketTraffic"));
  const transformed = await transformWithOxc(captureSource, "PacketTraffic.jsx", {
    jsx: { runtime: "classic", pragma: "jsx", pragmaFrag: "Fragment" },
  });
  const slots = [];
  const calls = [];
  let cursor = 0;
  let dirty = false;
  let effects = [];
  let root;
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
      if (!slots[i] || !same(slots[i].dependencies, dependencies)) slots[i] = { dependencies, value: callback() };
      return slots[i].value;
    },
    useCallback(callback, dependencies) { return hooks.useMemo(() => callback, dependencies); },
    useEffect(callback, dependencies) {
      const i = cursor++;
      if (!slots[i] || !same(slots[i].dependencies, dependencies)) {
        const cleanup = slots[i]?.cleanup;
        slots[i] = { dependencies };
        effects.push(() => { cleanup?.(); slots[i].cleanup = callback(); });
      }
    },
  };
  const scope = {
    ...hooks, ...uiText, AbortController, console,
    StatusBadge: "StatusBadge", EmptyState: "EmptyState",
    window: { setInterval: () => 1, clearInterval() {} },
    getPacketCaptureWindows: async (query) => { calls.push(query); return response; },
    jsx: (type, props, ...children) => ({ type, props: props || {}, children }),
  };
  runInNewContext(`${transformed.code}\nglobalThis.Component = PacketCaptureWindows;`, scope);
  const features = [{ capture_session_id: "session-a", window_start: "2026-10-15T06:56:10Z", window_end: "2026-10-15T06:58:10Z" }];
  function render() { cursor = 0; dirty = false; effects = []; root = scope.Component({ featureRows: features }); effects.forEach((effect) => effect()); }
  async function settle() { for (let i = 0; i < 40; i++) { await Promise.resolve(); if (dirty) render(); } assert.equal(dirty, false); }
  function* walk(node) {
    if (Array.isArray(node)) { for (const child of node) yield* walk(child); }
    else if (node && typeof node === "object") { yield node; yield* walk(node.children); }
  }
  const nodes = () => [...walk(root)];
  const text = (node) => Array.isArray(node) ? node.map(text).join("") : node && typeof node === "object" ? text(node.children) : typeof node === "string" || typeof node === "number" ? String(node) : "";
  const find = (predicate) => { const node = nodes().find(predicate); assert.ok(node, "missing capture UI node"); return node; };
  async function act(callback) { await callback(); await settle(); }
  render();
  await settle();
  return {
    calls, nodes, text,
    rows: () => nodes().filter((node) => node.type === "tbody").flatMap((node) => [...walk(node.children)].filter((child) => child.type === "tr")),
    change: (id, value) => act(() => find((node) => node.props.id === id).props.onChange({ target: { value } })),
    click: (label) => act(() => { const button = find((node) => node.type === "button" && text(node) === label); assert.equal(Boolean(button.props.disabled), false); return button.props.onClick(); }),
  };
}

function windows() {
  return Array.from({ length: 12 }, (_, index) => ({
    segment_id: index + 1,
    window_start: new Date(Date.parse("2026-10-15T06:56:10Z") + index * 10_000).toISOString(),
    window_end: new Date(Date.parse("2026-10-15T06:56:20Z") + index * 10_000).toISOString(),
    segment_status: "PROCESSED", observation: "PROCESSED", capture_eligible: true,
  }));
}

const identifiers = (app) => app.rows().map((row) => app.text(row.children[0]));

test("120-second response is paged locally without repeating rows or refetching", async () => {
  const app = await captureHarness({ items: windows(), total: 12 });
  assert.equal(app.rows().length, 10);
  assert.deepEqual(identifiers(app), ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10"]);
  assert.deepEqual(Object.keys(app.calls[0]).sort(), ["from", "session_id", "to"]);
  await app.click("다음");
  assert.deepEqual(identifiers(app), ["11", "12"]);
  assert.equal(app.calls.length, 1, "paging does not repeat the bounded API request");
  await app.change("capture-window-to", "2026-10-15T15:58:20");
  assert.deepEqual(identifiers(app).slice(0, 2), ["1", "2"], "query change resets the first page");
  assert.equal(app.calls.length, 2);
});

test("observation filters include processed, normalized READY/PENDING and missing windows", async () => {
  const items = windows();
  items[0] = { ...items[0], segment_status: "READY", observation: "PENDING", capture_eligible: false };
  items[1] = { ...items[1], segment_status: "READY", observation: undefined, capture_eligible: false };
  items[2] = { ...items[2], segment_id: null, segment_status: null, observation: "MISSING", capture_eligible: null };
  items[3] = { ...items[3], segment_status: "FAILED", observation: "FAILED", capture_eligible: false };
  const app = await captureHarness({ items, total: 12 });
  const filters = app.nodes().filter((node) => node.type === "option").map((node) => node.props.value);
  for (const observation of ["PROCESSED", "EMPTY", "PENDING", "MISSING", "FAILED"]) assert.ok(filters.includes(observation));
  assert.equal(filters.includes("COMPLETED"), false, "session status is not a window observation");
  await app.change("capture-window-status", "PROCESSED");
  assert.deepEqual(identifiers(app), ["5", "6", "7", "8", "9", "10", "11", "12"]);
  await app.change("capture-window-status", "PENDING");
  assert.deepEqual(identifiers(app), ["1", "2"]);
  assert.ok(app.nodes().filter((node) => node.type === "StatusBadge").every((node) => node.props.status === "pending"));
  await app.change("capture-window-status", "MISSING");
  assert.equal(app.rows().length, 1);
  assert.equal(app.nodes().find((node) => node.type === "StatusBadge").props.status, "missing");
  assert.ok(app.text(app.rows()[0]).includes("계산 불가"));
  assert.equal(app.text(app.rows()[0].children[5]), "-", "missing input is not eligible normal traffic");
  await app.change("capture-window-status", "FAILED");
  assert.deepEqual(identifiers(app), ["4"]);
});

test("filter changes reset pagination and filter the complete bounded interval", async () => {
  const items = windows();
  items[11] = { ...items[11], observation: "PENDING", segment_status: "READY" };
  const app = await captureHarness({ items, total: 12 });
  await app.click("다음");
  await app.change("capture-window-status", "PENDING");
  assert.deepEqual(identifiers(app), ["12"]);
  assert.equal(app.calls.length, 1);
});
