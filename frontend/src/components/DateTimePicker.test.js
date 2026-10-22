import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { transformWithOxc } from "vite";
import * as dateTime from "../utils/dateTimeInput.js";

async function picker(value = "2026-10-20T12:06:37", withSeconds = true) {
  const source = await readFile(new URL("./DateTimePicker.jsx", import.meta.url), "utf8");
  const { code } = await transformWithOxc(source.replace(/^import\b[\s\S]*?;\r?\n/gm, "").replace("export default function", "function"), "DateTimePicker.jsx", {
    jsx: { runtime: "classic", pragma: "jsx" },
  });
  const slots = [];
  const changes = [];
  const dialog = { opened: false, showModal() { this.opened = true; }, close() { this.opened = false; } };
  let cursor = 0;
  let root;
  const props = { id: "picked", label: "시작 (KST)", value, withSeconds, onChange(next) { changes.push(next); props.value = next; } };
  const scope = {
    ...dateTime,
    useId: () => "test-picker",
    useRef: () => ({ current: dialog }),
    useState(initial) {
      const i = cursor++;
      if (!(i in slots)) slots[i] = initial;
      return [slots[i], (next) => { slots[i] = typeof next === "function" ? next(slots[i]) : next; }];
    },
    jsx: (type, props, ...children) => ({ type, props: props || {}, children }),
  };
  runInNewContext(`${code}\nglobalThis.Picker = DateTimePicker;`, scope);
  const render = () => { cursor = 0; root = scope.Picker(props); };
  function* walk(node) {
    if (Array.isArray(node)) { for (const child of node) yield* walk(child); }
    else if (node && typeof node === "object") { yield node; yield* walk(node.children); }
  }
  const nodes = () => [...walk(root)];
  const find = (predicate) => { const found = nodes().find(predicate); assert.ok(found, "missing picker UI"); return found; };
  const act = (fn) => { fn(); render(); };
  render();
  return {
    changes, dialog, nodes,
    open: () => act(() => find((node) => node.props.id === "picked").props.onClick()),
    set: (field, next) => act(() => find((node) => node.props.id === `picked-${field}`).props.onChange({ target: { value: next } })),
    click: (text) => act(() => find((node) => node.type === "button" && node.children.includes(text)).props.onClick()),
    key: (event) => act(() => find((node) => node.type === "dialog").props.onKeyDown(event)),
  };
}

test("KST wall-clock noon/midnight conversions preserve the selected calendar date and seconds", () => {
  for (const hour of ["00", "01", "11", "12", "13", "23"]) {
    const value = `2026-10-20T${hour}:06:37`;
    assert.equal(dateTime.dateTimeInputValue(dateTime.parseDateTimeInput(value), true), value);
  }
  assert.equal(dateTime.dateTimeInputLabel("2026-10-20T00:06:37", true), "2026-10-20 오전 12:06:37");
  assert.equal(dateTime.dateTimeInputLabel("2026-10-20T12:06"), "2026-10-20 오후 12:06");
  assert.equal(dateTime.dateTimeInputValue({ date: "2026-10-20", period: "AM", hour: "12", minute: "6" }), "2026-10-20T00:06");
});

test("invalid dates and time fields are rejected instead of rolling into another day", () => {
  for (const value of ["2026-02-29T12:00", "2026-04-31T12:00", "2026-10-20T24:00", "2026-10-20T12:60", "0000-01-01T00:00", ""]) {
    assert.equal(dateTime.parseDateTimeInput(value), null, value);
  }
  assert.ok(dateTime.parseDateTimeInput("2024-02-29T23:59:59"));
  assert.equal(dateTime.dateTimeInputValue({ date: "2026-10-20", period: "AM", hour: "0", minute: "0" }), null);
});

test("calendar month navigation handles leap years, year boundaries and supported bounds", () => {
  assert.equal(dateTime.calendarDays("2024-02").filter(Boolean).length, 29);
  assert.equal(dateTime.calendarDays("2026-02").filter(Boolean).length, 28);
  assert.equal(dateTime.adjacentMonth("2026-12", 1), "2027-01");
  assert.equal(dateTime.adjacentMonth("2026-01", -1), "2025-12");
  assert.equal(dateTime.adjacentMonth("0001-01", -1), "0001-01");
  assert.equal(dateTime.adjacentMonth("9999-12", 1), "9999-12");
});

test("whole-field trigger opens picker; editing and cancelling do not change the query", async () => {
  const app = await picker();
  app.open();
  assert.equal(app.dialog.opened, true);
  app.set("period", "AM");
  app.set("minute", "15");
  assert.deepEqual(app.changes, []);
  app.click("취소");
  assert.equal(app.dialog.opened, false);
  assert.deepEqual(app.changes, []);
  app.open();
  app.click("적용");
  assert.deepEqual(app.changes, ["2026-10-20T12:06:37"]);
});

test("period is the first time control and applying midnight retains capture seconds", async () => {
  const app = await picker();
  app.open();
  const timeControls = app.nodes().filter((node) => /picked-(period|hour|minute|second)$/.test(node.props.id || ""));
  assert.deepEqual(timeControls.map((node) => node.props.id), ["picked-period", "picked-hour", "picked-minute", "picked-second"]);
  app.set("period", "AM");
  app.click("적용");
  assert.deepEqual(app.changes, ["2026-10-20T00:06:37"]);
});

test("invalid minutes stay in the dialog, and clearing explicitly returns an empty input", async () => {
  const app = await picker();
  app.open();
  app.set("minute", "60");
  app.click("적용");
  assert.equal(app.dialog.opened, true);
  assert.deepEqual(app.changes, []);
  assert.ok(app.nodes().some((node) => node.props.role === "alert"));
  app.click("지우기");
  assert.deepEqual(app.changes, [""]);
  assert.equal(app.dialog.opened, false);
});

test("Enter applies a valid draft without submitting the surrounding traffic-query form", async () => {
  const app = await picker("2026-10-20T13:11", false);
  app.open();
  let prevented = false;
  let stopped = false;
  app.key({ key: "Enter", target: { tagName: "INPUT" }, preventDefault() { prevented = true; }, stopPropagation() { stopped = true; } });
  assert.equal(prevented, true);
  assert.equal(stopped, true);
  assert.deepEqual(app.changes, ["2026-10-20T13:11"]);
});


test("Enter on the period selector keeps native selection behavior without applying", async () => {
  const app = await picker();
  app.open();
  let prevented = false;
  app.key({ key: "Enter", target: { tagName: "SELECT" }, preventDefault() { prevented = true; }, stopPropagation() {} });
  assert.equal(prevented, false);
  assert.equal(app.dialog.opened, true);
  assert.deepEqual(app.changes, []);
});
