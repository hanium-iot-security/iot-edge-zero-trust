import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { runInNewContext } from "node:vm";
import { transformWithOxc } from "vite";

async function componentSource(name) {
  const source = await readFile(new URL(`./${name}.jsx`, import.meta.url), "utf8");
  const result = await transformWithOxc(
    source.replace(/^import\b[\s\S]*?;\r?\n/gm, "").replace("export default function", "function"),
    `${name}.jsx`, { jsx: { runtime: "classic", pragma: "jsx" } },
  );
  return `${result.code}\nglobalThis.Component = ${name};`;
}

function* nodes(node) {
  if (Array.isArray(node)) { for (const child of node) yield* nodes(child); }
  else if (node && typeof node === "object") { yield node; yield* nodes(node.children); }
}

async function table(onRowClick) {
  const scope = { jsx: (type, props, ...children) => ({ type, props: props || {}, children }) };
  runInNewContext(await componentSource("DataTable"), scope);
  const row = { id: 7, name: "sensor" };
  const tree = scope.Component({ rows: [row], columns: [{ key: "name", header: "기기" }], onRowClick });
  return { row, rendered: [...nodes(tree)].find((n) => n.type === "tr" && n.props.onClick) };
}

function keyboard(key, target, extra = {}) {
  return { key, target, currentTarget: target, defaultPrevented: false, ...extra,
    preventDefault() { this.defaultPrevented = true; }, stopPropagation() {} };
}

test("clickable table rows keep table semantics and open once with Enter or Space", async () => {
  const opened = [];
  const { row, rendered } = await table((item) => opened.push(item));
  assert.equal(rendered.props.tabIndex, 0);
  assert.equal(rendered.props.role, undefined, "retain native table row semantics");
  const target = { focusCalls: 0, focus() { this.focusCalls++; } };
  for (const key of ["Enter", " "]) {
    const event = keyboard(key, target);
    rendered.props.onKeyDown(event);
    assert.equal(event.defaultPrevented, true, "Space must not scroll the page");
  }
  assert.deepEqual(opened, [row, row]);
  rendered.props.onKeyDown(keyboard("Enter", target, { repeat: true }));
  rendered.props.onKeyDown(keyboard("ArrowDown", target));
  assert.equal(opened.length, 2);
});

test("row activation ignores nested controls and focuses mouse-opened rows for restoration", async () => {
  let opened = 0;
  const { rendered } = await table(() => opened++);
  const row = { focusCalls: 0, focus() { this.focusCalls++; } };
  const button = { closest: () => button };
  rendered.props.onClick({ target: button, currentTarget: row });
  rendered.props.onKeyDown({ ...keyboard("Enter", button), currentTarget: row });
  assert.equal(opened, 0, "an inner button must not also activate its row");
  const cell = { closest: () => row };
  rendered.props.onClick({ target: cell, currentTarget: row });
  assert.equal(opened, 1);
  assert.equal(row.focusCalls, 1, "mouse-opened details need a focusable return target");
});

test("non-clickable table rows do not become keyboard controls", async () => {
  const scope = { jsx: (type, props, ...children) => ({ type, props: props || {}, children }) };
  runInNewContext(await componentSource("DataTable"), scope);
  const tree = scope.Component({ rows: [{ id: 1 }], columns: [{ key: "id" }] });
  const bodyRow = [...nodes(tree)].filter((n) => n.type === "tr").at(-1);
  assert.equal(bodyRow.props.tabIndex, undefined);
  assert.equal(bodyRow.props.onKeyDown, undefined);
});

// Small DOM boundary double: production event/effect code runs unchanged. Native
// browser tab order and layout remain covered by the separate live-browser QA.
function dom() {
  const listeners = new Map();
  const document = { activeElement: null, defaultView: { getComputedStyle: (element) => ({ visibility: element.visibility || "visible" }) },
    addEventListener(type, fn) { const set = listeners.get(type) || new Set(); set.add(fn); listeners.set(type, set); },
    removeEventListener(type, fn) { listeners.get(type)?.delete(fn); },
    dispatch(type, event) { for (const fn of [...(listeners.get(type) || [])]) fn(event); },
  };
  class Element {
    constructor(tag, parent = null, options = {}) {
      this.tagName = tag.toUpperCase(); this.parentElement = parent; this.ownerDocument = document;
      this.children = []; this.style = {}; this.disabled = false; this.hidden = false;
      this.connected = true; this.focusCalls = 0; this.attributes = new Map();
      this.tabIndex = ["BUTTON", "INPUT", "SELECT", "TEXTAREA", "A"].includes(this.tagName) ? 0 : -1;
      Object.assign(this, options); parent?.children.push(this);
    }
    get isConnected() { return this.connected && (!this.parentElement || this.parentElement.isConnected); }
    get isContentEditable() { return this.attributes.get("contenteditable") === "true"; }
    hasAttribute(name) { return this.attributes.has(name); }
    getAttribute(name) { return this.attributes.get(name) ?? null; }
    setAttribute(name, value) { this.attributes.set(name, String(value)); if (name === "tabindex") this.tabIndex = Number(value); }
    contains(other) { for (let e = other; e; e = e.parentElement) if (e === this) return true; return false; }
    matches(selector) { return selector === ":disabled" ? this.disabled : false; }
    closest() { for (let e = this; e; e = e.parentElement) if (e.hidden || e.inert || e.getAttribute("aria-hidden") === "true") return e; return null; }
    getClientRects() { return this.isConnected && !this.closest() ? [{}] : []; }
    querySelectorAll() {
      const all = []; const visit = (n) => { for (const child of n.children) { all.push(child); visit(child); } }; visit(this);
      return all.filter((n) => ["BUTTON", "A", "INPUT", "SELECT", "TEXTAREA", "SUMMARY"].includes(n.tagName) || n.hasAttribute("tabindex") || n.isContentEditable);
    }
    focus() {
      this.focusCalls++;
      if (!this.isConnected || this.disabled || !this.getClientRects().length || ["hidden", "collapse"].includes(this.visibility)) return;
      document.activeElement = this;
      document.dispatch("focusin", { target: this });
    }
  }
  document.body = new Element("body"); document.body.style.overflow = "auto";
  document.activeElement = document.body;
  return { document, Element, listeners, key(key, extra = {}) {
    const event = keyboard(key, document.activeElement, extra); document.dispatch("keydown", event); return event;
  } };
}

async function modalEnvironment() {
  const environment = dom();
  let current;
  let nextId = 0;
  const effect = (callback, deps) => {
    const index = current.cursor++; const previous = current.slots[index];
    if (!previous || !deps.every((value, i) => Object.is(value, previous.deps[i]))) {
      current.slots[index] = { deps, cleanup: previous?.cleanup, callback };
      const instance = current;
      instance.effects.push(() => { previous?.cleanup?.(); instance.slots[index].cleanup = callback(); });
    }
  };
  const scope = { document: environment.document, window: environment.document,
    useRef(initial) { const index = current.cursor++; return current.slots[index] ??= { current: initial }; },
    useId() { const index = current.cursor++; return (current.slots[index] ??= { id: `dialog-${++nextId}` }).id; },
    useEffect: effect, useLayoutEffect: effect,
    jsx: (type, props, ...children) => ({ type, props: props || {}, children }),
  };
  runInNewContext(await componentSource("DetailModal"), scope);
  return { ...environment, create(props = {}) {
    const backdrop = new environment.Element("div", environment.document.body);
    const dialog = new environment.Element("section", backdrop);
    const first = new environment.Element("button", dialog);
    const input = new environment.Element("input", dialog);
    const last = new environment.Element("button", dialog);
    const instance = { slots: [], effects: [], cursor: 0, props: { open: true, title: "상세", onClose() {}, ...props }, backdrop, dialog, first, input, last,
      render(patch = {}) {
        Object.assign(this.props, patch); this.cursor = 0; this.effects = []; current = this;
        const tree = scope.Component(this.props);
        if (tree) {
          backdrop.connected = true;
          const rendered = [...nodes(tree)].find((n) => n.props.role === "dialog");
          first.disabled = Boolean([...nodes(tree)].find((n) => n.props.className === "modal-close").props.disabled);
          if (rendered.props.ref) rendered.props.ref.current = dialog;
          if (rendered.props.tabIndex !== undefined) dialog.setAttribute("tabindex", rendered.props.tabIndex);
          this.tree = tree;
        } else backdrop.connected = false;
        if (!this.props.deferEffects) this.effects.forEach((run) => run()); return this;
      },
      unmount() {
        backdrop.connected = false;
        if (dialog.contains(environment.document.activeElement)) environment.document.activeElement = environment.document.body;
        this.slots.forEach((slot) => slot?.cleanup?.());
      },
      replayEffects() {
        this.slots.filter((slot) => slot?.callback).forEach((slot) => { slot.cleanup?.(); slot.cleanup = slot.callback(); });
      },
    };
    return instance.render();
  } };
}

test("opening focuses the dialog, wraps Tab in both directions, and repairs escaped focus", async () => {
  const env = await modalEnvironment();
  const opener = new env.Element("button", env.document.body); opener.focus();
  const modal = env.create();
  assert.equal(env.document.activeElement, modal.first);
  modal.last.focus(); assert.equal(env.key("Tab").defaultPrevented, true);
  assert.equal(env.document.activeElement, modal.first);
  assert.equal(env.key("Tab", { shiftKey: true }).defaultPrevented, true);
  assert.equal(env.document.activeElement, modal.last);
  opener.focus(); assert.equal(modal.dialog.contains(env.document.activeElement), true);
  modal.unmount();
  assert.equal(env.document.activeElement, opener);
  assert.equal(env.document.body.style.overflow, "auto");
  assert.equal([...env.listeners.values()].reduce((n, set) => n + set.size, 0), 0);
});

test("locked/no-control dialogs keep focus inside and do not close on Escape", async () => {
  const env = await modalEnvironment(); let closed = 0;
  const modal = env.create({ closeDisabled: true, onClose: () => closed++ });
  modal.first.disabled = true; modal.input.hidden = true; modal.last.disabled = true;
  env.document.activeElement = env.document.body;
  assert.equal(env.key("Tab").defaultPrevented, true);
  assert.equal(env.document.activeElement, modal.dialog);
  assert.equal(env.key("Escape").defaultPrevented, true);
  assert.equal(closed, 0);
  modal.unmount();
});

test("focus boundaries reflect disabled/hidden/dynamic controls and explicit tab order", async () => {
  const env = await modalEnvironment();
  const modal = env.create({ closeDisabled: true });
  assert.equal(env.document.activeElement, modal.input, "skip the disabled close button on opening");
  modal.last.visibility = "hidden";
  assert.equal(env.key("Tab").defaultPrevented, true);
  assert.equal(env.document.activeElement, modal.input, "a CSS-hidden last button is not a tab boundary");
  modal.last.visibility = "visible";
  modal.input.setAttribute("tabindex", "2"); modal.last.setAttribute("tabindex", "1");
  env.key("Tab"); assert.equal(env.document.activeElement, modal.last);
  modal.dialog.focus(); env.key("Tab", { shiftKey: true });
  assert.equal(env.document.activeElement, modal.input);
  modal.unmount();
});

test("polling callback updates do not reset focus or the open lifetime; Escape uses latest props", async () => {
  const env = await modalEnvironment(); let oldClose = 0; let latestClose = 0;
  const opener = new env.Element("button", env.document.body); opener.focus();
  const modal = env.create({ onClose: () => oldClose++ });
  modal.input.focus(); const calls = opener.focusCalls;
  modal.render({ onClose: () => latestClose++ });
  assert.equal(env.document.activeElement, modal.input);
  assert.equal(opener.focusCalls, calls);
  env.key("Escape"); assert.equal(oldClose, 0); assert.equal(latestClose, 1);
  modal.render({ closeDisabled: true }); env.key("Escape"); assert.equal(latestClose, 1);
  modal.unmount();
});

test("only the top nested dialog handles Escape and focus, and scrolling stays locked", async () => {
  const env = await modalEnvironment(); let lowerClosed = 0; let upperClosed = 0;
  const opener = new env.Element("button", env.document.body); opener.focus();
  const lower = env.create({ onClose: () => lowerClosed++ }); lower.input.focus();
  const upper = env.create({ onClose: () => upperClosed++ });
  assert.ok(Number(upper.backdrop.style.zIndex) > Number(lower.backdrop.style.zIndex));
  lower.first.focus(); assert.equal(upper.dialog.contains(env.document.activeElement), true);
  env.key("Escape"); assert.equal(upperClosed, 1); assert.equal(lowerClosed, 0);
  upper.unmount(); assert.equal(env.document.activeElement, lower.input);
  assert.equal(env.document.body.style.overflow, "hidden");
  lower.unmount(); assert.equal(env.document.activeElement, opener);
  assert.equal(env.document.body.style.overflow, "auto");
});

test("non-LIFO unmount never steals top focus and can restore past a removed parent", async () => {
  const env = await modalEnvironment();
  const opener = new env.Element("button", env.document.body); opener.focus();
  const lower = env.create(); const upper = env.create();
  lower.unmount(); assert.equal(upper.dialog.contains(env.document.activeElement), true);
  assert.equal(env.document.body.style.overflow, "hidden");
  const newest = env.create();
  assert.ok(Number(newest.backdrop.style.zIndex) > Number(upper.backdrop.style.zIndex));
  newest.unmount(); upper.unmount();
  assert.equal(env.document.activeElement, opener);
  assert.equal(env.document.body.style.overflow, "auto");
});

test("nested close falls back inside the remaining dialog if its opener became disabled", async () => {
  const env = await modalEnvironment(); const lower = env.create();
  lower.input.focus(); const upper = env.create(); lower.input.disabled = true;
  upper.unmount();
  assert.equal(lower.dialog.contains(env.document.activeElement), true);
  assert.notEqual(env.document.activeElement, lower.input);
  lower.unmount();
});

test("closing by open=false restores focus and disconnected openers are not focused", async () => {
  const env = await modalEnvironment();
  const opener = new env.Element("button", env.document.body); opener.focus();
  const modal = env.create(); modal.render({ open: false });
  assert.equal(env.document.activeElement, opener);
  const again = env.create(); const calls = opener.focusCalls; opener.connected = false;
  again.unmount(); assert.equal(opener.focusCalls, calls);
  assert.equal(env.document.body.style.overflow, "auto");
});

test("StrictMode-style effect replay leaves one trap and restores original body state", async () => {
  const env = await modalEnvironment(); let closed = 0;
  const opener = new env.Element("button", env.document.body); opener.focus();
  const modal = env.create({ onClose: () => closed++ }); modal.replayEffects();
  assert.equal(modal.dialog.contains(env.document.activeElement), true);
  assert.equal(env.document.body.style.overflow, "hidden");
  assert.equal(env.listeners.get("keydown").size, 1);
  assert.equal(env.listeners.get("focusin").size, 1);
  env.key("Escape"); assert.equal(closed, 1);
  modal.unmount(); assert.equal(env.document.activeElement, opener);
  assert.equal(env.document.body.style.overflow, "auto");
  assert.equal([...env.listeners.values()].reduce((n, set) => n + set.size, 0), 0);
});

test("nested StrictMode cleanup-all/setup-all preserves the external opener while DOM stays connected", async () => {
  const env = await modalEnvironment();
  const opener = new env.Element("button", env.document.body); opener.focus();
  const lower = env.create(); lower.input.focus(); const upper = env.create();
  const effects = [lower, upper].flatMap((modal) => modal.slots.filter((slot) => slot?.callback));
  // React can destroy all layout effects before recreating any of them, without
  // removing the dialog DOM. A retired dialog is not a valid restoration target.
  effects.forEach((slot) => slot.cleanup?.());
  assert.equal(lower.dialog.isConnected, true); assert.equal(upper.dialog.isConnected, true);
  assert.ok(env.document.activeElement === opener, "all retired lifetimes must restore the external opener");
  effects.forEach((slot) => { slot.cleanup = slot.callback(); });
  assert.equal(upper.dialog.contains(env.document.activeElement), true);
  assert.equal(env.listeners.get("keydown").size, 2);
  assert.equal(env.document.body.style.overflow, "hidden");
  upper.unmount(); lower.unmount();
  assert.ok(env.document.activeElement === opener, "the final close must still return to the original opener");
  assert.equal(env.document.body.style.overflow, "auto");
  assert.equal([...env.listeners.values()].reduce((n, set) => n + set.size, 0), 0);
});

for (const order of ["parent-first", "child-first"]) {
  test(`nested DOM ${order} layout setup preserves inner ownership and the external opener through replay`, async () => {
    const env = await modalEnvironment(); let outerClosed = 0; let innerClosed = 0;
    const opener = new env.Element("button", env.document.body); opener.focus();
    const outer = env.create({ deferEffects: true, onClose: () => outerClosed++ });
    const inner = env.create({ deferEffects: true, onClose: () => innerClosed++ });
    env.document.body.children.splice(env.document.body.children.indexOf(inner.backdrop), 1);
    inner.backdrop.parentElement = outer.dialog; outer.dialog.children.push(inner.backdrop);
    const sequence = order === "child-first" ? [inner, outer] : [outer, inner];
    sequence.forEach((modal) => modal.effects.forEach((run) => run()));
    assert.equal(inner.dialog.contains(env.document.activeElement), true, "the nested child owns focus regardless of effect setup order");
    assert.ok(Number(inner.backdrop.style.zIndex) > Number(outer.backdrop.style.zIndex));
    env.key("Escape"); assert.equal(innerClosed, 1); assert.equal(outerClosed, 0);

    const effects = sequence.flatMap((modal) => modal.slots.filter((slot) => slot?.callback));
    effects.forEach((slot) => slot.cleanup?.());
    assert.ok(env.document.activeElement === opener, "cleanup-all restores the external opener with nested DOM still connected");
    effects.forEach((slot) => { slot.cleanup = slot.callback(); });
    assert.equal(inner.dialog.contains(env.document.activeElement), true);
    assert.equal(env.listeners.get("keydown").size, 2);
    env.key("Escape"); assert.equal(innerClosed, 2); assert.equal(outerClosed, 0);

    inner.unmount();
    assert.equal(outer.dialog.contains(env.document.activeElement), true);
    assert.equal(env.document.activeElement.isConnected, true);
    assert.equal(env.document.body.style.overflow, "hidden");
    outer.unmount();
    assert.ok(env.document.activeElement === opener, "the final parent close restores the original external opener");
    assert.equal(env.document.body.style.overflow, "auto");
    assert.equal([...env.listeners.values()].reduce((n, set) => n + set.size, 0), 0);
  });
}
