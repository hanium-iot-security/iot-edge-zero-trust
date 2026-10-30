import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import FirewallTrafficFields from "../components/FirewallTrafficFields.js";
import {
  canReleaseFirewallRule,
  findFirewallRulesByTriggerEvent,
  findCurrentFirewallRuleByTriggerEvent,
  getCurrentFirewallRuleMap,
  selectCurrentFirewallRule,
} from "./firewallRuleSelection.js";

function renderRule(rule) {
  return renderToStaticMarkup(createElement("dl", null,
    createElement(FirewallTrafficFields, { rule }),
  ));
}

test("wide API rule with null protocol and port displays its IPv4 scope", () => {
  const response = { item: {
    id: 21, scope: "PI_INPUT_IPV4_ALL", protocol: null, dest_port: null,
    source_rule_id: 20, status: "PENDING", source_ip: "192.168.0.31",
  }, runtime_verified: false };
  assert.equal(renderRule(response.item),
    "<dl><div><dt>프로토콜</dt><dd>전체 IPv4</dd></div><div><dt>포트</dt><dd>모든 포트</dd></div></dl>");
});

test("legacy API rule without scope retains its existing TCP 1883 fields", () => {
  const response = { items: [{ id: 20, protocol: "tcp", dest_port: 1883 }] };
  const expected = "<dl><div><dt>프로토콜</dt><dd>tcp</dd></div><div><dt>포트</dt><dd>1883</dd></div></dl>";
  assert.equal(renderRule(response.items[0]), expected);
  assert.equal(renderRule({ ...response.items[0], scope: "MQTT_IPV4_TCP_1883" }), expected);
});

test("missing fields or an unknown scope are not presented as all IPv4", () => {
  for (const rule of [{}, { scope: "UNKNOWN", protocol: null, dest_port: null }]) {
    assert.equal(renderRule(rule),
      "<dl><div><dt>프로토콜</dt><dd>-</dd></div><div><dt>포트</dt><dd>-</dd></div></dl>");
  }
});

function scopedRules() {
  return [
    { id: 20, device_id: "pico_01", source_ip: "192.168.0.31", trigger_event_id: 7, status: "APPLIED",
      scope: "MQTT_IPV4_TCP_1883", protocol: "tcp", dest_port: 1883,
      updated_at: "2026-10-11T08:00:00Z" },
    { id: 21, device_id: "pico_01", source_ip: "192.168.0.31", trigger_event_id: null, source_rule_id: 20, status: "APPLIED",
      scope: "PI_INPUT_IPV4_ALL", protocol: null, dest_port: null,
      updated_at: "2026-10-11T08:01:00Z" },
  ];
}

test("releasing wide keeps the older MQTT rule visible and releasable", () => {
  const [mqtt, wide] = scopedRules();
  wide.status = "REMOVED";
  wide.updated_at = "2026-10-11T08:02:00Z";
  for (const rules of [[mqtt, wide], [wide, mqtt]]) {
    const selected = getCurrentFirewallRuleMap(rules).get("pico_01");
    assert.equal(selected, mqtt);
    assert.equal(canReleaseFirewallRule(selected), true);
    assert.match(renderRule(selected), /<dd>tcp<\/dd>/);
    assert.equal(findCurrentFirewallRuleByTriggerEvent(rules, "7"), mqtt);
  }
});

test("releasing MQTT keeps the older wide rule visible and releasable", () => {
  const [mqtt, wide] = scopedRules();
  mqtt.status = "REMOVED";
  mqtt.updated_at = "2026-10-11T08:02:00Z";
  const selected = getCurrentFirewallRuleMap([mqtt, wide]).get("pico_01");
  assert.equal(selected, wide);
  assert.equal(canReleaseFirewallRule(selected), true);
  assert.match(renderRule(selected), /<dd>전체 IPv4<\/dd>/);
  assert.equal(findCurrentFirewallRuleByTriggerEvent([mqtt, wide], 7), wide);
});

test("history 27 follows MQTT rule 29 to the null-trigger IPv4 child 30", () => {
  const [mqtt, wide] = scopedRules();
  const parent = { ...mqtt, id: 29, trigger_event_id: 27, status: "REMOVED" };
  const child = { ...wide, id: 30, source_rule_id: 29 };
  assert.equal(findCurrentFirewallRuleByTriggerEvent([child, parent], 27), child);
  assert.deepEqual(findFirewallRulesByTriggerEvent([child, parent], 27), [parent, child]);
});

test("history grouping follows descendants without adopting other devices, IPs, events, or disconnected cycles", () => {
  const [mqtt, wide] = scopedRules();
  const descendant = { ...wide, id: 22, source_rule_id: 21 };
  const unrelated = [
    { ...mqtt, id: 1, trigger_event_id: 6 },
    { ...wide, id: 2, source_rule_id: 1 },
    { ...wide, id: 31, source_rule_id: 20, device_id: "esp32_01" },
    { ...wide, id: 32, source_rule_id: 20, source_ip: "192.168.0.32" },
    { ...wide, id: 33, source_rule_id: 20, device_id: null },
    { ...wide, id: 34, source_rule_id: 20, source_ip: null },
    { ...wide, id: 35, source_rule_id: 20, trigger_event_id: 8 },
    { ...wide, id: 36, source_rule_id: 32 },
    { ...wide, id: 40, source_rule_id: 41 },
    { ...wide, id: 41, source_rule_id: 40 },
  ];
  const rules = Object.freeze([descendant, ...unrelated, wide, mqtt].map(Object.freeze));
  for (const input of [rules, [...rules].reverse()]) {
    assert.deepEqual(findFirewallRulesByTriggerEvent(input, "7"), [mqtt, wide, descendant]);
  }
  assert.deepEqual(findFirewallRulesByTriggerEvent(unrelated, 7), [], "no exact trigger root means no group");
});

test("exact history context filters roots, and multiple direct-trigger roots remain visible", () => {
  const [mqtt, wide] = scopedRules();
  const directWide = { ...wide, trigger_event_id: 7, source_rule_id: null };
  const otherDevice = { ...mqtt, id: 50, device_id: "esp32_01", updated_at: "2026-10-12T00:00:00Z" };
  const otherIp = { ...mqtt, id: 51, source_ip: "192.168.0.32", updated_at: "2026-10-12T00:00:00Z" };
  const context = { deviceId: "pico_01", sourceIp: "192.168.0.31" };
  const rules = [mqtt, directWide, otherDevice, otherIp];
  assert.deepEqual(findFirewallRulesByTriggerEvent(rules, 7, context), [mqtt, directWide]);
  assert.equal(findCurrentFirewallRuleByTriggerEvent(rules, 7, context), directWide);
  assert.deepEqual(findFirewallRulesByTriggerEvent([mqtt, { ...wide, source_ip: null }], 7), [mqtt]);
  assert.deepEqual(findFirewallRulesByTriggerEvent([{ ...mqtt, source_ip: null }, wide], 7), [{ ...mqtt, source_ip: null }]);
  for (const eventId of [null, undefined, "", 9]) {
    assert.deepEqual(findFirewallRulesByTriggerEvent(rules, eventId, context), []);
  }
});

test("new direct all-IPv4 roots and legacy MQTT-only roots retain their actual traffic fields", () => {
  const [mqtt, wide] = scopedRules();
  const directWide = { ...wide, trigger_event_id: 8, source_rule_id: null };
  assert.deepEqual(findFirewallRulesByTriggerEvent([mqtt, directWide], 8), [directWide]);
  assert.match(renderRule(findCurrentFirewallRuleByTriggerEvent([mqtt, directWide], 8)), /전체 IPv4.*모든 포트/);
  assert.doesNotMatch(renderRule(directWide), /1883/);
  assert.deepEqual(findFirewallRulesByTriggerEvent([mqtt], 7), [mqtt]);
  assert.match(renderRule(mqtt), /tcp.*1883/);
});

test("a newer removed rule does not hide failed residue, pending, or unknown state", () => {
  for (const status of ["FAILED", "PENDING", "UNKNOWN", null]) {
    const [mqtt, wide] = scopedRules();
    mqtt.status = status;
    wide.status = "REMOVED";
    const selected = selectCurrentFirewallRule([mqtt, wide]);
    assert.equal(selected, mqtt);
    assert.equal(canReleaseFirewallRule(selected), status === "FAILED");
    assert.equal(findCurrentFirewallRuleByTriggerEvent([mqtt, wide], 7), mqtt);
  }
});

test("the next scope becomes selected after each release until both are removed", () => {
  const rules = scopedRules();
  assert.equal(selectCurrentFirewallRule(rules).id, 21);
  rules[1].status = "REMOVED";
  rules[1].updated_at = "2026-10-11T08:02:00Z";
  assert.equal(selectCurrentFirewallRule(rules).id, 20);
  rules[0].status = "REMOVED";
  rules[0].updated_at = "2026-10-11T08:03:00Z";
  const selected = selectCurrentFirewallRule(rules);
  assert.equal(selected.id, 20);
  assert.equal(selected.status, "REMOVED");
  assert.equal(canReleaseFirewallRule(selected), false);
  assert.equal(findCurrentFirewallRuleByTriggerEvent(rules, 7).status, "REMOVED");
});

test("device and historical event matching do not adopt another device or event", () => {
  const [mqtt, wide] = scopedRules();
  const another = { ...wide, id: 30, device_id: "esp32_01", trigger_event_id: 8 };
  const rules = [mqtt, wide, another, { ...another, id: 31, device_id: null, trigger_event_id: null }];
  assert.equal(getCurrentFirewallRuleMap(rules).get("pico_01"), wide);
  assert.equal(getCurrentFirewallRuleMap(rules).get("esp32_01"), another);
  assert.equal(getCurrentFirewallRuleMap(rules).size, 2);
  assert.equal(findCurrentFirewallRuleByTriggerEvent(rules, 7), wide);
  assert.equal(findCurrentFirewallRuleByTriggerEvent(rules, 8), another);
  for (const id of [null, undefined, "", 9]) {
    assert.equal(findCurrentFirewallRuleByTriggerEvent(rules, id), null);
  }
});

test("equal timestamps select the latest ID consistently without mutating input", () => {
  const [mqtt, wide] = scopedRules();
  mqtt.updated_at = wide.updated_at;
  const rules = Object.freeze([Object.freeze(mqtt), Object.freeze(wide)]);
  assert.equal(selectCurrentFirewallRule(rules), wide);
  assert.equal(selectCurrentFirewallRule([...rules].reverse()), wide);
  assert.equal(selectCurrentFirewallRule([]), null);
  assert.equal(canReleaseFirewallRule(null), false);
});
