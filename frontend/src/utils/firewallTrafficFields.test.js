import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import FirewallTrafficFields from "../components/FirewallTrafficFields.js";
import {
  canReleaseFirewallRule,
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
    { id: 20, device_id: "pico_01", trigger_event_id: 7, status: "APPLIED",
      scope: "MQTT_IPV4_TCP_1883", protocol: "tcp", dest_port: 1883,
      updated_at: "2026-10-11T08:00:00Z" },
    { id: 21, device_id: "pico_01", trigger_event_id: 7, status: "APPLIED",
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

test("a newer removed rule does not hide failed residue, pending, or unknown state", () => {
  for (const status of ["FAILED", "PENDING", "UNKNOWN", null]) {
    const [mqtt, wide] = scopedRules();
    mqtt.status = status;
    wide.status = "REMOVED";
    const selected = selectCurrentFirewallRule([mqtt, wide]);
    assert.equal(selected, mqtt);
    assert.equal(canReleaseFirewallRule(selected), status === "FAILED");
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
