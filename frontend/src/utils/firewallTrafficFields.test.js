import assert from "node:assert/strict";
import test from "node:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import FirewallTrafficFields from "../components/FirewallTrafficFields.js";

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
    "<dl><div><dt>Protocol</dt><dd>전체 IPv4</dd></div><div><dt>Port</dt><dd>모든 포트</dd></div></dl>");
});

test("legacy API rule without scope retains its existing TCP 1883 fields", () => {
  const response = { items: [{ id: 20, protocol: "tcp", dest_port: 1883 }] };
  const expected = "<dl><div><dt>Protocol</dt><dd>tcp</dd></div><div><dt>Port</dt><dd>1883</dd></div></dl>";
  assert.equal(renderRule(response.items[0]), expected);
  assert.equal(renderRule({ ...response.items[0], scope: "MQTT_IPV4_TCP_1883" }), expected);
});

test("missing fields or an unknown scope are not presented as all IPv4", () => {
  for (const rule of [{}, { scope: "UNKNOWN", protocol: null, dest_port: null }]) {
    assert.equal(renderRule(rule),
      "<dl><div><dt>Protocol</dt><dd>-</dd></div><div><dt>Port</dt><dd>-</dd></div></dl>");
  }
});
