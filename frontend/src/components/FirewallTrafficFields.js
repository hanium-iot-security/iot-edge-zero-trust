import { createElement, Fragment } from "react";

export function getFirewallTrafficLabels(rule) {
  if (rule.scope === "PI_INPUT_IPV4_ALL") {
    return { protocol: "전체 IPv4", port: "모든 포트" };
  }
  return {
    protocol: rule.protocol || "-",
    port: rule.dest_port ?? "-",
  };
}

// Shared by device details, exact release and isolation history.
export default function FirewallTrafficFields({ rule }) {
  const labels = getFirewallTrafficLabels(rule);
  return createElement(
    Fragment,
    null,
    ...[["프로토콜", labels.protocol], ["포트", labels.port]].map(([name, value]) =>
      createElement("div", { key: name },
        createElement("dt", null, name),
        createElement("dd", null, value),
      ),
    ),
  );
}
