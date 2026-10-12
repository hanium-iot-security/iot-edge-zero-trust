function normalizedStatus(rule) {
  return String(rule?.status || "").trim().toUpperCase();
}

function ruleTime(rule) {
  return new Date(rule.updated_at || rule.created_at || 0).getTime() || 0;
}

// A released scope must not hide another scope that still needs attention.
export function selectCurrentFirewallRule(rules) {
  return rules.reduce((selected, rule) => {
    if (!selected) return rule;
    const unresolved = normalizedStatus(rule) !== "REMOVED";
    const selectedUnresolved = normalizedStatus(selected) !== "REMOVED";
    if (unresolved !== selectedUnresolved) return unresolved ? rule : selected;
    const difference = ruleTime(rule) - ruleTime(selected);
    if (difference > 0 || (difference === 0 && Number(rule.id) > Number(selected.id))) {
      return rule;
    }
    return selected;
  }, null);
}

export function getCurrentFirewallRuleMap(rules) {
  const result = new Map();
  for (const rule of rules) {
    if (!rule.device_id) continue;
    const existing = result.get(rule.device_id);
    result.set(rule.device_id, selectCurrentFirewallRule(existing ? [existing, rule] : [rule]));
  }
  return result;
}

export function findCurrentFirewallRuleByTriggerEvent(rules, triggerEventId) {
  if (triggerEventId === null || triggerEventId === undefined || triggerEventId === "") {
    return null;
  }
  return selectCurrentFirewallRule(rules.filter((rule) =>
    rule.trigger_event_id !== null && rule.trigger_event_id !== undefined &&
    rule.trigger_event_id !== "" && String(rule.trigger_event_id) === String(triggerEventId)
  ));
}

export function canReleaseFirewallRule(rule) {
  return Boolean(rule?.id) && ["APPLIED", "FAILED"].includes(normalizedStatus(rule));
}
