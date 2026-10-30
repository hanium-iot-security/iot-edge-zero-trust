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

function hasValue(value) {
  return value !== null && value !== undefined && value !== "";
}

export function findFirewallRulesByTriggerEvent(rules, triggerEventId, context = {}) {
  if (!hasValue(triggerEventId)) return [];
  const matchesTrigger = (rule) => hasValue(rule.trigger_event_id) &&
    String(rule.trigger_event_id) === String(triggerEventId);
  const matched = rules.filter((rule) => matchesTrigger(rule) &&
    (!hasValue(context.deviceId) || String(rule.device_id) === String(context.deviceId)) &&
    (!hasValue(context.sourceIp) || String(rule.source_ip) === String(context.sourceIp)));
  const included = new Set(matched);
  const children = new Map();
  for (const rule of rules) {
    if (!hasValue(rule.source_rule_id)) continue;
    const parentId = String(rule.source_rule_id);
    if (!children.has(parentId)) children.set(parentId, []);
    children.get(parentId).push(rule);
  }
  // Scope extensions may have no trigger. Follow only explicit links whose
  // device and source IP agree, so another isolation cycle cannot be inferred.
  for (let index = 0; index < matched.length; index++) {
    const parent = matched[index];
    if (!hasValue(parent.id)) continue;
    for (const child of children.get(String(parent.id)) || []) {
      if (included.has(child) ||
          (hasValue(child.trigger_event_id) && !matchesTrigger(child)) ||
          !hasValue(parent.device_id) || !hasValue(parent.source_ip) ||
          child.device_id !== parent.device_id || child.source_ip !== parent.source_ip) continue;
      included.add(child);
      matched.push(child);
    }
  }
  return matched;
}

export function findCurrentFirewallRuleByTriggerEvent(rules, triggerEventId, context = {}) {
  return selectCurrentFirewallRule(findFirewallRulesByTriggerEvent(rules, triggerEventId, context));
}

export function canReleaseFirewallRule(rule) {
  return Boolean(rule?.id) && ["APPLIED", "FAILED"].includes(normalizedStatus(rule));
}
