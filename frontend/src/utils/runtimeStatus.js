// Presentation only: never rewrite the API response or infer execution from settings.
export function observationState(data, { failed = false, now = Date.now(), requireFreshness = true } = {}) {
  const observedAt = data?.observed_at ? Date.parse(data.observed_at) : NaN;
  const maxAge = data?.max_age_seconds;
  let freshness;
  if (failed) freshness = "API_ERROR";
  else if (!data) freshness = "MISSING";
  else if (!Number.isFinite(observedAt) || !Number.isFinite(maxAge) || maxAge < 0 || now < observedAt) freshness = "UNKNOWN";
  else if (now - observedAt > maxAge * 1000) freshness = "STALE";
  else if (requireFreshness && data.freshness !== "FRESH") freshness = data.freshness || "UNKNOWN";
  else freshness = "FRESH";
  return { status: freshness === "FRESH" ? data.status || "UNKNOWN" : "UNKNOWN", freshness };
}
