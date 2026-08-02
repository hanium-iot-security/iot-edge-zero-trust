# Phase 5 Evaluation Contract

## Scenario Result JSONL

Scenario Result JSONL may contain rows for multiple runs. Exporter validation is
split into two steps.

1. Every row must satisfy the common row contract: `run_id`, `scenario_id`,
   `scenario_status`, and boolean `capture_eligible` are required. When
   `capture_eligible=false`, `capture_exclusion_reason` is required.
2. The current Run Manifest identity is selected by `run_id` and `scenario_id`.
   The `session_id` rule is applied only to selected candidate rows. Captured
   runs require a matching non-empty `session_id`; pre-capture failure runs
   require `session_id` to be null or omitted.

## Evaluation Scope

Official detection classification metrics are emitted only when `detection` is
inside `evaluation_scope` and the row is a valid run. For scopes such as
`DATA_ONLY` and `TRUST_ONLY`, classification is marked
`included_in_official_metrics=false` and does not contribute TP/FP/TN/FN.

Latency rows are also scoped by stage. A `TRUST_ONLY` run may publish trust
latencies, while detection, firewall, and block latencies are omitted.
`DATA_ONLY` publishes no stage latency rows.

## Source Commit Verification

Current exporter provenance records:

```json
{
  "method": "explicit_cli_arg",
  "head_verified": false,
  "dirty_worktree_verified": false
}
```

This means the `source_commit` value is an explicit CLI input and is not yet
verified against local Git `HEAD` or dirty worktree state. The official runner
must add HEAD and dirty-worktree verification before using this field as a fully
verified provenance guarantee.
