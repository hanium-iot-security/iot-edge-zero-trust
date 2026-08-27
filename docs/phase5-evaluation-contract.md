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

## Phase 6-A/6-B Recovery Evidence Reuse

Phase 6-A and Phase 6-B do not introduce a separate evaluation schema for
Recovery or Firewall Release. Official E2E runs continue to use the Phase 5
`RunManifest`, Scenario Result JSONL, artifact references, and read-only SQLite
evaluator.

Recovery evidence is attached through existing provenance fields:

- `artifacts[]` may include the normalized Baseline Recovery JSON artifact and
  its SHA256.
- `artifacts[]` may include Firewall Release Request audit evidence when the
  Worker processed a queued release.
- `matched_ids.firewall_release_request_ids` records the DB request IDs used as
  release evidence. The request body and artifacts must not include administrator
  secrets.
- `external_observations` or Scenario Result rows may record externally observed
  timestamps such as firewall release verification, recovery completion, and
  normal publish resumption when the Scenario Runner owns those observations.
- Detection, Trust, Firewall, and Block matching remain based on session/source
  identity, target device, source IP, observation window, and expected event type.

The evaluator must not infer these facts from similar timestamps alone:

- actual iptables rule existence
- actual MQTT TCP 1883 block
- official Firewall Release
- Baseline Recovery success
- normal MQTT publish resumption after Recovery

If Recovery evidence is missing or ambiguous, the official E2E result should
remain `HOLD`, `NOT_EVALUATED`, or another existing non-success status rather
than adding Phase 6-only pass/fail constants.

Offline Packet IF Dataset v2 provenance remains frozen. The official Phase 6-A
FULL_E2E run must use a new `run_id` and capture `session_id`; production code
must not hard-code specific historical session numbers such as the offline test
session.
