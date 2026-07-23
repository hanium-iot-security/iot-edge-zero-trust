# Phase 4 Trust Policy

Phase 4 Trust Score v2 is implemented in `edge.trust.trust_score_v2`.

The existing MVP `edge.trust.trust_score_service` remains for backward compatibility. Phase 4 code uses `processed_at`, `processing_reason`, `trust_score_history`, and `detector_checkpoints`.

## Processing Range

`apply_trust_score_v2_until()` requires a timezone-aware UTC cutoff with whole-second precision on a 10 second boundary.

Candidate events:

- `processed_at IS NULL`
- `id` is after the `trust_score_v2+detection_events` checkpoint
- `analysis_window_end <= cycle_cutoff` when analysis window metadata exists
- legacy rows without analysis windows may fall back to `detected_at < cycle_cutoff`

The function does not commit or rollback. The caller owns the transaction.

## Incident Family and Representative Events

Events are grouped by:

```text
device_id
analysis_window_start
analysis_window_end
```

Within one device window:

- Same rule incident family is represented once.
- Different rule incident families can be summed.
- AI events are capped to `-15` per window.
- Total window delta is capped to `-30`.
- Trust Score is clamped to `0..100`.

Representative event IDs are stored in `trust_score_history.representative_event_ids_json`.

## Isolation Boundary

Isolation happens only when:

```text
new_score < 30
```

Exactly `30` remains `danger` and is not isolated.

When a device first enters isolation, the same transaction creates:

- one `trust_score_history` row
- one `isolation_history` row with `trust_score_history_id`
- one `firewall_rules` row in `PENDING`

The firewall source IP comes from `devices.ip_address`. If a device has no source IP, the transaction fails rather than creating an invalid firewall row.

Already isolated devices are not scored again. Their events are marked with:

```text
processing_reason = ALREADY_ISOLATED
```

Unregistered or unmapped devices are marked with:

```text
processing_reason = UNMAPPED_DEVICE
```

Unknown or zero-delta event types that cannot affect score are marked with:

```text
processing_reason = UNMAPPED_EVENT_TYPE
```

## Firewall Repository

`edge.trust.firewall_repository` manages DB state only. It does not run iptables.

Supported transitions:

- create `PENDING`
- list due `PENDING`
- `PENDING -> APPLIED`
- transient failure retry
- validation failure to `FAILED`
- manual `FAILED -> PENDING`
- `APPLIED -> REMOVED`

Transient failures retry up to three attempts. The third transient failure moves the row to `FAILED`.

Manual reset currently sets retry count back to `0`.

Active firewall statuses are:

```text
PENDING
APPLIED
```

The DB active unique index remains the final duplicate defense.

## Backend APIs

Backend APIs only read stored state and validate query input.

Backend does not:

- run detectors
- recalculate Trust Score
- choose representative events
- run Firewall Worker
- run iptables

Phase 4 Trust History API reads `trust_score_history` directly and does not sum `detection_events.score_delta`.
