# Phase 4 Detection Migration and Cutover Base

This document covers Hyunsoo's Phase 4 PR 1 scope only.

## Migration 003

`db/migrations/003_phase4_detection.sql` adds the Phase 4 database contract on top of the existing 001 and 002 schema.

Main changes:

- `detection_events.dedupe_key`
- `detection_events.policy_version`
- Partial unique index on non-null `detection_events.dedupe_key`
- `packet_capture_segments` timing metadata
- Conditional nullable `packet_capture_segments.file_name`
- `isolation_history.trust_score_history_id`
- Partial unique index on non-null `isolation_history.trust_score_history_id`
- `firewall_rules.retry_count`
- `firewall_rules.last_attempted_at`
- `firewall_rules.next_retry_at`

`packet_capture_segments` is rebuilt because SQLite cannot safely relax the existing `file_name NOT NULL` contract and add the new table-level checks with simple `ALTER TABLE` statements.

The migration preserves:

- Existing segment IDs
- Existing session foreign keys
- Existing packet feature foreign keys
- Existing window values
- Existing status and error fields
- Existing autoincrement continuity
- Existing 10 second integer UTC window check
- Existing segment indexes and unique constraints

`FAILED` segments may have `file_name IS NULL`. `READY`, `PROCESSED`, and `EMPTY` rows still require a file name. `LATE_CAPTURE` rows must be `FAILED`, have no file name, no capture timing timestamps, and `captured_duration_seconds = 0`.

## Migration Runner Lifecycle

Migration 003 needs a table rebuild while `packet_feature_logs` references `packet_capture_segments`.

The migration runner handles this migration with an explicit lifecycle:

```text
save current foreign_keys setting
set foreign_keys = OFF before BEGIN
BEGIN
run migration statements
record schema_migrations version 3
PRAGMA foreign_key_check
PRAGMA integrity_check
COMMIT
restore original foreign_keys setting
```

If any step fails, the transaction is rolled back and the original schema and data remain in place.

## Checkpoint Keys

Phase 4 uses the existing `detector_checkpoints` table. The shared key list is defined in `edge.detection.checkpoint_repository`.

```text
mqtt_feature_builder+mqtt_logs
mqtt_feature_rule+feature_logs
mqtt_message_rule+mqtt_logs
mqtt_if+feature_logs
packet_rule+packet_feature_logs
packet_if+packet_feature_logs
trust_score_v2+detection_events
```

Checkpoint repository helpers do not call `commit()` or `rollback()`. Transaction ownership stays with the caller.

## Cutover Initializer

Import path:

```python
edge.detection.phase4_cutover_repository.initialize_phase4_cutover
```

Signature:

```python
def initialize_phase4_cutover(
    database_path: Path,
    phase4_cutover_at: datetime,
) -> Mapping[str, object]:
    ...
```

Input contract:

- `database_path` must already exist.
- `phase4_cutover_at` must be timezone-aware UTC with whole-second precision.
- The function does not run migrations.
- The function does not control systemd, runtime services, or operating system state.

The initializer runs one transaction:

```text
validate input
enable foreign_keys
start consistent snapshot
calculate source watermarks
mark legacy detection events
upsert seven checkpoints
re-read checkpoint rows
compare DB rows with returned summary
commit
```

On failure it rolls back the whole transaction. Partial checkpoint rows and partial legacy event updates must not remain.

## Watermark Policy

MQTT detector checkpoints use an existing verified
`mqtt_feature_builder+mqtt_logs` completion watermark when present. A legacy DB
without that watermark uses `phase4_cutover_at` as the explicit ownership
boundary, so the new producer starts from the next closed Window instead of
replaying legacy `mqtt_logs`. If the existing producer watermark is later than
`phase4_cutover_at`, initialization fails because the DB snapshot is newer than
the declared cutover boundary.

Packet detector checkpoints are calculated from each capture session's contiguous completed prefix:

- Start at `first_window_start`
- Include only `PROCESSED` and `EMPTY`
- Include only windows whose `window_end <= phase4_cutover_at`
- Stop at `READY`, `FAILED`, or a missing 10 second window
- Fail if a contiguous completed packet watermark would exceed `phase4_cutover_at`
- Use feature row IDs only from included segments
- Allow `EMPTY` segments to advance the completed watermark without a source feature ID

Trust Score v2 checkpointing closes legacy detection events before the cutover timestamp by setting:

```text
processed_at = phase4_cutover_at
processing_reason = LEGACY_MIGRATION
```

The initializer does not change legacy event type, detector type, source foreign keys, score delta, or `applied_to_score`.

## PR #24 Boundary

Woomin's PR #24 owns runtime cutover execution:

- Migration runtime
- Backup
- SHA256 verification
- Smoke test
- Rollback
- systemd service transitions
- Cutover result recording

This PR only provides:

- Migration 003
- Checkpoint repository helpers
- `initialize_phase4_cutover()`

PR #24 may import and call the initializer after it applies migrations. This PR does not copy PR #24 files, permanently merge PR #24, execute production cutover, stop services, or modify the production database.
