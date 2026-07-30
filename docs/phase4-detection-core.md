# Phase 4 Detection Core

This document describes the Phase 4 Database and Detection Core contracts owned by Hyunsoo.

## Runtime Checkpoint Adapter

Cutover code keeps using `edge.detection.checkpoint_repository` with `sqlite3.Connection`.

Runtime code uses `edge.detection.runtime_checkpoint_repository` with SQLAlchemy `Session`.

Both repositories share `PHASE4_CHECKPOINT_KEYS` from the original checkpoint repository. Runtime code must not redefine or rename checkpoint keys.

The seven Phase 4 keys are:

```text
mqtt_feature_builder+mqtt_logs
mqtt_feature_rule+feature_logs
mqtt_message_rule+mqtt_logs
mqtt_if+feature_logs
packet_rule+packet_feature_logs
packet_if+packet_feature_logs
trust_score_v2+detection_events
```

Runtime repository functions do not call `commit()` or `rollback()`. They participate in the caller transaction.

Runtime checkpoint updates must not move backwards. A stage run that tries to replace an existing `last_completed_window_end` or `last_processed_id` with an older value fails instead of silently overwriting the checkpoint. `last_completed_window_end` must be a timezone-aware UTC timestamp on an exact 10 second boundary.

## MQTT Feature Producer

`edge.features.collect_feature_logs.produce_mqtt_features_until()` creates MQTT feature rows incrementally.

Contract:

- `producer_cutoff` must be timezone-aware UTC.
- `producer_cutoff` must use whole-second precision.
- `producer_cutoff` must align to a 10 second boundary.
- Source rows are read from `mqtt_logs` after the producer checkpoint.
- Source rows must satisfy `received_at < producer_cutoff`.
- Feature windows use `[window_start, window_end)`.
- Phase 4 feature windows are stored as timezone-aware UTC whole-second strings ending in `Z`.
- Current open windows are not processed.
- Feature rows and the `mqtt_feature_builder+mqtt_logs` checkpoint are updated in the same transaction.
- Late source rows older than the completed watermark are consumed and logged as `LATE_SOURCE`, but they do not reopen completed feature windows.
- Empty closed windows advance `last_completed_window_end` when the caller has provided a verified cutoff.

## Detector Contract

`edge.detection.detector_contract` defines:

- `DetectorRunResult`
- `DetectorStage`
- `validate_cycle_window()`

All detector stages receive the same `cycle_range_start` and `cycle_cutoff` from the orchestrator. Stages do not read the current clock internally to choose their processing range.

## MQTT Adapters

Implemented adapters:

- `MqttFeatureRuleStage`
- `MqttMessageRuleStage`
- `MqttIsolationForestStage`
- `PacketRuleDetectorStage`
- `PacketIsolationForestStage`

They keep the existing MQTT rule and Isolation Forest meaning. They add incremental source selection, Phase 4 event writing, deterministic evidence JSON, dedupe keys, and checkpoint updates.

All MQTT adapters use the common event type to incident family mapping in `edge.trust.trust_policy`. Registered device events store `subject_ip` from `devices.ip_address`; unknown-device events may have no subject IP.

Adapter source selection uses the cycle window range as the eligibility boundary. It does not rely only on `source_id > last_processed_id`, so a lower-ID source row for a future window can still be processed when that window becomes eligible.

## Detection Event Writer

`write_detection_event()` inserts Phase 4 events without committing.

Source FK contract:

```text
feature_log_id XOR mqtt_log_id XOR packet_feature_log_id
```

Exactly one source FK must be provided. The source FK must match `source_table` and `source_id`.

Dedupe key format:

```text
{detector_name}:{source_table}:{source_id}:{event_type}:{policy_version}
```

The DB partial unique index remains the final duplicate defense. Duplicate inserts return a duplicate result instead of hiding unrelated constraint errors.

Evidence JSON is deterministic and must not contain secrets, credentials, full payloads, or stack traces.

## Orchestrator Stage Transaction Foundation

`run_detection_cycle()` runs each stage in an independent SQLAlchemy transaction.

If a later stage fails, previously committed stage results are not rolled back. The failed stage transaction is rolled back and the exception is re-raised.

The runtime orchestrator now provides watermark-based cycle boundaries, required
stage barriers, Trust Score invocation, a single-process lock, structured failure
logs, and Packet Rule/Packet IF stage registration.

Packet stages are wrapped by `PacketFeatureReadyStage`. Before a Packet detector
runs, it verifies that the entire cycle range belongs to one Capture Session's
contiguous `PROCESSED`/`EMPTY` prefix. `READY`, `FAILED`, missing windows, and
Session Gaps do not advance Packet checkpoints or Trust. When the Packet layer is
required, the common cycle cutoff is the earlier of the MQTT producer watermark
and the Packet Feature ready-through boundary, so a continuously lagging Packet
extractor does not starve every cycle. Packet IF additionally requires a verified
model artifact path, version, and SHA256 at startup.

Raspberry Pi deployment verification, final Packet IF model training, and
operator-driven Session Gap recovery remain operational follow-up work.

## Detection Orchestrator Runtime

The runtime fixes one `cycle_range_start` and `cycle_cutoff` per cycle and gives
the same range to every enabled stage. Required stages form the completion
barrier. Optional-stage checkpoints do not rewind a later cycle, and an
optional-stage exception is recorded as a structured `STAGE_FAILED` log without
blocking required-stage Trust processing. A required-stage exception still
fails the cycle and prevents Trust invocation.

Events produced late for an already completed window are retained as evidence
with `processing_reason=LATE_EVENT` and are not scored again.

`python -m edge.orchestration.run_detection_orchestrator --status` always
prints all seven Phase 4 checkpoint keys. Missing rows are shown as `MISSING`;
existing rows show their persisted `updated_at` value.
