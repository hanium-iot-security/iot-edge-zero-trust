# Packet IF bounded development inputs v3

This offline path preserves original Session states and candidate approval flags.
It does not activate a model or label unexplained alerts normal. The v1/v2 whole-
Session contracts remain unchanged. v3 normal inputs use `packet-bounded-normal-v1`;
inherited attack sessions retain their original v2 policy and provenance.

## Export

Use the existing `python -m ai.export_packet_if_dataset` command with `--spec`,
`--output`, and `--manifest-output`. A spec with this schema selects the explicit
bounded path. Do not supply `--db-snapshot`: each source pins its own immutable DB.
The spec and both new output files must share a directory. Outputs never overwrite
an existing file. Failed publication removes only newly created output files.

```json
{
  "schema_version": "packet-bounded-export-v1",
  "normal_inputs": {"path": "normal/dataset.json", "sha256": "<SHA256>"},
  "capture_context": {"path": "capture-context.json", "sha256": "<SHA256>"},
  "transitions": [],
  "attack_inputs": [{
    "dataset": {"path": "attacks/packet.csv", "sha256": "<SHA256>"},
    "manifest": {"path": "attacks/packet.manifest.json", "sha256": "<SHA256>"}
  }]
}
```

All references are relative to their declared input root, without path escapes.
`normal_inputs` is the existing `mqtt-if-candidate-dataset-v1` manifest. Its role
bindings, request/report links, source QC and per-device firmware/payload evidence
are reused. MQTT's feature-selection filter is not applied to Packet rows.

The capture-context JSON contains exactly `capture_filter` and `source_commits`.
It is a separately retained historical context record, not inferred from traffic
or a claim that a checkout authenticates installed device firmware. Operators must
retain the observation evidence for that record; hashing a statement does not
establish that the statement is true.

Stable roles map as follows: train → Packet train; calibration → Packet validation;
development validation → Packet test. V2's original admission split is preserved;
the mapping is explicit in the derived selections. Development-exposed V2 and
reconnect incidents are not a fresh final holdout. One Capture UUID keeps one role
across devices, Runs and MQTT/Packet data. Original IDs are never renumbered;
v3 row identity is `(session_id, packet_feature_log_id)` across independent DBs.

Export reruns admission into a temporary directory outside the input tree. Both
export and load hash the actual final/candidate DB, PCAP and diagnostics, check
standalone DB integrity, compare selected original rows, reconstruct the full
selected INBOUND grid, and verify Capture eligibility. Reported outside failures
are compared with the final DB. Selected failure, missing window, duplicate, IP
mismatch, maintenance overlap or modified artifact rejects the input. Loader
reconstructs expected rows and provenance without writing QC or modifying sources.
Refreshing CSV/manifest hashes cannot hide changed feature values.

Every normal train/calibration/evaluation role must exist. A trainable dataset also
requires a separate verified v2 attack test source with the same Capture policy.
No attack source means no successful trainable export. This checks input integrity,
not the statistical adequacy of attack coverage. The previous deployed report's two
attack rows do not establish broad attack detection.

## Controlled transitions

Each `transitions` entry has `evidence` (a path/SHA reference) and
`capture_artifacts` (the existing candidate-style list of `segment_id`, `pcap_path`,
`pcap_sha256`, `diagnostics_path`, `diagnostics_sha256`). Its PCAP reference set must
match the evidence's PCAP set exactly. Diagnostics must match actual selected
Segments and original names, window, interface and Capture UUID.

The evidence schema is `packet-normal-transition-evidence-v1`. The complete runnable
example is `tests/test_packet_normal_transition.py::make_evidence`; the adapter
integration example is `tests/test_packet_if_bounded.py::transition_source`.

Supported controlled kinds are `sender_restore`, `public_sender_deploy`,
`power_restart`, and `wifi_mqtt_reconnect`, for `esp32_01`, `esp32_02`, and `pico_01`.
Evidence is limited to one target device per record. Multiple records in the same
Capture may share its existing role and identical final snapshot; they cannot
create independent calibration/test groups. Overlapping duplicate source rows
are rejected.

Evidence includes whole 10-second selection bounds, actual operation record/time,
Capture identity, per-device payload schema, original MQTT raw bytes and pinned
PCAPs, before/after installation attestations with their original observation and
effectivity scope, and separate public-image/readback/runtime/library bytes.
For ESP32, the comparison image is a reproducible retained binary corresponding to
the installed readback; an `.ino` filename or source hash alone is insufficient.
Pico uses `seq`/`uptime_ms` and sensor validity; ESP32 uses `sequence`/`uptime_s`.
Power-preserving reconnects cannot reset sequence/uptime. Declared reset kinds may
reset only at the actual operation boundary; each side remains continuous.

The validator checks actual new TCP handshake and sequence linkage, MQTT 3.1.1
CONNECT → successful CONNACK → QoS0 PUBLISH, raw topic/body identity, complete
reassembled TCP bytes and correspondence to original DB payloads. Current bounded
support is a publish-only sender with exactly two relevant TCP flows. Unsupported
MQTT/control traffic, incomplete streams, RST on the new flow or unverified
installation/runtime scope rejects eligibility. Missing proof remains missing;
historical events may be retained only as development replay cases.

These are consistency checks of supplied evidence, not cryptographic authentication
of an operator's statement or a hardware attestation system. `training_approved`
and `whole_capture_session_approved` remain false. The trainer retains its existing
10-second transform, six features, train-only fitting and normal-validation
threshold selection. Model activation and new collection are separate operations.
