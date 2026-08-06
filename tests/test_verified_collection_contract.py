"""Phase 5 Verified Collection Manifest contract tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from edge.phase5.verified_collection_contract import (
    VERIFIED_COLLECTION_SCHEMA_VERSION,
    VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX,
    CollectionMethod,
    PayloadSchemaProvenance,
    ProvenanceMode,
    VerifiedCollectionArtifact,
    VerifiedCollectionManifest,
    VerifiedCollectionObservation,
    load_verified_collection_manifest,
    validate_verified_collection_identity,
    verified_collection_sha256,
)


SESSION_ID = "11111111-1111-4111-8111-111111111111"
ATTACK_SESSION_ID = "23d5dc5b-1e73-44e4-80ed-1d0c12bda7f9"
CAPTURE_COMMIT = "a" * 40
VERIFICATION_COMMIT = "b" * 40
STARTED_AT = datetime(2026, 8, 3, 10, 0, 0, tzinfo=timezone.utc)


def _artifact(
    relative_path: str = "evidence/session-snapshot.json",
    *,
    artifact_type: str = "session_snapshot",
    size_bytes: int = 12,
    sha256: str | None = None,
) -> VerifiedCollectionArtifact:
    return VerifiedCollectionArtifact(
        relative_path=relative_path,
        artifact_type=artifact_type,
        size_bytes=size_bytes,
        sha256=sha256 or ("c" * 64),
    )


def _observation(**overrides) -> VerifiedCollectionObservation:
    payload = {
        "sender_reported_packets": None,
        "gateway_observed_packets": 120,
        "feature_packet_count": 120,
        "observation_gap_packets": None,
        "observation_gap_cause": None,
        "gateway_first_attack_packet_at": None,
    }
    payload.update(overrides)
    return VerifiedCollectionObservation(**payload)


def _manifest(**overrides) -> VerifiedCollectionManifest:
    payload = {
        "run_id": "verified-normal-stable-train-01",
        "session_id": SESSION_ID,
        "collection_slot_id": "normal-stable-train-01",
        "source_capture_group_id": SESSION_ID,
        "split": "train",
        "traffic_label": "normal",
        "scenario": "normal_stable",
        "collection_device_id": "esp32_01",
        "target_device_id": None,
        "target_source_ip": None,
        "included_device_ids": ("esp32_01",),
        "background_traffic_present": False,
        "firmware_version": "phase5-normal-pilot-v1",
        "payload_schema_version": "phase5-normal-payload-v1",
        "payload_schema_provenance": PayloadSchemaProvenance.FIRMWARE_REPORTED,
        "firmware_reported_payload_schema_version": "phase5-normal-payload-v1",
        "normal_policy_version": "phase5-normal-policy-v1.1",
        "capture_source_commit_sha": CAPTURE_COMMIT,
        "verification_commit_sha": VERIFICATION_COMMIT,
        "capture_interface": "eth0",
        "capture_filter": "tcp or udp",
        "started_at": STARTED_AT,
        "first_window_start": STARTED_AT,
        "ended_at": STARTED_AT + timedelta(minutes=20),
        "verified_at": STARTED_AT + timedelta(days=3),
        "segment_count": 120,
        "processed_segment_count": 118,
        "empty_segment_count": 2,
        "eligible_feature_row_count": 118,
        "db_snapshot_sha256": "d" * 64,
        "observation": _observation(),
        "artifacts": (_artifact(),),
    }
    payload.update(overrides)
    return VerifiedCollectionManifest(**payload)


def _write_manifest(
    root: Path,
    manifest: VerifiedCollectionManifest,
    *,
    write_artifacts: bool = True,
    sidecar_sha256: str | None = None,
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    if write_artifacts:
        for artifact in manifest.artifacts:
            destination = root / artifact.relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"x" * artifact.size_bytes)
    path = root / "verified-collection-manifest.json"
    path.write_text(manifest.to_json(), encoding="utf-8")
    digest = sidecar_sha256 or verified_collection_sha256(manifest)
    Path(f"{path}{VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX}").write_text(
        f"{digest}\n",
        encoding="ascii",
    )
    return path


def _write_manifest_with_real_artifacts(root: Path, **overrides) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    evidence = root / "evidence"
    evidence.mkdir(parents=True, exist_ok=True)
    payload = b'{"session": "snapshot"}\n'
    (evidence / "session-snapshot.json").write_bytes(payload)
    artifact = VerifiedCollectionArtifact(
        relative_path="evidence/session-snapshot.json",
        artifact_type="session_snapshot",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
    )
    manifest = _manifest(artifacts=(artifact,), **overrides)
    path = root / "verified-collection-manifest.json"
    path.write_text(manifest.to_json(), encoding="utf-8")
    Path(f"{path}{VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX}").write_text(
        f"{verified_collection_sha256(manifest)}\n",
        encoding="ascii",
    )
    return path


# --- Canonical serialization -------------------------------------------------


def test_verified_collection_round_trip_and_canonical_hash() -> None:
    manifest = _manifest()
    restored = VerifiedCollectionManifest.from_json(manifest.to_json())

    assert restored == manifest
    assert verified_collection_sha256(restored) == verified_collection_sha256(manifest)
    assert manifest.schema_version == VERIFIED_COLLECTION_SCHEMA_VERSION
    assert manifest.provenance_mode is ProvenanceMode.VERIFIED_RETROSPECTIVE_IMPORT
    assert manifest.collection_method is CollectionMethod.MANUAL_HARDWARE


def test_canonical_json_is_key_order_independent() -> None:
    manifest = _manifest()
    payload = json.loads(manifest.to_json())
    shuffled = dict(reversed(list(payload.items())))

    assert verified_collection_sha256(
        VerifiedCollectionManifest.from_dict(shuffled)
    ) == verified_collection_sha256(manifest)


def test_datetimes_serialize_as_utc_z() -> None:
    payload = json.loads(_manifest().to_json())

    assert payload["started_at"] == "2026-08-03T10:00:00Z"
    assert payload["verified_at"] == "2026-08-06T10:00:00Z"


def test_verified_collection_rejects_unknown_fields() -> None:
    payload = json.loads(_manifest().to_json())
    payload["unexpected"] = True

    with pytest.raises(ValueError, match="unknown fields"):
        VerifiedCollectionManifest.from_dict(payload)


def test_verified_collection_rejects_missing_fields() -> None:
    payload = json.loads(_manifest().to_json())
    del payload["capture_source_commit_sha"]

    with pytest.raises(ValueError, match="missing fields"):
        VerifiedCollectionManifest.from_dict(payload)


# --- Field validation --------------------------------------------------------


def test_rejects_non_uuid4_session_id() -> None:
    with pytest.raises(ValueError, match="session_id"):
        _manifest(session_id="not-a-uuid")


def test_rejects_invalid_capture_commit_sha() -> None:
    with pytest.raises(ValueError, match="capture_source_commit_sha"):
        _manifest(capture_source_commit_sha="A" * 40)


def test_rejects_invalid_verification_commit_sha() -> None:
    with pytest.raises(ValueError, match="verification_commit_sha"):
        _manifest(verification_commit_sha="b" * 39)


def test_rejects_invalid_target_source_ip() -> None:
    with pytest.raises(ValueError, match="target_source_ip"):
        _manifest(
            traffic_label="attack",
            split="test",
            target_device_id="esp32_02",
            target_source_ip="192.168.0.999",
            collection_device_id="esp32_02",
            included_device_ids=("esp32_02",),
        )


def test_rejects_duplicate_included_device_ids() -> None:
    with pytest.raises(ValueError, match="included_device_ids"):
        _manifest(included_device_ids=("esp32_01", "esp32_01"))


def test_rejects_empty_included_device_ids() -> None:
    with pytest.raises(ValueError, match="included_device_ids"):
        _manifest(included_device_ids=())


def test_rejects_collection_device_missing_from_included_devices() -> None:
    with pytest.raises(ValueError, match="collection_device_id"):
        _manifest(collection_device_id="esp32_09")


def test_rejects_unknown_split() -> None:
    with pytest.raises(ValueError, match="split"):
        _manifest(split="holdout")


def test_rejects_unknown_traffic_label() -> None:
    with pytest.raises(ValueError, match="traffic_label"):
        _manifest(traffic_label="suspicious")


def test_rejects_unknown_collection_scenario() -> None:
    with pytest.raises(ValueError, match="scenario"):
        _manifest(scenario="mqtt_flood")


def test_normal_manifest_must_not_declare_targets() -> None:
    with pytest.raises(ValueError, match="target_device_id"):
        _manifest(target_device_id="esp32_01")


def test_attack_manifest_requires_targets() -> None:
    with pytest.raises(ValueError, match="target_device_id"):
        _manifest(
            traffic_label="attack",
            split="test",
            scenario="packet_rate_flood",
            collection_device_id="esp32_02",
            included_device_ids=("esp32_02",),
        )


def test_attack_manifest_requires_test_split() -> None:
    with pytest.raises(ValueError, match="attack"):
        _manifest(
            traffic_label="attack",
            split="train",
            scenario="packet_rate_flood",
            collection_device_id="esp32_02",
            target_device_id="esp32_02",
            target_source_ip="192.168.0.5",
            included_device_ids=("esp32_02",),
        )


def test_rejects_timestamp_order_violation() -> None:
    with pytest.raises(ValueError, match="ended_at"):
        _manifest(ended_at=STARTED_AT - timedelta(seconds=1))


def test_rejects_first_window_start_before_started_at() -> None:
    with pytest.raises(ValueError, match="first_window_start"):
        _manifest(first_window_start=STARTED_AT - timedelta(seconds=10))


def test_rejects_verified_at_before_ended_at() -> None:
    with pytest.raises(ValueError, match="verified_at"):
        _manifest(verified_at=STARTED_AT)


def test_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="started_at"):
        _manifest(started_at=datetime(2026, 8, 3, 10, 0, 0))


def test_rejects_segment_count_mismatch() -> None:
    with pytest.raises(ValueError, match="segment_count"):
        _manifest(segment_count=100)


def test_rejects_eligible_rows_of_zero() -> None:
    with pytest.raises(ValueError, match="eligible_feature_row_count"):
        _manifest(eligible_feature_row_count=0)


# --- Artifacts ---------------------------------------------------------------


def test_rejects_unsafe_artifact_relative_path() -> None:
    with pytest.raises(ValueError, match="relative_path"):
        _artifact("../escape.json")


def test_rejects_absolute_artifact_relative_path() -> None:
    with pytest.raises(ValueError, match="relative_path"):
        _artifact("/etc/passwd")


def test_rejects_duplicate_artifact_paths() -> None:
    with pytest.raises(ValueError, match="artifacts"):
        _manifest(artifacts=(_artifact(), _artifact()))


def test_rejects_empty_artifacts() -> None:
    with pytest.raises(ValueError, match="artifacts"):
        _manifest(artifacts=())


# --- Observation -------------------------------------------------------------


def test_session_53_observation_arithmetic() -> None:
    observation = _observation(
        sender_reported_packets=960,
        gateway_observed_packets=880,
        feature_packet_count=880,
        observation_gap_packets=80,
        observation_gap_cause="UNRESOLVED",
    )

    assert observation.observation_gap_packets == 80
    assert observation.observation_gap_cause == "UNRESOLVED"


def test_rejects_inconsistent_observation_gap() -> None:
    with pytest.raises(ValueError, match="observation_gap_packets"):
        _observation(
            sender_reported_packets=960,
            gateway_observed_packets=880,
            feature_packet_count=880,
            observation_gap_packets=70,
            observation_gap_cause="UNRESOLVED",
        )


def test_rejects_gateway_feature_packet_mismatch() -> None:
    with pytest.raises(ValueError, match="feature_packet_count"):
        _observation(gateway_observed_packets=880, feature_packet_count=879)


def test_rejects_observation_gap_without_cause() -> None:
    with pytest.raises(ValueError, match="observation_gap_cause"):
        _observation(
            sender_reported_packets=960,
            gateway_observed_packets=880,
            feature_packet_count=880,
            observation_gap_packets=80,
            observation_gap_cause=None,
        )


def test_retrospective_payload_provenance_forbids_firmware_reported_version() -> None:
    with pytest.raises(ValueError, match="firmware_reported_payload_schema_version"):
        _manifest(
            traffic_label="attack",
            split="test",
            scenario="packet_rate_flood",
            collection_device_id="esp32_02",
            target_device_id="esp32_02",
            target_source_ip="192.168.0.5",
            included_device_ids=("esp32_02",),
            payload_schema_version="phase5-packet-rate-udp-payload-v1",
            payload_schema_provenance=(
                PayloadSchemaProvenance.RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY
            ),
            firmware_reported_payload_schema_version="phase5-packet-rate-udp-payload-v1",
        )


def test_firmware_reported_provenance_requires_reported_version() -> None:
    with pytest.raises(ValueError, match="firmware_reported_payload_schema_version"):
        _manifest(firmware_reported_payload_schema_version=None)


# --- Loading -----------------------------------------------------------------


def test_load_verified_collection_checks_canonical_hash_sidecar_and_artifacts(
    tmp_path: Path,
) -> None:
    path = _write_manifest_with_real_artifacts(tmp_path / "run")
    expected = verified_collection_sha256(
        VerifiedCollectionManifest.from_json(path.read_text(encoding="utf-8"))
    )

    loaded = load_verified_collection_manifest(path, expected_sha256=expected)

    assert loaded.session_id == SESSION_ID
    assert loaded.artifacts[0].artifact_type == "session_snapshot"


def test_load_rejects_canonical_hash_mismatch(tmp_path: Path) -> None:
    path = _write_manifest_with_real_artifacts(tmp_path / "run")

    with pytest.raises(ValueError, match="SHA256 mismatch"):
        load_verified_collection_manifest(path, expected_sha256="f" * 64)


def test_load_rejects_sidecar_mismatch(tmp_path: Path) -> None:
    manifest = _manifest()
    path = _write_manifest(tmp_path / "run", manifest, sidecar_sha256="e" * 64)

    with pytest.raises(ValueError, match="sidecar SHA256 mismatch"):
        load_verified_collection_manifest(
            path,
            expected_sha256=verified_collection_sha256(manifest),
            verify_artifacts=False,
        )


def test_load_rejects_sidecar_referencing_another_file(tmp_path: Path) -> None:
    manifest = _manifest()
    path = _write_manifest(tmp_path / "run", manifest, write_artifacts=False)
    digest = verified_collection_sha256(manifest)
    Path(f"{path}{VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX}").write_text(
        f"{digest}  other-file.json\n",
        encoding="ascii",
    )

    with pytest.raises(ValueError, match="wrong file"):
        load_verified_collection_manifest(
            path,
            expected_sha256=digest,
            verify_artifacts=False,
        )


def test_load_accepts_sidecar_with_matching_filename(tmp_path: Path) -> None:
    manifest = _manifest()
    path = _write_manifest(tmp_path / "run", manifest, write_artifacts=False)
    digest = verified_collection_sha256(manifest)
    Path(f"{path}{VERIFIED_COLLECTION_SHA256_SIDECAR_SUFFIX}").write_text(
        f"{digest}  verified-collection-manifest.json\n",
        encoding="ascii",
    )

    loaded = load_verified_collection_manifest(
        path,
        expected_sha256=digest,
        verify_artifacts=False,
    )

    assert loaded.run_id == manifest.run_id


def test_load_rejects_artifact_size_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "run"
    path = _write_manifest_with_real_artifacts(root)
    (root / "evidence" / "session-snapshot.json").write_bytes(b"short")
    manifest = VerifiedCollectionManifest.from_json(path.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="size"):
        load_verified_collection_manifest(
            path,
            expected_sha256=verified_collection_sha256(manifest),
        )


def test_load_rejects_artifact_sha256_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "run"
    path = _write_manifest_with_real_artifacts(root)
    original = (root / "evidence" / "session-snapshot.json").read_bytes()
    tampered = b"X" + original[1:]
    (root / "evidence" / "session-snapshot.json").write_bytes(tampered)
    manifest = VerifiedCollectionManifest.from_json(path.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="SHA256"):
        load_verified_collection_manifest(
            path,
            expected_sha256=verified_collection_sha256(manifest),
        )


def test_load_rejects_missing_artifact(tmp_path: Path) -> None:
    root = tmp_path / "run"
    path = _write_manifest_with_real_artifacts(root)
    (root / "evidence" / "session-snapshot.json").unlink()
    manifest = VerifiedCollectionManifest.from_json(path.read_text(encoding="utf-8"))

    with pytest.raises(ValueError, match="missing"):
        load_verified_collection_manifest(
            path,
            expected_sha256=verified_collection_sha256(manifest),
        )


def test_load_rejects_wrong_schema_version(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir(parents=True)
    payload = json.loads(_manifest().to_json())
    payload["schema_version"] = "phase5-verified-collection-v2"
    path = root / "verified-collection-manifest.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="schema_version"):
        load_verified_collection_manifest(
            path,
            expected_sha256="a" * 64,
            verify_artifacts=False,
        )


# --- Identity ----------------------------------------------------------------


class _StubRunManifest:
    def __init__(
        self,
        *,
        run_id: str,
        session_id: str,
        scenario_id: str,
        target_device_id: str,
        source_ip: str,
    ) -> None:
        self.run_id = run_id
        self.session_id = session_id
        self.scenario = type("S", (), {"scenario_id": scenario_id})()
        self.target_device_id = target_device_id
        self.source_ip = source_ip


def _stub_run(**overrides) -> _StubRunManifest:
    payload = {
        "run_id": "verified-normal-stable-train-01",
        "session_id": SESSION_ID,
        "scenario_id": "normal_stable",
        "target_device_id": "esp32_01",
        "source_ip": "192.168.0.4",
    }
    payload.update(overrides)
    return _StubRunManifest(**payload)


def test_identity_accepts_matching_normal_run() -> None:
    validate_verified_collection_identity(
        _manifest(),
        run_manifest=_stub_run(),
        session_id=SESSION_ID,
        scenario="normal_stable",
        target_device_id=None,
        target_source_ip=None,
        included_device_ips={"esp32_01": "192.168.0.4"},
    )


def test_identity_rejects_run_id_mismatch() -> None:
    with pytest.raises(ValueError, match="run_id"):
        validate_verified_collection_identity(
            _manifest(),
            run_manifest=_stub_run(run_id="other-run"),
            session_id=SESSION_ID,
            scenario="normal_stable",
            target_device_id=None,
            target_source_ip=None,
            included_device_ips={"esp32_01": "192.168.0.4"},
        )


def test_identity_rejects_session_mismatch() -> None:
    with pytest.raises(ValueError, match="session_id"):
        validate_verified_collection_identity(
            _manifest(),
            run_manifest=_stub_run(),
            session_id=ATTACK_SESSION_ID,
            scenario="normal_stable",
            target_device_id=None,
            target_source_ip=None,
            included_device_ips={"esp32_01": "192.168.0.4"},
        )


def test_identity_rejects_scenario_mismatch() -> None:
    with pytest.raises(ValueError, match="scenario"):
        validate_verified_collection_identity(
            _manifest(),
            run_manifest=_stub_run(scenario_id="normal_stable"),
            session_id=SESSION_ID,
            scenario="normal_interval_jitter",
            target_device_id=None,
            target_source_ip=None,
            included_device_ips={"esp32_01": "192.168.0.4"},
        )


def test_identity_rejects_included_device_mismatch() -> None:
    with pytest.raises(ValueError, match="included_device_ids"):
        validate_verified_collection_identity(
            _manifest(),
            run_manifest=_stub_run(),
            session_id=SESSION_ID,
            scenario="normal_stable",
            target_device_id=None,
            target_source_ip=None,
            included_device_ips={"esp32_02": "192.168.0.5"},
        )


def test_identity_rejects_attack_target_mismatch() -> None:
    manifest = _manifest(
        run_id="verified-packet-rate-flood-test-01",
        session_id=ATTACK_SESSION_ID,
        collection_slot_id="packet-rate-flood-test-01",
        source_capture_group_id=ATTACK_SESSION_ID,
        split="test",
        traffic_label="attack",
        scenario="packet_rate_flood",
        collection_device_id="esp32_02",
        target_device_id="esp32_02",
        target_source_ip="192.168.0.5",
        included_device_ids=("esp32_02",),
        firmware_version="phase5-packet-rate-sender-v2",
        payload_schema_version="phase5-packet-rate-udp-payload-v1",
        payload_schema_provenance=(
            PayloadSchemaProvenance.RETROSPECTIVE_OPERATOR_ATTESTED_WITH_PCAP_INVENTORY
        ),
        firmware_reported_payload_schema_version=None,
    )

    with pytest.raises(ValueError, match="target_source_ip"):
        validate_verified_collection_identity(
            manifest,
            run_manifest=_stub_run(
                run_id="verified-packet-rate-flood-test-01",
                session_id=ATTACK_SESSION_ID,
                scenario_id="packet_rate_flood",
                target_device_id="esp32_02",
                source_ip="192.168.0.5",
            ),
            session_id=ATTACK_SESSION_ID,
            scenario="packet_rate_flood",
            target_device_id="esp32_02",
            target_source_ip="192.168.0.4",
            included_device_ips={"esp32_02": "192.168.0.5"},
        )
