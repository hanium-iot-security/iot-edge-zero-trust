from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path

import pytest

from ai.packet_if_phase5_manifest import (
    PacketIFRunManifestReference,
    load_verified_run_manifest,
    load_verified_session_manifest,
    normalize_device_ids,
    normalize_optional_ipv4,
    normalize_relative_path,
    validate_run_manifest_identity,
)
from edge.phase5.contracts import (
    RUN_MANIFEST_SCHEMA_VERSION,
    EvaluationScope,
    ExecutionNode,
    ExpectedOutcome,
    ManifestReference,
    ManifestStatus,
    RunManifest,
    RunStageStatuses,
    ScenarioReference,
    run_manifest_sha256,
)
from edge.phase5.verified_collection_contract import (
    VERIFIED_COLLECTION_SCHEMA_VERSION,
    PayloadSchemaProvenance,
    VerifiedCollectionArtifact,
    VerifiedCollectionManifest,
    VerifiedCollectionObservation,
    verified_collection_sha256,
)


SESSION_ID = "11111111-1111-4111-8111-111111111111"


def _run_manifest() -> RunManifest:
    started_at = datetime(2026, 8, 3, tzinfo=timezone.utc)
    return RunManifest(
        run_id="run-packet-flood-01",
        session_id=SESSION_ID,
        scenario=ScenarioReference(scenario_id="packet_flood"),
        target_device_id="esp32_01",
        source_ip="192.168.0.4",
        execution_node=ExecutionNode(node_id="esp32-01", registered=True),
        evaluation_scope=EvaluationScope.FULL_E2E,
        is_active=False,
        started_at=started_at,
        attack_started_at=started_at + timedelta(seconds=5),
        observation_deadline_at=started_at + timedelta(minutes=2),
        ended_at=started_at + timedelta(minutes=1),
        expected_outcome=ExpectedOutcome(
            detection_expected=True,
            trust_score_change_expected=True,
            firewall_expected=True,
            block_expected=True,
            evaluation_scope=EvaluationScope.FULL_E2E,
        ),
        statuses=RunStageStatuses(),
    )


def _write_run_manifest(tmp_path: Path) -> tuple[Path, str]:
    manifest = _run_manifest()
    path = tmp_path / "run-manifest.json"
    path.write_text(manifest.to_json(), encoding="utf-8")
    digest = run_manifest_sha256(manifest)
    Path(f"{path}.sha256").write_text(f"{digest}\n", encoding="ascii")
    return path, digest


def test_load_verified_run_manifest_checks_canonical_hash_and_sidecar(
    tmp_path: Path,
) -> None:
    path, digest = _write_run_manifest(tmp_path)

    manifest = load_verified_run_manifest(path, expected_sha256=digest.upper())

    assert manifest.run_id == "run-packet-flood-01"


def test_load_verified_run_manifest_rejects_manifest_tampering(
    tmp_path: Path,
) -> None:
    path, digest = _write_run_manifest(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + " ", encoding="utf-8")

    # Canonical JSON ignores formatting, so mutate a contract value as well.
    payload = path.read_text(encoding="utf-8").replace(
        '"scenario_id":"packet_flood"',
        '"scenario_id":"port_scan"',
    )
    path.write_text(payload, encoding="utf-8")

    with pytest.raises(ValueError, match="Run Manifest SHA256 mismatch"):
        load_verified_run_manifest(path, expected_sha256=digest)


def test_load_verified_run_manifest_rejects_sidecar_for_another_file(
    tmp_path: Path,
) -> None:
    path, digest = _write_run_manifest(tmp_path)
    Path(f"{path}.sha256").write_text(
        f"{digest}  another-run-manifest.json\n",
        encoding="ascii",
    )

    with pytest.raises(ValueError, match="references the wrong file"):
        load_verified_run_manifest(path, expected_sha256=digest)


def test_validate_run_manifest_identity_checks_packet_if_fields() -> None:
    manifest = _run_manifest()
    reference = PacketIFRunManifestReference(
        run_id=manifest.run_id,
        relative_path="runs/run-packet-flood-01/run-manifest.json",
        schema_version=RUN_MANIFEST_SCHEMA_VERSION,
        sha256=run_manifest_sha256(manifest),
    )

    validate_run_manifest_identity(
        manifest,
        reference,
        session_id=SESSION_ID,
        scenario="packet_flood",
        target_device_id="esp32_01",
        target_source_ip="192.168.0.4",
    )

    with pytest.raises(ValueError, match="source_ip mismatch"):
        validate_run_manifest_identity(
            manifest,
            reference,
            session_id=SESSION_ID,
            scenario="packet_flood",
            target_device_id="esp32_01",
            target_source_ip="192.168.0.5",
        )


@pytest.mark.parametrize(
    "path",
    [
        "/tmp/run.json",
        "../run.json",
        "C:/run.json",
        "runs/../run.json",
        r"runs\..\run-manifest.json",
        r"\\server\share\run-manifest.json",
        "runs/run-manifest.json:stream",
        "runs/CON/run-manifest.json",
        "runs/trailing./run-manifest.json",
        "runs/run?/run-manifest.json",
    ],
)
def test_normalize_relative_path_rejects_unsafe_paths(path: str) -> None:
    with pytest.raises(ValueError):
        normalize_relative_path(path, "relative_path")


def test_normalize_relative_path_uses_portable_posix_form() -> None:
    assert normalize_relative_path(
        r"runs\run-01\run-manifest.json",
        "relative_path",
    ) == "runs/run-01/run-manifest.json"


def test_run_manifest_reference_requires_canonical_filename() -> None:
    manifest = _run_manifest()

    with pytest.raises(ValueError, match="must end with 'run-manifest.json'"):
        PacketIFRunManifestReference(
            run_id=manifest.run_id,
            relative_path="runs/run-packet-flood-01/manifest.json",
            schema_version=RUN_MANIFEST_SCHEMA_VERSION,
            sha256=run_manifest_sha256(manifest),
        )


def test_validate_run_manifest_identity_rejects_null_session_id() -> None:
    manifest = _run_manifest()
    provisional = RunManifest(
        run_id=manifest.run_id,
        session_id=None,
        scenario=manifest.scenario,
        target_device_id=manifest.target_device_id,
        source_ip=manifest.source_ip,
        execution_node=manifest.execution_node,
        evaluation_scope=manifest.evaluation_scope,
        is_active=manifest.is_active,
        started_at=manifest.started_at,
        observation_deadline_at=manifest.observation_deadline_at,
        ended_at=manifest.ended_at,
        expected_outcome=manifest.expected_outcome,
        statuses=manifest.statuses,
        failure_stage="session_correlation",
        failure_reason_code="AWAITING_SESSION_CORRELATION",
        failure_reason="session_id not yet confirmed",
    )
    reference = PacketIFRunManifestReference(
        run_id=manifest.run_id,
        relative_path="runs/run-packet-flood-01/run-manifest.json",
        schema_version=RUN_MANIFEST_SCHEMA_VERSION,
        sha256=run_manifest_sha256(provisional),
    )

    with pytest.raises(ValueError, match="session_id mismatch"):
        validate_run_manifest_identity(
            provisional,
            reference,
            session_id=SESSION_ID,
            scenario="packet_flood",
            target_device_id="esp32_01",
            target_source_ip="192.168.0.4",
        )


def test_phase5_scalar_normalizers_are_strict() -> None:
    assert normalize_optional_ipv4("192.168.0.4", "target_source_ip") == (
        "192.168.0.4"
    )
    assert normalize_device_ids(
        ["esp32_02", "esp32_01"],
        "included_device_ids",
    ) == ("esp32_01", "esp32_02")

    with pytest.raises(ValueError, match="IPv4"):
        normalize_optional_ipv4("2001:db8::1", "target_source_ip")
    with pytest.raises(ValueError, match="duplicates"):
        normalize_device_ids(["esp32_01", "esp32_01"], "included_device_ids")


# --- Verified Collection chain -----------------------------------------------


def _collection_manifest(**overrides) -> VerifiedCollectionManifest:
    started_at = datetime(2026, 8, 3, tzinfo=timezone.utc)
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
        "capture_source_commit_sha": "a" * 40,
        "verification_commit_sha": "b" * 40,
        "capture_interface": "eth0",
        "capture_filter": "tcp or udp",
        "started_at": started_at,
        "first_window_start": started_at,
        "ended_at": started_at + timedelta(minutes=20),
        "verified_at": started_at + timedelta(days=3),
        "segment_count": 2,
        "processed_segment_count": 2,
        "empty_segment_count": 0,
        "eligible_feature_row_count": 2,
        "db_snapshot_sha256": "d" * 64,
        "observation": VerifiedCollectionObservation(feature_packet_count=20),
        "artifacts": (),
    }
    payload.update(overrides)
    if not payload["artifacts"]:
        payload["artifacts"] = (
            VerifiedCollectionArtifact(
                relative_path="evidence/session-snapshot.json",
                artifact_type="session_snapshot",
                size_bytes=3,
                sha256=hashlib.sha256(b"{}\n").hexdigest(),
            ),
        )
    return VerifiedCollectionManifest(**payload)


def _write_run_with_collection(
    tmp_path: Path,
    *,
    collection_overrides: dict | None = None,
    collection_relative_path: str = "verified-collection-manifest.json",
    tamper_collection: bool = False,
    tamper_sidecar: bool = False,
    tamper_evidence: bool = False,
    omit_collection_ref: bool = False,
) -> tuple[Path, PacketIFRunManifestReference]:
    run_dir = tmp_path / "runs" / "verified-normal-stable-train-01"
    (run_dir / "evidence").mkdir(parents=True, exist_ok=True)
    evidence_path = run_dir / "evidence" / "session-snapshot.json"
    evidence_path.write_bytes(b"{}\n")

    collection = _collection_manifest(**(collection_overrides or {}))
    collection_path = run_dir / collection_relative_path
    collection_path.parent.mkdir(parents=True, exist_ok=True)
    collection_path.write_text(collection.to_json(), encoding="utf-8")
    collection_digest = verified_collection_sha256(collection)
    sidecar_value = "e" * 64 if tamper_sidecar else collection_digest
    Path(f"{collection_path}.sha256").write_text(
        f"{sidecar_value}\n",
        encoding="ascii",
    )
    if tamper_collection:
        payload = json.loads(collection_path.read_text(encoding="utf-8"))
        payload["capture_interface"] = "eth1"
        collection_path.write_text(json.dumps(payload), encoding="utf-8")
    if tamper_evidence:
        evidence_path.write_bytes(b"tampered\n")

    started_at = datetime(2026, 8, 3, tzinfo=timezone.utc)
    session_ref = (
        None
        if omit_collection_ref
        else ManifestReference(
            relative_path=collection_relative_path,
            schema_version=VERIFIED_COLLECTION_SCHEMA_VERSION,
            sha256=collection_digest,
        )
    )
    run_manifest = RunManifest(
        run_id="verified-normal-stable-train-01",
        session_id=SESSION_ID,
        scenario=ScenarioReference(scenario_id="normal_stable"),
        target_device_id="esp32_01",
        source_ip="192.168.0.4",
        execution_node=ExecutionNode(node_id="esp32_01", registered=True),
        evaluation_scope=EvaluationScope.DATA_ONLY,
        is_active=False,
        started_at=started_at,
        observation_deadline_at=started_at + timedelta(minutes=20),
        ended_at=started_at + timedelta(minutes=20),
        expected_outcome=ExpectedOutcome(evaluation_scope=EvaluationScope.DATA_ONLY),
        statuses=RunStageStatuses(scenario_status=ManifestStatus.SUCCESS),
        session_manifest_ref=session_ref,
    )
    run_path = run_dir / "run-manifest.json"
    run_path.write_text(run_manifest.to_json(), encoding="utf-8")
    run_digest = run_manifest_sha256(run_manifest)
    Path(f"{run_path}.sha256").write_text(f"{run_digest}\n", encoding="ascii")
    return run_path, PacketIFRunManifestReference(
        run_id=run_manifest.run_id,
        relative_path=(
            "runs/verified-normal-stable-train-01/run-manifest.json"
        ),
        schema_version=RUN_MANIFEST_SCHEMA_VERSION,
        sha256=run_digest,
    )


def _load_chain(run_path: Path, reference, **overrides):
    run = load_verified_run_manifest(run_path, expected_sha256=reference.sha256)
    kwargs = {
        "session_id": SESSION_ID,
        "scenario": "normal_stable",
        "target_device_id": None,
        "target_source_ip": None,
        "included_device_ips": {"esp32_01": "192.168.0.4"},
        "required": True,
    }
    kwargs.update(overrides)
    return load_verified_session_manifest(run_path, run, **kwargs)


def test_dataset_run_reference_verifies_collection_manifest(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(tmp_path)

    collection = _load_chain(run_path, reference)

    assert collection is not None
    assert collection.session_id == SESSION_ID
    assert collection.provenance_mode.value == "VERIFIED_RETROSPECTIVE_IMPORT"


def test_chain_rejects_collection_hash_mismatch(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(tmp_path, tamper_collection=True)

    with pytest.raises(ValueError, match="SHA256 mismatch"):
        _load_chain(run_path, reference)


def test_chain_rejects_collection_sidecar_mismatch(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(tmp_path, tamper_sidecar=True)

    with pytest.raises(ValueError, match="sidecar SHA256 mismatch"):
        _load_chain(run_path, reference)


def test_chain_rejects_evidence_tampering(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(tmp_path, tamper_evidence=True)

    with pytest.raises(ValueError, match="artifact"):
        _load_chain(run_path, reference)


def test_manifest_reference_rejects_dot_dot_relative_path() -> None:
    """The contract layer blocks '..' before the chain loader ever runs."""
    with pytest.raises(ValueError, match=r"\.\."):
        ManifestReference(
            relative_path="evidence/../../escape.json",
            schema_version=VERIFIED_COLLECTION_SCHEMA_VERSION,
            sha256="c" * 64,
        )


def test_chain_rejects_symlink_escaping_run_directory(tmp_path: Path) -> None:
    """A portable-looking name that resolves outside the Run Directory is rejected.

    `ManifestReference` cannot see through symlinks, so the chain loader keeps
    its own containment check after resolving the path.
    """
    run_path, reference = _write_run_with_collection(tmp_path)
    outside = tmp_path / "outside-collection.json"
    outside.write_text("{}", encoding="utf-8")
    link = run_path.parent / "linked-collection.json"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):  # pragma: no cover - platform dependent
        pytest.skip("symlinks are not supported on this filesystem")

    run_manifest = load_verified_run_manifest(
        run_path,
        expected_sha256=reference.sha256,
    )
    hijacked = replace(
        run_manifest,
        session_manifest_ref=ManifestReference(
            relative_path="linked-collection.json",
            schema_version=VERIFIED_COLLECTION_SCHEMA_VERSION,
            sha256="c" * 64,
        ),
    )

    with pytest.raises(ValueError, match="escapes"):
        load_verified_session_manifest(
            run_path,
            hijacked,
            session_id=SESSION_ID,
            scenario="normal_stable",
            target_device_id=None,
            target_source_ip=None,
            included_device_ips={"esp32_01": "192.168.0.4"},
            required=True,
        )


def test_chain_rejects_unsupported_collection_schema_version(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(tmp_path)
    run_manifest = load_verified_run_manifest(
        run_path,
        expected_sha256=reference.sha256,
    )
    wrong_schema = ManifestReference(
        relative_path="verified-collection-manifest.json",
        schema_version="phase5-run-manifest-v1",
        sha256=run_manifest.session_manifest_ref.sha256,
    )
    hijacked = replace(run_manifest, session_manifest_ref=wrong_schema)

    with pytest.raises(ValueError, match="schema version"):
        load_verified_session_manifest(
            run_path,
            hijacked,
            session_id=SESSION_ID,
            scenario="normal_stable",
            target_device_id=None,
            target_source_ip=None,
            included_device_ips={"esp32_01": "192.168.0.4"},
            required=True,
        )


def test_chain_rejects_session_mismatch(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(tmp_path)

    with pytest.raises(ValueError, match="session_id"):
        _load_chain(
            run_path,
            reference,
            session_id="22222222-2222-4222-8222-222222222222",
        )


def test_chain_rejects_scenario_mismatch(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(tmp_path)

    with pytest.raises(ValueError, match="scenario"):
        _load_chain(run_path, reference, scenario="normal_interval_jitter")


def test_chain_rejects_device_mismatch(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(tmp_path)

    with pytest.raises(ValueError, match="included_device_ids"):
        _load_chain(
            run_path,
            reference,
            included_device_ips={"esp32_02": "192.168.0.5"},
        )


def test_chain_requires_reference_when_required(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(
        tmp_path,
        omit_collection_ref=True,
    )

    with pytest.raises(ValueError, match="session_manifest_ref"):
        _load_chain(run_path, reference)


def test_chain_allows_scenario_runner_run_without_reference(tmp_path: Path) -> None:
    run_path, reference = _write_run_with_collection(
        tmp_path,
        omit_collection_ref=True,
    )

    assert _load_chain(run_path, reference, required=False) is None
