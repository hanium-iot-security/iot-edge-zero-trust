from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from ai.packet_if_phase5_manifest import (
    PacketIFRunManifestReference,
    load_verified_run_manifest,
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
    RunManifest,
    RunStageStatuses,
    ScenarioReference,
    run_manifest_sha256,
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
