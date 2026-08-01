from __future__ import annotations

from datetime import datetime, timezone
import json

import pytest

from edge.phase5.contracts import (
    RUN_MANIFEST_SCHEMA_VERSION,
    EvaluationScope,
    ExpectedOutcome,
    ManifestStatus,
    RunArtifact,
    RunManifest,
    RunManifestValidationError,
    RunStageStatuses,
    validate_run_manifest_dict,
    validate_single_active_run,
)


def _manifest_dict(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "run_manifest_schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "run_id": "run-20260801-001",
        "session_id": "11111111-1111-4111-8111-111111111111",
        "scenario": {
            "scenario_id": "device-id-mismatch",
            "scenario_name": "Device ID mismatch",
            "scenario_version": "phase5-scenarios-v1",
        },
        "target_device_id": "esp32_01",
        "source_ip": "192.168.0.50",
        "execution_node": {
            "node_id": "pi-lab-01",
            "hostname": "iot-edge-pi-01",
            "registered": True,
        },
        "evaluation_scope": "FULL_RUN",
        "is_active": True,
        "started_at": "2026-08-01T01:00:00Z",
        "attack_started_at": "2026-08-01T01:00:05Z",
        "observation_deadline_at": "2026-08-01T01:01:00Z",
        "ended_at": "2026-08-01T01:01:30Z",
        "external_observations": {
            "operator_confirmed_at": "2026-08-01T01:01:20Z",
        },
        "expected_outcome": {
            "expected_event_types": [
                "PACKET_RATE_ANOMALY",
                "DEVICE_ID_MISMATCH",
            ],
            "detection_expected": True,
            "trust_score_change_expected": True,
            "firewall_expected": True,
            "block_expected": True,
            "evaluation_scope": "FULL_RUN",
        },
        "statuses": {
            "scenario_status": "SUCCESS",
            "detection_status": "SUCCESS",
            "trust_status": "SUCCESS",
            "firewall_status": "SUCCESS",
            "block_status": "SUCCESS",
            "data_status": "SUCCESS",
            "final_status": "SUCCESS",
        },
        "matched_ids": {
            "detection_event_ids": None,
            "trust_score_history_ids": [],
            "firewall_rule_ids": [3, 1, 3],
            "trigger_event_ids": [2],
        },
        "artifacts": [
            {
                "artifact_type": "evaluation_report",
                "relative_path": "reports/run-20260801-001.json",
                "size_bytes": 128,
                "sha256": "A" * 64,
            },
        ],
        "session_manifest_ref": "normal-sessions/session-manifest.json",
    }
    payload.update(overrides)
    return payload


def test_valid_manifest_with_required_fields_passes_validation() -> None:
    payload = _manifest_dict()

    result = validate_run_manifest_dict(payload)
    manifest = RunManifest.from_dict(payload)

    assert result.is_valid
    assert result.errors == ()
    assert manifest.run_manifest_schema_version == RUN_MANIFEST_SCHEMA_VERSION
    assert manifest.run_id == "run-20260801-001"
    assert manifest.execution_node.registered is True


def test_manifest_json_round_trip_is_stable() -> None:
    manifest = RunManifest.from_dict(_manifest_dict())

    payload_json = manifest.to_json()
    loaded = RunManifest.from_json(payload_json)

    assert loaded == manifest
    assert loaded.to_json() == payload_json
    assert json.loads(payload_json)["run_manifest_schema_version"] == (
        RUN_MANIFEST_SCHEMA_VERSION
    )


def test_unsupported_schema_version_is_rejected() -> None:
    payload = _manifest_dict(run_manifest_schema_version="phase5-run-manifest-v0")

    result = validate_run_manifest_dict(payload)

    assert not result.is_valid
    assert result.errors[0].code == "UNSUPPORTED_SCHEMA_VERSION"
    with pytest.raises(RunManifestValidationError, match="schema version"):
        RunManifest.from_dict(payload)


@pytest.mark.parametrize("field_name", ["run_id", "session_id"])
def test_empty_run_id_and_session_id_are_rejected(field_name: str) -> None:
    payload = _manifest_dict(**{field_name: "   "})

    result = validate_run_manifest_dict(payload)

    assert not result.is_valid
    assert any(error.field_path == field_name for error in result.errors)


def test_naive_datetime_is_rejected() -> None:
    payload = _manifest_dict(started_at=datetime(2026, 8, 1, 1, 0, 0))

    result = validate_run_manifest_dict(payload)

    assert not result.is_valid
    assert any(
        error.code == "INVALID_TIMESTAMP" and error.field_path == "started_at"
        for error in result.errors
    )


def test_utc_timestamp_serialization_uses_z_suffix() -> None:
    manifest = RunManifest.from_dict(
        _manifest_dict(
            started_at=datetime(2026, 8, 1, 1, 0, 0, tzinfo=timezone.utc),
            observation_deadline_at=datetime(
                2026,
                8,
                1,
                1,
                1,
                0,
                tzinfo=timezone.utc,
            ),
            ended_at=None,
        )
    )

    serialized = manifest.to_dict()

    assert serialized["started_at"] == "2026-08-01T01:00:00Z"
    assert serialized["observation_deadline_at"] == "2026-08-01T01:01:00Z"
    assert serialized["ended_at"] is None


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("observation_deadline_at", "2026-08-01T00:59:59Z"),
        ("ended_at", "2026-08-01T00:59:59Z"),
    ],
)
def test_start_deadline_and_end_time_order_is_validated(
    field_name: str,
    value: str,
) -> None:
    payload = _manifest_dict(**{field_name: value})

    result = validate_run_manifest_dict(payload)

    assert not result.is_valid
    assert any(
        error.code == "INVALID_TIME_ORDER" and error.field_path == field_name
        for error in result.errors
    )


def test_two_simultaneously_active_runs_are_rejected() -> None:
    first = RunManifest.from_dict(_manifest_dict(run_id="run-a"))
    second = RunManifest.from_dict(_manifest_dict(run_id="run-b"))

    result = validate_single_active_run([first, second])

    assert not result.is_valid
    assert result.errors[0].code == "MULTIPLE_ACTIVE_RUNS"


def test_sha256_format_is_validated() -> None:
    payload = _manifest_dict(
        artifacts=[
            {
                "artifact_type": "evaluation_report",
                "relative_path": "reports/run.json",
                "size_bytes": 128,
                "sha256": "not-a-sha",
            },
        ],
    )

    result = validate_run_manifest_dict(payload)

    assert not result.is_valid
    assert any(error.code == "INVALID_SHA256" for error in result.errors)


def test_negative_file_size_is_rejected() -> None:
    payload = _manifest_dict(
        artifacts=[
            {
                "artifact_type": "evaluation_report",
                "relative_path": "reports/run.json",
                "size_bytes": -1,
                "sha256": "a" * 64,
            },
        ],
    )

    result = validate_run_manifest_dict(payload)

    assert not result.is_valid
    assert any(error.code == "INVALID_SIZE" for error in result.errors)


@pytest.mark.parametrize(
    "relative_path",
    [
        "/tmp/run.json",
        "C:/tmp/run.json",
        "reports/../secret.json",
        "..\\secret.json",
    ],
)
def test_absolute_and_parent_escape_paths_are_rejected(relative_path: str) -> None:
    payload = _manifest_dict(
        artifacts=[
            {
                "artifact_type": "evaluation_report",
                "relative_path": relative_path,
                "size_bytes": 128,
                "sha256": "a" * 64,
            },
        ],
    )

    result = validate_run_manifest_dict(payload)

    assert not result.is_valid
    assert any(error.code == "INVALID_RELATIVE_PATH" for error in result.errors)


def test_matched_ids_preserve_null_and_empty_list_meaning() -> None:
    manifest = RunManifest.from_dict(
        _manifest_dict(
            matched_ids={
                "detection_event_ids": None,
                "trust_score_history_ids": [],
                "firewall_rule_ids": [7],
                "trigger_event_ids": None,
            }
        )
    )

    matched_ids = manifest.to_dict()["matched_ids"]

    assert matched_ids["detection_event_ids"] is None
    assert matched_ids["trust_score_history_ids"] == []
    assert matched_ids["firewall_rule_ids"] == [7]
    assert matched_ids["trigger_event_ids"] is None


def test_duplicate_ids_are_deduped_and_serialized_deterministically() -> None:
    manifest = RunManifest.from_dict(
        _manifest_dict(
            matched_ids={
                "detection_event_ids": [5, 2, 5, 3],
                "trust_score_history_ids": [9, 9],
                "firewall_rule_ids": [],
                "trigger_event_ids": [4, 1, 4],
            }
        )
    )

    first_json = manifest.to_json()
    second_json = manifest.to_json()
    matched_ids = manifest.to_dict()["matched_ids"]

    assert matched_ids["detection_event_ids"] == [2, 3, 5]
    assert matched_ids["trust_score_history_ids"] == [9]
    assert matched_ids["trigger_event_ids"] == [1, 4]
    assert first_json == second_json


def test_expected_outcome_and_stage_statuses_serialize_as_contract_values() -> None:
    manifest = RunManifest(
        run_id="run-status",
        session_id="session-status",
        scenario={"scenario_id": "packet-flood"},
        target_device_id="esp32_01",
        source_ip="192.168.0.50",
        execution_node={"node_id": "pi-lab-01", "registered": True},
        evaluation_scope=EvaluationScope.FULL_RUN,
        is_active=False,
        started_at=datetime(2026, 8, 1, 1, 0, 0, tzinfo=timezone.utc),
        observation_deadline_at=datetime(2026, 8, 1, 1, 1, 0, tzinfo=timezone.utc),
        expected_outcome=ExpectedOutcome(
            expected_event_types=("PACKET_RATE_ANOMALY", "DEVICE_ID_MISMATCH"),
            detection_expected=True,
            trust_score_change_expected=True,
            firewall_expected=False,
            block_expected=False,
            evaluation_scope=EvaluationScope.FULL_RUN,
        ),
        statuses=RunStageStatuses(
            scenario_status=ManifestStatus.SUCCESS,
            detection_status=ManifestStatus.SUCCESS,
            trust_status=ManifestStatus.HOLD,
            firewall_status=ManifestStatus.NOT_APPLICABLE,
            block_status=ManifestStatus.NOT_APPLICABLE,
            data_status=ManifestStatus.CAPTURE_INELIGIBLE,
            final_status=ManifestStatus.HOLD,
        ),
    )

    payload = manifest.to_dict()

    assert payload["expected_outcome"]["expected_event_types"] == [
        "DEVICE_ID_MISMATCH",
        "PACKET_RATE_ANOMALY",
    ]
    assert payload["statuses"]["trust_status"] == "HOLD"
    assert payload["statuses"]["data_status"] == "CAPTURE_INELIGIBLE"


def test_packet_if_dataset_manifest_is_not_embedded_in_run_manifest() -> None:
    manifest = RunManifest.from_dict(_manifest_dict())
    payload = manifest.to_dict()

    assert "packet_if_dataset_manifest" not in payload
    assert "dataset_manifest" not in payload
    assert payload["session_manifest_ref"] == "normal-sessions/session-manifest.json"

    invalid = _manifest_dict(packet_if_dataset_manifest={"sessions": []})
    result = validate_run_manifest_dict(invalid)
    assert any(
        error.code == "UNKNOWN_FIELD"
        and error.field_path == "$.packet_if_dataset_manifest"
        for error in result.errors
    )


def test_invalid_manifest_reports_field_level_errors() -> None:
    payload = _manifest_dict(
        run_id=" ",
        session_id="",
        started_at=datetime(2026, 8, 1, 1, 0, 0),
        unknown_top_level="value",
        execution_node={
            "node_id": "",
            "registered": "yes",
        },
    )

    result = validate_run_manifest_dict(payload)
    error_map = {(error.code, error.field_path) for error in result.errors}

    assert not result.is_valid
    assert ("UNKNOWN_FIELD", "$.unknown_top_level") in error_map
    assert ("INVALID_STRING", "run_id") in error_map
    assert ("INVALID_STRING", "session_id") in error_map
    assert ("INVALID_TIMESTAMP", "started_at") in error_map
    assert ("INVALID_STRING", "execution_node.node_id") in error_map
    assert ("INVALID_BOOL", "execution_node.registered") in error_map
