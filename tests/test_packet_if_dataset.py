from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pandas as pd
import pytest

from ai.packet_if_dataset import (
    ATTACK_LABEL,
    NORMAL_LABEL,
    PACKET_IF_DATASET_VERSION,
    TEST_SPLIT,
    TRAIN_SPLIT,
    VALIDATION_SPLIT,
    file_sha256,
    load_packet_if_dataset,
    load_packet_if_manifest,
    session_data_sha256s,
)
from ai.packet_if_phase5_manifest import PACKET_IF_DATASET_VERSION_V1
from edge.phase5.contracts import (
    RUN_MANIFEST_SCHEMA_VERSION,
    EvaluationScope,
    ExecutionNode,
    ExpectedOutcome,
    ManifestStatus,
    RunManifest,
    RunStageStatuses,
    ScenarioReference,
    run_manifest_sha256,
)
from edge.scenarios.run_scenario import ScenarioRunner


SESSION_IDS = {
    "train": "11111111-1111-4111-8111-111111111111",
    "validation": "22222222-2222-4222-8222-222222222222",
    "test_normal": "33333333-3333-4333-8333-333333333333",
    "test_attack": "44444444-4444-4444-8444-444444444444",
}


def _dataset_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for index, session_id in enumerate(SESSION_IDS.values(), start=1):
        rows.append(
            {
                "packet_feature_log_id": index,
                "session_id": session_id,
                "device_id": "esp32_01",
                "direction": "INBOUND",
                "window_start": f"2026-07-23T00:00:{(index - 1) * 10:02d}Z",
                "window_end": f"2026-07-23T00:00:{index * 10:02d}Z",
                "peer_ip": "192.168.1.100",
                "segment_window_start": f"2026-07-23T00:00:{(index - 1) * 10:02d}Z",
                "segment_window_end": f"2026-07-23T00:00:{index * 10:02d}Z",
                "segment_status": "PROCESSED",
                "segment_error_code": None,
                "start_delay_seconds": 0.0,
                "registered_device_id": "esp32_01",
                "registered_ip_address": "192.168.1.100",
                "packet_count": 10 + index,
                "total_bytes": 1_000 + index,
                "avg_packet_size": 100.0,
                "max_packet_size": 120,
                "mean_inter_arrival_time": 0.2,
                "distinct_dest_port_count": 1,
                "captured_duration_seconds": 10.0,
            }
        )
    return rows


def _manifest_sessions() -> list[dict[str, object]]:
    return [
        {
            "session_id": SESSION_IDS["train"],
            "split": TRAIN_SPLIT,
            "traffic_label": NORMAL_LABEL,
            "scenario": "normal_stable",
        },
        {
            "session_id": SESSION_IDS["validation"],
            "split": VALIDATION_SPLIT,
            "traffic_label": NORMAL_LABEL,
            "scenario": "normal_jitter",
        },
        {
            "session_id": SESSION_IDS["test_normal"],
            "split": TEST_SPLIT,
            "traffic_label": NORMAL_LABEL,
            "scenario": "normal_test",
        },
        {
            "session_id": SESSION_IDS["test_attack"],
            "split": TEST_SPLIT,
            "traffic_label": ATTACK_LABEL,
            "scenario": "packet_flood",
            "target_device_id": "esp32_01",
        },
    ]


def _write_dataset_bundle(
    tmp_path: Path,
    *,
    rows: list[dict[str, object]] | None = None,
    sessions: list[dict[str, object]] | None = None,
    manifest_overrides: dict[str, object] | None = None,
) -> tuple[Path, Path]:
    dataset_path = tmp_path / "packet_if.csv"
    pd.DataFrame(rows if rows is not None else _dataset_rows()).to_csv(
        dataset_path,
        index=False,
    )
    session_payloads = (
        sessions if sessions is not None else _manifest_sessions()
    )
    dataset_version = str(
        (manifest_overrides or {}).get(
            "dataset_version",
            PACKET_IF_DATASET_VERSION,
        )
    )
    try:
        per_session_sha256 = session_data_sha256s(dataset_path)
    except ValueError:
        per_session_sha256 = {}
    for session in session_payloads:
        session_id = str(session["session_id"])
        session.setdefault("status", "COMPLETED")
        session.setdefault("capture_interface", "eth0")
        session.setdefault("capture_filter", "tcp or udp")
        session.setdefault("source_commit_sha", "a" * 40)
        session.setdefault("started_at", "2026-07-23T00:00:00Z")
        session.setdefault("first_window_start", "2026-07-23T00:00:00Z")
        session.setdefault("ended_at", "2026-07-23T00:01:00Z")
        session.setdefault("capture_gap_start", None)
        session.setdefault("capture_gap_end", None)
        session.setdefault(
            "devices",
            [{"device_id": "esp32_01", "peer_ip": "192.168.1.100"}],
        )
        session.setdefault(
            "data_sha256",
            per_session_sha256.get(session_id, "0" * 64),
        )
        if dataset_version == PACKET_IF_DATASET_VERSION:
            session.setdefault("collection_slot_id", f"slot-{session_id}")
            session.setdefault("source_capture_group_id", session_id)
            session.setdefault("normal_policy_version", "phase5-normal-policy-v1.1")
            session.setdefault("firmware_version", "phase5-normal-pilot-v1")
            session.setdefault("payload_schema_version", "phase5-normal-payload-v1")
            devices = session.get("devices", [])
            session.setdefault(
                "included_device_ids",
                sorted(
                    {
                        str(device["device_id"])
                        for device in devices
                        if isinstance(device, dict) and "device_id" in device
                    }
                ),
            )
            session.setdefault("background_traffic_present", False)
            target_device_id = session.get("target_device_id")
            target_source_ip = None
            if target_device_id is not None:
                for device in devices:
                    if (
                        isinstance(device, dict)
                        and device.get("device_id") == target_device_id
                    ):
                        target_source_ip = str(device.get("peer_ip"))
                        break
            session.setdefault("target_source_ip", target_source_ip)
            session.setdefault(
                "run_manifest_ref",
                _write_run_manifest(tmp_path, session),
            )

    manifest: dict[str, object] = {
        "dataset_version": dataset_version,
        "capture_policy_version": "packet-capture-policy-v1",
        "capture_policy": {
            "version": "packet-capture-policy-v1",
            "nominal_window_seconds": 10.0,
            "max_start_delay_seconds": 1.0,
            "minimum_duration_seconds": 9.0,
            "epsilon_seconds": 0.01,
            "minimum_coverage_ratio": 0.9,
        },
        "dataset_sha256": file_sha256(dataset_path),
        "sessions": session_payloads,
    }
    if manifest_overrides:
        manifest.update(manifest_overrides)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2),
        encoding="utf-8",
    )
    return dataset_path, manifest_path


def _write_run_manifest(
    root: Path,
    session: dict[str, object],
) -> dict[str, str]:
    session_id = str(session["session_id"])
    run_id = f"run-{session_id}"
    relative_path = f"runs/{run_id}/run-manifest.json"
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    is_attack = session.get("traffic_label") == ATTACK_LABEL
    scope = EvaluationScope.FULL_E2E if is_attack else EvaluationScope.DATA_ONLY
    started_at = datetime(2026, 7, 23, tzinfo=timezone.utc)
    devices = [
        device
        for device in session.get("devices", [])
        if isinstance(device, dict)
    ]
    run_target_device_id = session.get("target_device_id")
    run_source_ip = session.get("target_source_ip")
    if run_target_device_id is None and devices:
        run_target_device_id = devices[0].get("device_id")
        run_source_ip = devices[0].get("peer_ip")
    statuses = RunStageStatuses(scenario_status=ManifestStatus.SUCCESS)
    manifest = RunManifest(
        run_id=run_id,
        session_id=session_id,
        scenario=ScenarioReference(scenario_id=str(session["scenario"])),
        target_device_id=run_target_device_id,
        source_ip=run_source_ip,
        execution_node=ExecutionNode(node_id="test-node", registered=True),
        evaluation_scope=scope,
        is_active=False,
        started_at=started_at,
        observation_deadline_at=started_at + timedelta(minutes=5),
        ended_at=started_at + timedelta(minutes=1),
        expected_outcome=ExpectedOutcome(evaluation_scope=scope),
        statuses=statuses,
    )
    path.write_text(manifest.to_json(), encoding="utf-8")
    digest = run_manifest_sha256(manifest)
    Path(f"{path}.sha256").write_text(f"{digest}\n", encoding="ascii")
    return {
        "run_id": run_id,
        "relative_path": relative_path,
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "sha256": digest,
    }


def test_load_dataset_assigns_splits_and_labels_by_session(tmp_path: Path) -> None:
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path)

    dataset = load_packet_if_dataset(dataset_path, manifest_path)

    assert dataset.session_ids(TRAIN_SPLIT) == (SESSION_IDS["train"],)
    assert dataset.session_ids(VALIDATION_SPLIT) == (SESSION_IDS["validation"],)
    assert set(dataset.session_ids(TEST_SPLIT)) == {
        SESSION_IDS["test_normal"],
        SESSION_IDS["test_attack"],
    }
    assert dataset.train["traffic_label"].tolist() == [NORMAL_LABEL]
    assert set(dataset.test["traffic_label"]) == {NORMAL_LABEL, ATTACK_LABEL}


def test_load_dataset_sorts_rows_deterministically(tmp_path: Path) -> None:
    rows = list(reversed(_dataset_rows()))
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    dataset = load_packet_if_dataset(dataset_path, manifest_path)

    assert dataset.test["session_id"].tolist() == sorted(
        [SESSION_IDS["test_normal"], SESSION_IDS["test_attack"]]
    )


def test_load_dataset_rejects_sha256_mismatch(tmp_path: Path) -> None:
    dataset_path, manifest_path = _write_dataset_bundle(
        tmp_path,
        manifest_overrides={"dataset_sha256": "0" * 64},
    )

    with pytest.raises(ValueError, match="packet dataset SHA256 mismatch"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_session_sha256_mismatch(tmp_path: Path) -> None:
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sessions"][0]["data_sha256"] = "0" * 64
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="Session SHA256 mismatch"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_manifest_requires_full_capture_policy_values(tmp_path: Path) -> None:
    _, manifest_path = _write_dataset_bundle(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    del manifest["capture_policy"]["epsilon_seconds"]
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    with pytest.raises(ValueError, match="epsilon_seconds"):
        load_packet_if_manifest(manifest_path)


def test_manifest_rejects_duplicate_session_id(tmp_path: Path) -> None:
    sessions = _manifest_sessions()
    sessions.append(dict(sessions[0]))
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="duplicate session_id"):
        load_packet_if_manifest(manifest_path)


def test_manifest_requires_lowercase_canonical_uuid4(tmp_path: Path) -> None:
    sessions = _manifest_sessions()
    sessions[0]["session_id"] = "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="canonical UUID4"):
        load_packet_if_manifest(manifest_path)


def test_manifest_requires_every_split(tmp_path: Path) -> None:
    sessions = [
        session
        for session in _manifest_sessions()
        if session["split"] != VALIDATION_SPLIT
    ]
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="missing splits"):
        load_packet_if_manifest(manifest_path)


def test_manifest_rejects_management_traffic_from_training(
    tmp_path: Path,
) -> None:
    sessions = _manifest_sessions()
    sessions[0]["scenario"] = "normal_management_traffic"
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="normal_management_traffic"):
        load_packet_if_manifest(manifest_path)


@pytest.mark.parametrize("split", [TRAIN_SPLIT, VALIDATION_SPLIT])
def test_manifest_rejects_attack_session_outside_test(
    tmp_path: Path,
    split: str,
) -> None:
    sessions = _manifest_sessions()
    for session in sessions:
        if session["split"] == split:
            session["traffic_label"] = ATTACK_LABEL

    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match=f"{split} session must be normal"):
        load_packet_if_manifest(manifest_path)


@pytest.mark.parametrize("missing_label", [NORMAL_LABEL, ATTACK_LABEL])
def test_manifest_requires_normal_and_attack_test_sessions(
    tmp_path: Path,
    missing_label: str,
) -> None:
    sessions = [
        session
        for session in _manifest_sessions()
        if not (
            session["split"] == TEST_SPLIT
            and session["traffic_label"] == missing_label
        )
    ]
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="test split must contain"):
        load_packet_if_manifest(manifest_path)


def test_load_dataset_rejects_unknown_session(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["session_id"] = "55555555-5555-4555-8555-555555555555"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="sessions missing from manifest"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_manifest_session_without_rows(tmp_path: Path) -> None:
    rows = _dataset_rows()[:-1]
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="no rows for manifest sessions"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_unmapped_device(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["device_id"] = None
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="requires mapped device_id"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_outbound_row(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["direction"] = "OUTBOUND"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="only accepts INBOUND"):
        load_packet_if_dataset(dataset_path, manifest_path)


@pytest.mark.parametrize(
    ("field_name", "bad_value", "message"),
    [
        ("segment_status", "FAILED", "status_not_eligible"),
        ("segment_error_code", "LATE_CAPTURE", "error_code_present"),
        ("start_delay_seconds", 2.0, "start_delay_exceeds_policy"),
    ],
)
def test_load_dataset_rejects_capture_policy_ineligible_source_rows(
    tmp_path: Path,
    field_name: str,
    bad_value: object,
    message: str,
) -> None:
    rows = _dataset_rows()
    rows[0][field_name] = bad_value
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match=message):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_segment_window_mismatch(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["segment_window_start"] = "2026-07-23T00:00:10Z"
    rows[0]["segment_window_end"] = "2026-07-23T00:00:20Z"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="must match"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_stale_registered_device_mapping(
    tmp_path: Path,
) -> None:
    rows = _dataset_rows()
    rows[0]["registered_ip_address"] = "192.168.1.200"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="registered_ip_address"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_duplicate_feature_id(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[1]["packet_feature_log_id"] = rows[0]["packet_feature_log_id"]
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="duplicate packet_feature_log_id"):
        load_packet_if_dataset(dataset_path, manifest_path)


@pytest.mark.parametrize("invalid_id", [-1, 1.5, True])
def test_load_dataset_rejects_invalid_feature_id(
    tmp_path: Path,
    invalid_id: object,
) -> None:
    rows = _dataset_rows()
    rows[0]["packet_feature_log_id"] = invalid_id
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(
        ValueError,
        match="packet_feature_log_id must be a non-negative integer",
    ):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_non_ten_second_window(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["window_end"] = "2026-07-23T00:00:09Z"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="exact 10-second intervals"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_applies_packet_feature_validation(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["captured_duration_seconds"] = 0
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(
        ValueError,
        match="captured_duration_below_policy",
    ):
        load_packet_if_dataset(dataset_path, manifest_path)


# ── peer_ip 검증 ──────────────────────────────────────────────────────────────

def test_load_dataset_rejects_missing_peer_ip_column(tmp_path: Path) -> None:
    rows = [{k: v for k, v in row.items() if k != "peer_ip"} for row in _dataset_rows()]
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="missing required columns"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_null_peer_ip(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["peer_ip"] = None
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="non-empty peer_ip"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_invalid_peer_ip(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["peer_ip"] = "not-an-ip"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="peer_ip must be a valid IPv4 address"):
        load_packet_if_dataset(dataset_path, manifest_path)


# ── UTC window 형식 검증 ──────────────────────────────────────────────────────

def test_load_dataset_accepts_canonical_utc_window_boundaries(
    tmp_path: Path,
) -> None:
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path)

    dataset = load_packet_if_dataset(dataset_path, manifest_path)

    assert dataset.train.iloc[0]["window_start"].endswith("00Z")
    assert dataset.train.iloc[0]["window_end"].endswith("10Z")


@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "2026-07-25 12:00:00",          # 공백 구분자
        "2026-07-25T21:00:00+09:00",    # timezone offset
        "2026-07-25T12:00:00.500Z",     # 소수점 초
        "2026-07-25T12:00:00",          # Z 없음
    ],
)
def test_load_dataset_rejects_non_utc_window_format(
    tmp_path: Path,
    bad_timestamp: str,
) -> None:
    rows = _dataset_rows()
    rows[0]["window_start"] = bad_timestamp
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="window_start must be in YYYY-MM-DDTHH:MM:SSZ format"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_non_utc_window_end_format(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["window_end"] = "2026-07-23T09:00:10+09:00"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(
        ValueError,
        match="window_end must be in YYYY-MM-DDTHH:MM:SSZ format",
    ):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_load_dataset_rejects_non_boundary_window_start(tmp_path: Path) -> None:
    rows = _dataset_rows()
    rows[0]["window_start"] = "2026-07-23T00:00:03Z"
    rows[0]["window_end"] = "2026-07-23T00:00:13Z"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, rows=rows)

    with pytest.raises(ValueError, match="window_start must be on a 10-second boundary"):
        load_packet_if_dataset(dataset_path, manifest_path)


# ── target_device_id 계약 ─────────────────────────────────────────────────────

def test_manifest_requires_target_device_id_for_attack_session(tmp_path: Path) -> None:
    sessions = _manifest_sessions()
    for session in sessions:
        if session.get("traffic_label") == ATTACK_LABEL:
            del session["target_device_id"]
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="attack session must specify target_device_id"):
        load_packet_if_manifest(manifest_path)


def test_manifest_rejects_target_device_id_on_normal_session(tmp_path: Path) -> None:
    sessions = _manifest_sessions()
    for session in sessions:
        if session.get("traffic_label") == NORMAL_LABEL:
            session["target_device_id"] = "esp32_01"
            break
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="normal session must not have target_device_id"):
        load_packet_if_manifest(manifest_path)


def test_load_dataset_rejects_attack_row_with_wrong_device_id(tmp_path: Path) -> None:
    rows = _dataset_rows()
    for row in rows:
        if row["session_id"] == SESSION_IDS["test_attack"]:
            row["device_id"] = "esp32_02"
            row["registered_device_id"] = "esp32_02"
    sessions = _manifest_sessions()
    for session in sessions:
        if session["session_id"] == SESSION_IDS["test_attack"]:
            session["devices"] = [
                {
                    "device_id": "esp32_01",
                    "peer_ip": "192.168.1.101",
                },
                {
                    "device_id": "esp32_02",
                    "peer_ip": "192.168.1.100",
                }
            ]
    dataset_path, manifest_path = _write_dataset_bundle(
        tmp_path,
        rows=rows,
        sessions=sessions,
    )

    with pytest.raises(ValueError, match="not matching target_device_id"):
        load_packet_if_dataset(dataset_path, manifest_path)


def test_manifest_v2_records_phase5_session_provenance(tmp_path: Path) -> None:
    _, manifest_path = _write_dataset_bundle(tmp_path)

    manifest = load_packet_if_manifest(manifest_path)
    attack = next(
        session
        for session in manifest.sessions
        if session.traffic_label == ATTACK_LABEL
    )

    assert manifest.dataset_version == PACKET_IF_DATASET_VERSION
    assert manifest.normal_policy_version == "phase5-normal-policy-v1.1"
    assert attack.collection_slot_id == f"slot-{SESSION_IDS['test_attack']}"
    assert attack.source_capture_group_id == SESSION_IDS["test_attack"]
    assert attack.run_manifest_ref is not None
    assert attack.run_manifest_ref.schema_version == RUN_MANIFEST_SCHEMA_VERSION
    assert attack.target_source_ip == "192.168.1.100"
    assert attack.included_device_ids == ("esp32_01",)


def test_manifest_v2_accepts_completed_success_run_manifest_under_dataset_root(
    tmp_path: Path,
) -> None:
    sessions = _manifest_sessions()
    attack = next(
        session
        for session in sessions
        if session["session_id"] == SESSION_IDS["test_attack"]
    )
    attack["scenario"] = "mqtt_abnormal_publish_rate"
    dataset_path, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    run_id = "run-packet-if-test-attack"
    run_manifest_rel = f"runs/{run_id}/run-manifest.json"
    run_manifest_path = tmp_path / run_manifest_rel
    run_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    started_at = datetime(2026, 7, 23, tzinfo=timezone.utc)
    run_manifest = RunManifest(
        run_id=run_id,
        session_id=SESSION_IDS["test_attack"],
        scenario=ScenarioReference(scenario_id="mqtt_abnormal_publish_rate"),
        target_device_id="esp32_01",
        source_ip="192.168.1.100",
        execution_node=ExecutionNode(node_id="unit-test-node", registered=True),
        evaluation_scope=EvaluationScope.FULL_E2E,
        is_active=False,
        started_at=started_at,
        observation_deadline_at=started_at + timedelta(minutes=5),
        ended_at=started_at + timedelta(minutes=1),
        expected_outcome=ExpectedOutcome(evaluation_scope=EvaluationScope.FULL_E2E),
        statuses=RunStageStatuses(scenario_status=ManifestStatus.SUCCESS),
    )
    run_manifest_path.write_text(run_manifest.to_json(), encoding="utf-8")
    digest = run_manifest_sha256(run_manifest)
    Path(f"{run_manifest_path}.sha256").write_text(f"{digest}\n", encoding="ascii")

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    attack_payload = next(
        session
        for session in payload["sessions"]
        if session["session_id"] == SESSION_IDS["test_attack"]
    )
    attack_payload["run_manifest_ref"] = {
        "run_id": run_id,
        "relative_path": run_manifest_rel,
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "sha256": digest,
    }
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    dataset = load_packet_if_dataset(dataset_path, manifest_path)

    assert SESSION_IDS["test_attack"] in set(dataset.test["session_id"])


def test_manifest_v2_rejects_dry_run_run_manifest(tmp_path: Path) -> None:
    sessions = _manifest_sessions()
    attack = next(
        session
        for session in sessions
        if session["session_id"] == SESSION_IDS["test_attack"]
    )
    attack["scenario"] = "mqtt_abnormal_publish_rate"
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    run_id = "run-packet-if-test-attack"
    runner = ScenarioRunner(
        execution_node="unit-test-node",
        execution_node_registered=True,
        runs_root=tmp_path / "runs",
    )
    _, dry_run_manifest = runner.run(
        "mqtt_abnormal_publish_rate",
        run_id=run_id,
        target_device_id="esp32_01",
        source_ip="192.168.1.100",
        session_id=SESSION_IDS["test_attack"],
        dry_run=True,
    )

    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    attack_payload = next(
        session
        for session in payload["sessions"]
        if session["session_id"] == SESSION_IDS["test_attack"]
    )
    attack_payload["run_manifest_ref"] = {
        "run_id": run_id,
        "relative_path": f"runs/{run_id}/run-manifest.json",
        "schema_version": RUN_MANIFEST_SCHEMA_VERSION,
        "sha256": run_manifest_sha256(dry_run_manifest),
    }
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    # dry_run sets ended_at=None (끝나지 않은 실행) AND scenario_status=NOT_EVALUATED.
    # 두 조건 모두 Dataset v2에서 거부 사유이며, ended_at 체크가 먼저 발화한다.
    with pytest.raises(ValueError, match=r"ended_at|scenario_status"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_active_run_manifest(tmp_path: Path) -> None:
    _, manifest_path = _write_dataset_bundle(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    attack_session = next(
        session
        for session in payload["sessions"]
        if session["session_id"] == SESSION_IDS["test_attack"]
    )
    ref = attack_session["run_manifest_ref"]
    run_manifest_path = tmp_path / ref["relative_path"]

    original = RunManifest.from_json(run_manifest_path.read_text(encoding="utf-8"))
    active_manifest = RunManifest(
        run_id=original.run_id,
        session_id=original.session_id,
        scenario=original.scenario,
        target_device_id=original.target_device_id,
        source_ip=original.source_ip,
        execution_node=original.execution_node,
        evaluation_scope=original.evaluation_scope,
        is_active=True,
        started_at=original.started_at,
        observation_deadline_at=original.observation_deadline_at,
        ended_at=None,
        expected_outcome=original.expected_outcome,
        statuses=RunStageStatuses(),
    )
    run_manifest_path.write_text(active_manifest.to_json(), encoding="utf-8")
    new_digest = run_manifest_sha256(active_manifest)
    Path(f"{run_manifest_path}.sha256").write_text(f"{new_digest}\n", encoding="ascii")
    ref["sha256"] = new_digest
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="is_active=True"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_incomplete_run_manifest(tmp_path: Path) -> None:
    _, manifest_path = _write_dataset_bundle(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    attack_session = next(
        session
        for session in payload["sessions"]
        if session["session_id"] == SESSION_IDS["test_attack"]
    )
    ref = attack_session["run_manifest_ref"]
    run_manifest_path = tmp_path / ref["relative_path"]

    original = RunManifest.from_json(run_manifest_path.read_text(encoding="utf-8"))
    incomplete_manifest = RunManifest(
        run_id=original.run_id,
        session_id=original.session_id,
        scenario=original.scenario,
        target_device_id=original.target_device_id,
        source_ip=original.source_ip,
        execution_node=original.execution_node,
        evaluation_scope=original.evaluation_scope,
        is_active=False,
        started_at=original.started_at,
        observation_deadline_at=original.observation_deadline_at,
        ended_at=None,
        expected_outcome=original.expected_outcome,
        statuses=RunStageStatuses(),
    )
    run_manifest_path.write_text(incomplete_manifest.to_json(), encoding="utf-8")
    new_digest = run_manifest_sha256(incomplete_manifest)
    Path(f"{run_manifest_path}.sha256").write_text(f"{new_digest}\n", encoding="ascii")
    ref["sha256"] = new_digest
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="ended_at"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_not_evaluated_scenario_status(tmp_path: Path) -> None:
    _, manifest_path = _write_dataset_bundle(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    attack_session = next(
        session
        for session in payload["sessions"]
        if session["session_id"] == SESSION_IDS["test_attack"]
    )
    ref = attack_session["run_manifest_ref"]
    run_manifest_path = tmp_path / ref["relative_path"]

    original = RunManifest.from_json(run_manifest_path.read_text(encoding="utf-8"))
    # completed (is_active=False, ended_at set) but NOT_EVALUATED — simulates dry-run or
    # a run that finished without a successful scenario outcome
    not_evaluated_manifest = RunManifest(
        run_id=original.run_id,
        session_id=original.session_id,
        scenario=original.scenario,
        target_device_id=original.target_device_id,
        source_ip=original.source_ip,
        execution_node=original.execution_node,
        evaluation_scope=original.evaluation_scope,
        is_active=False,
        started_at=original.started_at,
        observation_deadline_at=original.observation_deadline_at,
        ended_at=original.ended_at,
        expected_outcome=original.expected_outcome,
        statuses=RunStageStatuses(),
    )
    run_manifest_path.write_text(not_evaluated_manifest.to_json(), encoding="utf-8")
    new_digest = run_manifest_sha256(not_evaluated_manifest)
    Path(f"{run_manifest_path}.sha256").write_text(f"{new_digest}\n", encoding="ascii")
    ref["sha256"] = new_digest
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="scenario_status"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_source_capture_group_across_splits(
    tmp_path: Path,
) -> None:
    sessions = _manifest_sessions()
    shared_group = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    sessions[0]["source_capture_group_id"] = shared_group
    sessions[1]["source_capture_group_id"] = shared_group
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="must not cross Dataset splits"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_duplicate_collection_slot(tmp_path: Path) -> None:
    sessions = _manifest_sessions()
    sessions[0]["collection_slot_id"] = "normal-slot-01"
    sessions[1]["collection_slot_id"] = "normal-slot-01"
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="duplicate collection_slot_id"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_run_manifest_identity_mismatch(tmp_path: Path) -> None:
    _, manifest_path = _write_dataset_bundle(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["sessions"][0]["run_manifest_ref"]["run_id"] = "different-run-id"
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="Run Manifest run_id mismatch"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_run_manifest_sidecar_mismatch(tmp_path: Path) -> None:
    _, manifest_path = _write_dataset_bundle(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    relative_path = payload["sessions"][0]["run_manifest_ref"]["relative_path"]
    Path(f"{tmp_path / relative_path}.sha256").write_text(
        f"{'0' * 64}\n",
        encoding="ascii",
    )

    with pytest.raises(ValueError, match="sidecar SHA256 mismatch"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_exported_device_missing_from_collection(
    tmp_path: Path,
) -> None:
    sessions = _manifest_sessions()
    sessions[0]["included_device_ids"] = ["esp32_02"]
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="included_device_ids"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_mixed_normal_policy_versions(tmp_path: Path) -> None:
    sessions = _manifest_sessions()
    sessions[0]["normal_policy_version"] = "phase5-normal-policy-v1.0"
    sessions[1]["normal_policy_version"] = "phase5-normal-policy-v1.1"
    _, manifest_path = _write_dataset_bundle(tmp_path, sessions=sessions)

    with pytest.raises(ValueError, match="one normal_policy_version"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v2_rejects_awaiting_session_correlation_run_manifest(
    tmp_path: Path,
) -> None:
    _, manifest_path = _write_dataset_bundle(tmp_path)
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    session = payload["sessions"][0]
    ref = session["run_manifest_ref"]
    run_manifest_path = tmp_path / ref["relative_path"]

    original = RunManifest.from_json(run_manifest_path.read_text(encoding="utf-8"))
    provisional = RunManifest(
        run_id=original.run_id,
        session_id=None,
        scenario=original.scenario,
        target_device_id=original.target_device_id,
        source_ip=original.source_ip,
        execution_node=original.execution_node,
        evaluation_scope=original.evaluation_scope,
        is_active=original.is_active,
        started_at=original.started_at,
        observation_deadline_at=original.observation_deadline_at,
        ended_at=original.ended_at,
        expected_outcome=original.expected_outcome,
        statuses=original.statuses,
        failure_stage="session_correlation",
        failure_reason_code="AWAITING_SESSION_CORRELATION",
        failure_reason="session_id not yet confirmed",
    )
    provisional_json = provisional.to_json()
    run_manifest_path.write_text(provisional_json, encoding="utf-8")
    new_digest = run_manifest_sha256(provisional)
    Path(f"{run_manifest_path}.sha256").write_text(f"{new_digest}\n", encoding="ascii")
    ref["sha256"] = new_digest
    manifest_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="session_id mismatch"):
        load_packet_if_manifest(manifest_path)


def test_manifest_v1_remains_readable_for_local_fixtures(tmp_path: Path) -> None:
    _, manifest_path = _write_dataset_bundle(
        tmp_path,
        manifest_overrides={"dataset_version": PACKET_IF_DATASET_VERSION_V1},
    )

    manifest = load_packet_if_manifest(manifest_path)

    assert manifest.dataset_version == PACKET_IF_DATASET_VERSION_V1
    assert manifest.normal_policy_version is None
    assert all(session.run_manifest_ref is None for session in manifest.sessions)
