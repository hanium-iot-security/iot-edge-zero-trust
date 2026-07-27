from __future__ import annotations

import json
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

    manifest: dict[str, object] = {
        "dataset_version": PACKET_IF_DATASET_VERSION,
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
