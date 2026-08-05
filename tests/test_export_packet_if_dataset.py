from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from ai import export_packet_if_dataset as exporter
from ai.export_packet_if_dataset import (
    PacketIFSessionAnnotation,
    export_packet_if_dataset,
)
from ai.packet_if_dataset import DATASET_REQUIRED_COLUMNS, file_sha256
from ai.packet_if_phase5_manifest import PacketIFRunManifestReference
from db.migration_runner import MIGRATIONS_DIR, apply_migrations
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
from edge.packet.capture_policy import CapturePolicy


SESSION_ID = "11111111-1111-4111-8111-111111111111"
OTHER_SESSION_ID = "22222222-2222-4222-8222-222222222222"


def _export(
    db,
    *,
    output_path: Path,
    session_ids: list[str],
    target_device_ids: dict[str, str] | None = None,
):
    targets = target_device_ids or {}
    annotations: list[PacketIFSessionAnnotation] = []
    for session_id in session_ids:
        target_device_id = targets.get(session_id)
        target_source_ip = {
            "esp32_01": "192.168.0.4",
            "esp32_02": "192.168.0.5",
        }.get(target_device_id or "")
        scenario = "packet_flood" if target_device_id else "normal_stable"
        run_target_device_id = target_device_id or "esp32_01"
        run_source_ip = target_source_ip or "192.168.0.4"
        run_path, run_reference = _write_run_manifest(
            output_path.parent,
            session_id=session_id,
            scenario=scenario,
            target_device_id=run_target_device_id,
            source_ip=run_source_ip,
            is_attack=target_device_id is not None,
        )
        annotations.append(
            PacketIFSessionAnnotation(
                session_id=session_id,
                split="test" if target_device_id else "train",
                traffic_label="attack" if target_device_id else "normal",
                scenario=scenario,
                target_device_id=target_device_id,
                collection_slot_id=f"slot-{session_id}",
                source_capture_group_id=session_id,
                run_manifest_ref=run_reference,
                run_manifest_path=run_path,
                normal_policy_version="phase5-normal-policy-v1.1",
                firmware_version="phase5-normal-pilot-v1",
                payload_schema_version="phase5-normal-payload-v1",
                target_source_ip=target_source_ip,
                included_device_ids=("esp32_01", "esp32_02"),
                background_traffic_present=target_device_id is not None,
            )
        )
    return export_packet_if_dataset(
        db,
        output_path=output_path,
        manifest_path=output_path.with_suffix(".manifest.json"),
        session_annotations=annotations,
        capture_filter="tcp or udp",
        source_commit_sha="a" * 40,
        capture_policy=CapturePolicy(),
    )


def _write_run_manifest(
    root: Path,
    *,
    session_id: str,
    scenario: str,
    target_device_id: str,
    source_ip: str,
    is_attack: bool,
) -> tuple[Path, PacketIFRunManifestReference]:
    run_id = f"run-{session_id}"
    relative_path = f"runs/{run_id}/run-manifest.json"
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    started_at = datetime(2026, 7, 26, 10, tzinfo=timezone.utc)
    scope = EvaluationScope.FULL_E2E if is_attack else EvaluationScope.DATA_ONLY
    manifest = RunManifest(
        run_id=run_id,
        session_id=session_id,
        scenario=ScenarioReference(scenario_id=scenario),
        target_device_id=target_device_id,
        source_ip=source_ip,
        execution_node=ExecutionNode(node_id="test-node", registered=True),
        evaluation_scope=scope,
        is_active=False,
        started_at=started_at,
        observation_deadline_at=started_at + timedelta(minutes=5),
        ended_at=started_at + timedelta(minutes=1),
        expected_outcome=ExpectedOutcome(evaluation_scope=scope),
        statuses=RunStageStatuses(),
    )
    path.write_text(manifest.to_json(), encoding="utf-8")
    digest = run_manifest_sha256(manifest)
    Path(f"{path}.sha256").write_text(f"{digest}\n", encoding="ascii")
    return path, PacketIFRunManifestReference(
        run_id=run_id,
        relative_path=relative_path,
        schema_version=RUN_MANIFEST_SCHEMA_VERSION,
        sha256=digest,
    )


@pytest.fixture
def SessionLocal(tmp_path: Path):
    db_path = tmp_path / "packet-if-export.db"
    apply_migrations(db_path, MIGRATIONS_DIR)
    engine = create_engine(
        f"sqlite:///{db_path}",
        connect_args={"check_same_thread": False},
    )
    session_factory = sessionmaker(
        autocommit=False,
        autoflush=False,
        bind=engine,
    )
    try:
        yield session_factory
    finally:
        engine.dispose()


def test_export_filters_with_common_capture_policy_and_writes_canonical_csv(
    SessionLocal,
    tmp_path: Path,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", "192.168.0.4")
        session_pk = _insert_capture_session(db, SESSION_ID)
        eligible_segment = _insert_segment(
            db,
            session_pk=session_pk,
            segment_id=1,
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
            start_delay=0.2,
            duration=9.8,
        )
        short_segment = _insert_segment(
            db,
            session_pk=session_pk,
            segment_id=2,
            window_start="2026-07-26T10:00:10Z",
            window_end="2026-07-26T10:00:20Z",
            start_delay=0.2,
            duration=8.0,
        )
        _insert_packet_feature(
            db,
            feature_id=2,
            segment_id=eligible_segment,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=3,
            segment_id=eligible_segment,
            device_id="esp32_01",
            peer_ip="192.168.0.8",
            direction="OUTBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=4,
            segment_id=eligible_segment,
            device_id=None,
            peer_ip="192.168.0.99",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=5,
            segment_id=short_segment,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:10Z",
            window_end="2026-07-26T10:00:20Z",
        )
        _insert_packet_feature(
            db,
            feature_id=6,
            segment_id=eligible_segment,
            device_id="esp32_01",
            peer_ip="192.168.0.5",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        db.commit()

        output_path = tmp_path / "packet-if-v1.csv"
        result = _export(
            db,
            output_path=output_path,
            session_ids=[SESSION_ID],
        )

    assert result.exported_count == 1
    assert result.excluded_count == 4
    assert result.exclusion_reasons == {
        "captured_duration_below_policy": 1,
        "device_ip_mapping_changed": 1,
        "device_not_registered": 1,
        "direction_not_inbound": 1,
    }
    assert result.capture_policy_version == "packet-capture-policy-v1"
    assert result.dataset_sha256 == file_sha256(output_path)
    assert result.manifest_path.exists()
    assert result.manifest_sha256 == file_sha256(result.manifest_path)

    with output_path.open(newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        assert tuple(reader.fieldnames or ()) == DATASET_REQUIRED_COLUMNS
        rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["packet_feature_log_id"] == "2"
    assert rows[0]["session_id"] == SESSION_ID
    assert rows[0]["captured_duration_seconds"] == "9.8"
    assert rows[0]["segment_window_start"] == rows[0]["window_start"]
    assert rows[0]["segment_window_end"] == rows[0]["window_end"]
    assert rows[0]["segment_status"] == "PROCESSED"
    assert rows[0]["registered_device_id"] == "esp32_01"


def test_export_records_session_and_capture_policy_provenance(
    SessionLocal,
    tmp_path: Path,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", "192.168.0.4")
        session_pk = _insert_capture_session(
            db,
            SESSION_ID,
            capture_gap_start="2026-07-26T09:59:50Z",
            capture_gap_end="2026-07-26T10:00:00Z",
        )
        segment_id = _insert_segment(
            db,
            session_pk=session_pk,
            segment_id=1,
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=1,
            segment_id=segment_id,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        db.commit()

        result = _export(
            db,
            output_path=tmp_path / "provenance.csv",
            session_ids=[SESSION_ID],
        )

    manifest = json.loads(result.manifest_path.read_text(encoding="utf-8"))
    assert manifest["dataset_version"] == "packet-if-dataset-v2"
    assert manifest["capture_policy"] == {
        "epsilon_seconds": 0.01,
        "max_start_delay_seconds": 1.0,
        "minimum_coverage_ratio": 0.9,
        "minimum_duration_seconds": 9.0,
        "nominal_window_seconds": 10.0,
        "version": "packet-capture-policy-v1",
    }
    session = manifest["sessions"][0]
    assert session["collection_slot_id"] == f"slot-{SESSION_ID}"
    assert session["source_capture_group_id"] == SESSION_ID
    assert session["normal_policy_version"] == "phase5-normal-policy-v1.1"
    assert session["firmware_version"] == "phase5-normal-pilot-v1"
    assert session["payload_schema_version"] == "phase5-normal-payload-v1"
    assert session["included_device_ids"] == ["esp32_01", "esp32_02"]
    assert session["background_traffic_present"] is False
    assert session["run_manifest_ref"]["run_id"] == f"run-{SESSION_ID}"
    assert session["status"] == "COMPLETED"
    assert session["capture_interface"] == "eth0"
    assert session["capture_filter"] == "tcp or udp"
    assert session["source_commit_sha"] == "a" * 40
    assert session["capture_gap_start"] == "2026-07-26T09:59:50Z"
    assert session["capture_gap_end"] == "2026-07-26T10:00:00Z"
    assert session["devices"] == [
        {"device_id": "esp32_01", "peer_ip": "192.168.0.4"}
    ]
    assert len(session["data_sha256"]) == 64


def test_load_export_spec_parses_dataset_v2_session_contract(
    tmp_path: Path,
) -> None:
    run_path, run_reference = _write_run_manifest(
        tmp_path,
        session_id=SESSION_ID,
        scenario="normal_stable",
        target_device_id="esp32_01",
        source_ip="192.168.0.4",
        is_attack=False,
    )
    spec_path = tmp_path / "packet-if-export-spec-v2.json"
    spec_path.write_text(
        json.dumps(
            {
                "capture_filter": "tcp or udp",
                "source_commit_sha": "a" * 40,
                "sessions": [
                    {
                        "session_id": SESSION_ID,
                        "split": "train",
                        "traffic_label": "normal",
                        "scenario": "normal_stable",
                        "target_device_id": None,
                        "target_source_ip": None,
                        "collection_slot_id": "normal-stable-train-01",
                        "source_capture_group_id": SESSION_ID,
                        "run_manifest_path": str(run_path.relative_to(tmp_path)),
                        "run_manifest_ref": run_reference.to_dict(),
                        "normal_policy_version": "phase5-normal-policy-v1.1",
                        "firmware_version": "phase5-normal-pilot-v1",
                        "payload_schema_version": "phase5-normal-payload-v1",
                        "included_device_ids": ["esp32_01", "esp32_02"],
                        "background_traffic_present": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    capture_filter, source_sha, annotations = exporter._load_export_spec(
        spec_path
    )

    assert capture_filter == "tcp or udp"
    assert source_sha == "a" * 40
    assert len(annotations) == 1
    assert annotations[0].run_manifest_path == run_path.resolve()
    assert annotations[0].run_manifest_ref == run_reference
    assert annotations[0].included_device_ids == ("esp32_01", "esp32_02")


def test_load_export_spec_rejects_non_string_version(tmp_path: Path) -> None:
    run_path, run_reference = _write_run_manifest(
        tmp_path,
        session_id=SESSION_ID,
        scenario="normal_stable",
        target_device_id="esp32_01",
        source_ip="192.168.0.4",
        is_attack=False,
    )
    spec_path = tmp_path / "invalid-export-spec.json"
    spec_path.write_text(
        json.dumps(
            {
                "capture_filter": "tcp or udp",
                "source_commit_sha": "a" * 40,
                "sessions": [
                    {
                        "session_id": SESSION_ID,
                        "split": "train",
                        "traffic_label": "normal",
                        "scenario": "normal_stable",
                        "collection_slot_id": "normal-stable-train-01",
                        "source_capture_group_id": SESSION_ID,
                        "run_manifest_path": str(run_path.relative_to(tmp_path)),
                        "run_manifest_ref": run_reference.to_dict(),
                        "normal_policy_version": 1,
                        "firmware_version": "phase5-normal-pilot-v1",
                        "payload_schema_version": "phase5-normal-payload-v1",
                        "included_device_ids": ["esp32_01"],
                        "background_traffic_present": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="normal_policy_version"):
        exporter._load_export_spec(spec_path)


def test_export_rejects_feature_and_segment_window_mismatch(
    SessionLocal,
    tmp_path: Path,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", "192.168.0.4")
        session_pk = _insert_capture_session(db, SESSION_ID)
        segment_id = _insert_segment(
            db,
            session_pk=session_pk,
            segment_id=1,
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=1,
            segment_id=segment_id,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:10Z",
            window_end="2026-07-26T10:00:20Z",
        )
        db.commit()

        output_path = tmp_path / "mismatched.csv"
        with pytest.raises(ValueError, match="must match"):
            _export(
                db,
                output_path=output_path,
                session_ids=[SESSION_ID],
            )

    assert not output_path.exists()
    assert not output_path.with_suffix(".manifest.json").exists()


@pytest.mark.parametrize("status", ["RUNNING", "FAILED"])
def test_export_rejects_non_completed_capture_session(
    SessionLocal,
    tmp_path: Path,
    status: str,
) -> None:
    with SessionLocal() as db:
        _insert_capture_session(db, SESSION_ID, status=status)
        db.commit()

        with pytest.raises(ValueError, match="only accepts COMPLETED"):
            _export(
                db,
                output_path=tmp_path / f"{status.lower()}.csv",
                session_ids=[SESSION_ID],
            )


def test_export_only_reads_requested_sessions(SessionLocal, tmp_path: Path) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", "192.168.0.4")
        first_session = _insert_capture_session(db, SESSION_ID)
        second_session = _insert_capture_session(
            db,
            OTHER_SESSION_ID,
            first_window_start="2026-07-26T10:00:10Z",
        )
        first_segment = _insert_segment(
            db,
            session_pk=first_session,
            segment_id=1,
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        second_segment = _insert_segment(
            db,
            session_pk=second_session,
            segment_id=2,
            window_start="2026-07-26T10:00:10Z",
            window_end="2026-07-26T10:00:20Z",
        )
        _insert_packet_feature(
            db,
            feature_id=1,
            segment_id=first_segment,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=2,
            segment_id=second_segment,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:10Z",
            window_end="2026-07-26T10:00:20Z",
        )
        db.commit()

        output_path = tmp_path / "selected.csv"
        result = _export(
            db,
            output_path=output_path,
            session_ids=[OTHER_SESSION_ID],
        )

    assert result.exported_count == 1
    with output_path.open(newline="", encoding="utf-8") as csv_file:
        row = next(csv.DictReader(csv_file))
    assert row["session_id"] == OTHER_SESSION_ID
    assert row["packet_feature_log_id"] == "2"


def test_export_filters_attack_session_to_target_device(
    SessionLocal,
    tmp_path: Path,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", "192.168.0.4")
        _insert_device(db, "esp32_02", "192.168.0.5")
        session_pk = _insert_capture_session(db, SESSION_ID)
        segment_id = _insert_segment(
            db,
            session_pk=session_pk,
            segment_id=1,
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=1,
            segment_id=segment_id,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=2,
            segment_id=segment_id,
            device_id="esp32_02",
            peer_ip="192.168.0.5",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        db.commit()

        output_path = tmp_path / "attack-target.csv"
        result = _export(
            db,
            output_path=output_path,
            session_ids=[SESSION_ID],
            target_device_ids={SESSION_ID: "esp32_02"},
        )

    assert result.exported_count == 1
    assert result.exclusion_reasons == {"session_target_device_mismatch": 1}
    with output_path.open(newline="", encoding="utf-8") as csv_file:
        row = next(csv.DictReader(csv_file))
    assert row["device_id"] == "esp32_02"


def test_export_filters_device_not_in_included_device_ids() -> None:
    reason = exporter._exclusion_reason(
        _eligible_source_row(device_id="esp32_02", peer_ip="192.168.0.5"),
        CapturePolicy(),
        target_device_ids={},
        target_source_ips={},
        included_device_ids={SESSION_ID: frozenset({"esp32_01"})},
    )

    assert reason == "session_device_not_included"


def test_export_filters_attack_row_with_wrong_source_ip() -> None:
    reason = exporter._exclusion_reason(
        _eligible_source_row(device_id="esp32_01", peer_ip="192.168.0.4"),
        CapturePolicy(),
        target_device_ids={SESSION_ID: "esp32_01"},
        target_source_ips={SESSION_ID: "192.168.0.5"},
        included_device_ids={SESSION_ID: frozenset({"esp32_01"})},
    )

    assert reason == "session_target_source_ip_mismatch"


def test_export_requires_an_eligible_row_for_every_requested_session(
    SessionLocal,
    tmp_path: Path,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", "192.168.0.4")
        first_session = _insert_capture_session(db, SESSION_ID)
        _insert_capture_session(db, OTHER_SESSION_ID)
        segment_id = _insert_segment(
            db,
            session_pk=first_session,
            segment_id=1,
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=1,
            segment_id=segment_id,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        db.commit()

        output_path = tmp_path / "missing-session.csv"
        with pytest.raises(ValueError, match=OTHER_SESSION_ID):
            _export(
                db,
                output_path=output_path,
                session_ids=[SESSION_ID, OTHER_SESSION_ID],
            )

    assert not output_path.exists()


@pytest.mark.parametrize(
    "annotation",
    [
        PacketIFSessionAnnotation("", "train", "normal", "normal"),
        PacketIFSessionAnnotation(
            SESSION_ID,
            "test",
            "attack",
            "packet_flood",
        ),
        PacketIFSessionAnnotation(
            SESSION_ID,
            "train",
            "normal",
            "normal",
            "esp32_01",
        ),
    ],
)
def test_export_rejects_invalid_session_annotations(
    annotation: PacketIFSessionAnnotation,
) -> None:
    with pytest.raises(ValueError):
        exporter._normalize_session_annotations([annotation])


def test_export_rejects_holdout_split() -> None:
    annotation = PacketIFSessionAnnotation(
        SESSION_ID,
        "holdout",
        "normal",
        "normal_stable",
    )

    with pytest.raises(ValueError, match="invalid packet dataset split"):
        exporter._normalize_session_annotations([annotation])


def test_export_refuses_to_replace_existing_dataset(
    SessionLocal,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "existing.csv"
    output_path.write_text("preserve-me\n", encoding="utf-8")

    with SessionLocal() as db:
        with pytest.raises(FileExistsError, match="already exists"):
            _export(
                db,
                output_path=output_path,
                session_ids=[SESSION_ID],
            )

    assert output_path.read_text(encoding="utf-8") == "preserve-me\n"


def test_export_does_not_replace_file_created_during_publish_race(
    SessionLocal,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SessionLocal() as db:
        _insert_device(db, "esp32_01", "192.168.0.4")
        session_pk = _insert_capture_session(db, SESSION_ID)
        segment_id = _insert_segment(
            db,
            session_pk=session_pk,
            segment_id=1,
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=1,
            segment_id=segment_id,
            device_id="esp32_01",
            peer_ip="192.168.0.4",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        db.commit()

        output_path = tmp_path / "raced.csv"
        real_link = os.link

        def create_competing_file_then_link(source, destination) -> None:
            Path(destination).write_text("other-export\n", encoding="utf-8")
            real_link(source, destination)

        monkeypatch.setattr(
            exporter.os,
            "link",
            create_competing_file_then_link,
        )
        with pytest.raises(FileExistsError):
            _export(
                db,
                output_path=output_path,
                session_ids=[SESSION_ID],
            )

    assert output_path.read_text(encoding="utf-8") == "other-export\n"


def test_export_does_not_leave_file_when_no_rows_are_eligible(
    SessionLocal,
    tmp_path: Path,
) -> None:
    with SessionLocal() as db:
        session_pk = _insert_capture_session(db, SESSION_ID)
        segment_id = _insert_segment(
            db,
            session_pk=session_pk,
            segment_id=1,
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        _insert_packet_feature(
            db,
            feature_id=1,
            segment_id=segment_id,
            device_id=None,
            peer_ip="192.168.0.99",
            direction="INBOUND",
            window_start="2026-07-26T10:00:00Z",
            window_end="2026-07-26T10:00:10Z",
        )
        db.commit()
        output_path = tmp_path / "empty.csv"
        with pytest.raises(ValueError, match="no eligible"):
            _export(
                db,
                output_path=output_path,
                session_ids=[SESSION_ID],
            )

    assert not output_path.exists()


@pytest.mark.parametrize("session_ids", [[], [""], ["   "]])
def test_export_requires_non_empty_session_ids(
    SessionLocal,
    tmp_path: Path,
    session_ids: list[str],
) -> None:
    with SessionLocal() as db:
        with pytest.raises(ValueError, match="Session annotation|session_id"):
            _export(
                db,
                output_path=tmp_path / "dataset.csv",
                session_ids=session_ids,
            )


def _insert_device(db, device_id: str, ip_address: str) -> None:
    db.execute(
        text(
            """
            INSERT INTO devices (device_id, ip_address, status, trust_score)
            VALUES (:device_id, :ip_address, 'normal', 100)
            """
        ),
        {"device_id": device_id, "ip_address": ip_address},
    )


def _insert_capture_session(
    db,
    session_id: str,
    *,
    status: str = "COMPLETED",
    first_window_start: str = "2026-07-26T10:00:00Z",
    capture_gap_start: str | None = None,
    capture_gap_end: str | None = None,
) -> int:
    result = db.execute(
        text(
            """
            INSERT INTO packet_capture_sessions (
                session_id,
                capture_interface,
                started_at,
                first_window_start,
                ended_at,
                capture_gap_start,
                capture_gap_end,
                status
            )
            VALUES (
                :session_id,
                'eth0',
                :first_window_start,
                :first_window_start,
                :ended_at,
                :capture_gap_start,
                :capture_gap_end,
                :status
            )
            """
        ),
        {
            "session_id": session_id,
            "first_window_start": first_window_start,
            "ended_at": (
                None
                if status == "RUNNING"
                else "2026-07-26T10:01:00Z"
            ),
            "capture_gap_start": capture_gap_start,
            "capture_gap_end": capture_gap_end,
            "status": status,
        },
    )
    return int(result.lastrowid)


def _eligible_source_row(
    *,
    device_id: str,
    peer_ip: str,
) -> dict[str, Any]:
    return {
        "session_id": SESSION_ID,
        "direction": "INBOUND",
        "device_id": device_id,
        "registered_device_id": device_id,
        "peer_ip": peer_ip,
        "registered_ip_address": peer_ip,
        "segment_status": "PROCESSED",
        "segment_error_code": None,
        "start_delay_seconds": 0.1,
        "captured_duration_seconds": 9.9,
    }


def _insert_segment(
    db,
    *,
    session_pk: int,
    segment_id: int,
    window_start: str,
    window_end: str,
    start_delay: float = 0.2,
    duration: float = 9.8,
) -> int:
    db.execute(
        text(
            """
            INSERT INTO packet_capture_segments (
                id,
                capture_session_id,
                file_name,
                capture_interface,
                window_start,
                window_end,
                status,
                packet_count,
                processed_at,
                start_delay_seconds,
                captured_duration_seconds
            )
            VALUES (
                :segment_id,
                :session_pk,
                :file_name,
                'eth0',
                :window_start,
                :window_end,
                'PROCESSED',
                10,
                :window_end,
                :start_delay,
                :duration
            )
            """
        ),
        {
            "segment_id": segment_id,
            "session_pk": session_pk,
            "file_name": f"segment-{segment_id}.pcap",
            "window_start": window_start,
            "window_end": window_end,
            "start_delay": start_delay,
            "duration": duration,
        },
    )
    return segment_id


def _insert_packet_feature(
    db,
    *,
    feature_id: int,
    segment_id: int,
    device_id: str | None,
    peer_ip: str,
    direction: str,
    window_start: str,
    window_end: str,
) -> None:
    db.execute(
        text(
            """
            INSERT INTO packet_feature_logs (
                id,
                capture_segment_id,
                device_id,
                peer_ip,
                direction,
                window_start,
                window_end,
                packet_count,
                total_bytes,
                avg_packet_size,
                max_packet_size,
                mean_inter_arrival_time,
                distinct_dest_port_count,
                tcp_syn_count,
                mqtt_related_packet_count,
                non_mqtt_tcp_udp_packet_count,
                capture_scope
            )
            VALUES (
                :feature_id,
                :segment_id,
                :device_id,
                :peer_ip,
                :direction,
                :window_start,
                :window_end,
                10,
                1000,
                100.0,
                120,
                0.5,
                2,
                1,
                8,
                2,
                'gateway'
            )
            """
        ),
        {
            "feature_id": feature_id,
            "segment_id": segment_id,
            "device_id": device_id,
            "peer_ip": peer_ip,
            "direction": direction,
            "window_start": window_start,
            "window_end": window_end,
        },
    )
