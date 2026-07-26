"""Export eligible Packet IF training rows from the Phase 4 database."""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping, Sequence

from sqlalchemy import text
from sqlalchemy.orm import Session

from ai.packet_if_contract import PACKET_IF_NOMINAL_WINDOW_SECONDS
from ai.packet_if_dataset import (
    ATTACK_LABEL,
    DATASET_REQUIRED_COLUMNS,
    NORMAL_LABEL,
    PACKET_IF_DATASET_VERSION,
    VALID_SPLITS,
    file_sha256,
    session_data_sha256s,
)
from backend.app.database import SessionLocal
from edge.detection.phase4_time import format_db_utc, parse_db_utc
from edge.packet.capture_session_repository import (
    get_packet_feature_ready_through,
)
from edge.packet.capture_policy import (
    CaptureEligibilitySegment,
    CapturePolicy,
    is_capture_eligible,
)


@dataclass(frozen=True)
class PacketIFExportResult:
    output_path: Path
    manifest_path: Path
    exported_count: int
    excluded_count: int
    exclusion_reasons: dict[str, int]
    dataset_sha256: str
    manifest_sha256: str
    capture_policy_version: str


@dataclass(frozen=True)
class PacketIFSessionAnnotation:
    session_id: str
    split: str
    traffic_label: str
    scenario: str
    target_device_id: str | None = None


def export_packet_if_dataset(
    db: Session,
    *,
    output_path: Path,
    manifest_path: Path,
    session_annotations: Sequence[PacketIFSessionAnnotation],
    capture_filter: str,
    source_commit_sha: str,
    capture_policy: CapturePolicy,
) -> PacketIFExportResult:
    """Write a deterministic Packet IF CSV and its immutable provenance manifest.

    The caller owns the database transaction. Existing output files are never
    replaced so a dataset referenced by SHA256 cannot change silently. Only
    terminal COMPLETED Capture Sessions can be published.
    """
    annotations = _normalize_session_annotations(session_annotations)
    normalized_session_ids = tuple(
        annotation.session_id
        for annotation in annotations
    )
    normalized_targets = {
        annotation.session_id: annotation.target_device_id
        for annotation in annotations
        if annotation.target_device_id is not None
    }
    if not isinstance(capture_filter, str):
        raise ValueError("capture_filter must be a string")
    _validate_git_commit_sha(source_commit_sha)
    if output_path.exists():
        raise FileExistsError(f"Packet IF dataset already exists: {output_path}")
    if manifest_path.exists():
        raise FileExistsError(
            f"Packet IF dataset manifest already exists: {manifest_path}"
        )
    if output_path.resolve() == manifest_path.resolve():
        raise ValueError("dataset and manifest paths must be different")

    sessions = _select_capture_sessions(
        db,
        session_ids=normalized_session_ids,
    )
    _validate_capture_sessions(
        db,
        sessions,
        requested_session_ids=normalized_session_ids,
    )
    rows = _select_packet_feature_rows(
        db,
        session_ids=normalized_session_ids,
    )
    exported_rows: list[dict[str, Any]] = []
    exclusion_reasons: Counter[str] = Counter()

    for row in rows:
        _validate_source_window(row)
        reason = _exclusion_reason(
            row,
            capture_policy,
            target_device_ids=normalized_targets,
        )
        if reason is not None:
            exclusion_reasons[reason] += 1
            continue
        exported_rows.append(
            {
                column: row[column]
                for column in DATASET_REQUIRED_COLUMNS
            }
        )

    if not exported_rows:
        raise ValueError("no eligible Packet IF dataset rows were found")
    exported_session_ids = {
        str(row["session_id"])
        for row in exported_rows
    }
    missing_session_ids = sorted(set(normalized_session_ids) - exported_session_ids)
    if missing_session_ids:
        raise ValueError(
            "no eligible Packet IF rows for requested sessions: "
            + ", ".join(missing_session_ids)
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    output_created = False
    manifest_created = False
    try:
        _write_csv_atomically(output_path, exported_rows)
        output_created = True
        dataset_sha256 = file_sha256(output_path)
        per_session_sha256 = session_data_sha256s(output_path)
        manifest_payload = _build_manifest_payload(
            annotations=annotations,
            sessions=sessions,
            exported_rows=exported_rows,
            capture_filter=capture_filter,
            source_commit_sha=source_commit_sha,
            capture_policy=capture_policy,
            dataset_sha256=dataset_sha256,
            per_session_sha256=per_session_sha256,
        )
        _write_json_atomically(manifest_path, manifest_payload)
        manifest_created = True
    except BaseException:
        if manifest_created:
            manifest_path.unlink(missing_ok=True)
        if output_created:
            output_path.unlink(missing_ok=True)
        raise

    return PacketIFExportResult(
        output_path=output_path,
        manifest_path=manifest_path,
        exported_count=len(exported_rows),
        excluded_count=sum(exclusion_reasons.values()),
        exclusion_reasons=dict(sorted(exclusion_reasons.items())),
        dataset_sha256=dataset_sha256,
        manifest_sha256=file_sha256(manifest_path),
        capture_policy_version=capture_policy.version,
    )


def _select_packet_feature_rows(
    db: Session,
    *,
    session_ids: tuple[str, ...],
) -> list[dict[str, Any]]:
    placeholders = ", ".join(
        f":session_id_{index}"
        for index in range(len(session_ids))
    )
    params = {
        f"session_id_{index}": session_id
        for index, session_id in enumerate(session_ids)
    }
    rows = db.execute(
        text(
            f"""
            SELECT
                pfl.id AS packet_feature_log_id,
                pcs.session_id,
                pfl.device_id,
                pfl.direction,
                pfl.window_start,
                pfl.window_end,
                pfl.peer_ip,
                pcsg.window_start AS segment_window_start,
                pcsg.window_end AS segment_window_end,
                pcsg.status AS segment_status,
                pcsg.error_code AS segment_error_code,
                pcsg.start_delay_seconds,
                d.device_id AS registered_device_id,
                d.ip_address AS registered_ip_address,
                pfl.packet_count,
                pfl.total_bytes,
                pfl.avg_packet_size,
                pfl.max_packet_size,
                pfl.mean_inter_arrival_time,
                pfl.distinct_dest_port_count,
                pcsg.captured_duration_seconds
            FROM packet_feature_logs pfl
            JOIN packet_capture_segments pcsg
                ON pcsg.id = pfl.capture_segment_id
            JOIN packet_capture_sessions pcs
                ON pcs.id = pcsg.capture_session_id
            LEFT JOIN devices d
                ON d.device_id = pfl.device_id
            WHERE pcs.session_id IN ({placeholders})
            ORDER BY
                pcs.session_id ASC,
                pfl.window_start ASC,
                pfl.id ASC
            """
        ),
        params,
    ).mappings()
    return [dict(row) for row in rows]


def _select_capture_sessions(
    db: Session,
    *,
    session_ids: tuple[str, ...],
) -> list[dict[str, Any]]:
    placeholders = ", ".join(
        f":session_id_{index}"
        for index in range(len(session_ids))
    )
    params = {
        f"session_id_{index}": session_id
        for index, session_id in enumerate(session_ids)
    }
    rows = db.execute(
        text(
            f"""
            SELECT
                session_id,
                capture_interface,
                started_at,
                first_window_start,
                ended_at,
                capture_gap_start,
                capture_gap_end,
                status,
                (
                    SELECT COUNT(*)
                    FROM packet_capture_segments pcsg
                    WHERE pcsg.capture_session_id = packet_capture_sessions.id
                ) AS segment_count,
                (
                    SELECT MAX(pcsg.window_end)
                    FROM packet_capture_segments pcsg
                    WHERE pcsg.capture_session_id = packet_capture_sessions.id
                ) AS last_segment_window_end
            FROM packet_capture_sessions
            WHERE session_id IN ({placeholders})
            ORDER BY session_id ASC
            """
        ),
        params,
    ).mappings()
    return [dict(row) for row in rows]


def _validate_capture_sessions(
    db: Session,
    sessions: list[dict[str, Any]],
    *,
    requested_session_ids: tuple[str, ...],
) -> None:
    by_id = {
        str(session["session_id"]): session
        for session in sessions
    }
    missing = sorted(set(requested_session_ids) - set(by_id))
    if missing:
        raise ValueError(
            "Capture Sessions were not found: " + ", ".join(missing)
        )
    for session_id in requested_session_ids:
        session = by_id[session_id]
        if session["status"] != "COMPLETED":
            raise ValueError(
                "Packet IF export only accepts COMPLETED Capture Sessions: "
                f"session_id={session_id}, status={session['status']!r}"
            )
        for field_name in (
            "capture_interface",
            "started_at",
            "first_window_start",
            "ended_at",
        ):
            value = session[field_name]
            if value is None or not str(value).strip():
                raise ValueError(
                    "Capture Session provenance is incomplete: "
                    f"session_id={session_id}, field={field_name}"
                )
        if int(session["segment_count"]) <= 0:
            raise ValueError(
                f"Capture Session has no Segments: {session_id}"
            )
        readiness = get_packet_feature_ready_through(
            db,
            session_id=session_id,
        )
        if (
            readiness is None
            or readiness.packet_feature_ready_through is None
            or session["last_segment_window_end"] is None
            or readiness.packet_feature_ready_through
            != parse_db_utc(
                session["last_segment_window_end"],
                "last_segment_window_end",
            )
        ):
            raise ValueError(
                "Capture Session is not fully converted to a contiguous Packet "
                f"Feature prefix: {session_id}"
            )


def _validate_source_window(row: dict[str, Any]) -> None:
    parsed: dict[str, Any] = {}
    for field_name in (
        "window_start",
        "window_end",
        "segment_window_start",
        "segment_window_end",
    ):
        value = parse_db_utc(row[field_name], field_name)
        if str(row[field_name]) != format_db_utc(value):
            raise ValueError(
                f"{field_name} must use whole-second UTC Z format"
            )
        parsed[field_name] = value
    if (
        parsed["window_start"] != parsed["segment_window_start"]
        or parsed["window_end"] != parsed["segment_window_end"]
    ):
        raise ValueError(
            "Packet Feature window must match its Capture Segment window: "
            f"packet_feature_log_id={row['packet_feature_log_id']}"
        )


def _exclusion_reason(
    row: dict[str, Any],
    capture_policy: CapturePolicy,
    *,
    target_device_ids: Mapping[str, str],
) -> str | None:
    if row["direction"] != "INBOUND":
        return "direction_not_inbound"
    if row["device_id"] is None or row["registered_device_id"] is None:
        return "device_not_registered"
    if (
        row["registered_ip_address"] is None
        or str(row["registered_ip_address"]) != str(row["peer_ip"])
    ):
        return "device_ip_mapping_changed"
    target_device_id = target_device_ids.get(str(row["session_id"]))
    if target_device_id is not None and str(row["device_id"]) != target_device_id:
        return "session_target_device_mismatch"

    eligibility = is_capture_eligible(
        CaptureEligibilitySegment(
            status=str(row["segment_status"]),
            error_code=row["segment_error_code"],
            start_delay_seconds=row["start_delay_seconds"],
            captured_duration_seconds=row["captured_duration_seconds"],
        ),
        capture_policy,
    )
    return eligibility.exclusion_reason


def _normalize_session_annotations(
    annotations: Sequence[PacketIFSessionAnnotation],
) -> tuple[PacketIFSessionAnnotation, ...]:
    if not annotations:
        raise ValueError("at least one Session annotation is required")

    normalized: list[PacketIFSessionAnnotation] = []
    seen_session_ids: set[str] = set()
    for annotation in annotations:
        if not isinstance(annotation, PacketIFSessionAnnotation):
            raise ValueError(
                "session_annotations must contain PacketIFSessionAnnotation values"
            )
        session_id = annotation.session_id.strip()
        split = annotation.split.strip()
        traffic_label = annotation.traffic_label.strip()
        scenario = annotation.scenario.strip()
        target_device_id = (
            annotation.target_device_id.strip()
            if isinstance(annotation.target_device_id, str)
            else None
        )
        if not session_id:
            raise ValueError("session_id must be a non-empty string")
        if session_id in seen_session_ids:
            raise ValueError(f"duplicate Session annotation: {session_id}")
        if split not in VALID_SPLITS:
            raise ValueError(f"invalid packet dataset split: {split!r}")
        if traffic_label not in {NORMAL_LABEL, ATTACK_LABEL}:
            raise ValueError(
                f"invalid packet traffic label: {traffic_label!r}"
            )
        if not scenario:
            raise ValueError("scenario must be a non-empty string")
        if traffic_label == ATTACK_LABEL and not target_device_id:
            raise ValueError(
                f"attack session must specify target_device_id: {session_id}"
            )
        if traffic_label == NORMAL_LABEL and target_device_id is not None:
            raise ValueError(
                f"normal session must not have target_device_id: {session_id}"
            )
        seen_session_ids.add(session_id)
        normalized.append(
            PacketIFSessionAnnotation(
                session_id=session_id,
                split=split,
                traffic_label=traffic_label,
                scenario=scenario,
                target_device_id=target_device_id,
            )
        )
    return tuple(normalized)


def _build_manifest_payload(
    *,
    annotations: tuple[PacketIFSessionAnnotation, ...],
    sessions: list[dict[str, Any]],
    exported_rows: list[dict[str, Any]],
    capture_filter: str,
    source_commit_sha: str,
    capture_policy: CapturePolicy,
    dataset_sha256: str,
    per_session_sha256: dict[str, str],
) -> dict[str, Any]:
    sessions_by_id = {
        str(session["session_id"]): session
        for session in sessions
    }
    rows_by_session: dict[str, list[dict[str, Any]]] = {}
    for row in exported_rows:
        rows_by_session.setdefault(str(row["session_id"]), []).append(row)

    manifest_sessions: list[dict[str, Any]] = []
    for annotation in annotations:
        session = sessions_by_id[annotation.session_id]
        devices = sorted(
            {
                (str(row["device_id"]), str(row["peer_ip"]))
                for row in rows_by_session[annotation.session_id]
            }
        )
        manifest_sessions.append(
            {
                "session_id": annotation.session_id,
                "split": annotation.split,
                "traffic_label": annotation.traffic_label,
                "scenario": annotation.scenario,
                "target_device_id": annotation.target_device_id,
                "status": str(session["status"]),
                "capture_interface": str(session["capture_interface"]),
                "capture_filter": capture_filter,
                "source_commit_sha": source_commit_sha,
                "started_at": str(session["started_at"]),
                "first_window_start": str(session["first_window_start"]),
                "ended_at": str(session["ended_at"]),
                "capture_gap_start": (
                    str(session["capture_gap_start"])
                    if session["capture_gap_start"] is not None
                    else None
                ),
                "capture_gap_end": (
                    str(session["capture_gap_end"])
                    if session["capture_gap_end"] is not None
                    else None
                ),
                "devices": [
                    {
                        "device_id": device_id,
                        "peer_ip": peer_ip,
                    }
                    for device_id, peer_ip in devices
                ],
                "data_sha256": per_session_sha256[annotation.session_id],
            }
        )

    return {
        "dataset_version": PACKET_IF_DATASET_VERSION,
        "capture_policy_version": capture_policy.version,
        "capture_policy": {
            "version": capture_policy.version,
            "nominal_window_seconds": PACKET_IF_NOMINAL_WINDOW_SECONDS,
            "max_start_delay_seconds": capture_policy.max_start_delay_seconds,
            "minimum_duration_seconds": capture_policy.minimum_duration_seconds,
            "epsilon_seconds": capture_policy.epsilon_seconds,
            "minimum_coverage_ratio": (
                capture_policy.minimum_duration_seconds
                / PACKET_IF_NOMINAL_WINDOW_SECONDS
            ),
        },
        "dataset_sha256": dataset_sha256,
        "sessions": manifest_sessions,
    }


def _validate_git_commit_sha(value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(
            "source_commit_sha must be a lowercase 40-character SHA1"
        )


def _write_csv_atomically(
    output_path: Path,
    rows: list[dict[str, Any]],
) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as csv_file:
            temporary_path = Path(csv_file.name)
            writer = csv.DictWriter(
                csv_file,
                fieldnames=list(DATASET_REQUIRED_COLUMNS),
            )
            writer.writeheader()
            writer.writerows(rows)
            csv_file.flush()
            os.fsync(csv_file.fileno())
        os.link(temporary_path, output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_json_atomically(
    output_path: Path,
    payload: dict[str, Any],
) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as json_file:
            temporary_path = Path(json_file.name)
            json.dump(
                payload,
                json_file,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            json_file.write("\n")
            json_file.flush()
            os.fsync(json_file.fileno())
        os.link(temporary_path, output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _load_export_spec(
    path: Path,
) -> tuple[str, str, tuple[PacketIFSessionAnnotation, ...]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid Packet IF export spec JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Packet IF export spec must be a JSON object")

    capture_filter = payload.get("capture_filter")
    if not isinstance(capture_filter, str):
        raise ValueError("capture_filter must be a string")
    source_commit_sha = payload.get("source_commit_sha")
    _validate_git_commit_sha(source_commit_sha)

    raw_sessions = payload.get("sessions")
    if not isinstance(raw_sessions, list) or not raw_sessions:
        raise ValueError("export spec sessions must be a non-empty list")
    annotations: list[PacketIFSessionAnnotation] = []
    for raw_session in raw_sessions:
        if not isinstance(raw_session, dict):
            raise ValueError("each export Session must be a JSON object")
        annotations.append(
            PacketIFSessionAnnotation(
                session_id=str(raw_session.get("session_id", "")),
                split=str(raw_session.get("split", "")),
                traffic_label=str(raw_session.get("traffic_label", "")),
                scenario=str(raw_session.get("scenario", "")),
                target_device_id=raw_session.get("target_device_id"),
            )
        )
    return (
        capture_filter,
        source_commit_sha,
        _normalize_session_annotations(annotations),
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture Policy 적격 Packet Feature를 Packet IF CSV로 내보냅니다."
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="새로 생성할 CSV 경로. 기존 파일은 덮어쓰지 않습니다.",
    )
    parser.add_argument(
        "--manifest-output",
        type=Path,
        required=True,
        help="CSV와 함께 새로 생성할 Session Provenance Manifest 경로",
    )
    parser.add_argument(
        "--spec",
        type=Path,
        required=True,
        help="Split·Label·Scenario·Capture 출처를 선언한 Export Spec JSON",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    capture_filter, source_commit_sha, annotations = _load_export_spec(
        args.spec
    )
    with SessionLocal() as db:
        result = export_packet_if_dataset(
            db,
            output_path=args.output,
            manifest_path=args.manifest_output,
            session_annotations=annotations,
            capture_filter=capture_filter,
            source_commit_sha=source_commit_sha,
            capture_policy=CapturePolicy.from_env(),
        )

    print(f"output={result.output_path}")
    print(f"manifest={result.manifest_path}")
    print(f"exported_count={result.exported_count}")
    print(f"excluded_count={result.excluded_count}")
    print(f"capture_policy_version={result.capture_policy_version}")
    print(f"dataset_sha256={result.dataset_sha256}")
    print(f"manifest_sha256={result.manifest_sha256}")
    for reason, count in result.exclusion_reasons.items():
        print(f"excluded[{reason}]={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
