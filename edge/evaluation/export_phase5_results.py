"""CLI exporter for Phase 5 evaluation rows."""

from __future__ import annotations

import argparse
import csv
from datetime import datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any, Mapping, Sequence

from edge.evaluation.phase5_evaluator import (
    PHASE5_EVALUATION_SCHEMA_VERSION,
    Phase5EvaluationError,
    evaluate_phase5_run,
    summarize_evaluation_rows,
)
from edge.phase5.contracts import (
    ManifestStatus,
    RUN_MANIFEST_SHA256_SIDECAR_SUFFIX,
    RunManifest,
    RunManifestValidationError,
    run_manifest_sha256,
)


JSONL_FILENAME = "phase5-evaluation.jsonl"
CSV_FILENAME = "phase5-evaluation.csv"
SUMMARY_FILENAME = "phase5-evaluation-summary.json"

EXIT_SUCCESS = 0
EXIT_USAGE_ERROR = 64
EXIT_INPUT_ERROR = 65
EXIT_ENVIRONMENT_ERROR = 74

_SHA1_PATTERN = re.compile(r"^[0-9a-f]{40}$")

CSV_COLUMNS = (
    "evaluation_schema_version",
    "source_commit",
    "run_manifest_schema_version",
    "evaluation_identity",
    "run_id",
    "session_id",
    "scenario_id",
    "target_device_id",
    "source_ip",
    "evaluation_unit",
    "final_status",
    "scenario_status",
    "detection_status",
    "trust_status",
    "firewall_status",
    "block_status",
    "data_status",
    "valid_run",
    "tp",
    "fp",
    "tn",
    "fn",
    "matched_detection_event_ids",
    "matched_trust_score_history_ids",
    "matched_firewall_rule_ids",
    "trigger_event_ids",
    "matching_strategy",
    "failure_reasons",
    "latencies",
)


class Phase5ExportError(ValueError):
    exit_code = EXIT_INPUT_ERROR


class Phase5ExportEnvironmentError(Phase5ExportError):
    exit_code = EXIT_ENVIRONMENT_ERROR


def export_phase5_results(
    *,
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    output_dir: Path,
    evaluation_schema_version: str,
    source_commit: str,
) -> dict[str, Any]:
    """Evaluate one manifest and publish deterministic JSONL, CSV, and summary."""
    manifest, scenario_result = _validate_inputs(
        manifest_path=manifest_path,
        scenario_results_path=scenario_results_path,
        db_path=db_path,
        evaluation_schema_version=evaluation_schema_version,
        source_commit=source_commit,
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = output_dir / JSONL_FILENAME
    csv_path = output_dir / CSV_FILENAME
    summary_path = output_dir / SUMMARY_FILENAME

    existing_rows = _load_existing_jsonl(
        jsonl_path,
        evaluation_schema_version,
        source_commit,
    )
    row = evaluate_phase5_run(
        manifest,
        db_path=db_path,
        evaluation_schema_version=evaluation_schema_version,
        source_commit=source_commit,
        scenario_result=scenario_result,
    )
    rows = _dedupe_rows([*existing_rows, row])
    _write_jsonl_atomically(jsonl_path, rows)
    loaded_rows = _load_existing_jsonl(
        jsonl_path,
        evaluation_schema_version,
        source_commit,
    )
    _write_csv_atomically(csv_path, loaded_rows)
    summary = summarize_evaluation_rows(
        loaded_rows,
        evaluation_schema_version=evaluation_schema_version,
        source_commit=source_commit,
    )
    _write_json_atomically(summary_path, summary)
    return {
        "jsonl_path": jsonl_path,
        "csv_path": csv_path,
        "summary_path": summary_path,
        "row_count": len(loaded_rows),
        "evaluation_identity": row["evaluation_identity"],
        "summary": summary,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export Phase 5 evaluation JSONL, CSV, and summary files.",
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--scenario-results", type=Path, required=True)
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--evaluation-schema-version",
        required=True,
        help=f"Evaluation schema version, e.g. {PHASE5_EVALUATION_SCHEMA_VERSION}",
    )
    parser.add_argument(
        "--source-commit",
        required=True,
        help="Lowercase 40-character Git commit SHA for the evaluation code.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        result = export_phase5_results(
            manifest_path=args.manifest,
            scenario_results_path=args.scenario_results,
            db_path=args.db,
            output_dir=args.output_dir,
            evaluation_schema_version=args.evaluation_schema_version,
            source_commit=args.source_commit,
        )
    except Phase5ExportError as exc:
        print(f"error={exc}")
        return exc.exit_code
    except (RunManifestValidationError, Phase5EvaluationError, ValueError) as exc:
        print(f"error={exc}")
        return EXIT_INPUT_ERROR

    print(f"jsonl={result['jsonl_path']}")
    print(f"csv={result['csv_path']}")
    print(f"summary={result['summary_path']}")
    print(f"row_count={result['row_count']}")
    print(f"evaluation_identity={result['evaluation_identity']}")
    return EXIT_SUCCESS


def _validate_inputs(
    *,
    manifest_path: Path,
    scenario_results_path: Path,
    db_path: Path,
    evaluation_schema_version: str,
    source_commit: str,
) -> tuple[RunManifest, dict[str, Any]]:
    if not evaluation_schema_version.strip():
        raise Phase5ExportError("evaluation_schema_version must be non-empty")
    if _SHA1_PATTERN.fullmatch(source_commit) is None:
        raise Phase5ExportError(
            "source_commit must be a lowercase 40-character SHA1"
        )
    if not manifest_path.exists():
        raise Phase5ExportError(f"manifest not found: {manifest_path}")
    if not scenario_results_path.exists():
        raise Phase5ExportError(
            f"scenario results not found: {scenario_results_path}"
        )
    if not db_path.exists():
        raise Phase5ExportEnvironmentError(f"database not found: {db_path}")

    try:
        manifest_text = manifest_path.read_text(encoding="utf-8")
        manifest = RunManifest.from_json(manifest_text)
    except OSError as exc:
        raise Phase5ExportError(f"failed to read manifest: {manifest_path}") from exc
    except json.JSONDecodeError as exc:
        raise Phase5ExportError(f"invalid manifest JSON: {manifest_path}") from exc

    _validate_manifest_sidecar(manifest_path, manifest)
    scenario_result = _load_matching_scenario_result(scenario_results_path, manifest)
    scenario_result["_manifest_sha256"] = hashlib.sha256(
        manifest_text.encode("utf-8")
    ).hexdigest()
    scenario_result["_scenario_result_sha256"] = _canonical_json_sha256(
        scenario_result,
        exclude_meta=True,
    )
    scenario_result["_db_snapshot_sha256"] = _file_sha256(db_path)
    return manifest, scenario_result


def _load_matching_scenario_result(
    path: Path,
    manifest: RunManifest,
) -> dict[str, Any]:
    rows = _load_jsonl(path, "scenario results")
    matching: list[dict[str, Any]] = []
    malformed: list[str] = []
    for index, row in enumerate(rows, start=1):
        issue = _scenario_result_common_contract_issue(row)
        if issue is not None:
            malformed.append(f"line {index}: {issue}")
            continue
        if row["run_id"] != manifest.run_id:
            continue
        if row["scenario_id"] != manifest.scenario.scenario_id:
            continue
        issue = _scenario_result_manifest_contract_issue(row, manifest)
        if issue is not None:
            malformed.append(f"line {index}: {issue}")
            continue
        if manifest.session_id is not None and row.get("session_id") != manifest.session_id:
            continue
        matching.append(row)
    if malformed:
        raise Phase5ExportError(
            "scenario results contain invalid official rows: "
            + "; ".join(malformed)
        )
    if not matching:
        raise Phase5ExportError(
            "scenario results contain no row for the manifest identity"
        )
    if len(matching) > 1:
        raise Phase5ExportError(
            "scenario results contain multiple rows for the manifest identity"
        )
    return matching[0]


def _scenario_result_common_contract_issue(row: Mapping[str, Any]) -> str | None:
    for field_name in ("run_id", "scenario_id"):
        if not isinstance(row.get(field_name), str) or not row[field_name].strip():
            return f"{field_name} is required"
    if "session_id" in row and row["session_id"] is not None:
        if not isinstance(row["session_id"], str) or not row["session_id"].strip():
            return "session_id must be null or a non-empty string"
    raw_status = row.get("scenario_status")
    try:
        ManifestStatus(raw_status)
    except ValueError:
        return "scenario_status must be a ManifestStatus value"
    if not isinstance(row.get("capture_eligible"), bool):
        return "capture_eligible must be boolean"
    if row.get("capture_eligible") is False:
        reason = row.get("capture_exclusion_reason")
        if not isinstance(reason, str) or not reason.strip():
            return "capture_exclusion_reason is required when capture_eligible=false"
    if "block_confirmed" in row and not isinstance(row["block_confirmed"], bool):
        return "block_confirmed must be boolean when present"
    if row.get("block_confirmed") is True:
        if _parse_utc_timestamp(row.get("block_confirmed_at")) is None:
            return "block_confirmed_at is required when block_confirmed=true"
    elif row.get("block_confirmed_at") is not None:
        if _parse_utc_timestamp(row.get("block_confirmed_at")) is None:
            return "block_confirmed_at must be a UTC timestamp"
    return None


def _scenario_result_manifest_contract_issue(
    row: Mapping[str, Any],
    manifest: RunManifest,
) -> str | None:
    if manifest.session_id is not None:
        if not isinstance(row.get("session_id"), str) or not row["session_id"].strip():
            return "session_id is required for captured runs"
        return None
    if row.get("session_id") not in {None, ""}:
        return "session_id must be null or omitted for pre-capture runs"
    return None


def _load_existing_jsonl(
    path: Path,
    evaluation_schema_version: str,
    source_commit: str,
) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    rows = _load_jsonl(path, "existing evaluation JSONL")
    for index, row in enumerate(rows, start=1):
        if row.get("evaluation_schema_version") != evaluation_schema_version:
            raise Phase5ExportError(
                "existing JSONL schema version mismatch at "
                f"line {index}: {row.get('evaluation_schema_version')!r}"
            )
        if not isinstance(row.get("evaluation_identity"), str):
            raise Phase5ExportError(
                f"existing JSONL is missing evaluation_identity at line {index}"
            )
        if row.get("source_commit") != source_commit:
            raise Phase5ExportError(
                "existing JSONL source_commit mismatch at "
                f"line {index}: {row.get('source_commit')!r}"
            )
    return rows


def _load_jsonl(path: Path, label: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as jsonl_file:
            for line_number, line in enumerate(jsonl_file, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    payload = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise Phase5ExportError(
                        f"invalid {label} JSON at line {line_number}: {path}"
                    ) from exc
                if not isinstance(payload, dict):
                    raise Phase5ExportError(
                        f"{label} line {line_number} must be a JSON object"
                    )
                rows.append(payload)
    except OSError as exc:
        raise Phase5ExportError(f"failed to read {label}: {path}") from exc
    return rows


def _dedupe_rows(rows: Sequence[dict[str, Any]]) -> list[dict[str, Any]]:
    by_identity: dict[str, dict[str, Any]] = {}
    for row in rows:
        identity = str(row["evaluation_identity"])
        existing = by_identity.get(identity)
        if existing is not None:
            if _canonical_json(existing) != _canonical_json(row):
                raise Phase5ExportError(
                    "evaluation JSONL contains conflicting rows for identity: "
                    f"{identity}"
                )
            continue
        by_identity[identity] = row
    return sorted(
        by_identity.values(),
        key=lambda row: (
            str(row.get("run_id")),
            str(row.get("session_id")),
            str(row.get("scenario", {}).get("scenario_id")),
            str(row.get("evaluation_identity")),
        ),
    )


def _validate_manifest_sidecar(path: Path, manifest: RunManifest) -> None:
    sidecar_path = path.with_name(path.name + RUN_MANIFEST_SHA256_SIDECAR_SUFFIX)
    if not sidecar_path.exists():
        return
    expected = run_manifest_sha256(manifest)
    sidecar_parts = sidecar_path.read_text(encoding="utf-8").strip().split()
    if not sidecar_parts:
        raise Phase5ExportError(f"run manifest SHA256 sidecar is empty: {sidecar_path}")
    actual = sidecar_parts[0]
    if actual != expected:
        raise Phase5ExportError(
            f"run manifest SHA256 sidecar mismatch: {sidecar_path}"
        )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise Phase5ExportError(f"failed to read input artifact: {path}") from exc
    return digest.hexdigest()


def _canonical_json_sha256(
    payload: Mapping[str, Any],
    *,
    exclude_meta: bool = False,
) -> str:
    if exclude_meta:
        payload = {
            key: value
            for key, value in payload.items()
            if not str(key).startswith("_")
        }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _canonical_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _parse_utc_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    if parsed.utcoffset() != timedelta(0):
        return None
    return parsed


def _write_jsonl_atomically(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    _write_text_atomically(
        path,
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n"
            for row in rows
        ),
    )


def _write_csv_atomically(path: Path, rows: Sequence[Mapping[str, Any]]) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            newline="",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as csv_file:
            temporary_path = Path(csv_file.name)
            writer = csv.DictWriter(csv_file, fieldnames=list(CSV_COLUMNS))
            writer.writeheader()
            for row in rows:
                writer.writerow(_csv_row(row))
            csv_file.flush()
            os.fsync(csv_file.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _write_json_atomically(path: Path, payload: Mapping[str, Any]) -> None:
    _write_text_atomically(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def _write_text_atomically(path: Path, content: str) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as text_file:
            temporary_path = Path(text_file.name)
            text_file.write(content)
            text_file.flush()
            os.fsync(text_file.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _csv_row(row: Mapping[str, Any]) -> dict[str, str]:
    matched_ids = row.get("matched_ids", {})
    statuses = row.get("statuses", {})
    classification = row.get("classification", {})
    scenario = row.get("scenario", {})
    matching = row.get("matching", {})
    return {
        "evaluation_schema_version": _csv_value(row.get("evaluation_schema_version")),
        "source_commit": _csv_value(row.get("source_commit")),
        "run_manifest_schema_version": _csv_value(row.get("run_manifest_schema_version")),
        "evaluation_identity": _csv_value(row.get("evaluation_identity")),
        "run_id": _csv_value(row.get("run_id")),
        "session_id": _csv_value(row.get("session_id")),
        "scenario_id": _csv_value(scenario.get("scenario_id")),
        "target_device_id": _csv_value(row.get("target_device_id")),
        "source_ip": _csv_value(row.get("source_ip")),
        "evaluation_unit": _csv_value(row.get("evaluation_unit")),
        "final_status": _csv_value(row.get("final_status")),
        "scenario_status": _csv_value(statuses.get("scenario_status")),
        "detection_status": _csv_value(statuses.get("detection_status")),
        "trust_status": _csv_value(statuses.get("trust_status")),
        "firewall_status": _csv_value(statuses.get("firewall_status")),
        "block_status": _csv_value(statuses.get("block_status")),
        "data_status": _csv_value(statuses.get("data_status")),
        "valid_run": _csv_value(row.get("valid_run")),
        "tp": _csv_value(classification.get("tp")),
        "fp": _csv_value(classification.get("fp")),
        "tn": _csv_value(classification.get("tn")),
        "fn": _csv_value(classification.get("fn")),
        "matched_detection_event_ids": _csv_value(matched_ids.get("detection_event_ids")),
        "matched_trust_score_history_ids": _csv_value(
            matched_ids.get("trust_score_history_ids")
        ),
        "matched_firewall_rule_ids": _csv_value(matched_ids.get("firewall_rule_ids")),
        "trigger_event_ids": _csv_value(matched_ids.get("trigger_event_ids")),
        "matching_strategy": _csv_value(matching.get("strategy")),
        "failure_reasons": _csv_value(row.get("failure_reasons")),
        "latencies": _csv_value(row.get("latencies")),
    }


def _csv_value(value: Any) -> str:
    if value is None:
        return "null"
    if value == "NOT_APPLICABLE":
        return "N/A"
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


if __name__ == "__main__":
    raise SystemExit(main())
