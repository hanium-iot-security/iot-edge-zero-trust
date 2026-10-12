"""Bounded admission review: provenance, final snapshot, group/split consistency. Never approves."""
from contextlib import closing
from datetime import timedelta
import json
import shutil
import sqlite3
from uuid import uuid4

import pytest

from ai import normal_admission as admission
from ai.normal_admission import main, review_admission
from tests import test_normal_collection_export as base
from tests.test_normal_collection_export import IDS, START, digest, mutate_db, save_manifest, tree_hashes, utc

package = base.package  # shared synthetic three-device candidate fixture

EVIDENCE_SHA = "e" * 64


@pytest.fixture
def case(package, tmp_path):
    """Packages dir = tmp_path; the review writes to a sibling directory."""
    root = tmp_path
    output = tmp_path.parent / f"{tmp_path.name}-admission"
    (root / "request.json").write_text("{}", encoding="utf-8")

    class Case:
        packages = root
        out = output

        @staticmethod
        def manifest():
            return json.loads((package / "manifest.json").read_text())

        @staticmethod
        def final(complete=True, sql=None):
            """Final snapshot: a copy of the candidate snapshot, optionally completed or altered."""
            shutil.copy(package / "after.db", root / "final.db")
            with closing(sqlite3.connect(root / "final.db")) as db:
                if complete:
                    db.execute("UPDATE packet_capture_sessions SET status='COMPLETED', ended_at=?",
                               (utc(START + timedelta(seconds=30)),))
                for statement in sql or ():
                    db.execute(*statement) if isinstance(statement, tuple) else db.execute(statement)
                db.commit()

        @staticmethod
        def request(**changes):
            manifest = Case.manifest()
            specs = [{"device_id": device,
                      "firmware_id": "pico-app-1" if device == "pico_01" else "esp32-p0-1",
                      "payload_schema": "pico-bme280-v1" if device == "pico_01" else "esp32-telemetry-v1",
                      "profile": "P0", "effective_from": utc(START - timedelta(hours=1)),
                      "evidence": {"kind": "INSTALLED_BINARY_READBACK", "sha256": EVIDENCE_SHA,
                                   "observed_at": utc(START - timedelta(minutes=1))}} for device in IDS]
            request = {"schema_version": "normal-admission-request-v1",
                       "runs": [{"run_dir": "candidate", "manifest_sha256": digest(package / "manifest.json")}],
                       "final_snapshot": {"path": "final.db", "sha256": digest(root / "final.db")},
                       "device_specs": specs,
                       "slots": [{"collection_slot_id": "T1", "run_id": manifest["run_id"], "split": "UNASSIGNED"}]}
            request.update(changes)
            (root / "request.json").write_text(json.dumps(request), encoding="utf-8")
            return request

        @staticmethod
        def review(name="review"):
            return review_admission(root, root / "request.json", output / name)

    Case.final()
    return Case


def test_eligible_candidate_is_reported_without_any_approval_and_sources_stay_unchanged(case, package):
    case.request()
    before = tree_hashes(package)

    report = case.review()

    assert report["official_admission"] == "BOUNDED_ELIGIBLE" and report["blockers"] == []
    assert report["training_approved"] is False and report["whole_capture_session_approved"] is False
    assert report["whole_session"]["whole_session_eligible"] is True
    assert report["runs"][0]["candidate_qc"] == "PASS"
    assert report["range_consistency"] == [{"run_id": case.manifest()["run_id"], "match": True}]
    assert json.loads((case.out / "review" / "admission-report.json").read_text())["status"] == "PASS"
    assert tree_hashes(package) == before


@pytest.mark.parametrize("change,expected", [
    ("evidence_after_run", "provenance_after_run_start"),
    ("effective_after_run", "provenance_after_run_start"),
    ("missing_device", "device_specs_do_not_match_runs"),
    ("extra_device", "device_specs_do_not_match_runs"),
    ("duplicate_device", "duplicate_device_spec"),
    ("pico_declared_as_esp32", "payload_schema_mismatch"),
    ("esp32_declared_as_pico", "payload_schema_mismatch"),
])
def test_device_specs_must_match_runs_schemas_and_precede_the_run(case, change, expected):
    request = case.request()
    specs = request["device_specs"]
    if change == "evidence_after_run":
        specs[0]["evidence"]["observed_at"] = utc(START + timedelta(seconds=5))
    elif change == "effective_after_run":
        specs[0]["effective_from"] = utc(START + timedelta(seconds=10))
    elif change == "missing_device":
        specs.pop()
    elif change == "extra_device":
        specs.append({**specs[0], "device_id": "esp32_09"})
    elif change == "duplicate_device":
        specs.append(dict(specs[0]))
    elif change == "pico_declared_as_esp32":
        specs[-1]["payload_schema"] = "esp32-telemetry-v1"
    else:
        specs[0]["payload_schema"] = "pico-bme280-v1"
    case.request(device_specs=specs)

    report = case.review()

    assert report["official_admission"] == "HOLD"
    assert any(expected in item for item in report["blockers"])
    assert report["training_approved"] is False


def test_failed_run_qc_holds_the_admission(case, package):
    mutate_db(package, "UPDATE feature_logs SET publish_count=9 WHERE rowid=1")
    case.final()
    case.request()

    report = case.review()

    assert report["official_admission"] == "HOLD" and report["runs"][0]["candidate_qc"] == "HOLD"
    assert any("candidate_qc_hold" in item for item in report["blockers"])


def _second_run(package, tmp_path, same_group, shift=40):
    clone = tmp_path / "candidate2"
    shutil.copytree(package, clone)
    manifest = json.loads((clone / "manifest.json").read_text())
    manifest["run_id"] = str(uuid4())
    manifest["start_utc"] = utc(START + timedelta(seconds=shift))
    manifest["end_utc"] = utc(START + timedelta(seconds=shift + 20))
    if not same_group:
        manifest["source_capture_group_id"] = str(uuid4())
    save_manifest(clone, manifest)
    return manifest


def test_runs_from_different_capture_groups_are_refused(case, package, tmp_path):
    second = _second_run(package, tmp_path, same_group=False)
    first = case.manifest()
    case.request(
        runs=[{"run_dir": "candidate", "manifest_sha256": digest(package / "manifest.json")},
              {"run_dir": "candidate2", "manifest_sha256": digest(tmp_path / "candidate2" / "manifest.json")}],
        slots=[{"collection_slot_id": "T1", "run_id": first["run_id"], "split": "train"},
               {"collection_slot_id": "T2", "run_id": second["run_id"], "split": "train"}])

    assert "group:runs_span_multiple_capture_groups" in case.review()["blockers"]


def test_one_capture_group_cannot_cross_splits(case, package, tmp_path):
    second = _second_run(package, tmp_path, same_group=True)
    first = case.manifest()
    case.request(
        runs=[{"run_dir": "candidate", "manifest_sha256": digest(package / "manifest.json")},
              {"run_dir": "candidate2", "manifest_sha256": digest(tmp_path / "candidate2" / "manifest.json")}],
        slots=[{"collection_slot_id": "T1", "run_id": first["run_id"], "split": "train"},
               {"collection_slot_id": "V1", "run_id": second["run_id"], "split": "validation"}])

    assert "group:split_crosses_capture_group" in case.review()["blockers"]


def test_overlapping_runs_are_refused(case, package, tmp_path):
    second = _second_run(package, tmp_path, same_group=True, shift=10)
    first = case.manifest()
    case.request(
        runs=[{"run_dir": "candidate", "manifest_sha256": digest(package / "manifest.json")},
              {"run_dir": "candidate2", "manifest_sha256": digest(tmp_path / "candidate2" / "manifest.json")}],
        slots=[{"collection_slot_id": "T1", "run_id": first["run_id"], "split": "train"},
               {"collection_slot_id": "T2", "run_id": second["run_id"], "split": "train"}])

    assert "group:runs_overlap" in case.review()["blockers"]


def test_a_review_that_changes_the_source_package_holds(case, package, monkeypatch):
    case.request()
    real = admission.export_normal_collection

    def touching(path, *, output_dir):
        report = real(path, output_dir=output_dir)
        (path / "pcap" / "stray.txt").write_text("changed", encoding="utf-8")
        return report

    monkeypatch.setattr(admission, "export_normal_collection", touching)

    assert "run:1:source_package_changed" in case.review()["blockers"]


@pytest.mark.parametrize("slots,expected", [
    ("duplicate_slot", "duplicate_slot_id"),
    ("unknown_run", "slots_do_not_match_runs"),
    ("run_without_slot", "slots_do_not_match_runs"),
])
def test_slots_must_map_each_run_exactly_once(case, slots, expected):
    run_id = case.manifest()["run_id"]
    mapping = {
        "duplicate_slot": [{"collection_slot_id": "T1", "run_id": run_id, "split": "train"},
                           {"collection_slot_id": "T1", "run_id": run_id, "split": "train"}],
        "unknown_run": [{"collection_slot_id": "T1", "run_id": str(uuid4()), "split": "train"}],
        "run_without_slot": [{"collection_slot_id": "T1", "run_id": run_id, "split": "train"},
                             {"collection_slot_id": "T2", "run_id": str(uuid4()), "split": "train"}],
    }
    case.request(slots=mapping[slots])

    assert any(expected in item for item in case.review()["blockers"])


def test_final_snapshot_must_be_completed_and_match_the_declared_hash(case):
    case.final(complete=False)
    case.request()
    assert "final_snapshot:CandidateQCError" not in case.review("running")["blockers"]
    assert "final_snapshot:session_not_completed_or_mismatched" in case.review("running2")["blockers"]

    case.final()
    request = case.request()
    request["final_snapshot"]["sha256"] = "0" * 64
    case.request(final_snapshot=request["final_snapshot"])
    assert "final_snapshot:final_snapshot_checksum" in case.review("bad-hash")["blockers"]


def test_failure_inside_the_selected_range_holds(case):
    case.final(sql=["UPDATE packet_capture_segments SET status='FAILED', error_code='PARTIAL_CAPTURE' WHERE id=1"])
    case.request()

    report = case.review()

    assert report["official_admission"] == "HOLD"
    assert "final_snapshot:session_failure_inside_selected_range" in report["blockers"]


def test_failure_outside_the_selected_range_is_disclosed_but_keeps_the_bounded_admission(case):
    later = START + timedelta(seconds=300)
    case.final(sql=[("INSERT INTO packet_capture_segments(capture_session_id, file_name, capture_interface, "
                     "window_start, window_end, status, error_code) VALUES(1, 'late.pcap', 'eth0', ?, ?, "
                     "'FAILED', 'PARTIAL_CAPTURE')", (utc(later), utc(later + timedelta(seconds=10))))])
    case.request()

    report = case.review()

    assert report["official_admission"] == "BOUNDED_ELIGIBLE"
    assert report["whole_session"]["whole_session_eligible"] is False
    assert [item["error_code"] for item in report["whole_session"]["ineligible_segments"]] == ["PARTIAL_CAPTURE"]
    assert report["whole_capture_session_approved"] is False


@pytest.mark.parametrize("sql", [
    "UPDATE feature_logs SET max_payload_size=max_payload_size+1 WHERE rowid=1",
    "UPDATE mqtt_logs SET error_message='tampered' WHERE rowid=1",
    "UPDATE packet_feature_logs SET packet_count=packet_count+1 WHERE rowid=1",
])
def test_selected_rows_must_be_identical_in_the_final_snapshot(case, sql):
    case.final(sql=[sql])
    case.request()

    report = case.review()

    assert any(item.startswith("range_consistency:range_rows_changed") for item in report["blockers"])
    assert report["range_consistency"][0]["match"] is False


@pytest.mark.parametrize("mutate", [
    lambda r: r.update({"training_approved": True}),
    lambda r: r.update({"schema_version": "v0"}),
    lambda r: r["runs"][0].update({"manifest_sha256": "xyz"}),
    lambda r: r["runs"][0].update({"run_dir": "../escape"}),
    lambda r: r["slots"][0].update({"split": "holdout"}),
    lambda r: r["device_specs"][0]["evidence"].update({"observed_at": "yesterday"}),
    lambda r: r["device_specs"][0].update({"effective_from": utc(START + timedelta(seconds=5))}),
    lambda r: r["device_specs"][0].update({"payload_schema": "unknown"}),
    lambda r: r.pop("slots"),
])
def test_malformed_requests_are_refused_before_any_output(case, mutate):
    request = case.request()
    mutate(request)
    (case.packages / "request.json").write_text(json.dumps(request), encoding="utf-8")

    report = case.review()

    assert report["official_admission"] == "HOLD" and report["blockers"][0].startswith("preflight:")
    assert not (case.out / "review").exists()


def test_output_directory_must_be_new_and_outside_the_packages(case, tmp_path):
    case.request()
    assert case.review()["official_admission"] == "BOUNDED_ELIGIBLE"
    again = case.review()
    assert again["blockers"] == ["preflight:output_must_be_new"]
    inside = review_admission(case.packages, case.packages / "request.json", case.packages / "inside")
    assert inside["blockers"] == ["preflight:output_must_be_outside_package"]


def test_cli_exit_codes(case, capsys):
    case.request()
    argv = ["--packages-dir", str(case.packages), "--request", str(case.packages / "request.json")]

    assert main([*argv, "--output-dir", str(case.out / "cli-ok")]) == 0
    assert "training_approved=false" in capsys.readouterr().out
    case.final(complete=False)
    case.request()
    assert main([*argv, "--output-dir", str(case.out / "cli-hold")]) == 2
    assert "Blockers:" in capsys.readouterr().out
