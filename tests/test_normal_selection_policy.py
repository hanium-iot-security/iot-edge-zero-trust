"""MQTT selection policies: the legacy 100 B filter stays reproducible and phase9 keeps validity only."""
import csv
import json
import math

import pytest
from sqlalchemy import text

from ai.export_normal_collection import CandidateQCError, MQTT_COLUMNS
from ai.export_normal_features import export_normal_features
from ai.normal_selection_policy import (
    LEGACY_POLICY,
    PHASE9_POLICY,
    build_report,
    exclusion_reasons,
    main,
    select_rows,
)
from tests.conftest import cleanup_device


def row(**changes):
    values = {"id": 1, "device_id": "esp32_01", "window_start": "2026-10-04T12:00:00Z",
              "window_end": "2026-10-04T12:00:10Z", "publish_count": 2, "avg_payload_size": 57.0,
              "max_payload_size": 57, "avg_message_interval": 5.0, "min_message_interval": 5.0,
              "topic_count": 1, "abnormal_topic_count": 0, "malformed_payload_count": 0}
    values.update(changes)
    return values


PICO = dict(device_id="pico_01", avg_payload_size=130.0, max_payload_size=132)


class TestReasons:
    def test_a_normal_esp32_row_is_selected_by_both_policies(self):
        assert exclusion_reasons(row(), LEGACY_POLICY) == [] and exclusion_reasons(row(), PHASE9_POLICY) == []

    def test_pico_is_dropped_only_by_the_legacy_size_filter(self):
        assert exclusion_reasons(row(**PICO), LEGACY_POLICY) == ["avg_payload_outside_20_100", "max_payload_above_100"]
        assert exclusion_reasons(row(**PICO), PHASE9_POLICY) == []

    @pytest.mark.parametrize("changes,reason", [
        ({"avg_message_interval": 3.9}, "avg_interval_outside_4_6"),
        ({"min_message_interval": 6.1}, "min_interval_outside_4_6"),
    ])
    def test_interval_band_is_a_legacy_only_rule(self, changes, reason):
        assert reason in exclusion_reasons(row(**changes), LEGACY_POLICY)
        assert exclusion_reasons(row(**changes), PHASE9_POLICY) == []

    @pytest.mark.parametrize("changes,reason", [
        ({"publish_count": 4}, "publish_count_outside_1_3"),
        ({"publish_count": 0}, "publish_count_outside_1_3"),
        ({"topic_count": 2}, "topic_count_not_one"),
        ({"abnormal_topic_count": 1}, "abnormal_topic"),
        ({"malformed_payload_count": 1}, "malformed_payload"),
        ({"avg_payload_size": "nan"}, "non_numeric_or_non_finite_value"),
        ({"max_payload_size": "inf"}, "non_numeric_or_non_finite_value"),
        ({"min_message_interval": ""}, "non_numeric_or_non_finite_value"),
        ({"avg_message_interval": None}, "non_numeric_or_non_finite_value"),
    ])
    def test_validity_rules_apply_to_both_policies(self, changes, reason):
        for policy in (LEGACY_POLICY, PHASE9_POLICY):
            assert reason in exclusion_reasons(row(**changes), policy)

    def test_unknown_policy_is_refused(self):
        with pytest.raises(CandidateQCError, match="unknown_selection_policy"):
            exclusion_reasons(row(), "other")

    def test_select_rows_keeps_input_order(self):
        rows = [row(id=1), row(id=2, **PICO), row(id=3, publish_count=9), row(id=4, **PICO)]
        assert [item["id"] for item in select_rows(rows, PHASE9_POLICY)] == [1, 2, 4]
        assert [item["id"] for item in select_rows(rows, LEGACY_POLICY)] == [1]


def test_legacy_policy_selects_exactly_what_the_original_export_selects(db_session, tmp_path):
    device_id = "legacy_repro"
    cleanup_device(db_session, device_id)
    db_session.execute(text("INSERT INTO devices (device_id, ip_address, status, trust_score) "
                            "VALUES (:d, '192.168.0.96', 'normal', 100)"), {"d": device_id})
    variants = []
    for publish in (0, 1, 3, 4):
        variants.append({"publish_count": publish})
    for avg in (19.99, 20.0, 100.0, 100.01):
        variants.append({"avg_payload_size": avg})
    for maximum in (100, 101):
        variants.append({"max_payload_size": maximum})
    for interval in (3.99, 4.0, 6.0, 6.01):
        variants.append({"avg_message_interval": interval})
        variants.append({"min_message_interval": interval})
    variants += [{"topic_count": 0}, {"topic_count": 2}, {"abnormal_topic_count": 1}, {"malformed_payload_count": 1}, {}]
    for index, change in enumerate(variants):
        values = {"publish_count": 2, "avg_payload_size": 57.0, "max_payload_size": 57,
                  "avg_message_interval": 5.0, "min_message_interval": 5.0, "topic_count": 1,
                  "abnormal_topic_count": 0, "malformed_payload_count": 0, **change}
        db_session.execute(text(
            "INSERT INTO feature_logs (device_id, window_start, window_end, publish_count, avg_payload_size, "
            "max_payload_size, avg_message_interval, min_message_interval, topic_count, abnormal_topic_count, "
            "malformed_payload_count) VALUES (:device_id, :s, :e, :publish_count, :avg_payload_size, "
            ":max_payload_size, :avg_message_interval, :min_message_interval, :topic_count, "
            ":abnormal_topic_count, :malformed_payload_count)"),
            {"device_id": device_id, "s": f"2026-10-04 12:{index:02d}:00", "e": f"2026-10-04 12:{index:02d}:10", **values})
    db_session.commit()
    stored = [dict(item) for item in db_session.execute(text(
        "SELECT * FROM feature_logs WHERE device_id = :d ORDER BY window_start"), {"d": device_id}).mappings()]
    output = tmp_path / "legacy.csv"

    export_normal_features(db_session, output, device_id=device_id)

    exported = [item["window_start"] for item in csv.DictReader(output.open(encoding="utf-8"))]
    assert exported == [item["window_start"] for item in select_rows(stored, LEGACY_POLICY)]
    assert 0 < len(exported) < len(stored)
    cleanup_device(db_session, device_id)


def candidate_qc(root, name, rows, *, status="PASS"):
    folder = root / name
    folder.mkdir()
    (folder / "qc-report.json").write_text(json.dumps({"status": status, "run_id": f"run-{name}"}), encoding="utf-8")
    with (folder / "mqtt-features.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=MQTT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return folder


@pytest.fixture
def qc_dirs(tmp_path):
    source = tmp_path / "qc"
    source.mkdir()
    esp = [row(id=index, window_start=f"w{index}") for index in range(1, 4)]
    pico = [row(id=10 + index, **PICO) for index in range(4)] + [row(id=20, publish_count=7, **PICO)]
    return [candidate_qc(source, "a", esp), candidate_qc(source, "b", pico)]


def test_report_counts_rows_per_device_before_and_after(qc_dirs, tmp_path):
    report = build_report(qc_dirs, tmp_path / "out")

    assert report["devices"]["esp32_01"]["newly_included"] == 0
    pico = report["devices"]["pico_01"]
    assert (pico["rows"], pico[LEGACY_POLICY]["included"], pico[PHASE9_POLICY]["included"]) == (5, 0, 4)
    assert pico[LEGACY_POLICY]["exclusion_reasons"]["max_payload_above_100"] == 5
    assert pico[PHASE9_POLICY]["exclusion_reasons"] == {"publish_count_outside_1_3": 1}
    assert pico["newly_included"] == 4
    assert report["training_approved"] is False and report["run_ids"] == ["run-a", "run-b"]
    assert json.loads((tmp_path / "out" / "mqtt-selection-report.json").read_text()) == report
    assert {item["path"] for item in report["input_files"]} == {
        "a/qc-report.json", "a/mqtt-features.csv", "b/qc-report.json", "b/mqtt-features.csv"}
    assert all(len(item["sha256"]) == 64 for item in report["input_files"])


def test_report_never_modifies_the_inputs_and_writes_no_training_csv(qc_dirs, tmp_path):
    before = {path: path.read_bytes() for folder in qc_dirs for path in folder.iterdir()}

    build_report(qc_dirs, tmp_path / "out")

    assert {path: path.read_bytes() for folder in qc_dirs for path in folder.iterdir()} == before
    assert [path.name for path in (tmp_path / "out").iterdir()] == ["mqtt-selection-report.json"]


@pytest.mark.parametrize("problem,code", [
    ("not_pass", "candidate_qc_not_pass"),
    ("missing_csv", "candidate_qc_files_missing"),
    ("duplicate_dir", "qc_dirs_required_and_unique"),
    ("output_exists", "output_must_be_new"),
    ("output_inside", "output_must_be_outside_package"),
])
def test_report_refuses_unsafe_or_unverified_inputs(qc_dirs, tmp_path, problem, code):
    output = tmp_path / "out"
    if problem == "not_pass":
        qc_dirs.append(candidate_qc(qc_dirs[0].parent, "c", [row()], status="HOLD"))
    elif problem == "missing_csv":
        (qc_dirs[0] / "mqtt-features.csv").unlink()
    elif problem == "duplicate_dir":
        qc_dirs.append(qc_dirs[0])
    elif problem == "output_exists":
        output.mkdir()
    else:
        output = qc_dirs[1] / "inside"
    with pytest.raises(CandidateQCError, match=code):
        build_report(qc_dirs, output)


def test_cli_prints_the_per_device_counts_and_fails_closed(qc_dirs, tmp_path, capsys):
    argv = [item for folder in qc_dirs for item in ("--qc-dir", str(folder))]

    assert main([*argv, "--output-dir", str(tmp_path / "out")]) == 0
    assert "pico_01: rows=5 legacy=0 phase9=4 newly_included=4" in capsys.readouterr().out
    assert main([*argv, "--output-dir", str(tmp_path / "out")]) == 2
    assert "output_must_be_new" in capsys.readouterr().out


def test_nan_in_input_rows_is_excluded_not_crashed():
    assert exclusion_reasons(row(avg_payload_size=math.nan), PHASE9_POLICY) == ["non_numeric_or_non_finite_value"]
