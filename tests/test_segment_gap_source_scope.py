"""Scope admits healthy append activity without relaxing frozen recovery inputs."""
import sqlite3
from datetime import timedelta

import pytest

from edge.detection import segment_gap_source_scope as scope_module
from edge.packet.capture_policy import CapturePolicy

TEST_POLICY = CapturePolicy(max_start_delay_seconds=1.0, minimum_duration_seconds=9.0,
                            epsilon_seconds=0.01, version="configured-test-policy")

import test_packet_segment_gap_recovery as seed_module


@pytest.fixture
def source(tmp_path):
    seed = seed_module.seed_segment_gap_chain_database(tmp_path / "source.db")
    connection = sqlite3.connect(seed["database_path"])
    connection.execute("BEGIN")
    scope = scope_module.build_source_scope(connection, {
        "capture_session_id": seed["capture_session_id"], "window_start": seed_module.utc(10), "window_end": seed_module.utc(40),
    }, capture_policy=TEST_POLICY)
    connection.rollback()
    yield connection, scope, seed
    connection.close()


def verify(connection, scope):
    connection.execute("BEGIN")
    try:
        scope_module.verify_source_scope(connection, scope)
    finally:
        connection.rollback()


def append_segment(connection, scope, **changes):
    values = {"capture_session_id": scope["capture_session_pk"], "capture_interface": scope["capture_interface"],
              "file_name": "new.pcap", "window_start": seed_module.utc(60), "window_end": seed_module.utc(70),
              "status": "READY", "error_code": None, "error_message": None,
              "start_delay_seconds": 0.0, "captured_duration_seconds": 10.0}
    values.update(changes)
    cursor = connection.execute(f"INSERT INTO packet_capture_segments({','.join(values)}) "
                                f"VALUES ({','.join('?' for _ in values)})", tuple(values.values()))
    return cursor.lastrowid


def test_contiguous_ready_capture_and_current_receive_append_are_allowed(source):
    connection, scope, _ = source
    append_segment(connection, scope)
    connection.execute("INSERT INTO mqtt_logs(topic,received_at) VALUES ('iot/esp32_01/sensor',?)", (seed_module.utc(63),))
    connection.execute("UPDATE devices SET last_seen_at=?", (seed_module.utc(65),))
    connection.commit()
    verify(connection, scope)


@pytest.mark.parametrize("query", [
    "INSERT INTO mqtt_logs(topic,received_at) VALUES ('iot/esp32_01/sensor',?)",
    "INSERT INTO feature_logs(device_id,window_start,window_end) VALUES ('esp32_01',?, ?)",
    "INSERT INTO gateway_metrics(collected_at,memory_percent,disk_percent,interface_metrics_json) VALUES (?,1,1,'{}')",
])
@pytest.mark.parametrize("observed_second", [39, 39.999999, 40, 59])
def test_delayed_input_commit_uses_recovery_end_not_capture_tail(source, query, observed_second):
    connection, scope, _ = source
    assert scope["recovery_input_end"] == seed_module.utc(40)
    assert scope["tail_start"] == seed_module.utc(60)
    # The producer obtains its timestamp before the approval read transaction,
    # then commits after its high-water mark was frozen. A boundary-adjacent
    # normal observation must not be mistaken for backfill into the lost PCAP.
    observation = (seed_module.BASE + timedelta(seconds=observed_second)).isoformat().replace('+00:00', 'Z')
    values = (observation, seed_module.utc(70)) if query.count('?') == 2 else (observation,)
    connection.execute(query, values)
    connection.commit()
    if observed_second < 40:
        with pytest.raises(ValueError, match="input is outside"):
            verify(connection, scope)
    else:
        verify(connection, scope)


def test_produced_new_packet_features_only_bind_new_healthy_tail(source):
    connection, scope, _ = source
    segment_id = append_segment(connection, scope, status="PROCESSED")
    connection.execute("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,"
                       "packet_count,total_bytes,avg_packet_size,max_packet_size) VALUES (?,'192.168.0.4','INBOUND',?,?,2,10,5,5)",
                       (segment_id, seed_module.utc(60), seed_module.utc(70)))
    connection.commit()
    verify(connection, scope)


@pytest.mark.parametrize("changes", [
    {"start_delay_seconds": 2.0, "captured_duration_seconds": 8.0},
    {"captured_duration_seconds": None},
    {"captured_duration_seconds": 8.0},
    {"file_name": ""},
])
def test_ready_tail_requires_real_capture_policy_eligibility_and_filename(source, changes):
    connection, scope, _ = source
    append_segment(connection, scope, **changes)
    connection.commit()
    with pytest.raises(ValueError, match="normal tail|eligible"):
        verify(connection, scope)


def test_source_scope_uses_explicit_configured_policy_instead_of_defaults(source):
    connection, _, seed = source
    policy = CapturePolicy(max_start_delay_seconds=2.0, minimum_duration_seconds=8.0,
                           epsilon_seconds=0.01, version="explicit-two-second-policy")
    connection.execute("BEGIN")
    scope = scope_module.build_source_scope(connection, {
        "capture_session_id": seed["capture_session_id"], "window_start": seed_module.utc(10), "window_end": seed_module.utc(40),
    }, capture_policy=policy)
    connection.rollback()
    assert scope["capture_policy"]["max_start_delay_seconds"] == 2.0
    append_segment(connection, scope, start_delay_seconds=1.5, captured_duration_seconds=8.5)
    connection.commit()
    verify(connection, scope)


@pytest.mark.parametrize("changes", [
    {"status": "FAILED", "error_code": "PARTIAL_CAPTURE"},
    {"window_start": seed_module.utc(70), "window_end": seed_module.utc(80)},
    {"capture_interface": "eth1"},
    {"window_start": seed_module.utc(-10), "window_end": seed_module.utc(0)},
    {"status": "READY", "error_message": "unexplained"},
])
def test_new_failed_gapped_other_interface_or_prefix_capture_rejects(source, changes):
    connection, scope, _ = source
    append_segment(connection, scope, **changes)
    connection.commit()
    with pytest.raises(ValueError, match="normal tail|protected source scope"):
        verify(connection, scope)


@pytest.mark.parametrize("mutation", [
    "UPDATE packet_capture_segments SET packet_count=123 WHERE id=1",
    "DELETE FROM packet_feature_logs WHERE id=1",
    "UPDATE packet_feature_logs SET total_bytes=123 WHERE id=1",
    "UPDATE devices SET trust_score=80",
    "UPDATE devices SET ip_address='192.168.0.9'",
    "UPDATE devices SET status='isolated'",
    "UPDATE packet_capture_sessions SET updated_at='changed'",
    "UPDATE detector_checkpoints SET last_processed_id=42 WHERE detector_name='trust_score_v2'",
    "UPDATE schema_migrations SET name='changed' WHERE version=8",
    "CREATE TABLE unexpected_model_setting(value TEXT)",
])
def test_approved_inputs_security_config_checkpoints_and_schema_are_frozen(source, mutation):
    connection, scope, _ = source
    connection.execute(mutation)
    connection.commit()
    with pytest.raises(ValueError, match="protected source scope"):
        verify(connection, scope)


def test_new_feature_attached_to_existing_segment_is_rejected(source):
    connection, scope, _ = source
    connection.execute("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,"
                       "packet_count,total_bytes,avg_packet_size,max_packet_size) VALUES (1,'192.168.0.9','INBOUND',?,?,2,10,5,5)",
                       (seed_module.utc(0), seed_module.utc(10)))
    connection.commit()
    with pytest.raises(ValueError, match="new Packet Features"):
        verify(connection, scope)


def test_scope_requires_transaction_and_detects_unresealed_hwm_change(source):
    connection, scope, _ = source
    with pytest.raises(ValueError, match="transaction"):
        scope_module.verify_source_scope(connection, scope)
    scope["high_water_marks"]["packet_feature_logs"] += 1
    with pytest.raises(ValueError, match="SHA256"):
        verify(connection, scope)


@pytest.mark.parametrize("new_failure", [False, True])
def test_unrelated_previous_packet_values_are_outside_scope_but_new_failures_are_not(source, new_failure):
    connection, _, seed = source
    connection.execute("INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at,first_window_start,status) "
                       "VALUES ('22222222-2222-4222-8222-222222222222','eth0',?,?,'COMPLETED')",
                       (seed_module.utc(-120), seed_module.utc(-120)))
    session_pk = connection.execute("SELECT last_insert_rowid()").fetchone()[0]
    segment_id = append_segment(connection, {"capture_session_pk": session_pk, "capture_interface": "eth0"},
                                file_name="old.pcap", window_start=seed_module.utc(-120),
                                window_end=seed_module.utc(-110), status="PROCESSED")
    connection.execute("INSERT INTO packet_feature_logs(capture_segment_id,peer_ip,direction,window_start,window_end,"
                       "packet_count,total_bytes,avg_packet_size,max_packet_size) VALUES (?,'192.168.0.4','INBOUND',?,?,2,10,5,5)",
                       (segment_id, seed_module.utc(-120), seed_module.utc(-110)))
    connection.commit()
    connection.execute("BEGIN")
    scope = scope_module.build_source_scope(connection, {
        "capture_session_id": seed["capture_session_id"], "window_start": seed_module.utc(10), "window_end": seed_module.utc(40),
    }, capture_policy=TEST_POLICY)
    connection.rollback()
    if new_failure:
        connection.execute("UPDATE packet_capture_segments SET status='FAILED',error_code='PARTIAL_CAPTURE' WHERE id=?", (segment_id,))
    else:
        connection.execute("UPDATE packet_feature_logs SET total_bytes=42 WHERE capture_segment_id=?", (segment_id,))
    connection.commit()
    if new_failure:
        with pytest.raises(ValueError, match="protected source scope"):
            verify(connection, scope)
    else:
        verify(connection, scope)
