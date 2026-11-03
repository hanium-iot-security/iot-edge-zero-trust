"""Management commands only touch temporary SQLite databases."""
import json
import sqlite3
from datetime import timedelta

import pytest

from backend.tests.test_device_policy_api import (
    ADMIN_HEADERS, T0, api_client, create_device, rows, write, change_policy,
)

OMITTED = object()


def management(client):
    response = client.get('/api/devices/pico_01/management')
    assert response.status_code == 200, response.text
    return response.json()


def command(client, state, action='DELETE_UNUSED', **changes):
    payload = {
        'action': action, 'expected_revision': state['expected_revision'],
        'expected_ai_revision': state['expected_ai_revision'],
        'expected_hidden_at': state['hidden_at'], 'reason': 'remove test registration',
        'expected_instance_id': state['expected_instance_id'],
        'expected_management_operation_id': state['expected_management_operation_id'],
        **changes,
    }
    payload = {key: value for key, value in payload.items() if value is not OMITTED}
    return client.post('/api/devices/pico_01/management', headers=ADMIN_HEADERS, json=payload)


def test_unused_delete_audited_and_id_reusable(api_client):
    client, path, _ = api_client
    create_device(client)
    state = management(client)
    assert state['can_delete'] and not state['can_hide']
    response = command(client, state)
    assert response.status_code == 200, response.text
    assert response.json()['deleted']
    for table in ('devices', 'device_policy_revisions', 'device_ai_policy_revisions'):
        assert rows(path, f'SELECT count(*) FROM {table}') == [(0,)]
    audit = rows(path, 'SELECT action,payload_json FROM device_management_audits')[0]
    assert audit[0] == 'DELETE_UNUSED'
    assert json.loads(audit[1])['before_device']['device_id'] == 'pico_01'
    from backend.tests.test_device_policy_api import registration
    duplicate = client.post('/api/devices', headers=ADMIN_HEADERS, json=registration())
    assert duplicate.status_code == 201, duplicate.text
    assert command(client, state).status_code == 409
    # Even with identical clock/boundary/ID, the old audit cannot authorize the
    # new initial rows. A fresh authorized command creates its own audit.
    with pytest.raises(sqlite3.IntegrityError):
        write(path, "DELETE FROM device_ai_policy_revisions WHERE device_id='pico_01'")
    assert command(client, management(client)).status_code == 200
    assert rows(path, 'SELECT count(*) FROM device_management_audits') == [(2,)]
    with pytest.raises(sqlite3.IntegrityError):
        write(path, 'DELETE FROM device_management_audits')


@pytest.mark.parametrize('sql,params', [
    ('INSERT INTO mqtt_logs(device_id,topic) VALUES (?,?)', ('pico_01','iot/pico_01/sensor')),
    ('INSERT INTO mqtt_logs(device_id,topic,payload) VALUES (?,?,?)',
     ('other','iot/other/sensor','{"device_id":"pico_01"}')),
    ('INSERT INTO mqtt_logs(device_id,topic,payload) VALUES (?,?,?)',
     ('other','iot/other/sensor',json.dumps({'device_id':'\t\u2003pico_01\n'}))),
    ('INSERT INTO mqtt_logs(device_id,topic,payload) VALUES (?,?,?)',
     ('other','iot/other/sensor','{"device_id":"other","device_id":"pico_01"}')),
    ('INSERT INTO detection_events(subject_ip,detector_type,event_type) VALUES (?,?,?)',
     ('192.168.0.6','RULE','TEST')),
    ('INSERT INTO isolation_history(device_id) VALUES (?)', ('pico_01',)),
    ('UPDATE devices SET last_seen_at=? WHERE device_id=?', ('2026-10-02T00:00:04Z','pico_01')),
])
def test_new_history_between_preview_and_command_prevents_delete(api_client, sql, params):
    client, path, _ = api_client
    create_device(client)
    state = management(client)
    write(path, sql, params)
    response = command(client, state)
    assert response.status_code == 409, response.text
    assert rows(path, 'SELECT count(*) FROM devices') == [(1,)]
    assert rows(path, 'SELECT count(*) FROM device_management_audits') == [(0,)]
    assert not management(client)['can_delete']


def test_stale_revision_and_unauthenticated_command(api_client):
    client, path, _ = api_client
    create_device(client)
    state = management(client)
    assert command(client, state, expected_ai_revision=2).status_code == 409
    response = client.post('/api/devices/pico_01/management', json={
        'action':'DELETE_UNUSED','expected_revision':1,'expected_ai_revision':1,
        'expected_hidden_at':None,'reason':'test',
        'expected_instance_id':state['expected_instance_id'],
        'expected_management_operation_id':state['expected_management_operation_id'],
    })
    assert response.status_code in (401,403)
    assert rows(path, 'SELECT count(*) FROM devices') == [(1,)]


def test_delete_failure_rolls_back_audit_and_initial_metadata(api_client):
    client, path, _ = api_client
    create_device(client)
    write(path, "CREATE TRIGGER fail_device_delete BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT,'injected failure'); END")
    assert command(client, management(client)).status_code >= 400
    for table in ('devices','device_policy_revisions','device_ai_policy_revisions'):
        assert rows(path, f'SELECT count(*) FROM {table}') == [(1,)]
    assert rows(path, 'SELECT count(*) FROM device_management_audits') == [(0,)]


def test_hide_restore_visibility_and_pagination(api_client, monkeypatch):
    from backend.app.services import device_policy_service
    client, path, clock = api_client
    create_device(client)
    create_device(client, device_id='pico_02', ip_address='192.168.0.7')
    write(path, "INSERT INTO mqtt_logs(device_id,topic) VALUES ('pico_01','iot/pico_01/sensor')")
    monkeypatch.setattr(device_policy_service, 'verify_runtime_firewall', lambda _: {'available':True,'passed':True})
    clock['now'] = T0 + timedelta(seconds=10)
    assert change_policy(client, state='DISABLED').status_code == 201
    assert not management(client)['can_hide']
    clock['now'] = T0 + timedelta(seconds=20)
    state = management(client)
    assert state['can_hide'] and not state['can_delete']
    response = command(client, state, 'HIDE')
    assert response.status_code == 200, response.text
    assert response.json()['hidden_at']
    assert client.get('/api/devices?limit=1').json()['items'][0]['device_id'] == 'pico_02'
    assert client.get('/api/devices').json()['total'] == 1
    assert client.get('/api/devices?include_hidden=true').json()['total'] == 2
    assert client.get('/api/devices/pico_01').status_code == 200
    assert command(client, state, 'RESTORE').status_code == 409
    first_hidden = management(client)
    assert command(client, first_hidden, 'RESTORE').status_code == 200
    assert client.get('/api/devices').json()['total'] == 2
    assert command(client, management(client), 'HIDE').status_code == 200
    assert management(client)['hidden_at'] != first_hidden['hidden_at']
    assert command(client, first_hidden, 'RESTORE').status_code == 409
    assert command(client, management(client), 'RESTORE').status_code == 200
    assert rows(path, "SELECT status,trust_score FROM devices WHERE device_id='pico_01'") == [('normal',100)]
    assert rows(path, 'SELECT count(*) FROM mqtt_logs') == [(1,)]


@pytest.mark.parametrize('sql,params,blocker', [
    ('INSERT INTO feature_logs(device_id,window_start,window_end) VALUES (?,?,?)',
     ('pico_01','2026-10-02T00:00:10Z','2026-10-02T00:00:20Z'),'HISTORY_FEATURE_LOGS'),
    ('INSERT INTO firewall_rules(source_ip,status) VALUES (?,?)',
     ('192.168.0.6','REMOVED'),'HISTORY_FIREWALL_RULES'),
    ('INSERT INTO device_recovery_audits(operation_id,device_id,requested_at,payload_json) VALUES (?,?,?,?)',
     ('old-recovery','pico_01','2026-10-02T00:00:04Z','{}'),'HISTORY_DEVICE_RECOVERY_AUDITS'),
    ('INSERT INTO ai_device_completions(detector_name,device_key,completed_window_end,record_json) VALUES (?,?,?,?)',
     ('mqtt_if','pico_01','2026-10-02T00:00:20Z','{}'),'HISTORY_AI_DEVICE_COMPLETIONS'),
    ('INSERT INTO ai_warning_keys(warning_key,policy_json) VALUES (?,?)',
     ('["pico_01","mqtt_if","AI_ANOMALY","m1","v1"]',
      '{"version":"v1","window_seconds":10,"count_threshold":1,"cooldown_seconds":0}'),'HISTORY_AI_WARNING_KEYS'),
    ('INSERT INTO trust_score_history(device_id,analysis_window_start,analysis_window_end,previous_score,calculated_delta,capped_delta,actual_delta,new_score,representative_event_ids_json,policy_version) VALUES (?,?,?,?,?,?,?,?,?,?)',
     ('pico_01','2026-10-02T00:00:10Z','2026-10-02T00:00:20Z',100,0,0,0,100,'[]','test'),'HISTORY_TRUST_SCORE_HISTORY'),
])
def test_history_sources_are_retained(api_client, sql, params, blocker):
    client, path, _ = api_client
    create_device(client)
    write(path, sql, params)
    state = management(client)
    assert blocker in state['delete_blockers']
    assert command(client, state).status_code == 409


@pytest.mark.parametrize('mapped_device', [None, 'other', 'pico_01'])
def test_packet_ip_evidence_blocks_even_unmapped(api_client, mapped_device):
    client, path, _ = api_client
    create_device(client)
    write(path, "INSERT INTO packet_capture_sessions(session_id,capture_interface,started_at) VALUES ('00000000-0000-4000-8000-000000000001','eth0','2026-10-02T00:00:00Z')")
    write(path, "INSERT INTO packet_capture_segments(capture_session_id,file_name,capture_interface,window_start,window_end) VALUES (1,'one.pcap','eth0','2026-10-02T00:00:00Z','2026-10-02T00:00:10Z')")
    write(path, "INSERT INTO packet_feature_logs(capture_segment_id,device_id,peer_ip,direction,window_start,window_end,packet_count,total_bytes,avg_packet_size,max_packet_size) VALUES (1,?,'192.168.0.6','INBOUND','2026-10-02T00:00:00Z','2026-10-02T00:00:10Z',1,100,100,100)", (mapped_device,))
    state = management(client)
    assert 'HISTORY_PACKET_FEATURE_LOGS' in state['delete_blockers']
    assert command(client, state).status_code == 409
    assert rows(path, 'SELECT count(*) FROM packet_feature_logs') == [(1,)]


def test_active_registration_is_never_deleted(api_client):
    client, path, clock = api_client
    create_device(client)
    clock['now'] = T0 + timedelta(seconds=10)
    assert change_policy(client).status_code == 201
    assert 'INITIAL_REGISTRATION_REQUIRED' in management(client)['delete_blockers']
    assert command(client, management(client)).status_code == 409


def test_changed_ai_is_never_deleted_even_without_telemetry(api_client, monkeypatch):
    from backend.app.services import device_ai_policy_service
    from backend.app.config import settings
    client, path, clock = api_client
    create_device(client)
    clock['now'] = T0 + timedelta(seconds=10)
    monkeypatch.setattr(device_ai_policy_service, 'utc_now', lambda: clock['now'])
    monkeypatch.setattr(settings, 'trust_ai_mode', 'observe')
    response = client.post('/api/devices/pico_01/ai-policy-revisions', headers=ADMIN_HEADERS,
                           json={'expected_revision':1,'mode':'OBSERVE','reason':'test observation'})
    assert response.status_code == 201, response.text
    assert 'INITIAL_AI_POLICY_REQUIRED' in management(client)['delete_blockers']
    assert command(client, management(client)).status_code == 409


def test_hide_requires_fresh_released_runtime(api_client, monkeypatch):
    from backend.app.services import device_policy_service
    client, path, clock = api_client
    create_device(client)
    assert command(client, management(client), 'HIDE').status_code == 409
    assert command(client, management(client), 'RESTORE').status_code == 409
    monkeypatch.setattr(device_policy_service, 'verify_runtime_firewall', lambda _: {'available':True,'passed':True})
    clock['now'] = T0 + timedelta(seconds=10)
    assert change_policy(client, state='DISABLED').status_code == 201
    clock['now'] = T0 + timedelta(seconds=20)
    ready = management(client)
    assert ready['can_hide']
    monkeypatch.setattr(device_policy_service, 'verify_runtime_firewall', lambda _: {'available':False,'passed':False})
    assert 'FIREWALL_NOT_RELEASED' in management(client)['hide_blockers']
    assert command(client, ready, 'HIDE').status_code == 409
    assert rows(path, 'SELECT hidden_at FROM devices') == [(None,)]


def test_missing_management_schema_fails_closed_but_list_works(api_client):
    client, path, _ = api_client
    create_device(client)
    state = management(client)
    write(path, 'DROP VIEW device_management_history')
    assert client.get('/api/devices/pico_01/management').status_code == 503
    assert command(client, state).status_code == 503
    assert client.get('/api/devices').status_code == 200


def test_late_writer_evidence_survives_and_prevents_id_reuse(api_client, monkeypatch):
    import threading
    from backend.app.services import device_management_service
    from backend.tests.test_device_policy_api import registration
    client, path, _ = api_client
    create_device(client)
    state = management(client)
    original = device_management_service._state
    attempts = threading.Event()
    failures = []

    def writer():
        try:
            with sqlite3.connect(path, timeout=5) as connection:
                attempts.set()
                connection.execute("INSERT INTO mqtt_logs(device_id,topic) VALUES ('pico_01','iot/pico_01/sensor')")
        except Exception as exc:
            failures.append(exc)

    pending = []

    def read_then_write(*args, **kwargs):
        result = original(*args, **kwargs)
        worker = threading.Thread(target=writer)
        pending.append(worker)
        worker.start()
        assert attempts.wait(5)
        return result

    monkeypatch.setattr(device_management_service, '_state', read_then_write)
    assert command(client, state).status_code == 200
    pending[0].join(5)
    assert not pending[0].is_alive() and not failures
    assert rows(path, 'SELECT count(*) FROM mqtt_logs') == [(1,)]
    # Changing the requested IP does not bypass ID/topic evidence.
    response = client.post('/api/devices', headers=ADMIN_HEADERS,
                           json=registration(ip_address='192.168.0.8'))
    assert response.status_code == 409, response.text
    assert rows(path, 'SELECT count(*) FROM devices') == [(0,)]


def test_old_ip_evidence_prevents_reregistration_at_another_ip(api_client):
    from backend.tests.test_device_policy_api import registration
    client, path, _ = api_client
    create_device(client)
    assert command(client, management(client)).status_code == 200
    write(path, "INSERT INTO detection_events(subject_ip,detector_type,event_type) VALUES ('192.168.0.6','RULE','TEST')")
    response = client.post('/api/devices', headers=ADMIN_HEADERS,
                           json=registration(ip_address='192.168.0.8'))
    assert response.status_code == 409, response.text


def disabled_preview(client, clock, monkeypatch):
    from backend.app.services import device_policy_service
    monkeypatch.setattr(device_policy_service, 'verify_runtime_firewall', lambda _: {'available': True, 'passed': True})
    clock['now'] = T0 + timedelta(seconds=10)
    assert change_policy(client, state='DISABLED').status_code == 201
    clock['now'] = T0 + timedelta(seconds=20)
    return management(client)


def test_pre_hide_preview_cannot_hide_again_after_restore(api_client, monkeypatch):
    client, path, clock = api_client
    create_device(client)
    original = disabled_preview(client, clock, monkeypatch)
    assert command(client, original, 'HIDE').status_code == 200
    assert command(client, management(client), 'RESTORE').status_code == 200
    assert command(client, original, 'HIDE').status_code == 409
    assert rows(path, 'SELECT hidden_at FROM devices') == [(None,)]
    assert rows(path, 'SELECT count(*) FROM device_management_audits') == [(2,)]
    fresh = management(client)
    assert fresh['expected_management_operation_id'] != original['expected_management_operation_id']
    assert command(client, fresh, 'HIDE').status_code == 200


@pytest.mark.parametrize('action', ['DELETE_UNUSED', 'HIDE', 'RESTORE'])
@pytest.mark.parametrize('reason', [pytest.param(OMITTED, id='omitted'), None, '', ' \t\n\u2003'])
def test_cleanup_reason_is_optional(api_client, monkeypatch, action, reason):
    client, path, clock = api_client
    create_device(client)
    state = management(client) if action == 'DELETE_UNUSED' else disabled_preview(client, clock, monkeypatch)
    if action == 'RESTORE':
        assert command(client, state, 'HIDE').status_code == 200
        state = management(client)
    response = command(client, state, action, reason=reason)
    assert response.status_code == 200, response.text
    audit = rows(path, 'SELECT reason,payload_json FROM device_management_audits ORDER BY rowid DESC LIMIT 1')[0]
    assert audit[0] == '사유 미입력'
    assert json.loads(audit[1])['reason_provided'] is False


def test_cleanup_reason_is_trimmed_and_recorded_as_provided(api_client):
    client, path, _ = api_client
    create_device(client)
    assert command(client, management(client), reason='  operator cleanup  ').status_code == 200
    audit = rows(path, 'SELECT reason,payload_json FROM device_management_audits')[0]
    assert audit[0] == 'operator cleanup'
    assert json.loads(audit[1])['reason_provided'] is True


@pytest.mark.parametrize('reason', [42, False, [], {}, 'x' * 501, 'bad\x00reason'])
def test_optional_cleanup_reason_still_validates_supplied_values(api_client, reason):
    client, path, _ = api_client
    create_device(client)
    assert command(client, management(client), reason=reason).status_code == 422
    assert rows(path, 'SELECT count(*) FROM device_management_audits') == [(0,)]


@pytest.mark.parametrize('token', [pytest.param(OMITTED, id='omitted'), '', 'x' * 129, 42])
def test_management_operation_token_is_required_nullable_bounded_string(api_client, token):
    client, path, _ = api_client
    create_device(client)
    assert command(client, management(client), expected_management_operation_id=token).status_code == 422
    assert rows(path, 'SELECT count(*) FROM device_management_audits') == [(0,)]


NON_SQLITE_JSON_CANDIDATES = [
    '{"device_id":"pico_01","value":NaN}',
    '{"device_id":"pico_01","value":Infinity}',
    '{"device_id":"pico_01","value":-Infinity}',
    '{"device_id":"pico_01","device_id":"other","value":NaN}',
    '{"device_id":"other","device_id":"\\t\\u2003pico_01\\n","value":Infinity}',
]


@pytest.mark.parametrize('payload', NON_SQLITE_JSON_CANDIDATES)
@pytest.mark.parametrize('after_delete', [False, True])
def test_python_json_candidate_blocks_delete_and_reuse(api_client, payload, after_delete):
    from backend.tests.test_device_policy_api import registration
    client, path, _ = api_client
    create_device(client)
    state = management(client)
    if after_delete:
        assert command(client, state).status_code == 200
    write(path, 'INSERT INTO mqtt_logs(device_id,topic,payload) VALUES (?,?,?)',
          ('other', 'iot/other/sensor', payload))
    if after_delete:
        response = client.post('/api/devices', headers=ADMIN_HEADERS, json=registration(ip_address='192.168.0.8'))
        assert response.status_code == 409, response.text
        assert rows(path, 'SELECT count(*) FROM devices') == [(0,)]
    else:
        assert command(client, state).status_code == 409
        assert 'HISTORY_MQTT_LOGS' in management(client)['delete_blockers']
        assert rows(path, 'SELECT count(*) FROM device_management_audits') == [(0,)]
        assert rows(path, 'SELECT count(*) FROM devices') == [(1,)]
    assert rows(path, 'SELECT device_id,topic,payload FROM mqtt_logs') == [('other', 'iot/other/sensor', payload)]


@pytest.mark.parametrize('payload', [
    '{invalid', '{"device_id":"pico_01",',
    '{"device_id":"other","value":NaN}',
    '[{"device_id":"pico_01","value":Infinity}]',
    '{"nested":{"device_id":"pico_01"},"value":NaN}',
    '{"device_id":42,"value":-Infinity}',
])
def test_unrelated_invalid_payload_does_not_block_cleanup_or_reuse(api_client, payload):
    from backend.tests.test_device_policy_api import registration
    client, path, _ = api_client
    create_device(client)
    write(path, 'INSERT INTO mqtt_logs(device_id,topic,payload) VALUES (?,?,?)',
          ('other', 'iot/other/sensor', payload))
    assert command(client, management(client)).status_code == 200
    response = client.post('/api/devices', headers=ADMIN_HEADERS, json=registration())
    assert response.status_code == 201, response.text
    assert rows(path, 'SELECT payload FROM mqtt_logs') == [(payload,)]
