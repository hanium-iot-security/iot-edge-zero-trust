"""An old policy editor must not operate on a replacement with the same ID."""
from datetime import timedelta

import pytest

from backend.app.config import settings
from backend.app.services import device_ai_policy_service
from backend.tests.test_device_policy_api import ADMIN_HEADERS, T0, api_client, create_device, registration
from tests.device_policy_support import POLICY
from tests.test_device_management_api import command, management


@pytest.mark.parametrize('kind', ['rule', 'ai'])
@pytest.mark.parametrize('old_token', [False, True])
def test_old_policy_editor_cannot_write_replacement(api_client, monkeypatch, kind, old_token):
    client, _, clock = api_client
    monkeypatch.setattr(settings, 'trust_ai_mode', 'observe')
    monkeypatch.setattr(device_ai_policy_service, 'utc_now', lambda: clock['now'])
    create_device(client)
    old = management(client)
    assert command(client, old).status_code == 200
    assert client.post('/api/devices', headers=ADMIN_HEADERS, json=registration()).status_code == 201
    clock['now'] = T0 + timedelta(seconds=10)
    if kind == 'rule':
        url = '/api/devices/pico_01/policy-revisions'
        read_url = '/api/devices/pico_01/policy'
        payload = {'expected_revision': 1, 'registration_state': 'ACTIVE', 'policy': POLICY,
                   'reason': 'old editor activation'}
    else:
        url = '/api/devices/pico_01/ai-policy-revisions'
        read_url = '/api/devices/pico_01/ai-policy'
        payload = {'expected_revision': 1, 'mode': 'OBSERVE', 'reason': 'old editor observation'}
    if old_token:
        payload['expected_instance_id'] = old['expected_instance_id']
    response = client.post(url, headers=ADMIN_HEADERS, json=payload)
    assert response.status_code == 409, response.text
    assert response.json()['detail']['code'] == 'REGISTRATION_INSTANCE_CONFLICT'
    current = client.get(read_url).json()
    assert current['expected_instance_id'] != old['expected_instance_id']
    payload['expected_instance_id'] = current['expected_instance_id']
    response = client.post(url, headers=ADMIN_HEADERS, json=payload)
    assert response.status_code == 201, response.text


@pytest.mark.parametrize('kind', ['rule', 'ai'])
def test_initial_registration_keeps_existing_client_compatibility(api_client, monkeypatch, kind):
    client, _, clock = api_client
    monkeypatch.setattr(settings, 'trust_ai_mode', 'observe')
    monkeypatch.setattr(device_ai_policy_service, 'utc_now', lambda: clock['now'])
    create_device(client)
    clock['now'] = T0 + timedelta(seconds=10)
    if kind == 'rule':
        url = '/api/devices/pico_01/policy-revisions'
        payload = {'expected_revision': 1, 'registration_state': 'ACTIVE', 'policy': POLICY,
                   'reason': 'compatible initial activation'}
    else:
        url = '/api/devices/pico_01/ai-policy-revisions'
        payload = {'expected_revision': 1, 'mode': 'OBSERVE', 'reason': 'compatible initial AI policy'}
    assert client.post(url, headers=ADMIN_HEADERS, json=payload).status_code == 201
