"""The management migration preserves pre-existing registrations and history."""
import shutil
import sqlite3

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.schemas.device_management_schema import DeviceManagementRequest
from backend.app.security import RecoveryAdminContext
from backend.app.services import device_management_service as service
from backend.app.services import device_policy_service
from db.migration_runner import MIGRATIONS_DIR, apply_migrations, connect_database
from edge.policy.device_policy_repository import register_device
from tests.device_policy_support import LAN_POLICY, POLICY, T0


def test_pre019_pristine_registration_mints_instance_only_in_successful_delete(tmp_path, monkeypatch):
    migrations = tmp_path / 'pre019'
    migrations.mkdir()
    for path in MIGRATIONS_DIR.glob('*.sql'):
        if int(path.name.split('_')[0]) < 19:
            shutil.copyfile(path, migrations / path.name)
    path = tmp_path / 'upgrade.db'
    apply_migrations(path, migrations)
    connection = connect_database(path)
    try:
        register_device(connection, device_id='pico_02', ip_address='192.168.0.7',
                        device_type='SENSOR', mqtt_principal='pico_02', policy=POLICY,
                        reason='original test registration', created_by='tester',
                        ip_policy=LAN_POLICY, clock=lambda: T0)
    finally:
        connection.close()
    engine = create_engine(f'sqlite:///{path.as_posix()}')
    monkeypatch.setattr(settings, 'firewall_lock_path', str(tmp_path / 'firewall.lock'))
    monkeypatch.setattr(settings, 'firewall_lock_wait_seconds', 0)
    monkeypatch.setattr(device_policy_service, 'utc_now', lambda: T0)
    try:
        with Session(engine) as db:
            with pytest.raises(service.DeviceManagementUnavailable):
                service.get_device_management(db, 'pico_02')
            assert device_policy_service.list_devices(db)['total'] == 1
        apply_migrations(path, MIGRATIONS_DIR)
        with Session(engine) as db:
            state = service.get_device_management(db, 'pico_02')
            assert state['expected_instance_id'] is None and state['can_delete']
            request = DeviceManagementRequest(
                action='DELETE_UNUSED', expected_revision=1, expected_ai_revision=1,
                expected_hidden_at=None, expected_instance_id=None, reason='delete old test',
            )
            with sqlite3.connect(path) as connection:
                connection.execute("CREATE TRIGGER fail_delete BEFORE DELETE ON devices BEGIN SELECT RAISE(ABORT,'test rollback'); END")
            with pytest.raises(sqlite3.IntegrityError):
                service.manage_device(db, 'pico_02', request, RecoveryAdminContext('tester'))
            with sqlite3.connect(path) as connection:
                assert connection.execute('SELECT registration_instance_id FROM devices').fetchone() == (None,)
                assert connection.execute('SELECT count(*) FROM device_management_audits').fetchone() == (0,)
                connection.execute('DROP TRIGGER fail_delete')
            assert service.manage_device(db, 'pico_02', request, RecoveryAdminContext('tester'))['deleted']
        with sqlite3.connect(path) as connection:
            assert connection.execute("SELECT length(json_extract(payload_json,'$.before_device.registration_instance_id')) FROM device_management_audits").fetchone()[0] > 0
    finally:
        engine.dispose()
