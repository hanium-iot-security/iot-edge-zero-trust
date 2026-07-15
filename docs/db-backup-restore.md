# DB Backup and Restore

SQLite 운영 DB 파일은 기본적으로 `backend/data/iot_security.db`입니다. DB 파일, WAL/SHM 파일, 백업 파일은 Git에 commit하지 않습니다.

## Migration 적용 전 확인

1. 현재 DB 파일 경로를 확인합니다.

```bash
python - <<'PY'
from backend.app.config import settings
print(settings.database_url)
PY
```

2. DB 파일과 WAL/SHM 파일이 있는지 확인합니다.

```bash
ls backend/data/
```

3. 적용 전 기존 MQTT, Trust Score, 격리 상태를 확인합니다.

```bash
sqlite3 backend/data/iot_security.db "SELECT COUNT(*) FROM mqtt_logs;"
sqlite3 backend/data/iot_security.db "SELECT device_id, status, trust_score FROM devices;"
sqlite3 backend/data/iot_security.db "SELECT COUNT(*) FROM detection_events;"
```

## 백업

운영 DB를 직접 수정하기 전에 timestamp가 포함된 백업 파일을 만듭니다.

```bash
mkdir -p backend/data/backups
cp backend/data/iot_security.db backend/data/backups/iot_security_YYYYMMDD_HHMMSS.db
```

WAL mode 사용 중이면 적용 전 애플리케이션을 중지하거나 checkpoint 후 백업합니다.

```bash
sqlite3 backend/data/iot_security.db "PRAGMA wal_checkpoint(FULL);"
```

필요하면 `iot_security.db-wal`, `iot_security.db-shm`도 같은 timestamp로 함께 보관합니다.

## 복사본 검증

운영 DB 대신 백업 복사본에 먼저 migration을 적용합니다.

```bash
python - <<'PY'
from db.migration_runner import apply_migrations

result = apply_migrations("backend/data/backups/iot_security_YYYYMMDD_HHMMSS.db")
print(result)
PY
```

검증 항목:

- `schema_migrations`에 001, 002 기록이 있는지 확인
- 기존 `mqtt_logs`, `feature_logs`, `detection_events`, `devices` row 수가 유지되는지 확인
- 기존 `devices.status`, `devices.trust_score`, `detection_events.applied_to_score` 값이 유지되는지 확인
- `trust_score_history` 테이블은 생성되지만 기존 row에서 자동 생성된 history가 없는지 확인
- 기존 FastAPI 조회 테스트가 통과하는지 확인

```bash
sqlite3 backend/data/backups/iot_security_YYYYMMDD_HHMMSS.db "SELECT version, name FROM schema_migrations ORDER BY version;"
sqlite3 backend/data/backups/iot_security_YYYYMMDD_HHMMSS.db "SELECT COUNT(*) FROM trust_score_history;"
pytest -q backend/tests/test_read_api.py tests/test_trust_score_service.py
```

## 운영 DB 적용

복사본 검증이 끝난 뒤에만 운영 DB에 migration을 적용합니다.

```bash
python -m db.migration_runner
```

또는 DB 초기 생성 시에는 다음 명령을 사용합니다.

```bash
python -m db.create_tables
```

## 복구

문제가 있으면 애플리케이션을 중지한 뒤 현재 DB 파일을 보관하고 백업본으로 교체합니다.

```bash
mv backend/data/iot_security.db backend/data/iot_security.failed.db
cp backend/data/backups/iot_security_YYYYMMDD_HHMMSS.db backend/data/iot_security.db
```

WAL/SHM 파일이 남아 있으면 운영 DB 교체 전에 함께 정리합니다.

```bash
rm -f backend/data/iot_security.db-wal backend/data/iot_security.db-shm
```

복구 후 확인합니다.

```bash
sqlite3 backend/data/iot_security.db "PRAGMA integrity_check;"
sqlite3 backend/data/iot_security.db "SELECT device_id, status, trust_score FROM devices;"
pytest -q backend/tests/test_read_api.py tests/test_trust_score_service.py
```

운영 DB를 덮어쓰는 자동화는 제공하지 않습니다. 적용과 복구는 백업 파일 확인 후 수동으로 수행합니다.
