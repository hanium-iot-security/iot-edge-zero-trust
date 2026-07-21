# Phase 4 Cutover·Rollback 운영 가이드

## 1. 목적과 현재 상태

이 문서는 Phase 4 최초 Orchestrator 활성화 직전에 운영 DB를 안전하게 전환하고,
실패 시 검증된 백업으로 복원하는 절차를 정의한다.

> **현재 상태:** Cutover·Rollback 도구와 독립 DB Smoke Test 절차만 준비한다.
> 실제 운영 DB Cutover는 아직 실행하지 않는다.

실제 Cutover는 다음 조건을 모두 만족한 뒤 한 번만 수행한다.

- Migration 003과 Cutover Checkpoint DB 함수가 `develop`에 병합됨
- 공통 Detector Adapter, Orchestrator, Trust Score v2, Firewall Worker 병합 완료
- 독립 테스트 DB와 운영 DB 복사본 Smoke Test 통과
- Phase 3-B 통합 기준 Commit과 운영 DB Backup이 기록됨
- 기존 Detector·Trust Cron 중지 방법과 신규 systemd Unit 이름 확정

## 2. 역할 경계

원우민 담당 도구는 다음 순서를 제어한다.

```text
기존 실행 경로 중지
→ SQLite Backup API 기반 Snapshot·SHA256
→ Migration Runner 호출
→ foreign_key_check·integrity_check
→ Cutover Checkpoint DB 함수 호출
→ DB 재검증
→ 신규 서비스 시작
→ 기존·신규·Writer 서비스 실제 상태 검증
→ JSON 결과 기록
```

Migration 003의 Schema와 Checkpoint 계산·UPSERT는 정현수 담당 함수가 제공한다.
CLI가 사용하는 기본 함수 계약은 다음과 같다.

```python
# edge/detection/phase4_cutover_repository.py
def initialize_phase4_cutover(
    database_path: Path,
    phase4_cutover_at: datetime,
) -> Mapping[str, object]:
    checkpoint_keys = (
        "mqtt_feature_builder+mqtt_logs",
        "mqtt_feature_rule+feature_logs",
        "mqtt_message_rule+mqtt_logs",
        "mqtt_if+feature_logs",
        "packet_rule+packet_feature_logs",
        "packet_if+packet_feature_logs",
        "trust_score_v2+detection_events",
    )
    return {
        "legacy_migration_event_count": 0,
        "checkpoints": {
            key: {
                "last_processed_id": None,
                "last_completed_window_end": None,
            }
            for key in checkpoint_keys
        },
    }
```

각 Checkpoint 값에는 `last_processed_id`, `last_completed_window_end`가 반드시 존재한다.
함수는 요약을 반환하는 것뿐 아니라 `detector_checkpoints`에 7개 Row를 실제 UPSERT해야 한다.
Runner는 반환 요약과 DB Row의 Key·`last_processed_id`·UTC 완료 Window가 일치하는지
재조회한다. 함수가 없거나 Import할 수 없고, Migration 003이 적용·기적용되지 않았거나
요약과 DB가 다르면 신규 서비스를 시작하지 않고 Backup 복원 경로로 전환한다.

## 3. 공통 안전 계약

- `--database`로 SQLite 파일을 명시한다. `.env`의 경로를 추측하지 않는다.
- 운영 DB를 단순 파일 복사하지 않고 Python SQLite Backup API로 Snapshot을 만든다.
- Backup과 SHA256 Manifest의 파일명이 일치해야 한다.
- Backup 복원 전 SHA256, `PRAGMA integrity_check`, `PRAGMA foreign_key_check`를 검증한다.
- 실제 Cutover는 `--execute --confirm PHASE4-CUTOVER`가 모두 있어야 한다.
- 실제 Rollback은 `--execute --confirm PHASE4-ROLLBACK`이 모두 있어야 한다.
- Pi의 실제 Cutover·Rollback은 root 권한으로 실행한다.
- CLI는 전달받은 systemd Unit만 제어한다. Crontab은 자동 수정하지 않는다.
- `--writer-service`에는 Capture, Packet Feature, Gateway Metrics, MQTT Producer 등 운영 DB에
  쓰는 모든 Unit을 전달한다. Cutover 동안 중지하고 성공·실패 후 작업 전 상태로 복구한다.
- 기존·신규·Writer Unit의 작업 전 active/inactive 상태를 JSON에 기록한다. 실패 시에는
  작업 전 active였던 Unit만 다시 활성화하고 원래 inactive였던 Unit은 시작하지 않는다.
- DB별 Lock 파일로 Cutover·Smoke·Rollback의 동시 실행을 차단한다.
- POSIX에서는 `flock`이 사용하는 Lock 파일을 해제 후에도 삭제하지 않는다. 동일 경로의
  동일 inode를 다음 실행에서도 재사용하는 것이 정상이다.
- Execute·Smoke 직전에는 `discover_migrations()`로 전체 Migration 이름·연속 Version·SQL
  완결성을 검증하며, Version 3은 정확히 한 개여야 한다.
- 서비스 중지 전 운영 DB·Backup·Snapshot·SHA256 Manifest·결과 JSON·결과 임시 파일·
  Pre-rollback 출력 경로를 모두 계산하고 상호 충돌 여부를 확인한다. 출력 디렉터리별 쓰기
  Probe와 `fsync`, 실제 파일시스템 여유 공간도 확인한다. Dry Run은 파일·디렉터리를 만들지 않는다.
- 로그와 결과 파일에 비밀번호, Token, SSH Key, `.env` 전체 내용을 남기지 않는다.

## 4. 사전 기록

프로젝트 루트에서 실행한다.

```bash
cd /home/pi/iot-edge-zero-trust
source venv/bin/activate

git status --short
git rev-parse HEAD
python --version
systemctl list-units --type=service --state=running --no-pager
crontab -l
```

다음을 결과 문서에 기록한다.

- `develop` Commit SHA
- 실제 `DATABASE_URL`과 SQLite 파일 경로
- 기존 Detector·Trust 실행 방식과 중지 증거
- 신규 Orchestrator·Firewall Worker Unit 이름
- 실행 시각과 작업자

## 5. Dry Run

Dry Run은 파일·DB·서비스를 변경하지 않고 예정 작업만 JSON으로 출력한다.

```bash
python -m edge.scripts.run_phase4_cutover \
  --database /home/pi/iot-edge-zero-trust/backend/data/iot_security.db \
  --backup-dir /home/pi/iot-edge-zero-trust/backend/data/backups \
  --result /home/pi/iot-edge-zero-trust/data/exports/phase4-cutover.json \
  --git-sha "$(git rev-parse HEAD)" \
  --legacy-service mqtt-feature-rule.service \
  --legacy-service trust-score.service \
  --new-service detection-orchestrator.service \
  --new-service firewall-worker.service \
  --writer-service packet-capture.service \
  --writer-service gateway-metrics.service \
  --dry-run
```

위 Unit 이름은 예시다. 실제 구현·설치된 Unit만 전달한다. 기존 실행 경로가 Cron이면
`--legacy-service`로 가짜 Unit을 넣지 말고, 실제 Cutover 전에 Crontab을 별도로 중지하고
결과에 기록한다.

## 6. 독립 DB Smoke Test

Smoke Test는 운영 DB를 읽어 별도의 SQLite Snapshot을 만들고, 복사본에만 Migration과
Checkpoint 초기화를 수행한다. 원본 운영 DB는 변경하지 않는다.

```bash
python -m edge.scripts.run_phase4_cutover \
  --database /home/pi/iot-edge-zero-trust/backend/data/iot_security.db \
  --backup-dir /home/pi/iot-edge-zero-trust/backend/data/backups \
  --smoke-database /home/pi/iot-edge-zero-trust/backend/data/backups/phase4-cutover-smoke.db \
  --result /home/pi/iot-edge-zero-trust/data/exports/phase4-cutover-smoke.json \
  --git-sha "$(git rev-parse HEAD)" \
  --smoke-test
```

확인 기준:

- 원본 운영 DB는 실행 전·후 각각 SQLite Backup API로 논리 Snapshot을 생성함
- `source_snapshot_before`, `source_snapshot_after`와 각 SHA256 Manifest가 별도 보존됨
- 두 논리 Snapshot의 SHA256과 Table별 Row 수가 같고 `source_unchanged=true`임
- Migration 전 Smoke Snapshot Manifest와 Migration 후 Manifest가 별도 파일로 보존됨
- Smoke DB에 Migration 003 기록이 존재함
- `foreign_key_check` 결과가 0건임
- `integrity_check` 결과가 `ok`임
- Source별 Cutover Watermark와 Checkpoint 7개가 JSON 결과에 기록됨
- 기존 Segment Row 수·ID Digest와 Packet Feature Row 수가 보존되고 고아 FK가 0건임
- 기존 주요 Table Row 수가 감소하지 않고 Migration 전 Detection Event ID가 최종 ID 집합에
  모두 포함됨. 신규 `LEGACY_MIGRATION` Event ID 추가는 허용함
- Migration 직후뿐 아니라 Checkpoint 초기화 후 `smoke_final` 증적에서도 보존 계약을 다시 검증함
- 보존 검사가 실패하면 `failure_stage=data-preservation-check` 또는
  `failure_stage=final-data-preservation-check`로 기록됨

기존 Smoke DB를 재사용하지 말고 실행별 새 경로를 사용한다. 실패한 Smoke DB와 결과 JSON은
삭제하지 않고 원인 분석용으로 보존한다.

## 7. 실제 운영 Cutover

> 이 절차는 Phase 4 통합 Smoke Test 전에는 실행하지 않는다.

1. 기존 Detector·Trust Cron을 중지한다. systemd Unit은 도구가 작업 전 상태를 기록하고 중지한다.
2. 신규 Orchestrator·Firewall Worker Unit과 모든 DB Writer Unit 이름을 확정한다.
3. Dry Run과 독립 DB Smoke Test 결과를 확인한다.
4. 다음 명령을 root 권한으로 실행한다.

```bash
sudo /home/pi/iot-edge-zero-trust/venv/bin/python \
  -m edge.scripts.run_phase4_cutover \
  --database /home/pi/iot-edge-zero-trust/backend/data/iot_security.db \
  --backup-dir /home/pi/iot-edge-zero-trust/backend/data/backups \
  --result /home/pi/iot-edge-zero-trust/data/exports/phase4-cutover.json \
  --git-sha "$(git rev-parse HEAD)" \
  --legacy-service mqtt-feature-rule.service \
  --legacy-service trust-score.service \
  --new-service detection-orchestrator.service \
  --new-service firewall-worker.service \
  --writer-service packet-capture.service \
  --writer-service gateway-metrics.service \
  --execute \
  --confirm PHASE4-CUTOVER
```

성공 시 JSON 결과에는 다음이 포함된다.

- 운영 DB·Backup·SHA256 경로와 Digest
- `phase4_cutover_at` UTC
- Commit SHA
- 적용·건너뛴 Migration Version
- Source별 초기 Checkpoint 요약
- FK·Integrity 결과
- 중지한 기존 서비스와 시작한 신규 서비스
- Writer를 포함한 전체 Unit의 작업 전·후 active 상태
- 성공 판정 시 기존 Unit은 inactive, 신규 Unit은 active, Writer는 작업 전 상태와 일치함
- 실패 시 `failure_stage`, `primary_error`, `rollback_attempted`, `rollback_succeeded`,
  `rollback_error`와 하위 호환용 `error` 요약

도중 실패하면 도구가 생성한 Backup을 검증해 자동 복원을 시도하고 기존 systemd Unit을
재시작한다. 복구 명령 이후 전체 Unit의 실제 상태가 작업 전 상태와 정확히 일치해야만
`rolled_back`, `rollback_succeeded=true`로 기록한다. `rollback_failed`이면 서비스를 임의로
재시작하지 말고 아래 명시적 Rollback 절차를 수행한다.

## 8. 명시적 Rollback

먼저 변경 없는 Dry Run으로 대상 경로를 확인한다.

```bash
python -m edge.scripts.rollback_phase4_cutover \
  --database /home/pi/iot-edge-zero-trust/backend/data/iot_security.db \
  --backup /home/pi/iot-edge-zero-trust/backend/data/backups/ACTUAL_BACKUP.db \
  --sha256 /home/pi/iot-edge-zero-trust/backend/data/backups/ACTUAL_BACKUP.db.sha256 \
  --result /home/pi/iot-edge-zero-trust/data/exports/phase4-rollback.json \
  --pre-rollback-backup-dir /home/pi/iot-edge-zero-trust/backend/data/backups/pre-rollback \
  --git-sha "$(git rev-parse HEAD)" \
  --new-service detection-orchestrator.service \
  --new-service firewall-worker.service \
  --legacy-service mqtt-feature-rule.service \
  --legacy-service trust-score.service \
  --writer-service packet-capture.service \
  --writer-service gateway-metrics.service \
  --dry-run
```

경로와 SHA256을 다시 확인한 뒤 실행한다.

```bash
sudo /home/pi/iot-edge-zero-trust/venv/bin/python \
  -m edge.scripts.rollback_phase4_cutover \
  --database /home/pi/iot-edge-zero-trust/backend/data/iot_security.db \
  --backup /home/pi/iot-edge-zero-trust/backend/data/backups/ACTUAL_BACKUP.db \
  --sha256 /home/pi/iot-edge-zero-trust/backend/data/backups/ACTUAL_BACKUP.db.sha256 \
  --result /home/pi/iot-edge-zero-trust/data/exports/phase4-rollback.json \
  --pre-rollback-backup-dir /home/pi/iot-edge-zero-trust/backend/data/backups/pre-rollback \
  --git-sha "$(git rev-parse HEAD)" \
  --new-service detection-orchestrator.service \
  --new-service firewall-worker.service \
  --legacy-service mqtt-feature-rule.service \
  --legacy-service trust-score.service \
  --writer-service packet-capture.service \
  --writer-service gateway-metrics.service \
  --execute \
  --confirm PHASE4-ROLLBACK
```

명시적 Rollback은 대상 운영 DB가 실제 일반 파일인지 먼저 확인하고, 전달된 기존·신규·Writer
Unit이 실제 systemd에 존재하는지 서비스 변경 전에 확인한다. 이후 Unit을 모두 중지한 후 현재
DB를 `pre_manual_rollback` Backup·SHA256으로 추가 보존한다. 지정
Backup 복원과 검증이 끝나면 기존 Unit을 시작하고 Writer는 작업 전 상태로 복구하며 신규 Unit은
중지 상태를 유지한다. 명령 실행 후 이 실제 상태가 확인돼야만 성공으로 기록한다. 복원이 검증되기
전에는 기존 Cron을 재시작하지 않는다. Rollback 이후
새 Cutover를 시도하려면 새 Backup·SHA256과 새로운 `phase4_cutover_at`을 생성한다.

## 9. 결과 기록

자동 생성된 JSON 결과와 함께
[`phase4-cutover-result-template.md`](phase4-cutover-result-template.md)를 작성한다.
실행하지 않은 항목은 성공으로 간주하지 않고 `미검증`으로 남긴다.
