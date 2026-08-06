# Packet Checkpoint Gap Recovery Runbook

이 절차는 승인된 `packet_rule` 또는 `packet_if` Checkpoint 하나를 다음 Capture Session 시작 경계로 전진시킨다. Orchestrator의 자동 Session Gap 통과를 허용하지 않으며, 운영 DB에서는 병합 후 별도 승인하에 수행한다.

## 1. Migration과 사전 격리

1. 운영 절차와 분리하여 Migration 005를 백업·검증 후 먼저 적용한다. Recovery CLI는 Migration을 자동 적용하지 않는다.
2. 관련 systemd 서비스의 enabled/active 상태를 기록하고 active DB Writer만 중지한다. `packet-capture.service`는 disabled/inactive를 유지한다.
3. Packet Capture, 공격, Extractor, Manual Runner 프로세스가 실행 중이 아닌지 확인한다.
4. DB 전체에서 `status='RUNNING'` Capture Session이 0건인지 확인한다. stale Row도 자동 무시하지 않는다.
5. Repository의 tracked/staged 변경은 없어야 하며 untracked inventory는 보존한다.

## 2. 경로와 플랫폼 Gate

Dry-run은 Windows와 POSIX에서 지원한다. Execute는 POSIX 전용이며 Raspberry Pi에서만 수행한다. 실제 POSIX lock 상호운용은 병합 후 운영 DB가 아닌 Pi 복사 DB Smoke에서 검증한다.

`plan_output.parent`와 최상위 `artifact_dir`는 미리 존재해야 한다. Repository 내부 경로는 Git ignore 대상이어야 하며 CLI가 상위 Directory를 자동 생성하지 않는다.

## 3. Dry-run

현재 Session이 소진됐고 Target Session이 COMPLETED/full-ready인지 확인한 뒤 실행한다.

```bash
python -m edge.detection.run_packet_checkpoint_recovery dry-run \
  --db-path /absolute/path/iot.db \
  --repository-root /absolute/path/iot-edge-zero-trust \
  --detector packet_rule \
  --current-session-id CURRENT_UUID \
  --target-session-id TARGET_UUID \
  --approved-by OPERATOR \
  --reason "approved session gap recovery" \
  --plan-output /ignored/existing/plan.json
```

Plan의 DB 절대경로, SHA256, Lock, RUNNING Summary, skipped Session 분류를 검토한다. 처리 가능한 full-ready Session을 건너뛰면 Plan SHA에 바인딩된 `SKIP-PROCESSABLE-SESSIONS:<digest>` 확인값이 추가로 필요하다.

## 4. Execute와 결과

```bash
python -m edge.detection.run_packet_checkpoint_recovery execute \
  --plan-file /ignored/existing/plan.json \
  --db-path /absolute/path/iot.db \
  --artifact-dir /ignored/existing/artifacts \
  --confirm "REBASE-PACKET-CHECKPOINT"
```

Exit Code 2는 Commit 전 거부다. Exit Code 3은 DB Commit 뒤 검증 또는 Result JSON 기록 실패로 `HOLD` 상태이며, Checkpoint·Audit·Backup을 유지하고 자동 Restore하지 않는다. 운영자는 Checkpoint, Audit Row, Backup SHA256, integrity/FK, 보호 테이블 불변을 확인한다.

## 5. 후속 검증

승인한 Target Session에 대해 해당 Detector의 Manual Runner만 실행한다. Recovery 전 active였던 서비스만 원복한다. 공식 Trust/Firewall E2E는 새 Holdout Session에서 별도로 수행한다.
