# Packet Checkpoint Gap Recovery Runbook

이 절차는 승인된 Checkpoint 하나를 다음 Capture Session 시작 경계로 전진시킨다. Orchestrator의 자동 Session Gap 통과를 허용하지 않으며, 운영 DB에서는 병합 후 별도 승인하에 수행한다.

- `gap-recovery`(기본값): 기존 `packet_rule`/`packet_if` 절차다. Target은 `COMPLETED`이면서 전체 feature-ready여야 하고 RUNNING Session은 없어야 한다.
- `live-resume`: `packet_rule` 전용 명시적 절차다. 종료 전 Checkpoint와 현재 유일한 RUNNING Target의 `first_window_start` 사이 downtime만 건너뛴다. Target의 `first_window_start` 이후 Packet Feature는 건너뛰지 않고 Packet Rule이 정상 소비한다.

## 1. Migration과 사전 격리

1. 운영 절차와 분리하여 Migration 005를 백업·검증 후 먼저 적용한다. Recovery CLI는 Migration을 자동 적용하지 않는다.
2. 관련 systemd 서비스의 enabled/active 상태를 기록한다.
3. `gap-recovery`에서는 active DB Writer를 중지하고 `packet-capture.service`, Extractor, Orchestrator, Manual Runner가 실행 중이 아닌지 확인한다. DB 전체의 RUNNING Capture Session도 0건이어야 한다.
4. `live-resume`에서는 `packet-capture.service`를 유지한다. Execute가 Orchestrator, Packet Rule/IF Manual Runner, Packet Feature Extractor Lock을 짧게 획득하는 동안에도 Capture 자체는 계속될 수 있다. Target 이외의 RUNNING Session이 있으면 실행하지 않는다.
5. Repository의 tracked/staged 변경은 없어야 하며 untracked inventory는 보존한다.

## 2. 경로와 플랫폼 Gate

Dry-run은 Windows와 POSIX에서 지원한다. Execute는 POSIX 전용이며 Raspberry Pi에서만 수행한다. 실제 POSIX lock 상호운용은 병합 후 운영 DB가 아닌 Pi 복사 DB Smoke에서 검증한다.

`plan_output.parent`와 최상위 `artifact_dir`는 미리 존재해야 한다. Repository 내부 경로는 Git ignore 대상이어야 하며 CLI가 상위 Directory를 자동 생성하지 않는다.

## 3. Dry-run

### 3.1 일반 Gap Recovery

현재 Session이 소진됐고 Target Session이 COMPLETED/full-ready인지 확인한 뒤 실행한다. `--mode`를 생략하면 이 모드다.

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

### 3.2 Packet Rule Live Resume

Target은 현재 유일한 RUNNING Session이어야 한다. `first_window_start`가 존재하고, 그 시점부터 시작하는 연속 terminal `PROCESSED`/`EMPTY` prefix가 최소 한 Window 있어야 한다. 연속 prefix 뒤의 정상 `READY` tail은 허용하지만 FAILED/Extractor error, Window 누락·겹침, 잘못된 Feature 수는 HOLD 조건이다.

```bash
python -m edge.detection.run_packet_checkpoint_recovery dry-run \
  --mode live-resume \
  --db-path /absolute/path/iot.db \
  --repository-root /absolute/path/iot-edge-zero-trust \
  --detector packet_rule \
  --current-session-id CURRENT_COMPLETED_UUID \
  --target-session-id CURRENT_RUNNING_UUID \
  --approved-by OPERATOR \
  --reason "approved live packet-rule resume" \
  --plan-output /ignored/existing/live-resume-plan.json
```

Plan의 `checkpoint.after.last_processed_id`가 Before와 같고, `last_completed_window_end`가 Target의 `first_window_start`와 정확히 같은지 확인한다. Target의 현재 `packet_feature_ready_through`로 점프하면 안 된다.

## 4. Execute와 결과

일반 Gap Recovery:

```bash
python -m edge.detection.run_packet_checkpoint_recovery execute \
  --plan-file /ignored/existing/plan.json \
  --db-path /absolute/path/iot.db \
  --artifact-dir /ignored/existing/artifacts \
  --confirm "APPLY-PACKET-CHECKPOINT-GAP-RECOVERY"
```

Live Resume:

```bash
python -m edge.detection.run_packet_checkpoint_recovery execute \
  --plan-file /ignored/existing/live-resume-plan.json \
  --db-path /absolute/path/iot.db \
  --artifact-dir /ignored/existing/artifacts \
  --confirm "APPLY-PACKET-LIVE-RESUME"
```

Plan 생성 뒤 Target status/identity/`first_window_start`가 바뀌거나 ready prefix가 퇴행하면 Execute는 거부된다. Capture/Extractor가 정상적으로 늘린 terminal prefix 또는 trailing READY tail은 재검증 후 허용된다. 다른 RUNNING Session, FAILED/error, 연속성 파손, DB backup 중 변경은 모두 Commit 전 HOLD 조건이다.

Exit Code 2는 Commit 전 거부다. Exit Code 3은 DB Commit 뒤 검증 또는 Result JSON 기록 실패로 `HOLD` 상태이며, Checkpoint·Audit·Backup을 유지하고 자동 Restore하지 않는다. 운영자는 Checkpoint, Audit Row, Backup SHA256, integrity/FK, 보호 테이블 불변을 확인한다.

## 5. 후속 검증

승인한 Target Session에 대해 해당 Detector의 Manual Runner만 실행한다. Recovery 전 active였던 서비스만 원복한다. Live Resume에서는 Packet Rule이 Target `first_window_start` 이후의 기존 Feature부터 처리하는지 확인한다. 공식 Trust/Firewall E2E는 새 Holdout Session에서 별도로 수행한다.

이 문서는 코드 경로를 설명한다. 실제 Raspberry Pi의 systemd/lock/capture 동시 동작 Cutover 검증은 코드 PR과 별도로 수행하고 증거를 기록해야 한다.
