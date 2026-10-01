# Packet Checkpoint Gap Recovery Runbook

이 절차는 승인된 Checkpoint 하나를 다음 Capture Session 시작 경계로 전진시킨다. Orchestrator의 자동 Session Gap 통과를 허용하지 않으며, 운영 DB에서는 병합 후 별도 승인하에 수행한다.

- `gap-recovery`(기본값): 기존 `packet_rule`/`packet_if` 절차다. Target은 `COMPLETED`이면서 전체 feature-ready여야 하고 RUNNING Session은 없어야 한다.
- `live-resume`: `packet_rule`/`packet_if`의 명시적 절차다. 종료 전 Checkpoint와 현재 유일한 RUNNING Target의 `first_window_start` 사이 downtime만 건너뛴다. Target의 `first_window_start` 이후 Packet Feature는 건너뛰지 않고 해당 Detector가 정상 소비한다. 두 Packet Stage가 모두 required이면 각 Detector에 대해 별도 Plan·Execute·Audit가 필요하며 Target과 After 경계가 같아야 한다.

## 1. Migration과 사전 격리

1. 운영 절차와 분리하여 Migration 005를 백업·검증 후 먼저 적용한다. Recovery CLI는 Migration을 자동 적용하지 않는다.
2. 관련 systemd 서비스의 enabled/active 상태를 기록한다.
3. `gap-recovery`에서는 active DB Writer를 중지하고 `packet-capture.service`, Extractor, Orchestrator, Manual Runner가 실행 중이 아닌지 확인한다. DB 전체의 RUNNING Capture Session도 0건이어야 한다.
4. `live-resume`에서는 `packet-capture.service`를 유지한다. Execute가 Orchestrator, Packet Rule/IF Manual Runner, Packet Feature Extractor Lock을 짧게 획득하는 동안에도 Capture 자체는 계속될 수 있다. Target 이외의 RUNNING Session이 있으면 실행하지 않는다.
5. Repository의 tracked/staged 변경은 없어야 하며 untracked inventory는 보존한다.

## 2. 경로와 플랫폼 Gate

Dry-run은 Windows와 POSIX에서 지원한다. Execute는 POSIX 전용이며 Raspberry Pi에서만 수행한다. 실제 POSIX lock 상호운용은 병합 후 운영 DB가 아닌 Pi 복사 DB Smoke에서 검증한다.

`plan_output.parent`와 최상위 `artifact_dir`는 미리 존재해야 한다. Repository 내부 경로는 Git ignore 대상이어야 하며 CLI가 상위 Directory를 자동 생성하지 않는다.

Repository 점검은 Git 미추적 일반 파일의 크기·SHA256을 기록하고, 일반 파일이 아닌
심볼릭 링크·FIFO·소켓은 거부한다. Git 목록에서 생략되는 FIFO·소켓도 하위 Directory까지
검사한다. `.git`과 Git ignore 대상 Directory는 탐색에서 제외하며, 검사 중 발견한 파일을
삭제하거나 수정하지 않는다.

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

### 3.2 Packet Detector Live Resume

Target은 현재 유일한 RUNNING Session이어야 한다. `first_window_start`가 존재하고, 그 시점부터 시작하는 연속 terminal `PROCESSED`/`EMPTY` prefix가 최소 한 Window 있어야 한다. 연속 prefix 뒤의 정상 `READY` tail은 허용하지만 FAILED/Extractor error, Window 누락·겹침, 잘못된 Feature 수는 HOLD 조건이다.

```bash
python -m edge.detection.run_packet_checkpoint_recovery dry-run \
  --mode live-resume \
  --db-path /absolute/path/iot.db \
  --repository-root /absolute/path/iot-edge-zero-trust \
  --detector DETECTOR_NAME \
  --current-session-id CURRENT_COMPLETED_UUID \
  --target-session-id CURRENT_RUNNING_UUID \
  --approved-by OPERATOR \
  --reason "approved live packet detector resume" \
  --plan-output /ignored/existing/live-resume-DETECTOR_NAME-plan.json
```

`DETECTOR_NAME`에는 `packet_rule` 또는 `packet_if`만 사용한다. Plan의 `checkpoint.after.last_processed_id`가 Before와 같고, `last_completed_window_end`가 Target의 `first_window_start`와 정확히 같은지 확인한다. Target의 현재 `packet_feature_ready_through`로 점프하면 안 된다.

Orchestrator에서 `packet_rule`과 `packet_if`가 모두 required이면 같은 Target을 대상으로 각 Detector의 Dry-run과 Execute를 별도로 수행한다. 두 Plan의 After 경계가 동일한 Target `first_window_start`인지 확인하고, Execute 후에는 Detector별 Recovery Audit가 정확히 하나씩 생성됐는지 확인한다. 어느 한 Audit라도 없거나 Target/경계가 다르면 Orchestrator는 fail-closed로 catch-up을 거부한다.

## 4. Execute와 결과

### 수집되지 않은 마지막 실패 구간에서의 명시적 복구

현재 Session이 `FAILED`이면 기본 동작은 계속 거부한다. `live-resume`의
`--allow-failed-current-session` 옵션은 Checkpoint까지 정상 구간이 모두 소비됐고,
그 직후에 캡처가 시작되지 않은 `LATE_CAPTURE` 구간 하나만 남은 경우에만 허용한다.
파일, 캡처 시작 시각, Packet Feature가 있거나 수집 시간이 0이 아니면 거부한다.
FAILED Session과 Segment는 원래 상태로 보존하고, 건너뛴 구간은 Plan과 Audit에 기록한다.

Dry-run에 `--allow-failed-current-session`을 명시한 경우 Execute 확인값은
`APPLY-PACKET-FAILED-TAIL-LIVE-RESUME`이다. 중간에 처리 가능한 Session이 있으면
기존의 Plan SHA 기반 `--confirm-skip-processable` 확인도 필요하다. 이 복구는
과거의 탐지 공백을 성공적으로 처리한 것으로 바꾸지 않으며, 이후의 새 실험과
과거 공백의 증거를 분리하여 기록해야 한다.

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
  --plan-file /ignored/existing/live-resume-DETECTOR_NAME-plan.json \
  --db-path /absolute/path/iot.db \
  --artifact-dir /ignored/existing/artifacts \
  --confirm "APPLY-PACKET-LIVE-RESUME"
```

Plan 생성 뒤 Target status/identity/`first_window_start`가 바뀌거나 ready prefix가 퇴행하면 Execute는 거부된다. Capture/Extractor가 정상적으로 늘린 terminal prefix 또는 trailing READY tail은 재검증 후 허용된다. 다른 RUNNING Session, FAILED/error, 연속성 파손, DB backup 중 변경은 모두 Commit 전 HOLD 조건이다.

Exit Code 2는 Commit 전 거부다. Exit Code 3은 DB Commit 뒤 검증 또는 Result JSON 기록 실패로 `HOLD` 상태이며, Checkpoint·Audit·Backup을 유지하고 자동 Restore하지 않는다. 운영자는 Checkpoint, Audit Row, Backup SHA256, integrity/FK, 보호 테이블 불변을 확인한다.

## 5. 후속 검증

승인한 Target Session에 대해 해당 Detector의 Manual Runner만 실행한다. Recovery 전 active였던 서비스만 원복한다. Live Resume에서는 required인 모든 Packet Detector에 유효한 공식 Audit가 있고, 각 Detector가 Target `first_window_start` 이후의 기존 Feature부터 처리하는지 확인한다. 공식 Trust/Firewall E2E는 새 Holdout Session에서 별도로 수행한다.

이 문서는 코드 경로를 설명한다. 실제 Raspberry Pi의 systemd/lock/capture 동시 동작 Cutover 검증은 코드 PR과 별도로 수행하고 증거를 기록해야 한다.

### 관리자 복구 이후에도 처리 시각 확인

Device 상태·점수 복구 성공과 탐지 재개 성공은 별도 조건이다. 서비스의 `active`
표시나 Device의 `normal/100`만으로 실험을 재개하지 않는다. 관리자 복구 이후
활성화된 Packet·MQTT Detector와 Trust 처리 Checkpoint가 두 번 이상
연속 전진하고, 실제 새 MQTT 수신 및 현재 Capture Session의 Feature 처리가
이어지는지 확인한다. 처리 시각이 정체되면 해당 회차를 완료로 기록하지 않는다.

Baseline Recovery는 쓰기 Transaction 안에서 Backup·무결성 검사를 수행하므로,
Capture의 DB 기록과 경합할 수 있다. 캡처 경계에서 지연이 발생했는지 실제 Timing
Metadata와 `LATE_CAPTURE` 이력을 확인한다. 작업 시점을 경계에서 떨어뜨리는 것은
운영상 완화책이며 자동 복구나 지연 방지의 보장은 아니다. 기존 Capture 적격 기준을
완화하지 않고, FAILED 전환이 발생하면 감사 기록을 보존하는 복구 절차로 처리한다.
