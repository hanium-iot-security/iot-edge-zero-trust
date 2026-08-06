# Phase 5 Raspberry Pi Scenario Hook 최소 설계

## 1. 목적

Phase 5 Scenario Runner가 실제 공격을 실행하기 전에 대상 Run·Session·Device·IP를 기준으로 최소 안전 조건을 확인하고, 공격 명령 종료 후 잔여 공격 프로세스가 없는지 검증한다.

이 설계는 공격 Offline Test Session 수집을 가능하게 하는 최소 구현만 다룬다. Trust Score, Device 상태, Firewall Rule을 자동 복구하거나 삭제하지 않는다.

## 2. 현재 문제

현재 `BaselineCheck`와 `CleanupHook`은 인자를 받지 않고, `ScenarioRunner`도 `baseline_check()`와 `cleanup_hook()`을 인자 없이 호출한다. 따라서 Hook이 현재 실행의 `run_id`, `scenario_id`, `session_id`, `target_device_id`, `source_ip`, `target_host`, `evaluation_scope`를 알 수 없다.

`edge/scenarios/cleanup.py`의 Pi Hook은 주석 뼈대만 있으며, 기본 no-op Hook은 실제 `--execute`에서 의도적으로 거부된다.

## 3. 선택한 접근

### 3.1 불변 Context 전달

`ScenarioHookContext`를 추가하고 Baseline·Cleanup Hook이 동일 Context를 받도록 한다.

필드:

- `run_id`
- `scenario_id`
- `session_id`
- `target_device_id`
- `source_ip`
- `target_host`
- `evaluation_scope`
- `execution_node`

`started_at`, `attack_started_at` 등 실행 시각은 최소 구현에서 제외한다. 현재 목표인 대상 식별과 안전 Gate에 필수적이지 않고, Cleanup은 상태 변경이 아니라 잔여 프로세스 확인만 수행하기 때문이다.

### 3.2 Baseline Hook 책임

읽기 전용 검사만 수행한다.

필수 검사:

1. 운영 DB 경로가 명시적으로 설정되고 읽기 가능함
2. `target_device_id`가 필요한 시나리오라면 DB에 대상 Device가 존재함
3. 대상 Device 상태가 `normal`임
4. 대상 Device 또는 `source_ip`에 연결된 활성 Firewall 상태가 `PENDING` 또는 `APPLIED`가 아님
5. 필수 systemd 서비스가 `active`임
6. Packet Capture 상태가 시나리오 실행 조건과 충돌하지 않음
7. 충돌 가능한 공격·Recovery·Packet Detector 프로세스가 없음

실패 시 `(False, 구체적인 사유)`를 반환하고 공격 명령은 실행하지 않는다.

### 3.3 Cleanup Hook 책임

공격 직후 다음만 확인한다.

1. Scenario Runner가 실행한 공격 명령이 종료됨
2. 프로젝트 공격 모듈의 잔여 프로세스가 없음
3. 다음 Observation 단계가 가능함

Cleanup Hook은 아래 동작을 하지 않는다.

- `firewall_rules` 이력 삭제
- Trust Score 초기화
- Device 상태 초기화
- iptables Rule 자동 삭제
- Firewall 자동 Release
- Trust Compensation 자동 실행

Firewall·Trust 결과는 공식 평가 증적으로 보존한다. 복구가 필요하면 운영자가 승인된 Release·Trust Compensation 절차를 별도로 수행한다.

## 4. Dry-run·실행 계약

- Dry-run에서는 Baseline·Cleanup Hook을 호출하지 않는다.
- 실제 `--execute`에서는 기본 no-op Hook을 계속 거부한다.
- Baseline 실패 또는 예외는 공격 명령 실행 전 `ENVIRONMENT_ERROR`로 기록한다.
- Cleanup 실패 또는 예외는 `RESET_FAILED`로 기록한다.
- 동일 Run의 Context가 Baseline과 Cleanup에 전달되어야 한다.

## 5. 변경 범위

예상 변경 파일:

- `edge/scenarios/cleanup.py`
  - `ScenarioHookContext`
  - Hook Protocol 시그니처 변경
  - 최소 Pi Baseline·Cleanup 구현
- `edge/scenarios/run_scenario.py`
  - Context 생성 및 전달
  - Dry-run·오류 상태 회귀 유지
- `tests/test_scenario_runner.py` 및 필요한 인접 테스트
  - Context 전달
  - Baseline 실패·예외
  - Cleanup 실패·예외
  - Dry-run Hook 미호출
  - 기본 Hook 실행 거부
- Scenario Runner Runbook 문서
  - Pi 실행 전 Gate
  - 공격 후 Observation
  - 운영자 Release·Trust Compensation 경계

## 6. 제외 범위

- 실제 Raspberry Pi 운영 DB 쓰기
- 실제 iptables 변경
- 실제 ESP32·MQTT 공격 실행
- 공격 Offline Test Session 수집
- Dataset v2 Export
- Packet IF 학습·배포
- 자동 Observation 상태 머신
- PID 추적 시스템
- 매 Run DB `integrity_check`
- 매 Run NTP 검사
- 자동 MQTT Publish Smoke

## 7. 테스트 전략

### 단위 테스트

1. Baseline·Cleanup에 동일 Context 전달
2. 다른 Run의 Context 혼입 방지
3. Baseline `False` 시 공격 명령 미실행
4. Baseline 예외 시 `ENVIRONMENT_ERROR`
5. Cleanup `False` 또는 예외 시 `RESET_FAILED`
6. Dry-run에서 Hook 미호출
7. 기본 no-op Hook으로 `--execute` 거부
8. 기존 Run Manifest·JSONL 계약 회귀 유지

### 인접 회귀

- Scenario Runner 집중 테스트
- Phase 5 Run Manifest·Evaluation Exporter 테스트
- Packet IF Dataset v2 Manifest 테스트
- 전체 `pytest` 가능 범위
- `compileall`
- `git diff --check`

### 실기기 검증

코드 병합 전 실제 Pi에서는 다음만 수행한다.

1. Baseline Hook 읽기 전용 Smoke
2. 실제 공격 없이 Hook 모듈 로드 및 실패 사유 확인
3. Scenario Dry-run
4. 운영자 승인 후 대표 공격 1회 Pilot
5. 서비스·DB·Capture·잔여 프로세스 상태 확인

## 8. 성공 기준

- 실제 `--execute`가 최소 Pi Hook 없이는 계속 거부됨
- 올바른 Context가 Hook에 전달됨
- 안전 조건 실패 시 공격이 시작되지 않음
- 공격 종료 후 자동 상태 복구 없이 잔여 프로세스만 검증함
- 기존 Scenario Runner, Run Manifest, Dataset v2 계약과 정합성이 유지됨
- 실제 Pi 쓰기 작업과 최종 Merge는 사용자 승인 전 수행하지 않음
