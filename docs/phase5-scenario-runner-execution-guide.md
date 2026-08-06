# Scenario Runner 실행·중지·복구 가이드

대상: Raspberry Pi #2 또는 관리 노트북에서 Scenario Runner를 실행하는 담당자
작성 기준 코드: `edge/scenarios/run_scenario.py`
실제 Pi 경로·복구 명령: 실기기 검증 후 최종화 필요 — 이 문서의 `[TODO: 실기기 검증 필요]` 표시 부분을 채워 넣어야 함

---

## 0. 실행 전 반드시 확인 — Pi Baseline/Cleanup 연결 전 실공격 금지

Scenario Runner는 기본적으로 항상 Dry-run으로 동작한다. 실제 공격을 실행하려면 아래 조건을 모두 만족해야 하며, 하나라도 빠지면 Runner가 실행 자체를 거부한다 (코드로 강제됨).

1. CLI에 `--execute` 플래그를 명시해야 한다. 지정하지 않으면 무조건 Dry-run.
2. `--execute`와 함께 `--baseline-check-module`, `--cleanup-hook-module`로 실제 Pi 훅을 지정해야 한다. 이 두 옵션 없이 `--execute`만 주면 항상 거부된다 — CLI가 기본으로 만드는 `ScenarioRunner`에는 실제 훅이 연결되어 있지 않기 때문이다.

두 옵션은 `module.submodule:function_name` 형식으로 실제 훅 함수의 위치를 지정한다.
Pi에서는 상대경로 기본값이 다른 DB를 가리키지 않도록 운영 DB의 절대경로를 먼저 명시한다.

```bash
export DATABASE_URL="sqlite:////home/pi/iot-edge-zero-trust/backend/data/iot_security.db"

python -m edge.scenarios.run_scenario \
  --scenario mqtt_abnormal_publish_rate \
  --target-device-id esp32_02 \
  --session-id <실제 Capture Session ID> \
  --execution-node <Pi 식별자> \
  --execution-node-registered \
  --baseline-check-module edge.scenarios.cleanup:pi_baseline_check \
  --cleanup-hook-module edge.scenarios.cleanup:pi_cleanup_hook \
  --execute
```

> `edge.scenarios.cleanup:pi_baseline_check`와 `pi_cleanup_hook`은 동일한 `ScenarioHookContext`를 받는다. Baseline은 SQLite read-only 조회, 필수 Runtime, Capture Session, 활성 Firewall 요청, 충돌 프로세스를 확인한다. Cleanup은 잔여 공격·수동 실행 프로세스만 확인하며 DB·Trust·Device·Firewall·iptables 상태를 변경하지 않는다.

Hook 경로는 저장소에서 검토한 신뢰 가능한 모듈만 지정한다. 모듈을 불러올 수 없거나 지정한 속성이 호출 가능한 함수가 아니면 실행 전에 종료 코드 2로 거부된다. Baseline Hook 예외는 공격 시작 전 `ENVIRONMENT_ERROR`로, 공격 후 Cleanup Hook 예외는 `RESET_FAILED`로 기록하며 결과 Manifest를 보존한다.

이 게이트가 뚫리지 않았는데 `--execute`를 줬을 때 나오는 에러 메시지:

```
UnsafeExecutionRefusedError: <scenario_id>의 실공격 실행이 거부되었습니다:
baseline_check/cleanup_hook이 아직 기본 no-op 구현입니다.
```

이 메시지가 뜨면 정상 동작이다. 아직 Pi 훅이 연결 안 됐다는 뜻이므로, 코드를 우회하려 하지 말고 담당자에게 Pi 훅 연결 상태를 확인한다.

---

## 1. Scenario별 필수 인자

`python -m edge.scenarios.run_scenario --list`로 등록된 시나리오와 최소/목표 반복 횟수를 확인할 수 있다. 아래는 각 시나리오가 실제로 요구하는 인자 요약이다 (`edge/scenarios/scenario_registry.py` 및 각 계열 정의 기준).

### MQTT 비정상 전송 계열

| scenario_id | scope | 필수 인자 | 비고 |
|---|---|---|---|
| `mqtt_abnormal_publish_rate` | FULL_E2E (대표) | `--target-device-id` | 목표 반복 10회 |

### 식별·메시지 정책 위반 계열

| scenario_id | scope | 필수 인자 | 비고 |
|---|---|---|---|
| `mqtt_device_id_mismatch` | FULL_E2E (대표) | `--target-device-id` | 목표 반복 10회. Runner가 내부적으로 `--topic-device-id`(target-device-id 값)와 `--payload-device-id`(target과 다른 등록 기기, 자동 선택)를 조립한다 — 사람이 직접 두 값을 지정할 필요 없음 |
| `mqtt_unknown_device` | DETECTION_ONLY | 없음 (`--target-device-id` 불필요) | 최소 1회 |
| `mqtt_abnormal_topic` | DETECTION_ONLY | `--target-device-id` | 최소 1회 |
| `mqtt_malformed_payload` | DETECTION_ONLY | `--target-device-id` | 최소 1회 |
| `mqtt_large_payload` | DETECTION_ONLY | `--target-device-id` | 최소 1회 |

### Packet 이상 행위 계열 (Packet Rule Gate 필요)

| scenario_id | scope | 필수 인자 | 비고 |
|---|---|---|---|
| `packet_rate_flood` | FULL_E2E (대표) | `--source-ip` | 목표 반복 10회. `--target-host`는 선택(미지정 시 Broker 기본값) |
| `packet_byte_rate_flood` | DETECTION_ONLY | `--source-ip` | 최소 1회. `--target-host` 선택 |
| `packet_port_scan` | DETECTION_ONLY | `--source-ip` | 최소 1회. `--target-host` 선택 (내부적으로 `--target`으로 전달됨) |

Packet 계열 3개는 전부 `requires_packet_rule_gate=True`다. Phase 4 Packet Rule Orchestrator 등록·Local Smoke Test가 확인되지 않으면 `HOLD` 상태로 기록되고 공격이 실행되지 않는다 (§3 참고).

### source-ip와 target-host를 혼동하지 말 것

- `--source-ip`: Attack Node 자신의 IP. Manifest에 기록되어 상관분석에 쓰인다.
- `--target-host`: 공격 패킷을 실제로 받는 목적지(Raspberry Pi/Broker) IP. 지정하지 않으면 attack 스크립트 자체 기본값(BROKER_HOST)이 쓰인다.

두 값은 의미가 다르므로 절대 같은 값을 넣지 않는다. `--target-host`를 지정하지 않아도 정상 동작하지만(기본값 사용), Packet Capture 원본과 실행 로그가 정확히 어느 목적지로 갔는지 증적에 남기고 싶다면 명시적으로 지정한다.

### FULL_E2E 공식 실행 시 추가로 필요한 것

`--execute`를 붙여 FULL_E2E 시나리오(`mqtt_abnormal_publish_rate`, `mqtt_device_id_mismatch`, `packet_rate_flood`)를 공식 실행하려면 `--session-id`, `--target-device-id`, `--source-ip` 세 값을 모두 실행 전에 확정해야 한다. 하나라도 없으면 `MissingRequiredInputError`로 공격 시작 전에 거부된다 — Exporter는 Manifest를 사후에 재작성하지 않으므로, 상관관계 없는 Run을 만든 뒤 나중에 채우는 흐름은 성립하지 않는다.

`--execution-node-registered`를 지정하지 않으면(기본값 False), Attack Node가 DB에 등록되지 않은 것으로 간주되어 FULL_E2E가 자동으로 DETECTION_ONLY로 하향된다 — 이 경우 `--session-id` 요구도 함께 해제된다.

### 격리·Firewall 도달 가능성 확인 전 운영 Gate

Registry의 `firewall_rule_expected=true`, `block_expected=true`는 대표 시나리오가 최종적으로 검증해야 할 **후보 계약**이지, 현재 실기기에서 달성됐다는 결과가 아니다. 현재 실행량이 독립된 10초 Window를 충분히 만들고 Trust Score를 30점 미만까지 낮추는지는 아직 실측되지 않았다. Pi 증적으로 Trust 감점→`isolated`→Firewall `APPLIED`→실제 차단이 확인되기 전까지 공식 FULL_E2E 반복 실행과 완료 판정은 운영상 `HOLD`한다. 이 PR의 병합만으로 FULL_E2E 격리 검증이 완료된 것으로 기록하지 않는다.

---

## 1.1 Pi Hook 최소 안전 계약

- `--session-id`가 있으면 해당 `packet_capture_sessions` Row가 `RUNNING`이고 `ended_at IS NULL`이어야 하며 `packet-capture.service`도 `active`여야 한다.
- `--session-id`가 없는 Detection-only 실행에서는 의도하지 않은 수집을 막기 위해 `packet-capture.service`가 `inactive`여야 한다.
- 대상 Device가 있으면 DB에 존재하고 `devices.status=normal`이어야 한다.
- 대상 Device 또는 Source IP에 `PENDING`/`APPLIED` Firewall Rule이 있으면 공격을 시작하지 않는다.
- DB에 활성 Row가 없더라도 실제 iptables에 대상 Source IP의 `hanium-firewall:` Rule이 남아 있으면 공격을 시작하지 않는다. Baseline은 기존 root Wrapper의 `list` 명령으로 읽기만 하며 Rule을 삭제하지 않는다.
- 공격 종료 직후 Cleanup은 잔여 Process만 확인한다. Detection·Trust·Firewall·실제 Block Observation 전에 자동 Release나 Trust Recovery를 수행하지 않는다.
- 복구가 필요하면 증적 확인 후 기존 승인형 Firewall Release, Baseline Recovery, Trust Score Compensation 절차를 별도로 사용한다.

## 2. Dry-run과 반복 실행 방법

### Dry-run (기본값, 실공격 없음)

`--execute`를 빼면 항상 Dry-run이다. 인자 조립·Manifest 생성·명령 계약(예: `mqtt_device_id_mismatch`가 어떤 command를 만드는지)까지 실제 실행과 동일한 경로로 검증할 수 있다.

```bash
python -m edge.scenarios.run_scenario \
  --scenario mqtt_abnormal_publish_rate \
  --target-device-id esp32_02 \
  --run-id smoke-001
```

Dry-run 결과는 `scenario_status=NOT_EVALUATED`, `scenario_runner_status=DRY_RUN`으로 기록되며, `attack_started_at`이 채워지지 않는다 — 공식 TP/FP/TN/FN 지표 집계에서 자동으로 제외된다. Dry-run 산출물을 평가 exporter에 그대로 넣어 공식 지표로 쓰지 않는다.

### 단일 실행 (실공격)

```bash
python -m edge.scenarios.run_scenario \
  --scenario mqtt_abnormal_publish_rate \
  --target-device-id esp32_02 \
  --source-ip <Attack Node IP> \
  --session-id <실제 Capture Session ID> \
  --execution-node <Pi 식별자> \
  --execution-node-registered \
  --run-id run-2026-08-05-001 \
  --baseline-check-module edge.scenarios.cleanup:pi_baseline_check \
  --cleanup-hook-module edge.scenarios.cleanup:pi_cleanup_hook \
  --execute
```

`--baseline-check-module`/`--cleanup-hook-module`은 §0에서 설명한 실제 Pi 훅 연결 옵션이다. 생략하면 실행이 거부된다.

### 반복 실행

`--times N`으로 같은 조건을 N회 반복한다. `--run-id`는 반복 실행에서는 지정하지 않는다 (매 실행마다 자동으로 새 UUID가 발급됨).

```bash
python -m edge.scenarios.run_scenario \
  --scenario mqtt_abnormal_publish_rate \
  --target-device-id esp32_02 \
  --source-ip <Attack Node IP> \
  --session-id <실제 Capture Session ID> \
  --execution-node <Pi 식별자> \
  --execution-node-registered \
  --times 10 \
  --baseline-check-module edge.scenarios.cleanup:pi_baseline_check \
  --cleanup-hook-module edge.scenarios.cleanup:pi_cleanup_hook \
  --execute
```

반복 실행 중 `RESET_FAILED`(Cleanup 실패) 또는 `HOLD`(Packet Rule Gate 미확인)가 나오면 그 시점에서 자동으로 중단되고 이후 반복은 실행되지 않는다. `SCENARIO_FAILED`는 조기 중단시키지 않지만, 배치 안에 하나라도 있으면 최종 종료 코드가 0이 아니게 된다.

### Packet 계열 예시

```bash
python -m edge.scenarios.run_scenario \
  --scenario packet_rate_flood \
  --target-device-id <Attack Node에 귀속된 Device ID> \
  --source-ip <Attack Node 자신의 IP> \
  --target-host <Raspberry Pi/Broker IP> \
  --session-id <실제 Capture Session ID> \
  --execution-node <Pi 식별자> \
  --execution-node-registered \
  --times 10 \
  --baseline-check-module edge.scenarios.cleanup:pi_baseline_check \
  --cleanup-hook-module edge.scenarios.cleanup:pi_cleanup_hook \
  --execute
```

---

## 3. 실행 중지·Timeout·실패 상태 확인

### 실행 중 강제 중지

포그라운드에서 실행 중이면 `Ctrl+C`로 중단할 수 있다. 다만 이미 시작된 공격 프로세스(subprocess)가 정상적으로 정리되는지는 보장되지 않으므로, 중단 후 반드시 아래를 확인한다.

- `ps aux | grep attacks.` 로 공격 프로세스가 남아있지 않은지 확인
- `[TODO: 실기기 검증 필요]` 남은 프로세스 강제 종료 및 iptables/Firewall Rule 정리 절차 (Pi 실제 환경 확정 후 채움)

### Timeout

명령 실행 Timeout은 기본 120초(`DEFAULT_COMMAND_TIMEOUT_SECONDS`)다. 이 시간을 넘기면 `scenario_runner_status=SCENARIO_FAILED`, `error_reason=command_timeout`으로 기록된다.

Packet Port Scan(`packet_port_scan`)처럼 포트 범위·타임아웃 설정에 따라 실행 시간이 길어질 수 있는 시나리오는, Runner가 `--end_port`/`--timeout_ms` 조합이 이 120초 Timeout에 근접·초과할 것으로 판단되면 실행 전에 명시적으로 거부한다(공격 스크립트 자체의 사전 검증). 기본값(`start_port=1, end_port=256, timeout_ms=150`)은 안전 범위(약 38초) 안에 들어오도록 이미 설정되어 있다.

### 실패 상태 값과 의미

`scenario_runner_status`(Runner 내부 세부 상태)와 `scenario_status`(exporter 공식 상태)는 다르다.

| scenario_runner_status | scenario_status (공식) | 의미 |
|---|---|---|
| `SUCCESS` | `SUCCESS` | 정상 완료 |
| `DRY_RUN` | `NOT_EVALUATED` | Dry-run — 공식 집계 제외 |
| `HOLD` | `HOLD` | Packet Rule Gate 미확인으로 실행 자체를 하지 않음 |
| `SCENARIO_FAILED` | `FAILED` | 공격 프로세스가 non-zero exit 또는 timeout |
| `ENVIRONMENT_ERROR` | `ENVIRONMENT_ERROR` | Baseline 실패, 공격 실행 파일을 못 찾음 등 환경 문제 |
| `RESET_FAILED` | `ENVIRONMENT_ERROR`로 매핑 | 공격은 실행됐으나 Cleanup(정리)이 실패 — 다음 Run을 바로 시작하지 말고 수동 확인 필요 |

`RESET_FAILED`가 나오면 반복 실행은 자동으로 멈춘다. 이 상태에서 이어서 실행하기 전에 반드시:

1. 활성 Firewall Rule·iptables Rule이 남아있는지 확인
2. 공격 프로세스·MQTT Client가 완전히 종료됐는지 확인
3. `[TODO: 실기기 검증 필요]` 수동 정리 절차 확정 (§4 Cleanup 금지 사항 준수)

### CLI 종료 코드

- `0`: 전부 성공 (또는 전부 Dry-run/성공)
- `1`: 하나 이상 실패(`SCENARIO_FAILED` 포함) 했거나 조기 중단(`RESET_FAILED`/`HOLD`)됨
- `2`: 입력 자체가 잘못됨 (알 수 없는 scenario_id, 중복 run_id, 잘못된 run_id 형식, 필수 인자 누락, 안전하지 않은 실행 시도 등) — 이 경우 아무 Run도 생성되지 않는다

---

## 4. Manifest·stdout·stderr 저장 경로

기본 저장 루트는 `data/phase5/runs/` (`--runs-root`로 변경 가능)이다. 각 실행(run_id)마다 다음 구조로 저장된다.

```
data/phase5/runs/<run_id>/
├── run-manifest.json          # RunManifest (Exporter가 읽는 계약 스키마, 사후 수정 안 함)
├── run-manifest.json.sha256   # 무결성 확인용 sidecar
├── scenario-result.jsonl      # ScenarioResultRow 1줄 (실행 명령·상태·target_host 등 증적)
├── scenario-result.jsonl.sha256
└── logs/
    ├── <scenario_id>__<run_id>__stdout.log
    └── <scenario_id>__<run_id>__stderr.log
```

- `run_id`는 영문/숫자/`-`/`_`/`.`만 허용되며, 경로 구분자·절대경로·`..`는 거부된다(입력 검증). 지정하지 않으면 UUID가 자동 발급된다.
- Dry-run/HOLD인 경우 `logs/` 디렉토리 자체가 생성되지 않는다(공격 프로세스를 실행하지 않았으므로).
- `scenario-result.jsonl`에는 `target_host` 필드가 포함된다 — `RunManifest` 스키마 자체에는 없고 이 파일에만 증적으로 남는다.
- 동일 `run_id`로 재실행은 불가능하다(`DuplicateRunIdError`). 재실행은 항상 새 `run_id`를 받는다.

---

## 5. Cleanup 금지 사항과 승인된 복구 절차

Pi에서 실제 `cleanup_hook`을 구현할 때 다음은 절대 하지 않는다:

- `firewall_rules` 이력 Row를 직접 DELETE
- Trust Score를 직접 임의의 값으로 초기화
- Device 상태를 직접 임의의 값으로 초기화

대신:

- Firewall Rule은 승인된 Firewall Release 절차(예: 상태를 REMOVED로 전이)로만 정리한다. Audit 이력을 보존해야 한다.
- Trust Score를 되돌려야 하는 경우 `edge/trust/trust_compensation.py`의 `inspect_trust_compensation`/`execute_trust_compensation` (또는 CLI `edge/trust/run_trust_compensation.py`)을 사용한다. 이 절차는 운영자가 건별로 `approved_by`·`reason`·`--confirm`을 입력해야 하는 승인 도구이며, DB 백업·SHA256·Audit JSON 로그를 남긴다.
- 이 보상 절차는 사람이 승인해서 건별로 실행하는 도구이므로, Scenario Runner의 자동 `cleanup_hook`이 매 반복 실행 뒤 자동으로 호출하지 않는다. 자동 Cleanup은 "정상 상태로 복귀했는지 확인"까지만 담당하고, 이미 반영된 Trust Score를 되돌려야 하는 예외 상황은 운영자가 별도로 위 도구를 사용해 처리한다.

`[TODO: 실기기 검증 필요]` 실제 Pi에서 iptables Rule 제거, MQTT Client/스캔 Process 종료의 정확한 명령어는 `edge/scenarios/cleanup.py` 하단의 `pi_cleanup_hook` 예시 뼈대를 채운 뒤 이 문서에 반영한다.

---

## 6. 빠른 체크리스트 (매 실행 전)

- [ ] Device 상태 `normal`, 시작 Trust Score 기록, 활성 Firewall/iptables Rule 없음, 정상 MQTT 연결 가능 확인 (Baseline)
- [ ] `--execute` 없이 Dry-run으로 먼저 명령·인자가 올바른지 확인
- [ ] FULL_E2E 공식 실행이면 `--session-id`, `--target-device-id`, `--source-ip`를 모두 미리 확정
- [ ] 격리 도달 실기기 증적이 없으면 Firewall·Block 완료를 선언하지 않고 공식 FULL_E2E 실행을 `HOLD`
- [ ] Packet 계열이면 Packet Rule Gate 확인 상태 점검 (`PHASE5_PACKET_RULE_GATE_CONFIRMED` 환경변수 또는 담당자 확인)
- [ ] 실행 후 `scenario-result.jsonl`의 `scenario_runner_status` 확인, `RESET_FAILED`면 수동 정리 후 재개
- [ ] `RESET_FAILED`/이상 상황 시 Trust Score를 임의로 되돌리지 않고 승인된 보상 절차 사용
