# 기기별 OFF/OBSERVE의 실제 추론 연결

기존 MQTT·Packet IF Stage가 Migration 012의 저장된 AI revision을 읽어 추론 대상을 선택한다.
`AI_DEVICE_POLICY_ENABLED=false`가 기본값이며 운영 설정을 자동 변경하지 않는다.
새 모드에는 검증된 모델 Bundle, `TRUST_AI_MODE=observe`, Migration 014의 승인된 Stage 시작 기록이 필요하다.
실제 실행 근거와 경고를 조회하려면 Migration 013 및 `RUNTIME_EVIDENCE_ENABLED=true`도 사용한다.

## 처리 기준

- 매 Stage 실행에서 등록·기기 정책·AI revision·활성화 기록을 같은 SQLite snapshot으로 읽는다.
  프로세스 시작 당시 정책을 계속 캐시하지 않으므로 새 revision은 다음 실행에 반영된다.
- 원본 10초 Window에 유효했던 revision을 기존 `decide_ai_window`에 공급한다.
  OFF는 추론·AI 이벤트를 제외하고 제외 수와 처리 경계를 남긴다. Raw·Feature·Rule 수집은 유지한다.
- OBSERVE는 등록 효력, 해당 OBSERVE revision 효력, 승인된 Stage 시작 경계 중 가장 늦은 시점부터
  추론·결과·경고를 남긴다. 이후 OBSERVE로 바뀌어도 과거 OFF Window를 되살리지 않는다.
- 등록·정책·AI 설정이 없거나 손상된 기기는 해당 사유로 제외한다. 모델·스키마·활성화 기록 오류는
  Stage 실패이며 이벤트·완료·Checkpoint를 함께 rollback한다. 전부 OFF여도 모델 검증은 생략하지 않는다.
- 실제 기기 OBSERVE 근거는 기존 Trust 방어를 사용해 AI 단독 감점·격리에서 제외한다.
  같은 Window의 Rule 판정과 기존 감점은 유지한다.

## 최초 Stage 시작 경계

MQTT IF를 오래 비활성화한 경우 모델 경로만 설정하면 과거 데이터 대량 추론이나 무감사 생략이
생길 수 있다. 최초 연결은 Stage별 불변 승인 기록과 해당 Stage의 Checkpoint 시작을 함께 확정한다.
기존 Packet Capture 초기화·장애 복구 경계를 AI 승인으로 대체하지 않는다.

승인 기록에는 모델 version/SHA256, 이전 Checkpoint, UTC 10초 경계 B, 과거 제외 범위·행 수,
Stage 구성, 승인자·사유·시각을 보관한다. 한 Stage의 최초 활성화만 지원하며 이미 승인된 모델을
다른 모델로 교체하는 기능은 이번 범위에 없다.

현재 구현은 B를 이미 완료된 Trust 경계와 일치하도록 제한한다. 다른 required Stage도 B까지
완료되어야 하며 대상 Stage의 기존 완료 경계는 B 이하여야 한다. 기존 Packet 미승인 공백이나 다른 Stage의
미처리를 이 명령으로 건너뛰지 않는다. 조건이 맞지 않으면 기존 복구·처리 전진부터 확인한다.

### 준비와 명시적 적용

먼저 사본에서 검증한다. 운영에서는 사용할 모델·Stage·기기 정책·실제 제외 범위를 검토하고,
Orchestrator를 중지한 별도의 점검 시간에 적용한다. 아래 명령은 서비스를 직접 제어하지 않는다.
준비와 적용 시 **사용하려는 동일한 Stage 설정**과 `AI_DEVICE_POLICY_ENABLED=true`,
`TRUST_AI_MODE=observe`, Bundle pin을 제공해야 한다. 환경값을 켜는 것만으로 승인이 생기지 않는다.

```text
python -m edge.orchestration.manage_ai_activation --db <검증할 DB> prepare --stage mqtt_if --boundary <승인 UTC 10초 경계> --approved-by <승인자> --reason <사유> --output <새 계획.json>
python -m edge.orchestration.manage_ai_activation --db <같은 DB> apply --plan <계획.json>
```

`prepare`는 읽기 전용으로 계획을 만들며 기존 계획 파일을 덮지 않는다. 계획은 해당 DB의 절대 경로에
묶인다. 사본에서 만든 계획을 운영 DB에 그대로 적용하지 않고 그 DB에서 새로 준비한다.

`apply`는 기존 Orchestrator와 같은 공유 잠금을 잡고 실제 모델·Stage 구성·Checkpoint·제외 범위를
다시 확인한다. 달라지면 HOLD한다. 불변 승인 기록과 대상 Stage의 B 설정은 하나의 DB 트랜잭션이다.
다른 Stage의 Checkpoint는 수정하지 않는다. 같은 계획의 재실행은 실제 저장된 감사와 처리 위치를
확인해 기존 결과를 반환하며, 커밋 후 출력이 유실돼도 처리 위치를 되돌리지 않는다.

종료 코드: 0은 준비/적용 성공, 2는 입력·모델·DB·사전 조건 HOLD, 3은 공유 잠금 충돌이다.
새 명령을 호출하지 않으면 Migration만으로 승인·Checkpoint·모델 실행이 바뀌지 않는다.

## 완료 경계와 재시작

정책 연결 모드의 Stage는 승인 B 이후 자신의 완료 경계부터만 분석한다. 이미 완료한 범위는
재개방하지 않는다. 공통 처리 시작이 해당 AI의 미완료 경계보다 더 늦은 시각이면 묵시적으로 생략하지
않고 HOLD한다. 특히 optional Stage 실패 뒤 이런 상태가 생길 수 있으므로 운영 관찰 Stage는
required로 구성하는 것을 권장한다. 과거 공백 처리는 기존 복구 계약을 따른다.

`runtime-status`의 Stage에는 실제 프로세스가 사용한 `ai_device_policy_enabled`를 기록한다.
설정 API의 OFF/OBSERVE와 완료 근거의 `ai_mode`·`ai_revision`을 구분하고, 관측이 없거나 오래됐으면
정상 적용으로 해석하지 않는다. Windows에서는 실제 Boot ID가 없어 UNKNOWN일 수 있다.

## 검증 범위

로컬 시험은 작은 합성 Bundle·임시 SQLite를 사용한다. 저장된 OFF→OBSERVE→OFF, 재시작 없는 변경,
미이관·손상 기기, 승인 전/경계, 처리 완료 재시도, 저장 실패 rollback, 실제 이벤트의 Trust 무감점과
기존 Rule 감점, 관리 명령의 읽기 전용 준비·공유 잠금·중복 적용을 확인한다.

실제 Pi의 Migration·승인 적용·재시작·동시 수집 부하, 실제 센서의 추론·화면 표시와 모델 성능은
별도 검증 대상이다. 이 코드 연결이나 합성 시험을 공식 모델 학습·운영 활성화 완료로 보지 않는다.
