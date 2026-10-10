# Phase 9 현수 구현·검증 기록 (2026-10-10)

## 기준선과 범위

- 작업 전 로컬 `feature/hyunsu-phase8-policy-trust`는 깨끗했고 HEAD는 `8189cd3`였다. 원격 `develop`은 계획 기준 `53ec270`이며 Phase 8 PR #88 head `4ace33c`가 포함된다. 기존 브랜치를 유지하고 `codex/phase9-hyunsoo`를 `origin/develop`에서 생성했다. 이 작업에서 merge, 운영 DB 변경, Pi 배포·재시작은 하지 않았다.
- PR #107(정상 운용 v1), #108(복구), #109(수집 전 점검), #110(모델 정보 API), #111(Pi IPv4 격리)은 2026-10-10 조회 시 open이다. #110은 MQTT를 `LEGACY_CONTRACT_UNAVAILABLE`로 표시하며 새 MQTT Bundle과 실행 근거를 제외 범위에 둔다. AI 정책·경고·Stage 활성화 Migration과 Broker 전용 Feature Migration은 develop 및 공개 PR에서 확인되지 않았다.
- 이 문서의 로컬 PASS는 임시 SQLite/합성 입력이다. 운영 Pi, 운영 DB 사본, 실제 방화벽·공격 결과가 아니다.

## 정상 운용 기준 v1 검토 — P9-08/V06·V07

근거는 PR #107의 `d591e04`에 담긴 `docs/phase9-normal-operating-range.md`, `docs/phase9-message-contract.md`와 계획 11절이다. 아래 Run은 모두 Session 108의 한 개발 그룹이다. 학습·Session·정상 패턴 승인은 false이며 P1·P2 개발 허용을 Train 승인으로 해석하지 않는다.

| 조건 | 180초 예비 관측 | 판정 |
| --- | --- | --- |
| P0 ESP32 1·2 | 각 36건, 55B, 약 5초 도착 | 첫 본 수집의 기본 후보만 유지 |
| P0 Pico | 35건, 128~130B, 4.727~5.327초 도착 | 100B 고정 학습 필터는 Pico에 맞지 않지만 Rule 상한과는 별개 |
| P1 ESP32 2 | 36건, 52~53B, 4.078~5.846초 도착, 10초 Window당 1/2/3건도 관측 | Profile별 QC와 독립 그룹 전에는 Train 제외 |
| P2 ESP32 2 | 36건, 52~83B, 4.984~5.013초 도착 | RSSI·Free Heap 실제 값과 원본/Feature 대조 후 편입 결정 |
| P2 중 Pico | 127~130B, 3.501~6.462초 도착; uptime 송신 간격 5.028~5.034초, 순번 누락 없음 | 도착 변동 원인 미확인. 5.0초 단일 메시지 대체 Feature로 실제 주기를 인증하지 않음 |

P0/P1/P2의 INBOUND Packet 관측 최대 약 0.504pps·65.612B/s는 짧은 개발 표본이다. 당시 세 기기 정책 revision의 발행 수 15건/10초, Payload 5,120B, Packet 10pps·2,500B/s, 예상 주기 설명값 5초는 유지한다. 모두 **초과(`>`)**일 때 탐지한다. Packet 공통 Port Scan은 서로 다른 포트 >5 **AND** SYN >5, 기존 Broker 수치 10·20도 인상하지 않았다. 실행 직전에는 실제 정책 revision·운영 override를 다시 확인해야 한다. 공격 생성기·정상 재접속·희소 패킷을 포함한 기기별 전후 오탐/민감도는 운영 자료가 없어 미평가다.

경계 설계: 각 기기 정책의 네 값에 대해 바로 아래·정확히 같음·바로 위, 10초 경계·지연 입력을 적용한다. Packet/Byte Rate는 실제 `captured_duration_seconds`로 비교하고 `115/9.2=12.5`를 반드시 정확한 경계로 검사한다. 별도 Port Scan, Broker 목적지 SYN 집중, 다른 포트 스캔+정상 MQTT, MQTT publish/byte flood, 같은 Window의 대표 감점과 −30 cap을 회귀한다. 정상 최대값의 임의 배수로 상한을 조정하지 않는다.

## 코드 변경과 협업 계약

| 작업 | 변경 파일 | 구현·검증 판정 |
| --- | --- | --- |
| P9-08 Rate | `edge/detection/packet_rule_detector.py`, `tests/test_phase9_packet_rate_boundaries.py` | SQLite REAL의 십진 표현으로 교차 곱 비교. 115/9.2의 float 오탐을 제거하고 실제 초과를 탐지. 비교만 수정했으며 상한은 그대로다. 로컬 PASS |
| P9-08 Broker | `packet_rule_detector.py`, `edge/trust/trust_policy.py`, `backend/app/config.py`, Packet Rule 테스트 | 공통 정책 기본 버전 `packet-rule-policy-v4`. 전체 포트 SYN 대신 **Broker 목적지 전용 SYN 패킷 수**를 사용한다. 이 지표가 NULL/컬럼 없음인 과거 행은 Broker DoS로 감점하지 않는다. 옛 결합 조건상 의심 행에는 `BROKER_DOS_EVIDENCE_UNAVAILABLE`·후보 감점 0·구체적 사유를 기록한다. 다른 Port Scan/Rate는 유지. 판정 fixture PASS; Feature 생성·Migration·Pi는 HOLD |
| P9-03 AI 결정 | `edge/policy/ai_window_decision.py`, MQTT/Packet IF Stage, 관련 테스트 | 원본 UTC Window의 등록·AI revision과 승인 Stage 시작 경계로 추론 가능 여부를 선택한다. OFF/OBSERVE만 허용하고 ENFORCE·손상·미이관·DISABLED를 구별한다. Stage는 선택기를 주입받으면 OFF 추론을 건너뛰고 Checkpoint는 전진한다. 로컬 PASS; 저장 조회·승인 활성화 연결은 HOLD |
| P9-03 반복 경고 | `edge/detection/ai_warning_aggregation.py`, `tests/test_phase9_ai_warning_aggregation.py` | 기기·탐지기·유형·모델·경고 버전, 원본 Window별 W/N/C 집계. 같은 ID/Window 중복 계수 금지, 지연 닫힌 구간 연결, 재시작 상태 재사용, OFF·품질 제외 구분. 순수 판정 PASS; 저장·알림·조회 API는 HOLD |
| P9-06 실행 근거 | `edge/detection/ai_run_evidence.py`, `detector_contract.py`, MQTT/Packet IF Stage, 관련 테스트 | 기기·Window별 입력/실제 추론/정상/이상/제외, Packet 실제 모델·Bundle, AI revision을 결과에 담는다. `completion_sink`는 Stage와 같은 DB 세션/트랜잭션에서 호출하고 실패 시 Checkpoint와 함께 rollback한다. 무입력은 기기별 정상으로 만들지 않는다. 로컬 PASS; 종민 저장·우민 API는 HOLD |

Broker 저장 접점 **제안**: nullable `packet_feature_logs.broker_target_syn_count`는 검증된 IPv4 Broker 주소·목적지 TCP 포트의 SYN=1/ACK=0 **패킷 횟수/10초 Window**이다. 재전송 중복 제거를 하지 않는 이름이다. 다른 포트 SYN, 일반 MQTT packet count, 9001·IPv6는 임의 포함하지 않는다. 종민이 Feature·Migration·NULL 이관·컬럼명을 확정하고 우민이 보호 Broker 주소/포트 설정을 확인해야 한다. 현재 Detector는 컬럼이 없으면 NULL로 투영하므로 새 스키마가 적용되기 전 Broker 판단은 근거 부족이다. Packet IF의 기존 6개 입력은 변경하지 않았다. 기존 Event·Trust 이력은 소급 변경하지 않는다.

AI 저장 접점 **제안**: `device_ai_policy_revisions`의 device_id·양의 revision·OFF/OBSERVE mode·UTC 10초 effective_from을 단일 일관성 snapshot으로 공급해야 한다. Stage 활성화 감사에는 Stage·모델 hash/version·원래 Checkpoint·승인 경계 B·과거 제외 범위/건수·승인자가 필요하다. 제외 감사와 해당 Stage CP 시작 경계는 한 트랜잭션에서 확정하고 적용 전 중단·중복 적용·커밋 후 응답 유실을 구분해야 한다. 현재 선택기는 주입 접점이며 이 승인 저장/원자적 적용 경로를 임의로 대체하지 않는다. 기기별 모드를 실제 운영에 켜기 전 `TRUST_AI_MODE=observe`, MQTT Bundle 검증, required/optional Stage 계약이 필요하다.

경고 집계 저장은 원본 이벤트를 변경하지 않고 집계 키·처리한 ID/Window·최근 경계·마지막 알림·억제 수를 원자적으로 보존해야 한다. `WarningLedger`는 저장 소유자가 트랜잭션에서 읽고 저장할 판정 상태다. 알림은 DB commit 뒤에만 발행해야 한다. W/N/C의 운영값은 승인 자료로 아직 확정되지 않았으므로 테스트 값 60초/3회/120초를 운영값으로 사용하지 않는다.

P9-06 저장/조회는 `AICompletionRecord`를 Stage Event·Checkpoint와 같은 트랜잭션으로 확정하고, API는 Boot·observed_at·만료와 대조해야 한다. MQTT legacy loader는 실제 모델 버전/hash를 보증하지 않으므로 해당 필드를 NULL로 내보낸다. Packet은 검증된 Artifact의 model version/hash를 기록한다. 이벤트 없음·다른 기기의 전진·DB health를 정상 추론으로 변환하지 않는다.

## 미완료 접점 — Phase 10 인계

- **P9-02/V09:** 우민의 새 MQTT Bundle metadata/외부 hash·Feature 순서·낮을수록 이상인 점수·Validation Threshold·비교 연산 계약이 미확정이다. 현재 `ai_detector.py`는 legacy joblib `predict()`를 사용한다. 새 Bundle 로더/오프라인·Runtime 동일 판정과 1건 Window 5.0 대체 표시를 연결한 뒤 활성화한다. #110의 모델 정보 API는 MQTT를 `LEGACY_CONTRACT_UNAVAILABLE`로 명시한다.
- **P9-03/V14~V15:** 종민 AI revision·활성화 감사 Migration, 원자적 CP 적용, 과거 공백 제외 저장이 없다. 이 브랜치의 순수 결정/Stage 주입만으로 운영 전환을 승인할 수 없다. 우민 API와 실제 Stage Registry 연결, 모델 장애·required/optional 실패 및 커밋 후 응답 유실 회귀가 필요하다.
- **P9-03/V17:** 종민 경고 저장/Migration과 우민 `GET /api/ai-warnings`, commit 후 알림 경로가 없다. 로컬 집계 판정을 운영 경고 완료로 표시하지 않는다.
- **P9-04:** 기존 Packet Loader의 외부 Bundle SHA·Feature 6개·높을수록 이상인 점수와 `>` Threshold 검증은 기존 코드에 있다. 세 기기 안정/재접속/희소 Packet 자료의 비교·채택은 우민·종민 후속이다.
- **P9-05/V22:** 복구 후 서비스 active만으로 완료 판정하지 않는다. #108의 관리자 명령을 통합할 때 동일 Boot/대상에서 필수 처리 경계가 두 차례 실제 전진했는지, 입력/FAILED/품질/신선도를 함께 확인한다. 이 PR의 운영 복구 실행은 미검증이다.
- **P9-06/V23:** `completion_sink`의 실제 저장 테이블·Migration과 `/api/runtime-status`가 없다. Stage 비활성, 모델 초기화 실패, 무입력, 지연, 관측 만료를 API와 Pi에서 구별하는 시험은 남아 있다.
- **P9-08/V27~V28:** 종민 Feature·Migration/API, 우민 Broker 대상 설정, 선우 공격 회귀 검토와 승인된 Pi 시험이 필요하다. `broker_target_syn_count` 이름/정의가 달라지면 Detector projection을 확정 계약에 맞춰 수정한다.
- **P9-09/V39·V41:** #111의 새 `PI_INPUT_IPV4_ALL`은 관리자 확장 범위다. Trust의 기본 자동 격리 `MQTT_IPV4_TCP_1883`을 바꾸지 않았다. 두 범위 중 하나라도 남거나 해제 대기라면 기기 전체 해제·점수 복구 완료로 표시하지 않는 실제 Worker/API 대조는 우민·종민 통합 뒤 검증한다.
- **P9-10:** 운영 Pi/DB 사본·실제 모델/Stage·Broker 공격·방화벽·재부팅·화면 연결·부하 회귀와 후보 동결은 미검증이다. 정상 수집과 정책 변경·공격·복구 시험을 겹치지 않는다. 한국어 UI 문구 통일은 Phase 10 소유 담당이다.

## 실행한 로컬 검증

| 계획 검증 | 이번 브랜치 결과 | 남은 선행 작업 |
| --- | --- | --- |
| V06 | 로컬 통과: 114/115/116 ÷ 9.2와 상한 12.5의 엄격한 `>` 경계, 기존 Packet·MQTT Rule 회귀 | 당시 운영 revision과 Pi replay |
| V07 | 부분 통과: 기존 Rule·Trust 회귀와 정상 자료 검토 | P0/P1/P2 공식 후보 replay·공격 민감도 평가 |
| V09 | 부분 통과: Packet 기존 Bundle/6개 입력 회귀; MQTT 1건의 5.0 대체는 기존 Feature 코드 확인 | MQTT Bundle hash·Feature 순서·점수 방향·Threshold 계약 및 QC 대조 |
| V13 | 로컬 통과: OFF→OBSERVE→OFF 원본 10초 Window, OFF의 AI 추론/이벤트 제외·Stage CP 전진 | 저장 revision/운영 Stage 연결 |
| V14 | 부분 통과: 미이관·DISABLED·손상 revision 구별 | 모델 누락/hash 오류와 required/optional Stage 통합 |
| V15 | 미검증: 활성화 감사·시작 CP의 원자 저장 계약 부재 | 종민 Migration/승인 적용 경로 |
| V16 | 로컬 통과: 기존 OBSERVE AI 무감점·무격리 및 Rule 동시 대표 감점 회귀 | 기기별 AI revision을 실제 Trust 경로에 연결 |
| V17 | 로컬 판정 통과: N회·중복·쿨다운·지연·재시작 상태·OFF·품질 제외 | 집계 저장/조회/알림의 원자성·운영 W/N/C |
| V22 | 미검증: 같은 Boot/대상 두 차례 전진의 실제 복구 경로 | 우민 #108 통합·Pi 재부팅 시험 |
| V23 | 로컬 부분 통과: 0이벤트 정상 추론·OFF/품질 제외·무입력 근거와 CP 트랜잭션 rollback | 저장 Migration·API·Stage 장애/관측 만료 대조 |
| V27 | 로컬 통과: 다른 포트 스캔+MQTT와 Broker SYN 집중 반례 | 종민 Feature 실제 생성·승인 Broker 설정·Pi 공격 시험 |
| V28 | 로컬 부분 통과: NULL Broker 지표 근거 부족, Packet IF 6개 입력 불변 | 9001/IPv6/미설정 대상의 실제 Feature·운영 판정 |
| V39·V41 | 기존 자동 차단 범위 및 AI OBSERVE 무차단 회귀 확인 | #111 범위 동시 존재·부분 해제·Worker/API/Pi 상태 대조 |

여기의 “로컬 통과”는 SQLite fixture·합성 입력의 결과이며 실장비 결과가 아니다. `edge/features/collect_feature_logs.py`는 MQTT 1건 Window의 두 간격 Feature를 5.0초로 채운다. 이는 실측이 아니라 대체값이며, 운영 Feature 행에는 아직 별도의 출처 필드가 없다. 새 MQTT Bundle을 연결할 때 출처 표시 계약을 추가해야 한다.

```powershell
$env:PATH = 'C:\Users\Hyunsoo\AppData\Local\Programs\Git\bin;' + $env:PATH
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_packet_rule_detector.py tests/test_packet_rule_policy_v4.py tests/test_packet_rule_runner.py tests/test_phase8_trust_gates.py tests/test_phase4_trust_firewall.py tests/test_ai_observation.py tests/test_packet_ai_detector.py tests/test_run_packet_ai_detector.py tests/test_detection_orchestrator_runner.py tests/test_rule_detector.py tests/test_rule_runner.py tests/test_ai_detector.py tests/test_ai_runner.py tests/test_phase9_ai_window_decision.py tests/test_phase9_ai_warning_aggregation.py tests/test_phase9_ai_run_evidence.py tests/test_phase9_packet_rate_boundaries.py
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_broker_dos_attack.py tests/test_firewall_rule_wrapper.py
.venv\Scripts\python.exe -m pytest -q --tb=short tests backend/tests
```

관련 Rule·Trust·AI·Orchestrator 회귀 **390 passed**, Git Bash Wrapper 단독 **27 passed**. 첫 전체 재실행은 잘못된 `C:\Program Files\Git\bin` 경로 때문에 Windows WSL `bash.exe`가 선택되어 Wrapper 테스트 실패가 발생했고, 45%에서 중단했다. 실제 설치 경로를 사용한 최종 전체 재실행은 **3334 passed, 24 skipped, 3 warnings, 0 failed** (740.53초)였다. 3개 경고는 Starlette/anyio 1건과 Paho MQTT Callback API 2건의 deprecation 경고다. 전체 실행 도중 추가한 Packet IF OFF→OBSERVE Window 시험은 별도 실행에서 **1 passed, 14 deselected**였고, 경고 버전 분리 시험을 포함한 집계 시험은 **5 passed**였다. skipped는 PASS에 포함하지 않는다.
