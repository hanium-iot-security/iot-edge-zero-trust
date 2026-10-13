# Phase 9 현수 구현·검증 기록

## 2026/10/13 후속 통합

아래의 미연결/HOLD 기록은 각 검증 당시의 기준이다. 후속 #127에서 기존 #118 판정·Stage를
사용해 Migration 012의 실제 기기별 revision snapshot, Migration 015의 승인 시작 경계,
기존 Orchestrator 실행 경로를 연결한다. 완료·경고 저장과 runtime-status는 Migration 014을
사용한다. 현재 연결·관리 명령·제한은 [기기별 추론 연결 절차](phase9-ai-policy-runtime.md)와
PR의 최종 로컬 시험 결과를 기준으로 확인한다. 실제 Pi 활성화·공식 모델 평가·화면 연결은
별도 검증이며 P9-03/P9-06 전체 운영 완료를 뜻하지 않는다.

## 기준선과 범위

- 작업 전 로컬 `feature/hyunsu-phase8-policy-trust`는 깨끗했고 HEAD는 `8189cd3`였다. 원격 `develop`은 계획 기준 `53ec270`이며 Phase 8 PR #88 head `4ace33c`가 포함된다. 기존 브랜치를 유지하고 `codex/phase9-hyunsoo`를 `origin/develop`에서 생성했다. 이 작업에서 merge, 운영 DB 변경, Pi 배포·재시작은 하지 않았다.
- PR #107(정상 운용 v1), #108(복구), #109(수집 전 점검), #110(모델 정보 API), #111(Pi IPv4 격리)은 2026-10-10 조회 시 open이다. #110은 MQTT를 `LEGACY_CONTRACT_UNAVAILABLE`로 표시하며 새 MQTT Bundle과 실행 근거를 제외 범위에 둔다. AI 정책·경고·Stage 활성화 Migration과 Broker 전용 Feature Migration은 develop 및 공개 PR에서 확인되지 않았다.
- 이 문서의 로컬 PASS는 임시 SQLite/합성 입력이다. 운영 Pi, 운영 DB 사본, 실제 방화벽·공격 결과가 아니다.

## 2026-10-12 원격 develop 재확인

- 원격 `develop`은 `5a0325f`로 전진했다. PR #107~#114 중 #107, #108, #109, #110, #111, #112(MQTT IF offline Bundle), #113, #114(기기별 AI 정책 저장)가 merge commit으로 포함됐다. 위 2026-10-10 상태는 당시 조회 기록이다. 이 작업 브랜치에는 develop을 병합하거나 재배치하지 않았다.
- PR #112의 `ai/mqtt_if_artifact.py`와 `docs/phase9-mqtt-if-offline-bundle.md`는 **offline** Bundle 검사 계약을 제공한다. 현재 이 브랜치의 MQTT Stage는 여전히 legacy loader를 사용한다. 모델 해시·Feature 순서·점수 방향·Threshold·비교 연산을 운영 Runtime까지 연결하고 새 develop 위에서 다시 검증해야 한다.
- PR #114의 Migration 012와 `edge/policy/device_ai_policy_resolver.py`는 `device_ai_policy_revisions` 저장·조회 계약을 제공한다. 이 브랜치의 `ai_window_selector`는 아직 해당 resolver 또는 운영 Stage Registry에 연결되지 않았다. 활성화 감사·경고·완료 기록의 영속 저장 계약도 이 merge 결과에서 확인되지 않았다. 따라서 아래의 관련 HOLD는 "저장 revision 부재"가 아니라 "확정된 저장 revision과 실행 경로의 미연결"로 읽어야 한다.
- Broker 목적지 전용 Feature/Migration은 이 `develop`에서 확인되지 않았다. 기존 로컬 시험은 이전 기준 `53ec270` 위에서 실행했다. 최신 develop과의 통합 diff·회귀 및 Pi 결과는 미검증이며 병합 전에 별도로 확인해야 한다.

## 2026-10-13 #118 재검토·MQTT Bundle 연결

- PR 기존 head `20338fa`에 원격 `develop`의 `f752230`을 충돌 없이 병합했다(`da54a48`). 위 10/10·10/12 절과 문서 하단 전체 회귀 수치는 당시 기록이며 이번 통합 결과와 구별한다.
- #112의 검사 snapshot·scorer를 MQTT Stage Registry에 연결했다. 세 Bundle 설정은 함께 지정해야 하며 외부 pin·모델 Version·`TRUST_AI_MODE=observe` 검사가 선행한다. 모두 빈 기본값은 legacy 경로를 유지한다. 자세한 설정과 범위는 `docs/phase9-mqtt-if-offline-bundle.md`의 #118 절을 따른다.
- 이벤트와 완료 수집기에 실제 모델 Version·Bundle SHA를 연결하고, 이벤트에는 원점수·엄격한 `<` Threshold·5개 Feature·단일 메시지 간격 대체 여부를 기록한다. `/api/models`는 MQTT Bundle도 파일당 64 MiB 이내에서 역직렬화 없이 검사하고 `runtime=UNKNOWN`을 유지한다.
- 손상된 AI 모드/revision의 일부만 남은 근거가 legacy 강제 감점으로 넘어가는 오류를 수정했다. MQTT 최상위·Packet 중첩 근거가 충돌해도 자동 감점 대상에서 제외한다. 필드가 없거나 두 필드가 모두 NULL인 기존 이벤트의 동작은 유지한다.
- AI revision의 시각이 NULL·문자열·naive datetime 등으로 손상되면 예외로 중단하던 경로를 `INVALID_AI_REVISION` 제외 판정으로 바꿨다.
- 모든 기기가 OFF인 legacy Stage도 잘못된 객체·미학습 모델을 정상으로 취급하지 않도록 모델 타입·학습 상태·입력 차원·점수를 확인한다. 실패 시 Checkpoint를 전진시키지 않는다.
- 실제 `.env`, 운영 DB·모델, Pi 서비스를 변경하지 않았다. 공식 자료 학습·모델 활성화는 수행하지 않았다. 기기별 selector 주입, 활성화 감사·시작 경계, 경고·완료 기록 저장은 여전히 후속 통합이다.

### 이번 통합 검증

Windows Python 3.10.11, numpy 2.0.2, scipy 1.15.3, scikit-learn 1.6.1,
joblib 1.4.2의 기존 가상환경에서 임시 SQLite·합성 Bundle로 실행했다.

```powershell
python -m pytest -q --tb=short tests/test_ai_detector.py tests/test_ai_runner.py tests/test_phase8_trust_gates.py tests/test_detection_orchestrator_runner.py tests/test_packet_ai_detector.py tests/test_run_packet_ai_detector.py tests/test_packet_rule_detector.py tests/test_packet_rule_policy_v4.py tests/test_packet_rule_runner.py tests/test_rule_detector.py tests/test_rule_runner.py tests/test_broker_dos_attack.py tests/test_phase9_ai_window_decision.py tests/test_phase9_ai_warning_aggregation.py tests/test_phase9_ai_run_evidence.py tests/test_phase9_packet_rate_boundaries.py tests/test_ai_observation.py tests/test_phase4_trust_firewall.py
python -m pytest -q --tb=short tests/test_mqtt_if_runtime.py tests/test_model_info_api.py tests/test_mqtt_if_artifact.py tests/test_mqtt_feature_pipeline.py tests/test_predict_packet_isolation_forest.py
```

- 첫 명령: **450 passed**, 55.72초. Rule·Trust·AI·Orchestrator와 세 결함의 회귀를 포함한다.
- 둘째 명령: **212 passed, 2 skipped**, 36.88초. Windows symlink 생성 권한이 없는 두 fixture만 건너뛰었다. 신규 MQTT Runtime 20개, 실제 SQLite 이벤트·완료근거·중복방지·OFF 추론 제외·정상 무이벤트 완료와 추론/저장 실패 rollback을 포함한다.
- 합계 **662 passed, 2 skipped, 0 failed**. `git diff --check`도 통과했다. 이번 수정 후 전체 `tests backend/tests` 재실행과 Pi 시험은 하지 않았다. 아래 3,352개 전체 통과는 이전 기준선 결과다.

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
| P9-03 AI 결정 | `edge/policy/ai_window_decision.py`, MQTT/Packet IF Stage, 관련 테스트 | 원본 UTC Window의 등록·AI revision과 승인 Stage 시작 경계로 추론 가능 여부를 선택한다. OFF/OBSERVE만 허용하고 ENFORCE·손상·미이관·DISABLED를 구별한다. Stage는 선택기를 주입받으면 OFF 추론을 건너뛰고 Checkpoint는 전진한다. 순수 함수·주입 시험 PASS; 운영 Stage Registry·저장 조회·승인 활성화 연결은 HOLD |
| P9-03 반복 경고 | `edge/detection/ai_warning_aggregation.py`, `tests/test_phase9_ai_warning_aggregation.py` | 기기·탐지기·유형·모델·경고 버전, 원본 Window별 W/N/C 집계. 같은 ID/Window 중복 계수 금지, 지연 닫힌 구간 연결, 재시작 상태 재사용, OFF·품질 제외 구분. 순수 판정 PASS; 저장·알림·조회 API는 HOLD |
| P9-06 실행 근거 | `edge/detection/ai_run_evidence.py`, `detector_contract.py`, MQTT/Packet IF Stage, 관련 테스트 | 기기·원본 Window별 입력/실제 추론/정상/이상/제외와 AI revision·모드를 결과에 담는다. 실제 추론한 Packet Window에는 모델·Bundle을 기록하고 OFF 제외에는 모델 추론 근거를 만들지 않는다. MQTT legacy 모델 식별자는 미확인으로 둔다. `completion_sink`는 Stage와 같은 DB 세션/트랜잭션에서 호출하고 실패 시 Checkpoint와 함께 rollback한다. 무입력은 기기별 정상으로 만들지 않는다. 수집기·주입 시험 PASS; 종민 저장·우민 API와 운영 Stage Registry 연결은 HOLD |

Broker 저장 접점 **제안**: nullable `packet_feature_logs.broker_target_syn_count`는 검증된 IPv4 Broker 주소·목적지 TCP 포트의 SYN=1/ACK=0 **패킷 횟수/10초 Window**이다. 재전송 중복 제거를 하지 않는 이름이다. 다른 포트 SYN, 일반 MQTT packet count, 9001·IPv6는 임의 포함하지 않는다. 종민이 Feature·Migration·NULL 이관·컬럼명을 확정하고 우민이 보호 Broker 주소/포트 설정을 확인해야 한다. 현재 Detector는 컬럼이 없으면 NULL로 투영하므로 새 스키마가 적용되기 전 Broker 판단은 근거 부족이다. Packet IF의 기존 6개 입력은 변경하지 않았다. 기존 Event·Trust 이력은 소급 변경하지 않는다.

배포 전에는 운영 `PACKET_RULE_POLICY_VERSION` override를 확인해야 한다. 코드 기본 버전은 v4지만 운영 override가 v3이면 새 Broker 판정을 옛 버전으로 잘못 표기할 수 있다. 운영 임계값은 임의로 바꾸지 않고, 실제 Feature 계약·설정·판정 버전을 함께 승인한다.

AI 저장 접점 **제안**: `device_ai_policy_revisions`의 device_id·양의 revision·OFF/OBSERVE mode·UTC 10초 effective_from을 단일 일관성 snapshot으로 공급해야 한다. Stage 활성화 감사에는 Stage·모델 hash/version·원래 Checkpoint·승인 경계 B·과거 제외 범위/건수·승인자가 필요하다. 제외 감사와 해당 Stage CP 시작 경계는 한 트랜잭션에서 확정하고 적용 전 중단·중복 적용·커밋 후 응답 유실을 구분해야 한다. 현재 선택기는 주입 접점이며 이 승인 저장/원자적 적용 경로를 임의로 대체하지 않는다. 선택기를 주입받은 두 IF Stage는 `TRUST_AI_MODE=observe`가 아니면 생성을 거부한다. 운영 활성화에는 이 설정뿐 아니라 MQTT Bundle 검증, required/optional Stage 계약이 필요하다. Trust에는 명시된 기기 OBSERVE/OFF 근거의 무감점 방어를 추가했지만 이것이 승인 감사·원자 적용을 대신하지 않는다.

경고 집계 저장은 원본 이벤트를 변경하지 않고 집계 키·처리한 ID/Window·최근 경계·마지막 알림·억제 수를 원자적으로 보존해야 한다. `WarningLedger`는 저장 소유자가 트랜잭션에서 읽고 저장할 판정 상태다. 알림은 DB commit 뒤에만 발행해야 한다. W/N/C의 운영값은 승인 자료로 아직 확정되지 않았으므로 테스트 값 60초/3회/120초를 운영값으로 사용하지 않는다.

P9-06 저장/조회는 `AICompletionRecord`를 Stage Event·Checkpoint와 같은 트랜잭션으로 확정하고, API는 Boot·observed_at·만료와 대조해야 한다. MQTT legacy loader는 실제 모델 버전/hash를 보증하지 않으므로 해당 필드를 NULL로 내보낸다. MQTT Bundle과 Packet은 검증된 Artifact의 model version/hash를 기록한다. 이벤트 없음·다른 기기의 전진·DB health를 정상 추론으로 변환하지 않는다.

## 미완료 접점 — Phase 10 인계

- **P9-02/V09:** MQTT Bundle 로더·scorer·모델 정보 API와 1건 Window 5.0 대체 표시의 로컬 연결은 완료했다. 공식 자료 QC·학습·Threshold 평가, P9-03 시작 경계와 실제 Pi 활성화는 미완료다. Bundle 설정이 없는 경우에만 API는 `LEGACY_CONTRACT_UNAVAILABLE`을 반환한다.
- **P9-03/V14~V15:** AI revision 저장은 Migration 012에 있다. 운영 Stage의 일관된 revision 조회·selector 주입, 활성화 감사·원자적 CP 적용·과거 공백 제외 저장은 아직 연결하지 않았다. 순수 결정/Stage 주입만으로 운영 전환을 승인할 수 없으며 required/optional 실패와 커밋 후 응답 유실의 실제 승인 경로 회귀가 필요하다.
- **P9-03/V17:** 종민 경고 저장/Migration과 우민 `GET /api/ai-warnings`, commit 후 알림 경로가 없다. 로컬 집계 판정을 운영 경고 완료로 표시하지 않는다.
- **P9-04:** 기존 Packet Loader의 외부 Bundle SHA·Feature 6개·높을수록 이상인 점수와 `>` Threshold 검증은 기존 코드에 있다. 세 기기 안정/재접속/희소 Packet 자료의 비교·채택은 우민·종민 후속이다.
- **P9-05/V22:** 복구 후 서비스 active만으로 완료 판정하지 않는다. #108의 관리자 명령을 통합할 때 동일 Boot/대상에서 필수 처리 경계가 두 차례 실제 전진했는지, 입력/FAILED/품질/신선도를 함께 확인한다. 이 PR의 운영 복구 실행은 미검증이다.
- **P9-06/V23:** `completion_sink`의 실제 저장 테이블·Migration과 `/api/runtime-status`가 없다. Stage 비활성, 모델 초기화 실패, 무입력, 지연, 관측 만료를 API와 Pi에서 구별하는 시험은 남아 있다.
- **P9-08/V27~V28:** 종민 Feature·Migration/API, 우민 Broker 대상 설정, 선우 공격 회귀 검토와 승인된 Pi 시험이 필요하다. `broker_target_syn_count` 이름/정의가 달라지면 Detector projection을 확정 계약에 맞춰 수정한다.
- **P9-09/V39·V41:** #111의 새 `PI_INPUT_IPV4_ALL`은 관리자 확장 범위다. 현 코드의 자동 격리는 TCP 목적지 1883 규격(계획상의 `MQTT_IPV4_TCP_1883`)이며 이를 바꾸지 않았다. 두 범위 중 하나라도 남거나 해제 대기라면 기기 전체 해제·점수 복구 완료로 표시하지 않는 실제 Worker/API 대조는 우민·종민 통합 뒤 검증한다.
- **P9-10:** 운영 Pi/DB 사본·실제 모델/Stage·Broker 공격·방화벽·재부팅·화면 연결·부하 회귀와 후보 동결은 미검증이다. 정상 수집과 정책 변경·공격·복구 시험을 겹치지 않는다. 한국어 UI 문구 통일은 Phase 10 소유 담당이다.

## 실행한 로컬 검증

| 계획 검증 | 이번 브랜치 결과 | 남은 선행 작업 |
| --- | --- | --- |
| V06 | 부분 통과: 114/115/116 ÷ 9.2와 상한 12.5의 엄격한 `>` 경계, 기존 Packet·MQTT Rule 회귀 | 네 임계값의 기기별 개발 자료 replay·당시 운영 revision/Pi 대조 |
| V07 | 부분 통과: 기존 Rule·Trust 회귀와 정상 자료 검토 | P0/P1/P2 공식 후보 replay·공격 민감도 평가 |
| V09 | 로컬 부분 통과: MQTT Bundle 외부 pin·5개 입력·낮을수록 이상·엄격한 `<`·대체 간격·모델 교체 snapshot, Packet 기존 Bundle/6개 입력 회귀 | 공식 자료 QC·학습·Threshold 평가·Pi 적용 |
| V13 | 순수/주입 시험 통과: OFF→OBSERVE→OFF 원본 10초 Window, OFF의 AI 추론/이벤트 제외·Stage CP 전진 | 저장 revision/운영 Stage 연결 |
| V14 | 부분 통과: 미이관·DISABLED·손상 revision 구별. 전부 OFF인 legacy Stage의 누락·잘못된 타입·미학습 모델 거부, 새 Bundle hash·Version 오류 시 초기화 실패 | 활성화 승인 경로의 required/optional Stage 통합 |
| V15 | 미검증: 활성화 감사·시작 CP의 원자 저장 계약 부재 | 종민 Migration/승인 적용 경로 |
| V16 | 로컬 통과: 기기 OBSERVE evidence가 전역 enforce여도 AI 무감점·무격리, 같은 Window Rule 감점 유지 | 기기별 revision의 실제 저장·Stage 활성화 연결 |
| V17 | 로컬 판정 통과: N회·중복·쿨다운·지연·재시작 상태·OFF·품질 제외 | 집계 저장/조회/알림의 원자성·운영 W/N/C |
| V22 | 미검증: 같은 Boot/대상 두 차례 전진의 실제 복구 경로 | 우민 #108 통합·Pi 재부팅 시험 |
| V23 | 로컬 부분 통과: 0이벤트 정상 추론·OFF/품질 제외·무입력 근거와 CP 트랜잭션 rollback. 기기별 완료 시각은 Cycle cutoff가 아닌 원본 Window 끝 | 저장 Migration·API·Stage 장애/관측 만료 대조 |
| V27 | 로컬 통과: 다른 포트 스캔+MQTT와 Broker SYN 집중 반례 | 종민 Feature 실제 생성·승인 Broker 설정·Pi 공격 시험 |
| V28 | 로컬 부분 통과: NULL Broker 지표 근거 부족, Packet IF 6개 입력 불변 | 9001/IPv6/미설정 대상의 실제 Feature·운영 판정 |
| V39·V41 | 기존 자동 차단 범위 및 AI OBSERVE 무차단 회귀 확인 | #111 범위 동시 존재·부분 해제·Worker/API/Pi 상태 대조 |

여기의 “로컬 통과”는 SQLite fixture·합성 입력의 결과이며 실장비 결과가 아니다. `edge/features/collect_feature_logs.py`는 MQTT 1건 Window의 두 간격 Feature를 5.0초로 채운다. 이는 실측이 아니라 대체값이며, 운영 Feature 행에는 아직 별도의 출처 필드가 없다. 새 MQTT Bundle 결과·이벤트는 기존 Feature 의미에 따라 `interval_is_fallback`을 표시한다.

## 재검토에서 수정한 판정 근거

- 한 Cycle이 여러 Window를 처리할 때 모든 기기 완료 기록에 Cycle cutoff를 쓰면 앞선 기기가 나중 Window까지 처리된 것처럼 보였다. 기기별 `completed_window_end`를 원본 `window_start + 10초`로 바꾸고 무입력 Stage 표지만 cutoff를 사용한다.
- 미래의 손상된 AI revision을 검증하다 과거의 정상 OFF Window까지 무효화했다. 원본 Window까지 효력이 있는 revision 접두부만 검증한다. 미래 손상은 그 효력 시점부터 제외한다.
- Packet IF의 Capture 품질 제외와 MQTT IF의 유지보수 제외가 DISABLED·정책 오류를 가렸다. 주입된 AI 결정을 먼저 평가하고 제외 사유·revision·모드를 기록한다. Capture 품질 검사는 추론 가능 Window에 그대로 적용한다.
- MQTT legacy 이벤트가 탐지 정책 버전 `mqtt-if-v1`을 실제 모델 버전처럼 표시했다. 모델 버전은 미확인으로 두고 탐지 정책 버전을 별도 필드로 남긴다.
- 전역 Trust 기본값 `enforce`에서 기기 OBSERVE AI 이벤트가 단독 감점될 수 있었다. 명시된 기기 OBSERVE 근거는 AI 감점·격리 0으로 처리하고 Rule 대표 감점은 유지한다. OFF·손상된 기기 AI 근거도 새 자동 대응에서 제외한다. 모드·revision이 없는 기존 AI 이벤트는 기존 전역 Trust 정책을 따른다.
- 선택기를 주입한 Stage가 전역 enforce 설정으로 생성될 수 있었다. MQTT/Packet IF 생성 시 `TRUST_AI_MODE=observe`를 요구하고, Packet `from_settings`는 모델을 읽기 전에 설정을 검사한다. 저장/API 승인 경로와 운영 Registry 연결은 아직 없다.
- MQTT IF의 모든 기기가 OFF이면 추론 경로가 없어 모델 파일 누락을 발견하지 못한 채 Checkpoint가 전진했다. 선택기가 활성화된 Stage는 OFF 여부와 무관하게 기존 loader로 모델을 먼저 확인한다. 이는 legacy 파일의 로드 검증이며 새 Bundle hash 검증을 의미하지 않는다.

운영 경로 확인: `stage_registry.py`와 독립 runner는 현재 `ai_window_selector`·`completion_sink`를 주입하지 않는다. 따라서 위 로컬 주입 시험은 실제 기기별 AI 활성화나 실행 기록의 영속화를 증명하지 않는다. 확정된 AI revision 저장과 이번 MQTT Bundle 로더에 더해 활성화 감사·경고·완료 저장 계약을 연결·검증해야 한다. 이 전에는 P9-03·P9-06을 운영 완료로 표시하지 않는다.

### 기존 기준선의 실행 명령·결과

```powershell
$env:PATH = 'C:\Users\Hyunsoo\AppData\Local\Programs\Git\bin;' + $env:PATH
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_packet_rule_detector.py tests/test_packet_rule_policy_v4.py tests/test_packet_rule_runner.py tests/test_phase8_trust_gates.py tests/test_phase4_trust_firewall.py tests/test_ai_observation.py tests/test_packet_ai_detector.py tests/test_run_packet_ai_detector.py tests/test_detection_orchestrator_runner.py tests/test_rule_detector.py tests/test_rule_runner.py tests/test_ai_detector.py tests/test_ai_runner.py tests/test_phase9_ai_window_decision.py tests/test_phase9_ai_warning_aggregation.py tests/test_phase9_ai_run_evidence.py tests/test_phase9_packet_rate_boundaries.py
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_broker_dos_attack.py tests/test_firewall_rule_wrapper.py
.venv\Scripts\python.exe -m pytest -q --tb=short tests backend/tests
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_packet_ai_detector.py tests/test_phase9_ai_warning_aggregation.py
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_phase8_trust_gates.py tests/test_phase9_ai_window_decision.py tests/test_packet_ai_detector.py tests/test_phase9_ai_run_evidence.py tests/test_ai_observation.py
```

초기 구현 시 관련 Rule·Trust·AI·Orchestrator 회귀 **390 passed**, Git Bash Wrapper 단독 **27 passed**, 전체 **3334 passed / 24 skipped / 3 warnings**였다. 첫 전체 시도의 Git Bash 경로 오류와 재검토 중 추가 결함을 발견해 중단한 두 전체 시도는 PASS로 계산하지 않는다.

재검토 수정 후 위 마지막 집중 명령은 **113 passed**이고, 올바른 Git Bash 경로에서 실행한 최종 전체 명령은 **3352 passed, 24 skipped, 3 warnings, 0 failed** (784.51초)였다. 경고 3개는 Starlette/anyio 1건과 Paho MQTT Callback API 2건의 deprecation 경고다. skipped는 PASS에 포함하지 않는다. 이 결과는 로컬 fixture와 Windows 실행 환경의 회귀이며 Pi 실기기 완료가 아니다.
