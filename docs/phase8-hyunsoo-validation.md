# Phase 8 현수 로컬 검증 기록

기준 브랜치 `codex/phase8-hyunsoo`, 최초 기준 커밋 `559fa41fcd5cdf4deb74219a902ca91a9ec8095b`. 작업 시작 전 `review-pr24`는 깨끗한 상태였다. 로컬에 원격 설정은 없었고, 기존 reflog의 GitHub URL에서 develop을 직접 fetch해 기준 커밋을 확보했다. 최초 fetch 후 `origin/develop`은 `c8ea2bc`였으며, 작업 브랜치는 요청한 `559fa41`에서 생성했다. Git이 표시한 `559fa41` 작성 시각은 2026-08-28 20:01:38 +09:00로, 요청문에 적힌 2026-09-30과 다르다.

2026-10-02 최초 로컬 통합: develop `aa3660f`와 #84(계약), #86(MQTT 원본 유효성), #87(Migration 007·정책 저장소)를 로컬 브랜치에 병합했다. 이때 원격 PR 승인·병합, push, 운영 DB 변경은 하지 않았다. 병합 전 현수 작업은 `.worktrees/phase8-preserve-20261002` 사본과 `phase8-hyunsoo-before-pr-integration-2026-10-02` stash로 보존했다. Subscriber와 Feature 수집기의 충돌은 두 변경을 함께 반영해 해결했다. 이후 현수 변경은 `6f9a17d`로 커밋·push했다.

| 작업 ID | 수정 파일 | 재현 결함·해결 | 로컬 판정 |
| --- | --- | --- | --- |
| P8-S01 / V16 | `edge/trust/trust_score_service.py`, `run_trust_score_update.py`, `edge/detection/legacy_guard.py`, 구형 Rule/AI runner, README·시연·운영 문서, `tests/test_phase4_trust_firewall.py` | v2가 Packet Rate·Byte Rate·AI를 같은 FLOODING Window에서 대표 −20으로 처리해 80→60을 만든 후 MVP writer가 재감점할 수 있었다. Phase 4/v2 schema 자체를 쓰기 전 검사해 거부하며 신규 정책 테이블 존재를 조건으로 사용하지 않는다. v2 재실행 시 점수·상태·Event·History·Firewall·checkpoint snapshot 불변을 검증했다. | **로컬 PASS** |
| P8-02 / V07 | `edge/policy/resolver.py`, `repository.py`, `docs/phase8-hyunsoo-contract.md`, `tests/test_phase8_policy_resolver.py` | 현재 등록/정책 조회는 지연 Raw에 새 등록·정책을 소급할 수 있었다. 원본 UTC Window의 등록·기기 정책 revision을 배치 snapshot에서 선택하고 현재/예정을 구분한다. 누락·중복·역순·무효 revision은 명시적 이유로 무효 처리한다. Topic/Payload와 IP의 역사적 귀속을 검증했다. Migration 007 실제 테이블 projection을 연결했다. | **Migration 007 임시 DB PASS; API·운영 DB 연결 HOLD** |
| P8-05 / V05–V06, V11–V12 | `edge/detection/rule_detector.py`, `mqtt_adapters.py`, `packet_rule_detector.py`, `edge/features/packet_feature_repository.py`, `tests/test_packet_rule_detector.py`, `tests/test_phase8_trust_gates.py` | 네 상한이 기기별 revision을 사용하지 않았다. Publish Count·Payload·Packet Rate·Byte Rate만 기기별 상한으로 평가하고 `>` 경계, 실제 Capture duration, 동일 정책 객체의 evidence를 검증했다. Packet 관리 IP·Capture 품질·Port Scan·Broker DoS 등 기존 조건과 detector `policy_version`/dedupe key를 유지했다. 예정 정책 재조회와 동일 Window 재실행에서 Event가 늘지 않았다. | **로컬 fixture PASS; 운영 값 이관 HOLD** |
| P8-06 / V08–V10 | `edge/mqtt/subscriber.py`, `edge/features/collect_feature_logs.py`, `edge/detection/mqtt_adapters.py`, `packet_ai_detector.py`, `edge/trust/trust_score_v2.py`, `edge/orchestration/run_detection_orchestrator.py`, `edge/trust/run_firewall_worker.py`, `tests/test_phase8_trust_gates.py`, `tests/test_packet_rule_detector.py` | 현재 등록/IP 조회는 PENDING을 배제하거나 지연 Raw를 오귀속할 수 있었다. PENDING Raw·last_seen·Feature·MQTT/Packet IF predictor·Event를 통과시키고 Trust는 원본 상태로 제외한다. DISABLED MQTT 수신은 비활성 통신으로 기록한다. 예약 비활성화는 접수 시각부터 대응을 막고 제외 Event를 처리 완료한다. Trust는 Worker와 같은 절대 파일 lock 다음 `BEGIN IMMEDIATE`에서 재조회·변경한다. | **로컬 fixture PASS; API/Worker 실기기 경합·FAILED 재시도 HOLD** |
| P8-10 | `tests/test_phase8_policy_resolver.py`, `tests/test_phase8_trust_gates.py`, `tests/test_packet_rule_detector.py`, `tests/test_phase4_trust_firewall.py`, `tests/test_firewall_worker_runner.py` | 두 기기별 임계값, 정확한 상한/초과, 경계/지연 Window, UNKNOWN 비소급, PENDING predictor 입력, 정책 누락·무효 revision, 비활성 예약, v2 대표 감점·cap·Rule 우선, 중복 방지를 fixture로 검증했다. | **관련 회귀 PASS** |
| P8-11 | `docs/phase8-hyunsoo-contract.md` | #84 계약, #86 MQTT, #87 Migration·저장소를 로컬에 반영하고 공유 파일 충돌을 해결했다. 우민 등록·정책 API/Recovery·Firewall와 남은 계약 및 병합 순서를 기록했다. | **로컬 PR 코드 통합 PASS; API·운영 통합 HOLD** |

## 실행한 검증

```powershell
.venv\Scripts\python.exe -m pytest -q tests/test_phase8_policy_resolver.py tests/test_phase8_trust_gates.py tests/test_phase4_trust_firewall.py tests/test_trust_score_service.py tests/test_trust_score_integration.py tests/test_trust_compensation.py tests/test_rule_detector.py tests/test_rule_runner.py tests/test_ai_runner.py tests/test_mqtt_identity.py tests/test_mqtt_feature_pipeline.py tests/test_mqtt_feature_builder_runtime.py tests/test_packet_rule_detector.py tests/test_packet_rule_runner.py tests/test_packet_rule_policy_v3.py tests/test_packet_rule_management_exclusion.py tests/test_detection_orchestrator_runner.py tests/test_packet_feature_extractor.py tests/test_firewall_worker_runner.py
```

최초 실행 결과: **423 passed, 2 skipped, 1 warning** (46.05초). #84·#86·#87 로컬 통합 후 Migration 007 임시 DB를 사용하는 테스트로 수정하고 다음 전체 회귀를 실행했다.

```powershell
$env:PATH='C:\Users\Hyunsoo\AppData\Local\Programs\Git\bin;'+$env:PATH
.venv\Scripts\python.exe -m pytest -q --tb=short tests backend/tests
```

최종 결과: **2393 passed, 13 skipped, 3 warnings** (143.21초). Windows에서 Firewall wrapper 테스트가 Git Bash를 쓰도록 PATH를 지정했다. skipped 테스트를 통과로 계산하지 않는다. 운영 DB 복사본과 Pi 실기기 검증은 이 결과에 포함되지 않는다.

## 2026-10-03 PR 리뷰 보완

- #84의 리뷰 수정 `125e564`를 한때 `f605f4f`로 cherry-pick했다. 이후 #84·#86·#87이 develop에 병합되어, 현수 브랜치를 최신 develop `7ab389a` 위에 rebase했다. 동일한 #84 패치는 upstream에 있어 rebase에서 중복 커밋을 생략했다. #87의 후속 `c681fb9`와 develop의 별도 #89 AI 관측 코드도 기준에 포함됐으며, 현수 PR의 의존 코드 중복 diff를 제거했다. 이전 이력은 로컬 `backup/phase8-pr88-before-rebase`에 보존했다.
- `load_policy_resolver()`는 `devices`와 `device_policy_revisions`를 한 SQLite SELECT의 스냅샷으로 읽는다. 별도 SELECT 사이 신규 등록이 완료되어 정상 revision을 orphan으로 오판하고 Subscriber의 Raw 저장을 중단하던 경합을 실제 WAL 동시 등록 fixture로 재현·검증했다.
- SQLite 3.40.1에서 `unixepoch('2026-09-30T00:00:09.999999Z')`와 `unixepoch('2026-09-30T00:00:10Z')`가 같은 정수 초로 반환됨을 확인했다. MQTT Feature·Rule 조회와 Phase 4 cutover는 SQL에서 경계 초를 후보로 포함한 뒤 Python에서 원본 마이크로초 UTC 시각으로 정확한 반열린 구간을 판정한다. 09.999999초 Raw가 원래 Window의 Feature·Rule에 들어가고 10.000000초 Raw는 다음 Window에만 들어가는 경계 테스트를 추가했다.

```powershell
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_phase4_cutover_repository.py tests/test_packet_capture_safety.py tests/test_phase8_trust_gates.py tests/test_mqtt_feature_builder_runtime.py
$env:PATH='C:\Users\Hyunsoo\AppData\Local\Programs\Git\bin;'+$env:PATH
.venv\Scripts\python.exe -m pytest -q --tb=short tests backend/tests
```

rebase 전 관련 검증: **89 passed, 5 skipped**. rebase 전 전체 Windows 로컬 회귀: **2400 passed, 15 skipped, 3 warnings** (440.29초). Linux 2406개 통과는 리뷰어가 보고한 별도 결과이며 이 변경 후 재실행 결과가 아니다.

최신 develop `7ab389a` 위에서는 #89 AI 관측 테스트 fixture에 실제 ACTIVE 정책 revision을 추가했다. 정책이 없는 ACTIVE 기기는 `POLICY_UNAVAILABLE`로 처리하는 Phase 8 경계를 유지하고, #89의 관측 동작을 변경하지 않았다. 구형 Trust 테스트는 Phase 4/v2 DB의 쓰기 전 거부를 확인하도록 조정했다. 관련 Orchestrator·Trust·AI 회귀는 **122 passed**다. 같은 최신 기준에서 전체 Windows 로컬 회귀를 다시 실행한 결과는 **2495 passed, 15 skipped, 3 warnings** (470.65초)이다. Pi·운영 DB 복사본·Runtime Firewall 실기기 상태·Pico G2는 여전히 **미검증**이다.

## 의존성 및 판정 경계

- 종민: #87의 Migration 007은 `devices.registration_effective_from`과 단일 `device_policy_revisions` 테이블을 사용한다. 별도의 `device_registration_revisions`는 없다. Subscriber/Feature의 #86 `is_json_valid` projection은 로컬 충돌 해결에 반영했다. 운영 ESP32 두 대의 실제 정책값 backfill과 운영 DB 복사본 검증은 남았다. 이 브랜치는 Migration 번호를 임의로 정하거나 운영 DB를 수정하지 않았다.
- 우민: 등록/정책 API의 다음 UTC 경계·현재/예정 반환, 예약 비활성화의 `requested_at` 영속화, Recovery·Firewall Worker와 동일 절대 파일 lock → DB write lock 순서, `SQLITE_BUSY`/FAILED 재시도 시 전체 재조회. 공유 `run_firewall_worker.py`의 절대 경로 변경을 병합 확인해야 한다.
- 현수: #87의 실제 컬럼 projection과 Migration 007 임시 DB 회귀는 완료했다. API 병합 뒤 통합 Orchestrator 및 standalone Packet runner를 운영 DB 복사본에서 재검증한다. MVP Rule/AI runner는 Phase 4/v2 DB에서 운영 실행을 거부한다.
- Pi 실기기 E2E, Runtime Firewall 실제 상태, Pico G2는 **미검증**이다.
- 작업 폴더의 `backend/data`에는 운영 DB가 없고 `.gitkeep`만 있어 ESP32 두 대의 실제 점수·정책값을 담은 운영 DB 복사본 검증은 **미수행**이다. 위 PASS는 Migration으로 생성한 임시 SQLite fixture에 한한다.
