# Phase 8 현수: resolver·탐지·Trust 연결 계약

최초 기준: develop `559fa41fcd5cdf4deb74219a902ca91a9ec8095b`. 2026-10-03 현재 #84·#86·#87은 develop `7ab389a`에 병합됐고 현수 브랜치는 그 커밋 위에 재배치했다. #84의 리뷰 수정 `125e564`와 #87의 후속 수정 `c681fb9`도 이 기준에 포함된다. 이 문서는 현수의 Rule·Identity·Trust 연결을 설명하며, 저장/API 계약의 기준은 `docs/contracts/device-policy-v1.md`다. 운영 DB는 변경하지 않았다.

## UTC 원본 시각과 resolver

`DevicePolicyResolver`는 Migration 007의 `devices`와 `device_policy_revisions`를 Window/배치 단위로 읽은 불변 snapshot이다. 두 집합은 단일 SQLite SELECT에서 읽어 동시 등록이 끼어들어도 서로 다른 시점의 행을 섞지 않는다. 조회 키는 **원본의 UTC 10초 `window_start`**이며 처리 시각이 아니다. 정확히 경계에 접수한 변경도 다음 10초부터 효력이 생긴다. 종민의 `device_policy_resolver.py`와 같은 등록·정책 시점 계약을 따르고, 탐지용 adapter는 SQLAlchemy Session의 동일 DB 연결에서 읽는다. API의 현재/예정 정책은 저장소의 `get_policy_snapshot()` 계약을 따른다. 원본 `mqtt_logs.topic`, `payload`, `received_at`, 후보 `device_id`는 판정으로 수정하지 않는다.

현재 repository projection 계약:

| Table | 필수 열 | 뜻 |
| --- | --- | --- |
| `devices` | `device_id`, `ip_address`, `registration_effective_from` | 신규 등록의 최초 효력 시각은 UTC 10초 경계. 기존 기기의 NULL은 정책 도입 전부터 등록된 ID라는 뜻이다. |
| `device_policy_revisions` | `device_id`, `revision`, `effective_from`, `created_at`, `registration_state`, `policy_profile`, `expected_publish_interval_seconds`, `publish_count_max`, `payload_size_max_bytes`, `packet_rate_max_pps`, `byte_rate_max_bytes_per_second` | 등록 상태와 v1의 프로필·정상 주기·네 상한을 함께 저장하는 불변 이력. `created_at`은 예약 DISABLED 접수 판단에 사용한다. |

007 컬럼과 이관 이력이 모두 없는 기존 DB에서만 Phase 4 경로를 유지한다. 007 이력 또는 등록 메타데이터가 있는데 정책 테이블이 사라졌으면 불완전한 스키마로 거부하고 자동 대응 트랜잭션을 중단한다. 정책 테이블만 있고 위 필수 컬럼이 빠지면 평가를 거부한다. 등록 전 Window는 `UNREGISTERED_AT_WINDOW`, 기존 ACTIVE 기기의 정책 누락은 `POLICY_UNAVAILABLE`, 잘못된 revision은 `INVALID_POLICY_REVISION`이다. 프로필·주기·네 상한·순번·상태·효력 시각은 저장/API의 공통 v1 검증을 사용하고 숫자 문자열·bool·실수 순번을 정수로 보정하지 않는다. 신규 기기의 최초 정책 효력은 `registration_effective_from`과 같아야 하며, 최초 revision 1이 없는 이력도 사용하지 않는다. 기존 NULL 등록 기기는 이관 이전 Window에도 등록된 ID로 유지하되 정책이 없는 과거 Window는 `POLICY_UNAVAILABLE`이다. 잘못된 행은 해당 기기만 정책·자동 대응에서 제외하고 다른 기기의 Raw 저장을 중단하지 않는다. 등록 효력 시각 자체가 잘못되면 `INVALID_REGISTRATION_REVISION`으로 귀속과 자동 대응을 거부하며 원본 ID 후보·Topic·Payload는 Raw에 보존한다. 이때 코드 기본 임계값으로 판정하지 않는다. PENDING·DISABLED도 등록된 ID이므로 UNKNOWN으로 바꾸지 않는다. MQTT Topic/Payload ID를 각각 그 Window의 등록 집합과 비교하고, 저장된 Payload의 원본 유효성은 #86의 `is_json_valid`로 판정한다. Packet IP도 그 Window의 유일한 등록 소유자에만 귀속하며, 기존 후보 ID는 evidence에 남긴다.

Migration 007은 revision 유일성·순번·임계값·UTC 경계·상태 전이와 불변 트리거를 제공한다. 기존 ESP32의 최초 revision은 운영 설정의 **실제 값**을 확인해 `db/backfill_device_policies.py`로 이관해야 하며 코드 기본값으로 대체하면 안 된다. 이관과 복사 DB 검증 전에는 Phase 8 운영 활성화를 HOLD한다.

기기 정책 `revision`은 `detection_events.policy_version`(알고리즘), AI model version, `trust_score_history.policy_version`, checkpoint/dedupe key와 독립이다. 정책 변경만으로 완료 Window 재실행이나 중복 감점을 만들지 않는다. Rule evidence에는 device ID, revision, Window, 관측값, 상한, 단위를 남긴다. Publish Count는 messages/10s, Payload는 bytes, Packet/Byte Rate는 실제 `captured_duration_seconds`로 나눈 packets/second·bytes/second다. 네 비교는 모두 `>`이다. Packet Capture 품질, 관리 IP 제외, Port Scan, Broker DoS, Identity, Malformed는 기존 조건을 유지한다.

## 상태와 원자적 대응

PENDING은 Raw·last_seen·Feature·Identity·활성 predictor·Detection Event까지 진행한다. Trust는 원본 Window가 PENDING이면 `PENDING_AT_WINDOW`로 완료하고 감점·차단하지 않는다. DISABLED 수신은 `mqtt_logs.error_message`에 `disabled_device_communication`을 남기고 새 Feature/자동 대응을 제외한다. 과거 ACTIVE Window도 처리 시점이 DISABLED 또는 예약 비활성화 상태면 `DISABLE_REQUESTED_OR_DISABLED`로 완료한다. 제외 Event는 `processed_at`과 `applied_to_score=0`을 남긴다. `score_delta`는 후보 감점이고 실제 감점은 `trust_score_history.actual_delta`다.

Trust 단계는 Worker와 같은 **절대 경로** `firewall_lock_path()`를 먼저 잡고, 동일 SQLite 연결에서 `BEGIN IMMEDIATE` 후 등록 상태·요청·점수·기존 차단을 다시 읽어 점수/이력/요청/checkpoint를 한 트랜잭션으로 commit한다. 이미 열린 SQLite 트랜잭션에는 중복 BEGIN을 하지 않는다. 우민의 등록/비활성화 API와 Recovery, Firewall Worker의 공유 순서는 **파일 lock → DB write lock**이다. DB lock을 잡은 채 파일 lock이나 OS 명령을 기다리지 않는다. `SQLITE_BUSY`/충돌 시 rollback하고 새 트랜잭션에서 상태와 요청을 다시 읽어야 한다. 비활성화 접수는 새 자동 대응을 즉시 막고 기존 차단을 자동 해제하지 않는다.

## 병합 순서와 남은 검증

1. #84·#86·#87은 develop에 병합됐다. 현수 PR의 최종 diff는 이 기준의 현수 변경만 포함하도록 재배치했다.
2. Subscriber/Feature·`edge/policy`의 동시 등록과 마이크로초 경계 회귀를 확인한다. develop의 #89 AI 관측 모드는 현수 구현 범위가 아니며, 유효 정책을 가진 ACTIVE 기기 fixture와 함께 통합 회귀를 확인한다.
3. 우민의 P8-04 등록/정책 API에서 `state_change_guard`와 공용 파일 lock → DB write lock, 비활성화 예약 및 FAILED 재시도 경계를 연결한다. API는 이 브랜치에 아직 포함되지 않았다.
4. 운영값 backfill과 Pi 배포·Recovery/Firewall 실기기 검증은 우민·종민의 별도 결과로 판정한다.

현재 로컬 fixture 검증은 실기기 Pi E2E, Runtime Firewall 상태, Pico G2 동작을 증명하지 않는다. API의 FAILED 재시도·동시 비활성화 처리와 운영 정책값 이관은 후속 통합 검증 대상이다.
