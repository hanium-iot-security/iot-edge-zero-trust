# Phase 9 방화벽 DB/runtime 주기 대조

기존 `firewall-runtime-snapshot.timer`의 5초 관측에 DB 대조 결과를 함께 저장한다. 새 Migration, Timer, 설정은 없다. 자동 복구·Rule 재생성·삭제는 수행하지 않는다. 기존 Worker의 처리와 Recovery 승인 조건은 그대로다.

## 관측과 읽기 경계

Observer는 기존 Firewall 공유 잠금 안에서 Wrapper `list`를 한 번 실행하고, 현재 DB를 SQLite `mode=ro`, `query_only=ON`, 짧은 명시적 `BEGIN`으로 읽는다. DB 연결을 닫은 뒤 기존 `firewall-runtime.json`을 한 번 원자 교체한다. DB 잠금 대기는 최대 1초이며, 공유 잠금 획득에 실패하면 파일을 덮어쓰지 않는다. 기존 파일은 설정된 TTL 이후 `UNKNOWN`이 된다.

Snapshot은 기존 `firewall-runtime-snapshot-v2` 형식에 `boot_id`와 `consistency`를 추가한다. 기존 Recovery verifier는 추가 필드를 무시하므로 대상 IP의 실제 Rule 부재 검증은 계속 동작한다. DB 대조 실패와 OS 관측 실패는 별도다. 예를 들어 DB를 읽지 못해 `consistency.status=UNKNOWN`이어도 정상 완료한 OS 관측의 `available=true`는 유지된다.

비교 대상은 `hanium-firewall:<rule_id>`로 관리하는 IPv4 INPUT Rule이다. Rule ID, Source IP, Scope를 정확히 대조한다. MQTT TCP/1883 및 Pi INPUT IPv4 전체 Scope를 지원한다. 관리하지 않는 Rule, IPv6, FORWARD 또는 장치 네트워크 전체의 정상 여부는 판정하지 않는다.

## GET /api/firewall-runtime-status

인증 없는 읽기 전용 API다. Snapshot과 현재 DB만 읽으며 Wrapper·sudo·iptables를 실행하지 않는다. DB의 유효한 Scope/Release 스키마와 실제 값을 확인하고 관측 시 저장한 DB fingerprint와 대조한다. 관측 이후 관련 DB 상태가 바뀌었으면 기존 경고를 재사용하지 않고 `WAITING`/`DB_CHANGED`를 반환한다.

| status | 의미 |
|---|---|
| `MATCH` | 관측 시점의 비교 대상 DB/관리 Rule이 일치함 |
| `MISMATCH` | 확정된 불일치가 하나 이상 있음. 다른 Rule의 전환 대기는 `waiting`으로 함께 표시 가능 |
| `WAITING` | PENDING Rule, PENDING 해제 요청, DB 변경 이후 새 관측 대기 |
| `UNKNOWN` | 관측·DB·스키마·boot 근거를 신뢰할 수 없음 |

DB 변경시각은 기존 초 단위 기록이다. 관측과 같은 초의 변경도 순서를 증명할 수 없으므로 다음 관측까지 기다린다. 해제 요청이 아직 PENDING이면 Rule이 이미 `REMOVED`이고 OS에서 사라졌어도 `WAITING`이다.

응답은 `server_time`, `observed_at`, `boot_id`, `status`, `reason_code`, `age_seconds`, `max_age_seconds`, `warnings`, `waiting`, `warning_count`, `waiting_count`를 제공한다. 각 경고는 `kind`, `rule_id`, 예상/실제 `source_ip`·`scope`, `key`, `first_seen_at`, `last_seen_at`, `duration_seconds`를 가진다.

경고 종류는 `APPLIED_MISSING`, `REMOVED_RESIDUAL`, `FAILED_RESIDUAL`, `ORPHAN_RUNTIME`, `IDENTITY_MISMATCH`다. `FAILED` 상태인데 OS Rule이 없으면 불일치로 세지 않는다. PENDING 및 처리 전환은 경고 수에 포함하지 않는다.

현재 기본 TTL은 기존 `FIREWALL_RUNTIME_SNAPSHOT_MAX_AGE_SECONDS=15`다. 오래된 관측, 미래 관측, OS 오류, 손상된 JSON/DB, 스키마 불일치, boot ID 부재·불일치에서는 경고/대기 목록을 비운 `UNKNOWN`을 반환한다. 서버가 Linux boot ID를 읽지 못하는 개발 환경도 `UNKNOWN`이며 실제 관측 성공으로 간주하지 않는다. 응답의 `reason_code`가 첫 진단 근거다. OS 관측 실패의 원문은 기존 JSON 루트 `error`, Observer의 DB 대조 실패 이유는 `consistency.reason_code`와 기존 서비스 journal에서 확인한다. API는 원문 오류를 그대로 외부에 노출하지 않는다.

## 경고 시간의 의미

동일한 불일치가 연속 관측되면 JSON의 최초/최신 관측시각과 관측 간 지속시간을 유지한다. 같은 Snapshot 재조회나 동일 관측시각의 중복 저장으로 최신시각·지속시간을 늘리지 않는다. 정상 관측, 불명 상태, TTL을 넘는 관측 공백, 재부팅 이후에는 다음 불일치를 새 에피소드로 기록한다. 새 에피소드는 서비스 경고 로그에도 남는다.

이 파일은 현재 관측 상태이며 과거 경고의 영구 감사 저장소가 아니다. `MATCH`나 경고 해소만으로 Recovery를 승인하지 않는다. Recovery는 [기존 Runtime Verifier](firewall-runtime-verifier.md)의 대상별 Gate를 계속 사용한다.

## 검증 범위

로컬 임시 SQLite·가짜 Wrapper 관측으로 두 Scope, DB/OS 불일치, 해제 전환, 초 경계, stale/future/boot/손상, 중복·재시작 에피소드, DB 무변경, JSON 단일 발행 및 기존 Recovery 형식 호환을 검증한다. 실제 Pi의 Timer 배포, 부팅 후 관측, 운영 DB 규모의 소요시간과 공유 잠금 경합은 Pi 복귀 후 확인해야 한다. 운영 DB나 실제 방화벽에 변경을 적용한 결과가 아니다.
