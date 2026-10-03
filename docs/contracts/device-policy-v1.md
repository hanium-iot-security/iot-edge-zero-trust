# Phase 8 기기 등록·정책 공유 계약 v1

작성: 2026-10-01 / 작업: P8-02 / 기준: develop `c8ea2bc` (PR #82).

이 문서는 P8-03~07의 구현 기준이다. 계약 확정과 각 기능의 구현·배포 완료는 구분한다.
기존 조회 API는 `docs/api-spec.md`를 따른다. 팀원 검토 결과로 계약을 바꾸면 이 문서와
예시를 함께 수정하고 변경 내용을 공유한다. 전원 검토 완료 여부는 별도로 기록한다.

P8-04 Backend 등록·정책 API는 `backend/app/routers/devices.py`와
`backend/app/services/device_policy_service.py`에서 구현하며, P8-03의 공통 저장소와
Migration 007을 사용한다. 로컬 API 검증은 Pi 운영 배포·P8-05/06 Rule·Trust 연결·
P8-07 화면 구현 완료를 대신하지 않는다. 운영 활성화 순서는
[기기 정책 API 운영 확인](../device-policy-api-runbook.md)을 따른다.

## 1. 담당 접점과 구현 순서

| 담당 | 소유 범위 | 이 계약에서 가져갈 것 |
| --- | --- | --- |
| 우민 | 등록/정책 명령 API, Recovery·Capture, 장비·통합 | 요청 검증·관리자 보호·충돌 응답·운영 확인 |
| 종민 | Migration·저장/조회, MQTT 원본·Feature, 데이터 검증 | 초기 revision·불변 이력·원자적 저장·UTC 조회 |
| 현수 | Identity·정책 resolver·Rule·Trust | 당시 등록 집합·정책 조회·자동 대응 자격 |
| 소유 | Devices 등록/편집·조회/모달 수정 | JSON 예시·현재/예정 정책·오류/충돌 표시 |
| 선우 | Packet·차단·복구 검토 | 단위·경계·실제 검증 결과 |

P8-S01~05의 기존 기능 수정은 독립 진행한다. 신규 기능은 계약 → Migration/저장 →
API와 Rule 연결(병렬) → 등록 상태별 Trust 보호 → 실제 API/UI 통합 순서다.
Migration 번호는 종민이 배정한다. 공유 파일은 담당자끼리 순차 병합한다.

## 2. 입력 필드와 고정 상한

새 요청은 아래 필드만 허용한다(`extra=forbid`). 숫자 문자열, bool, null,
NaN/Infinity와 묵시적 잘라내기·보정은 허용하지 않는다. JSON 실수 필드는 정수도
허용하되 정수 필드는 `15.0`도 거부한다. 폼은 전송 전에 명시적으로 숫자로 변환한다.

| 필드 | 형식·허용 범위 | 기본/의미 |
| --- | --- | --- |
| `device_id` | ASCII `^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$` | 필수, 대소문자 구분, 등록 후 불변 |
| `ip_address` | 정규 IPv4 문자열, RFC1918 | 필수, ID와 별도 UNIQUE, 변경/재사용 금지 |
| `device_type` | `SENSOR`, `CAMERA`, `ACTUATOR`, `OTHER` | 표시용 필수 값, 타입 변경으로 모델/룰 변경 없음 |
| `mqtt_principal` | ASCII `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$` | 필수 기록, Broker 계정 자동 생성 아님 |
| `policy.policy_profile` | `periodic-sensor-v1` | 첫 버전 단일 템플릿, AI Profile 아님 |
| `policy.expected_publish_interval_seconds` | 유한 number, 0 초과~86400 | 정상 동작 설명값, 센서 초기값 5.0 |
| `policy.publish_count_max` | integer, 1~10000 | 10초당 메시지 수, 기본 15 |
| `policy.payload_size_max_bytes` | integer, 1~1048576 | 원본 MQTT Payload 바이트, 기본 5120 |
| `policy.packet_rate_max_pps` | 유한 number, 0 초과~100000 | 실제 유효 캡처 초당 packet 수, 기본 10.0 |
| `policy.byte_rate_max_bytes_per_second` | 유한 number, 0 초과~125000000 | **bytes/s**, 기본 2500.0; bit/s 아님 |
| `reason` | string, trim 후 1~500자 | 등록·변경 사유, 제어 문자 금지 |
| `expected_revision` | integer, 1~2147483647 | 정책 변경 시 필수, 최신 저장 revision과 비교 |
| `registration_state` | `PENDING`, `ACTIVE`, `DISABLED` | 변경 요청에서만 허용 |

위 최대값은 첫 구현의 **관리 입력 검증 상한**이다. 권장 탐지 임계값이나 Pi 처리 성능을
뜻하지 않는다. 0을 탐지 끄기로 해석하지 않는다. 실제 이관값은 Pi 설정 override를
확인해 보존한다. 상한 밖의 기존 값은 보고하고 이관을 보류하며 임의로 줄이지 않는다.
템플릿은 입력값 복사 용도다. 템플릿 수정으로 기존 revision을 소급 변경하지 않는다.

IP는 `is_private`만으로 판단하지 않고 `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`을 명시적으로 검사한다. 실제 허용 LAN CIDR 안의 host 주소만 허용하고
네트워크/브로드캐스트·Pi/관리 주소·보호/Packet 제외 주소를 거부한다.
P8-04에서 운영자가 정한 단일 `DEVICE_REGISTRATION_CIDR`과 기존
`FIREWALL_PROTECTED_IPS`, `CAPTURE_INTERFACE_IP`, `PACKET_RULE_EXCLUDED_PEER_IPS`를
합쳐 검증한다. CIDR은 서버 설정이며 요청 본문으로 받지 않는다. /24를 추정하지 않는다.
허용 LAN 미설정·잘못된 운영 설정이면 Write를 503으로 거부한다. DHCP 예약의 실제
적용 여부는 운영 점검에서 확인하고, 요청에 `dhcp_verified=true` 같은 우회 값을 받지 않는다.

Device ID·IP·Principal·Device Type 수정, 삭제, DISABLED 재활성화, 임의 Topic/목적지,
AI 설정과 점수 직접 입력은 이번 명령 API 범위 밖이다. Topic은 서버가
`iot/{device_id}/sensor`로 산출한다. 비밀번호·관리자 키는 본문·정책·감사에 저장하지 않는다.

## 3. API 요청·응답

`device-policy-v1.examples.json`은 프론트 개발용 **가상 응답**이다.
새 경로가 열렸다고 판단하거나 실제 호출 성공의 증거로 사용하지 않는다.

| 경로 | 계약 |
| --- | --- |
| `POST /api/devices` | ID/IP/type/principal, 완전한 `policy`, reason 입력. 서버가 PENDING·revision 1·Topic·효력 시점 생성. 201 `{device,policy}` 반환; policy는 아래 정책 조회와 같은 구조 |
| `GET /api/devices` | 기존 `{items,total}`·status/limit/offset 유지. 기존 필드 삭제/이름 변경 없음 |
| `GET /api/devices/{device_id}` | 기존 DeviceItem 확장. Trust `status`와 등록 상태 분리 |
| `GET /api/devices/{device_id}/policy` | `device_id`, `server_time`, `latest_revision`, `current`, `pending` 반환. current/pending은 revision 객체 또는 null |
| `POST /api/devices/{device_id}/policy-revisions` | expected_revision·reason·registration_state·완전한 policy 입력. 201로 정책 조회와 같은 구조 반환; pending이 새 revision |

부분 PATCH를 도입하지 않는다. 상태만 바꾸더라도 전체 정책을 보내고 서버는 잠금 안에서
expected_revision과 대조한다. 등록 초기 상태·revision·Topic·효력 시점·작성자는
서버 소유 필드다. 입력하면 422로 거부한다. 아무 변화 없는 revision도 만들지 않고 409로 반환한다.

정책 revision 객체는 `device_id`, `revision`, `effective_from`, `registration_state`,
`policy`, `created_at`, `created_by`, `reason`을 포함한다. created_by는
`require_recovery_admin`의 인증 결과에서 얻는다. 현재 공용 키의 principal은 개인 신원 증명이 아니다.

DeviceItem에는 `device_type`, `mqtt_principal`, `mqtt_topic`, `registration_state`,
`registration_effective_from`, `current_policy_revision`, `pending_policy_revision`,
`auto_response_eligible`, `auto_response_exclusion_reason`을 추가한다.
신규 기기의 효력 시작 전에는 화면상 PENDING, current revision은 null, pending은 1,
자동 대응 false다. 이는 해당 과거 Window에 이미 등록됐다는 뜻이 아니다.
기존 기기의 revision 누락은 Devices 목록/상세의 200 응답에서 상태 null·
`POLICY_UNAVAILABLE`로 노출한다. 해당 기기의 정책 상세 GET과 Write는 503으로 거부한다.
정상적인 초기 효력 대기는 정책 상세 GET도 200이며 current=null, pending=revision 1이다.
표시용 eligibility가 명령 실행 권한을 대신하지 않는다.

기존 status 필터는 Trust 상태 필터로 유지한다. 등록 상태 필터는 첫 버전 필수가 아니다.
현재/예정 정책은 별도 표시하고 응답의 `server_time`으로 적용 시점을 설명한다.
Devices 요약은 현재 페이지, Dashboard 요약은 전체라는 기존 범위를 유지한다.
점수 등급과 등록 준비/활성/비활성 집계를 구분하고 PENDING의 100점을 검증 완료로 표시하지 않는다.

### 오류와 관리자 경로

| 상태 | code / 의미 |
| --- | --- |
| 401 | 기존 `RECOVERY_ADMIN_UNAUTHORIZED` |
| 503 | 기존 `RECOVERY_ADMIN_NOT_CONFIGURED`, `DEVICE_POLICY_CONFIG_UNAVAILABLE` 또는 등록된 기기의 `POLICY_UNAVAILABLE` |
| 404 | `DEVICE_NOT_FOUND` |
| 409 | `DEVICE_ID_CONFLICT`, `DEVICE_IP_CONFLICT`, `REVISION_CONFLICT`, `PENDING_REVISION_EXISTS`, `NO_POLICY_CHANGE`, `STATE_TRANSITION_BLOCKED`, `POLICY_WRITE_BUSY` |
| 422 | FastAPI 필드 검증: 자료형·범위·미지원 필드·ID/IP·허용 LAN 등 |

신규 업무 오류는 `detail: {code,message,...}`로 반환한다. revision 충돌은
current_revision/pending_revision/latest_revision도 제공한다. 기존 인증 오류 문자열과 기존 GET 404
문자열은 변경하지 않는다. 프론트는 문자열·업무 오류 객체·422 배열을 각각 처리한다.
현재 API helper의 `error.code`는 Axios 코드이므로 업무 코드는
`error.responseData?.detail?.code`에서 읽는다.
충돌 시 재조회하되 작성 중 값은 보존하고 자동 재전송하지 않는다. 네트워크 오류로
결과가 불명확하면 조회로 등록/최신 revision을 확인한 뒤 재시도한다.

422 배열은 `type`, `loc`, `msg`만 반환하며 입력 원문을 포함하지 않는다.
정책 GET은 관리자 키를 요구하지 않는 기존 읽기 경로다.
관리자 변경 요청은 기존 `X-Recovery-Admin-Key` 인증을 사용한다. 키는 메모리에서만
유지하고 모달 종료/기기 전환 시 폐기한다. 로컬 개발은 브라우저가 접속하는 API까지
loopback이어야 하며, Pi API는 검증된 SSH 포워딩 loopback 또는 HTTPS 경로를 사용한다.
페이지가 localhost라는 이유만으로 일반 LAN HTTP API에 키를 보내지 않는다.
완료 응답 전에 서버가 commit해야 하고, 실패는 일부 저장 없이 rollback한다.

## 4. 효력 시점·조회·중복 방지

- DB write lock을 얻은 뒤 서버가 시각을 결정한다. 효력은 그 시각의 **엄격히 다음**
  UTC 10초 경계다. 00:00:09.900 → 00:00:10Z, 정확히 00:00:10Z → 00:00:20Z.
- 모든 새 정책 시각은 UTC `YYYY-MM-DDTHH:MM:SSZ`. 입력으로 과거 효력 시점을 받지 않는다.
  효력 시각은 정수 초 10초 배수. created_at/server_time도 UTC Z이며 소수 초를 허용한다.
- POST 응답의 server_time과 current/pending은 쓰기 잠금 후 결정한 접수 시각을 기준으로
  반환한다. GET은 조회 시각 기준이다. 응답이 효력 경계를 지나 도착할 수도 있으므로,
  저장 후와 효력 시점 이후에는 GET으로 재조회하며 클라이언트 시각으로 상태를 확정하지 않는다.
- `window_start <= t < window_end`로 원본 시각을 10초 Window에 귀속한다.
  당시 `effective_from <= window_start`인 최신 revision을 선택한다.
  처리 시각·현재 설정·최신 등록 집합으로 과거를 다시 해석하지 않는다.
- 적용 예정 revision이 있으면 추가 변경을 409로 거부한다. `expected_revision`은
  최대 저장 revision과 대조한다. 첫 버전은 예정 변경 취소를 지원하지 않는다.
- 탐지 알고리즘의 policy_version과 **device_policy_revision**을 구분한다.
  기기 설정 변경만으로 탐지 버전·checkpoint·이벤트 중복 키를 바꾸지 않는다.
- evidence에는 device_id, device_policy_revision, window_start/end, 관측값,
  임계값, 단위와 비교 연산 `>`를 같은 정책 객체에서 기록한다.
- 늦게 온 Raw는 보존하고 이미 완료된 Window는 다시 감점하지 않는다. 제외 수·사유를 남긴다.

### 현수·종민이 공유할 resolver 인터페이스

구현 위치는 Edge의 공통 정책 모듈로 통일한다. Backend 응답 DTO에 탐지 판단을 넣지 않는다.
첫 버전은 DB 트랜잭션을 호출자가 소유하며 resolver가 commit하지 않는다.

```text
resolve_device_policy(connection, device_id, window_start_utc)
  -> {resolution: OK | NOT_REGISTERED | POLICY_UNAVAILABLE,
      device_id, device_policy_revision: int | null,
      effective_from: UTC-Z | null, registration_state: state | null,
      policy: immutable snapshot | null, reason: string | null}

registered_device_ids_at(connection, window_start_utc) -> set[device_id]
registered_device_by_ip_at(connection, source_ip, window_start_utc) -> device_id | null
```

등록 효력 전도 NOT_REGISTERED에 포함한다. 등록된 기기의 revision이 누락되거나
모순되면 POLICY_UNAVAILABLE로 구분한다.
MQTT는 Topic ID·Payload ID **양쪽 모두** 당시 등록 집합과 대조한다.
PENDING/DISABLED도 등록된 식별자다. 자동 대응 제외와 UNKNOWN을 혼동하지 않는다.
Packet IP도 당시 등록 효력으로 조회한다. resolver 결과는 관측 정책이고, Trust는
처리 시점의 현재/예정 상태를 별도로 같은 쓰기 트랜잭션에서 검사한다.

## 5. 등록 상태·Trust·Worker 경계

| 당시 상태 | 수집/탐지 | 새 감점·차단 |
| --- | --- | --- |
| 등록 효력 전/미등록 | 기존 UNKNOWN/미등록 처리 | 다른 등록 기기에 귀속 금지 |
| PENDING | 정상적으로 기록·유효 Feature 분석 | 제외 |
| ACTIVE | 당시 정책으로 분석 | 현재/예정 상태 및 기존 Trust 계약을 통과할 때만 |
| DISABLED | 비활성 수신으로 기록 | 제외 |
| 정책 누락/오류 | 운영 오류 기록 | 제외 |

상태를 바꾸는 전환은 PENDING→ACTIVE, PENDING/ACTIVE→DISABLED만 지원한다.
PENDING/ACTIVE에서 상태를 유지한 정책값 변경은 허용한다. DISABLED는 첫 버전에서
재활성화뿐 아니라 정책 편집도 409로 거부한다. ACTIVE 전환은
Broker 계정·본인 Topic 허용/타 Topic 거부·실제 수신·정책 연결 증거를 운영자가 확인하고
reason에 증적 식별자를 남긴 뒤 요청한다. Subscriber의 last_seen만으로 ACL 인증을 대신하지 않는다.

DISABLED 예약을 수락하면 경계 전에도 새 자동 대응 생성을 중지한다.
과거 PENDING은 이후 ACTIVE가 되어도 감점하지 않고, 과거 ACTIVE라도 처리 시점에
DISABLED 또는 비활성화 예정이면 제외한다. `processed_at`, `applied_to_score=0`,
구체적 사유와 checkpoint 완료는 기록한다. 점수/감점 이력/격리 이력/차단 요청은 만들지 않는다.
제외된 과거 이벤트를 나중에 자동 재감점하지 않는다.

비활성화는 대상 device_id **또는 같은 고정 source_ip**의 APPLIED/PENDING 차단,
PENDING 해제 요청, 불확실한 Runtime 상태가 있으면 409로 보류한다.
같은 기기의 차단 이력이 다른 IP를 사용하면 현재 IP의 관측만으로 비활성화하지 않는다.
FAILED라는 이유만으로 잔존 규칙이 없다고 가정하지 않는다. 마지막 변경 시도 이후의
fresh 관측과 Worker 상호 배제가 필요하다. 기존 차단을 자동 해제하지 않는다.
기존 관리자 해제·복구는 가능하되 등록 상태를 변경하거나 ACTIVE로 되돌리지 않는다.

DB-only 경로는 첫 SELECT 전 `BEGIN IMMEDIATE` → 재검증 → 변경 → commit.
Worker 상호 배제가 필요한 경로는 **공용 파일 lock → DB write lock** 순서를 지킨다.
DB lock을 잡고 외부 명령이나 파일 lock을 기다리지 않는다. busy는 전체 rollback 후
새 상태로 재판단하거나 409로 반환한다. Worker FAILED 재시도도 자동 대응 자격을 검사한다.

## 6. DB·이관 계약과 검증

`devices`의 Trust 필드는 보존하고 등록 메타데이터/효력 시작 시점을 추가한다.
`device_policy_revisions`에는 불변 스냅샷·작성자·사유를 저장한다.
`UNIQUE(device_id,revision)`, `UNIQUE(device_id,effective_from)`, 양의 revision,
FK/NOT NULL·수치/상태/UTC 경계 검증과 정규화 IP UNIQUE를 저장 경로 전체에 적용한다.

등록은 device+초기 revision을 하나의 트랜잭션으로 생성한다. backfill과 seed도 같은
저장 검증을 사용하고 재실행 시 기존 값을 덮어쓰지 않는다. 기존 빈/중복 IP·지원 범위 밖
설정은 진단 후 보류한다. 운영 override가 확인된 모든 기존 기기를 ACTIVE로 이관하되
Trust 점수·차단·이력은 변경하지 않는다. 과거 정책을 재구성할 수 없는 구간은 공식
재평가에서 제외하고 한계를 기록한다. 임의 기본값으로 과거를 정상/공격으로 재분류하지 않는다.

기존 Rule 감점표·Incident Family 대표·10초 최대 −30·격리 `<30`·Rule 우선은 유지한다.
FLOODING 대표는 일반 과다 전송 −20, Broker DoS가 있으면 −25가 될 수 있다.
AI 관찰 모드의 기존 운영 설정은 유지한다. AI 경고·감점 정책 평가와 재학습은 Phase 9에서 진행한다.

검증은 노션 V01~V13/V16/V19~V22와 연결한다. 특히 다음을 공동 완료 기준으로 사용한다.

- 중복 ID/IP·strict 자료형·잘못된 LAN/관리 IP·인증 실패에서 DB 변경 없음.
- 정확히 10초 경계, 같은 revision 동시 요청, pending 중 변경, 저장 실패 후 반쪽 행 없음.
- 다른 두 기기에 동일 입력·다른 임계값 → 당시 revision에 맞는 결과.
- 등록 전 Topic/Payload UNKNOWN이 나중에 다른 기기의 MISMATCH가 되지 않음.
- PENDING/비활성화 예정에서 Rule·AI 이상을 실제 생성해도 새 감점·차단 없음.
- API 실제 응답에서 추가 필드 보존, 충돌 재조회·초안 보존, UTC/KST 구분.
- 별도 프로세스의 Worker·상태 변경·재시도 경합에서 교착·동시 성공·잔존 차단 위장 없음.

P8-02 완료 자료는 이 문서·JSON 예시·담당 접점이다. P8-03~07 구현 완료나 팀원의 검토
완료를 대신하지 않는다. 운영값·LAN·Pi 모델 활성 상태는 배포 시 실제 장비에서 확인한다.
