# Phase 9 Pi 입력 격리

이 변경은 이미 격리된 기기의 적용된 MQTT 차단을 관리자가 Pi IPv4 입력 전체 차단으로 확장하는 첫 경로를 추가한다. 운영 DB 마이그레이션, 실제 장비 차단, 서비스 배포와 재부팅 검증은 이 문서 작성 시 실행하지 않았다.

## 범위와 기존 동작

| scope | 적용 범위 | DB protocol / dest_port |
|---|---|---|
| `MQTT_IPV4_TCP_1883` | 해당 IPv4에서 Pi INPUT으로 들어오는 TCP 1883 | `tcp` / `1883` |
| `PI_INPUT_IPV4_ALL` | 해당 IPv4에서 Pi INPUT으로 들어오는 모든 IPv4 프로토콜·포트 | `NULL` / `NULL` |

자동 Trust 격리의 신규 규칙은 계속 MQTT 1883이다. 배포나 마이그레이션으로 기존 행 또는 ID의 차단 범위를 넓히지 않는다. 광역 차단도 Pi INPUT에 한정된다. 다른 호스트 간 통신, FORWARD와 IPv6는 이 범위에 포함되지 않는다. 정상 기기에 광역 자동 격리를 선택하는 정책 연결은 후속 범위다.

관리 API는 새 `PENDING` 행만 승인한다. 해당 응답의 `runtime_verified=false`는 실제 방화벽 적용 확인 전임을 뜻한다. Worker는 이후 별도의 적용·정확한 규칙 확인을 수행한다. 새 광역 규칙이 확인되기 전에 원본 MQTT 규칙을 제거하지 않으며, 확인 이후에도 자동 제거하지 않는다.

## 마이그레이션 011

`011_pi_input_isolation.sql`은 잠정 예약한 번호다. 공식 정상 자료 편입/QC 마이그레이션과 별개이며 번호가 실제 통합 전에 충돌하면 조정해야 한다.

기존 `firewall_rules` ID와 모든 기존 열의 값을 유지하고, 기존 행에 MQTT scope 및 NULL 승인 메타데이터를 붙인다. 삭제된 높은 ID도 `sqlite_sequence`에 보존하여 과거 ID를 재사용하지 않는다. Release의 기존 FK와 광역 source FK는 같은 `firewall_rules` ID를 참조한다. 상태/IP 인덱스를 재생성하며 활성 유일성은 `(source_ip, scope)`로 바뀐다. 따라서 서로 다른 scope의 두 규칙은 공존할 수 있고, 같은 IP·scope의 PENDING/APPLIED 중복은 차단된다.

Runner는 003과 같은 FK 재구성 경로로 011 전체를 한 트랜잭션에서 적용하고 `foreign_key_check` 및 `integrity_check` 뒤에 완료한다. 실패하면 테이블·행·인덱스·sequence·011 완료 메타데이터가 함께 롤백된다. 운영 적용 전에 별도 DB 사본에서 동일 검사를 실행하고 원본·WAL을 포함한 기존 백업 절차를 지켜야 한다. 이 문서는 운영 적용 승인을 대신하지 않는다.

완전한 pre-011 DB에서는 기존 MQTT 조회·자동 처리·명시적 해제가 유지되고 광역 승인만 503 `MIGRATION_011_REQUIRED`로 거부된다. 열 일부만 존재하거나 완료 버전과 열이 맞지 않으면 scope 판단을 실패로 처리한다.

## 관리자 승인 API

`POST /api/firewall-rules/{source_rule_id}/scope-extension-requests`

기존 `X-Recovery-Admin-Key` 인증을 사용하고 서버 인증 principal을 `requested_by`로 기록한다. 요청자가 actor를 지정할 수 없다. API 프로세스는 OS 명령을 실행하지 않으며 `iot-edge-api.service`의 `NoNewPrivileges=true`를 유지한다.

요청 예시의 주소와 revision은 응답을 다시 읽어 확인한 현재 값으로 대체한다. 실제 관리 키는 본문·URL·로그에 넣지 않는다.

```json
{
  "device_id": "pico_01",
  "source_ip": "192.168.0.31",
  "approved_policy_revision": 1,
  "scope": "PI_INPUT_IPV4_ALL",
  "reason": "Pi 입력 전체 격리 필요성을 확인한 관리자 승인",
  "request_id": "6af7a972-a852-4e21-86f3-4632c68ea331",
  "confirm": "EXTEND-PI-INPUT-7-192.168.0.31-REV-1"
}
```

첫 승인에는 다음 조건이 모두 필요하다.

- source ID가 기존 `APPLIED` MQTT 규칙이며 device/IP/사양이 요청과 일치한다.
- 기기의 현재 상태가 `isolated`이고 현재 소유 IPv4가 요청과 일치한다.
- 현재 적용된 정책이 `ACTIVE`이며 승인 revision이 정확히 같다. 적용 예정 DISABLED 정책도 거부한다.
- source 또는 기존 관련 광역 규칙에 해제 작업이 남아 있지 않다.
- 같은 기기 또는 IP에 이전 광역 PENDING/APPLIED/FAILED가 없다. REMOVED 광역도 정확한 성공 해제 감사가 있어야 후속 새 승인을 허용한다.

승인은 Worker와 같은 파일 lock을 잡은 뒤 서버 DB에서 `BEGIN IMMEDIATE`를 사용한다. source 해제·정책 관리 요청도 같은 lock 순서를 사용한다. 잠금 경합은 409로 거부하며 호출자의 기존 DB 쓰기를 버리고 재승인하지 않는다. 승인 후 Worker가 실제 적용하기 직전에 source/IP/기기 상태/정책 revision/해제 대기를 다시 확인한다. DHCP 변경, 정책 변경, 원본 상태 변경 또는 해제 대기가 생겼으면 적용을 중단한다.

`request_id`는 소문자 정규 UUID4다. 동일 principal/source/device/IP/revision/scope/reason의 재요청은 기존 행의 ID를 반환한다. FAILED 또는 REMOVED 이후에도 새 규칙을 삽입하지 않는다. 바인딩이 달라지면 409 `REQUEST_ID_BINDING_MISMATCH`다. 응답은 신규·재요청 모두 201이며 `created`/`replayed`로 구분한다. 응답이 유실되면 동일 UUID와 동일 요청으로 재조회하고, 새 UUID를 만들어 반복 차단하지 않는다.

## 정확한 해제와 부분 실패

해제 API는 기존 `POST /api/firewall-rules/{rule_id}/release-requests`이며 확인 문자열은 `RELEASE-FIREWALL-RULE-{rule_id}`다. 각 scope의 ID를 따로 해제한다. 같은 IP의 다른 scope 규칙은 보존한다.

APPLIED뿐 아니라 FAILED 행에도 명시적 해제 요청을 만들 수 있다. Worker는 FAILED 정리를 정확한 ID의 PENDING 해제 요청으로만 허용한다. 정확한 scope/IP/ID 규칙을 삭제한 뒤 잔여 규칙이 없음을 확인해야 REMOVED로 기록한다. 삭제 또는 확인이 실패하면 성공으로 처리하지 않는다. 기기 IP·정책·보호 목록이 바뀌어도 과거 정확한 규칙의 확인·삭제는 허용된다.

광역 규칙이 이미 APPLIED인 경우 원본 MQTT를 별도로 감사 해제해도 광역 재시작 복원이 가능하다. 원본이 REMOVED이면 정확한 source ID의 SUCCEEDED 해제 요청과 non-null `released_at`이 있어야 하며, `requested_at <= released_at <= processed_at`이어야 한다. Rule 제거 commit과 Request 성공 commit 사이 중단 후 다음 cycle에서 정상 수렴하는 경우도 포함한다. 현재 제거보다 이전의 과거 성공은 인정하지 않는다. 첫 PENDING 광역 적용에는 source APPLIED 조건을 그대로 적용한다.

Baseline 복구는 모든 scope의 활성 DB 규칙·해제 대기와 실제 관리 규칙을 확인한다. FAILED 행에 런타임 DROP이 남아 있어도 복구를 통과하지 않는다. Runtime snapshot은 마지막 적용/해제 시도 이후 관측돼야 하며, 오래되거나 알 수 없는 규칙·형식·중복이 있으면 HOLD한다. v2 snapshot은 모든 관리 규칙에 explicit scope를 기록한다. v1은 기존 MQTT 형식만 읽기 호환하고 v2의 누락/미지 scope는 UNAVAILABLE이다.

## 특권 Wrapper 보호

특권 insert는 `/etc/hanium/firewall-protected-ipv4.conf`와 실제 Pi에 할당된 모든 IPv4를 확인한다. 보호 파일은 root:root 0644, `/etc/hanium`과 부모 경로는 root 소유이고 다른 사용자에게 쓰기를 허용하지 않아야 한다. 파일은 일반 파일·비심볼릭링크이며 최소 한 개의 실제 승인 RFC1918 주소가 필요하다. 누락·잘못된 형식·권한·비어 있는 파일·Pi 주소 조회 실패는 insert를 거부한다.

읽기 관측으로 확인한 현재 관리 주소 `192.168.0.3`, Pi `192.168.0.20`은 운영자가 보호 파일 설치 직전에 다시 확인해야 한다. 예제 파일은 추측한 주소를 넣지 않는다. 실제 Pi 주소는 보호 파일에 빠져도 Wrapper의 로컬 IPv4 조회에서 추가 차단한다. loopback은 RFC1918 입력 규칙에서 거부된다. 사용자 프로세스 설정은 이 특권 보호를 대체하지 않는다.

Wrapper 세 인자 호출은 기존 MQTT scope로 유지한다. 광역 check/insert/delete는 네 번째 고정 scope를 전달한다. 호출자가 chain/target/port/binary를 지정할 수 없다. 보호 집합은 insert에만 적용하여, DHCP나 보호 목록 변경 후에도 과거 정확한 규칙을 정리할 수 있다.

## 검증과 남은 실제 확인

로컬 검증은 임시 SQLite DB·가짜 Worker/runtime·Wrapper dry-run만 사용한다. 새/기존 DB, FK·sequence·원자성, UUID 재요청, 승인 이후 IP/정책/해제 변경, FAILED 잔여 정리와 복구 HOLD를 검사한다. 이 결과는 실제 Pi 차단 또는 재부팅 검증을 뜻하지 않는다.

검토된 별도 Linux namespace 검증 자료가 준비되면 관리자가 격리된 시험 환경에서 실행한다. 운영 DB와 기기를 사용하지 않고 새 namespace의 INPUT에서 두 scope 공존, MQTT 이외 포트/프로토콜 범위, exact ID·scope 삭제, 중복/부분 실패를 확인한다. namespace와 고정 보호 파일·실제 로컬 IPv4 강제 검사는 분리해서 근거를 남긴다. namespace 생성·실제 iptables 시험에 필요한 범용 관리자 권한은 현재 비대화형 sudo로 허용되지 않아 아직 실행하지 않았다. 기존 제한된 root-owned Wrapper sudo의 허용 여부와는 별개다.

이후 실제 운영 시험은 보호 경계·별도 시험 근거·운영 백업 확인 후 진행한다. 실제 장비 접근, DHCP 이동, 서비스/보드 재시작, Pi 재부팅 후 복원과 운영 DB 마이그레이션은 각각 별도 검증 상태로 기록한다. 통신이 멈춘 사실만으로 전체 격리·설치 펌웨어·모델 추론·공식 정상 자료 편입을 인증하지 않는다.

## 이후 운영 설치 순서

다음은 검토용 준비 순서이며 지금 운영에 적용하지 않는다.

1. 원본 DB·WAL과 현재 방화벽 규칙을 보관하고, 원래 서비스별 active 상태와 일시정지 계획을 기록한다. 별도 DB 사본에서 migration 011의 FK/integrity/원래 ID·높은 sequence 보존을 확인한다.
2. 실제 관리자·라우터·Pi IPv4를 재확인하고 root 소유 보호 디렉토리/파일을 먼저 준비한다. 새 Wrapper에서는 기존 MQTT insert도 이 보호 파일의 영향을 받는다. 이후 root:root 0755 Wrapper와 `NOSETENV` sudoers를 검토·설치하고 `visudo`로 확인한다. 관리 API의 기존 `NoNewPrivileges=true`는 유지한다.
3. 모든 scope의 저장·조회·Worker·snapshot·release를 함께 읽을 수 있는 정합 릴리스를 준비한다. 운영 DB migration과 서비스 배포는 별도 승인·실제 검증 대상으로 기록하고, 사본 테스트 통과만으로 완료 처리하지 않는다.
4. 원래 active였던 서비스만 복귀시켜 읽기 전용 list/snapshot과 기존 MQTT 경로를 확인한다. 그 근거 이후 별도 광역 차단·정확한 해제·DHCP/재시작/재부팅 시험을 진행하고 각각 실제 실행 여부를 남긴다.
