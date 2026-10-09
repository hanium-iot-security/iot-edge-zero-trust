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

기존 단위·회귀 검증은 임시 SQLite DB·가짜 Worker/runtime·Wrapper dry-run을 사용한다. 새/기존 DB, FK·sequence·원자성, UUID 재요청, 승인 이후 IP/정책/해제 변경, FAILED 잔여 정리와 복구 HOLD를 검사한다. 이 결과는 실제 Pi 차단 또는 재부팅 검증을 뜻하지 않는다.

### 2026/10/9 검증 결과

Windows에서 Worker·Wrapper·Snapshot 관련 184개와 DB·API·정책·복구 관련 494개가 통과했다. 두 묶음의 공통 42개를 제외한 동일 소스의 21개 suite를 Pi 별도 디렉토리에서 함께 실행하여 **636 passed in 101.94s**를 확인했다. Linux 시험 소스는 `6b866961af1200192b8fbe3ae83e8b1939d88f1f`, 전송 TAR SHA256은 `782550c692e0b526872ff6fe3a422434c58d57ef7306b703722f3539b01d97b2`다.

임시 DB·가짜 실행기와 실제 Bash Wrapper의 dry-run을 사용했다. FAILED 광역 삽입 잔여 규칙이 있을 때 baseline 복구 HOLD, 정확한 감사 해제, 오래된 관측 HOLD, 후속 관측 이후 정상 복구까지 연결해 검증했다. 시험 전후 운영 코드·Boot ID와 기존 수집/탐지/방화벽 서비스 active 상태는 유지됐다. 실제 특권 iptables 동작·물리 장비·DHCP·재부팅 검증 결과는 아니다.

### 별도 namespace 실제 시험

`infra/scripts/validate_pi_input_isolation.py`는 stdlib만 사용하는 별도 검증 도구다. 기본 실행과 `--dry-run`은 namespace·프로세스·네트워크 명령을 호출하지 않고 계획 JSON만 출력한다. 실제 실행에는 Linux, euid 0, 정확한 확인 문자열 `CREATE-DISPOSABLE-PI-INPUT-NAMESPACES`가 모두 필요하다. 고정 `/usr/sbin/ip`, `/usr/sbin/iptables`, `/usr/bin/ping`, `/bin/bash`와 현재 Python을 먼저 확인하며, 의존성이 없으면 namespace 생성 전에 실패한다. 임의 바이너리 경로 override와 sudo 호출 기능은 없다.

검토한 소스와 Wrapper의 SHA를 보관한 뒤, 승인된 격리 Linux 시험 환경에서 계획부터 확인한다. 작업 디렉토리는 검토한 repository root다.

```text
python3 infra/scripts/validate_pi_input_isolation.py --dry-run
```

아래 명령은 2026/10/9의 WSL Ubuntu 임시 namespace 시험에서 실행했다. 승인된 격리 시험 환경의 root에서만 사용한다. 출력 JSON과 stderr의 namespace/PID 생성 기록은 기존 파일을 덮어쓰지 않는 새 시험 기록으로 각각 보관한다.

```text
python3 infra/scripts/validate_pi_input_isolation.py --execute --confirm CREATE-DISPOSABLE-PI-INPUT-NAMESPACES
```

도구는 무작위 이름의 Pi/client namespace 두 개를 새로 만든다. 이름이 이미 있으면 거부하고 기존 namespace는 삭제하지 않는다. veth와 peer는 처음부터 두 새 namespace 안에서만 생성하며, 물리 NIC·host INPUT·host route·서비스·DB·`/etc` 파일을 쓰지 않는다. 모든 iptables 호출은 자신이 만든 Pi namespace 안으로 고정한다. 서버와 TCP/UDP/ICMP probe는 부모가 기록한 namespace inode가 현재 inode와 일치하고 host inode와 다름을 확인한 후 listen/send한다. 시험 IP `10.253.94.1/2/3`은 운영 주소·기기 등록값이 아니다. 두 namespace 사이에만 연결되며 host로 연결하거나 default route를 추가하지 않는다.

시험은 source A/B 각각 TCP 1883·9001·22 echo, UDP 9002 echo와 ICMP를 확인한다. 포트 22는 namespace 안의 시험 echo이며 실제 SSH 서비스가 아니다. UDP는 send 성공만으로 통과하지 않고 동일 nonce와 발신 peer의 응답을 요구한다.

1. 두 source의 모든 probe가 정상인 baseline을 확인한다.
2. 기존 Scope를 A에만 삽입하여 A의 TCP 1883만 차단되고 B와 나머지 probe는 정상인지 확인한다.
3. 넓은 Scope를 함께 삽입하여 A의 모든 IPv4 probe가 차단되고 B는 정상인지 확인한다.
4. 넓은 Scope의 exact ID·match만 삭제하고 기존 MQTT 차단이 남는지 확인한다.
5. 넓은 Scope를 다시 삽입한 뒤 기존 Rule의 exact ID·match만 삭제하고 넓은 차단이 남는지 확인한다.
6. 마지막 넓은 Rule을 정확히 삭제하여 A/B 전체 정상 복원을 확인한다. 차단 단계마다 해당 Rule의 packet/byte counter가 이번 probe 이후 실제 증가해야 한다.

Wrapper는 `HANIUM_FW_DRY_RUN=1`로 고정 match만 얻으며 그 출력이 Worker와 같은 사양일 때 namespace의 실제 iptables에 전달한다. **운영 Wrapper의 root 소유 보호 파일 검사·실제 Pi 주소 강제 검사·sudoers 호출, Worker 승인·DB 상태 전이, 물리 장비·DHCP·재부팅은 이 도구의 검증 범위가 아니다.** IPv6·FORWARD도 시험하지 않는다. PASS는 위 namespace 동작과 정상 cleanup에만 한정된다.

SIGINT/SIGTERM/SIGHUP는 취소 flag로 기록하여 자원 생성·receipt 기록 사이를 끊지 않는다. 자식 명령도 별도 session으로 실행하여 터미널 Ctrl-C가 생성 명령을 중간에 끊지 않게 한다. 실패·취소 시 자신이 시작한 서버를 terminate, 필요 시 kill 후 유한 시간 wait/reap하고, inode가 여전히 일치하는 자신이 생성한 namespace만 정리한다. 종료/회수 확인이나 삭제 실패는 PASS로 숨기지 않고 exit 1과 남은 이름/PID·오류를 기록한다. 생성 명령이 timeout/비정상 종료되어 성공을 입증하지 못하면 해당 이름을 `unconfirmed_namespace_creations`로 보고하고 자동 채택·삭제하지 않는다. namespace 정체가 바뀌거나 서버가 살아 있는지 불명확하면 자동 삭제하지 않는다. SIGKILL·전원 중단은 정리를 보장할 수 없으므로, 생성 요청/완료 기록의 이름과 inode 및 실제 PID의 namespace를 운영자가 대조한 뒤 별도로 처리한다. 이름 prefix나 재사용된 PID만으로 기존 자원을 일괄 삭제하지 않는다.

host의 기존 link/route는 전후 읽기 fingerprint만 비교한다. 차이가 있거나 사후 관측이 실패하면 결과는 실패이며 자동 복구·삭제하지 않는다. host INPUT 자체는 관측하지 않으므로 불변을 인증하지 않는다. 각 명령과 서버 종료 대기에는 유한 제한시간이 있지만 전체 시험의 hard deadline은 별도 제공하지 않는다.

**2026/10/9 WSL 실제 시험 — 통과:** 검토·커밋된 `4c96760739132b18b33f274d8efbbaa9b4364efc` 소스를 Ubuntu, Python 3.14.4, kernel `6.18.33.1-microsoft-standard-WSL2`, iptables `1.8.11 (nf_tables)`, euid 0에서 실행했다. 신규 도구의 오류·취소·정리 단위 검증은 Windows Python 3.10.11에서 **41 passed in 0.16s**다. WSL 실제 시험은 7단계 × 2개 source × 5개 probe의 70개 기대 결과를 모두 만족했다. 각 차단 단계에서 해당 DROP의 packet/byte counter 증가를 확인했다.

| 단계 | source A | 정상 대조 source B |
| --- | --- | --- |
| baseline | 모든 probe 정상 | 모든 probe 정상 |
| legacy | TCP 1883만 차단 | 모든 probe 정상 |
| wide / wide_again | 5개 probe 모두 차단 | 모든 probe 정상 |
| release_wide_preserve_legacy | TCP 1883만 차단 유지 | 모든 probe 정상 |
| release_legacy_preserve_wide | 5개 probe 모두 차단 유지 | 모든 probe 정상 |
| restored | 모든 probe 정상, 관리 규칙 없음 | 모든 probe 정상 |

결과는 `status=PASS`, exit 0, `server_reaped=true`, `remaining_owned_namespaces=[]`, `unconfirmed_namespace_creations=[]`, `cleanup_errors=[]`다. 시험 이후 별도 `ip netns list` 조회도 비어 있었다. host link/route의 전후 읽기 fingerprint는 동일했으며 host INPUT 자체는 이 시험의 관측·인증 대상이 아니다. Wrapper dry-run match를 namespace의 실제 iptables로 적용했고, 사용한 Wrapper SHA256은 `19e4d9632ef431df32b7ec799f69c86cf3d46e044854deae95bf5007be08f5fb`다. 개인 보관 원본 JSON의 SHA256은 `0609ebf295b8aab874fa0e4725fede9c64a04bffb220a66613fbfbd4a9380d86`이며 원본 로그·개인 output은 PR에 포함하지 않는다.

이 결과는 운영 Pi의 특권 Wrapper 보호 파일·실제 Pi 주소 검사·sudoers·Worker/DB 상태 전이·물리 장비·DHCP·재부팅 검증을 대신하지 않는다. 해당 항목과 운영 Migration/배포는 여전히 미검증이다. 운영 Pi의 범용 비대화형 sudo는 허용되지 않았고 최근 SSH 연결도 timeout이었다. 이후 Pi 연결·승인된 관리 권한과 운영 백업을 확인한 뒤 별도 검증한다.

이후 실제 운영 시험은 보호 경계·별도 시험 근거·운영 백업 확인 후 진행한다. 실제 장비 접근, DHCP 이동, 서비스/보드 재시작, Pi 재부팅 후 복원과 운영 DB 마이그레이션은 각각 별도 검증 상태로 기록한다. 통신이 멈춘 사실만으로 전체 격리·설치 펌웨어·모델 추론·공식 정상 자료 편입을 인증하지 않는다.

## 이후 운영 설치 순서

다음은 검토용 준비 순서이며 지금 운영에 적용하지 않는다.

1. 원래 서비스별 active 상태와 일시정지 계획을 기록한다. 쓰기 서비스 정지 또는 기존 SQLite 온라인 백업 절차로 일관된 DB 사본과 필요한 WAL·현재 방화벽 규칙을 보관한다. 별도 DB 사본에서 migration 011의 FK/integrity/원래 ID·높은 sequence 보존을 확인한다.
2. 실제 관리자·라우터·Pi IPv4를 재확인하고 root 소유 보호 디렉토리/파일을 먼저 준비한다. 새 Wrapper에서는 기존 MQTT insert도 이 보호 파일의 영향을 받는다. 이후 root:root 0755 Wrapper와 `NOSETENV` sudoers를 검토·설치하고 `visudo`로 확인한다. 관리 API의 기존 `NoNewPrivileges=true`는 유지한다.
3. 모든 scope의 저장·조회·Worker·snapshot·release를 함께 읽을 수 있는 정합 릴리스를 준비한다. 운영 DB migration과 서비스 배포는 별도 실제 검증 대상으로 기록하고, 사본 테스트 통과만으로 완료 처리하지 않는다.
4. 원래 active였던 서비스만 복귀시켜 읽기 전용 list/snapshot과 기존 MQTT 경로를 확인한다. 그 근거 이후 별도 광역 차단·정확한 해제·DHCP/재시작/재부팅 시험을 진행하고 각각 실제 실행 여부를 남긴다.
