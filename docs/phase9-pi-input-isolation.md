# Phase 9 Pi 입력 격리

운영자가 전체 범위를 설정하면 격리된 기기의 Pi IPv4 입력을 모든 포트·프로토콜에서 차단한다. 기존 관리자 확장 API와 정확한 규칙별 해제도 유지한다. 2026/10/25~26 코드 적용·실물 차단과 해제 결과는 [최신 검증 기록](phase9-pi-input-isolation-validation-20261026.md)에 정리했다. 아래의 10/9~11 설치 준비·미배포 설명은 날짜가 명시된 당시 기록이다.

## 범위와 기존 동작

| scope | 적용 범위 | DB protocol / dest_port |
|---|---|---|
| `MQTT_IPV4_TCP_1883` | 해당 IPv4에서 Pi INPUT으로 들어오는 TCP 1883 | `tcp` / `1883` |
| `PI_INPUT_IPV4_ALL` | 해당 IPv4에서 Pi INPUT으로 들어오는 모든 IPv4 프로토콜·포트 | `NULL` / `NULL` |

`FIREWALL_AUTO_SCOPE`의 기본값 `MQTT_IPV4_TCP_1883`은 기존 MQTT 격리를 유지한다. 운영자가 `PI_INPUT_IPV4_ALL`을 설정하면 Worker가 현재 ACTIVE 정책·동일 IPv4·isolated 상태의 APPLIED MQTT 원본에서 별도 광역 PENDING 행을 생성한다. 원본 행의 범위와 Trust 판단 기준은 바꾸지 않는다. 해제를 먼저 처리하고 남은 배치 한도에서 확장을 예약하며, 새 규칙은 이후 cycle에서 재검증하여 적용한다.

자동 확장은 `system:firewall-worker`, 운영 설정을 나타내는 reason, 현재 정책 revision, UUID4와 원본 ID를 기록한다. 같은 원본에 광역 이력이 하나라도 있으면 FAILED·REMOVED를 포함해 자동 재생성하지 않는다. 감사 해제 이후 별도 관리자 요청으로 재확장할 수 있다. 명시적 ALL 설정은 완전한 migration 011 스키마가 없으면 실패하며 dry-run은 행을 생성하지 않는다.

광역 차단은 해당 source IPv4의 Pi INPUT에 한정된다. 다른 호스트 간 통신, FORWARD와 IPv6는 이 범위에 포함되지 않는다. 보호된 관리자·라우터·Pi 주소에는 적용하지 않는다. 다음 Worker cycle에서 적용하므로 Trust의 isolated 전이와 광역 규칙 적용 사이에는 대기 시간이 있다. 운영 화면의 APPLIED/runtime 관측으로 실제 적용을 확인한다.

관리 API는 새 `PENDING` 행만 승인한다. 해당 응답의 `runtime_verified=false`는 실제 방화벽 적용 확인 전임을 뜻한다. Worker는 이후 별도의 적용·정확한 규칙 확인을 수행한다. 새 광역 규칙이 확인되기 전에 원본 MQTT 규칙을 제거하지 않으며, 확인 이후에도 자동 제거하지 않는다.

## 마이그레이션 011

`011_pi_input_isolation.sql`은 이 PR에 배정한 번호다. 2026/10/11 최신 develop과 공개 미병합 PR의 변경 파일에서 중복이 없음을 확인했고, 통합 후보의 001..011 유일·연속 검사도 통과했다. 공식 정상 자료 편입/QC의 후속 마이그레이션은 012 이후 번호를 사용한다.

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

정상 복구는 현재 IP뿐 아니라 대상 기기의 미해결 FAILED 규칙에 남은 과거 source IP도 검사한다. 해당 주소들에서 다른 기기 소유 행과 처리된 해제 요청까지 포함한 마지막 방화벽 활동 이후의 runtime 관측을 요구한다. 과거 REMOVED 규칙의 주소를 영구적으로 묶지는 않는다.

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

### 2026/10/11 최소 표시 보완과 로컬 회귀

Devices 상세와 Isolation 정확한 해제·이력의 protocol/port를 공통 표시 컴포넌트로 연결했다. `PI_INPUT_IPV4_ALL` 응답의 NULL은 `전체 IPv4` / `모든 포트`로 표시하고 scope 없는 legacy의 TCP 1883 표시는 유지한다. 광역 승인 UI나 전체 상태 번역을 추가한 변경은 아니다.

API·repository·worker·recovery·migration·wrapper·snapshot 회귀 **242개**, 프론트 **13개**가 통과했다. 프론트의 새 3개 계약 시험은 mock API 응답을 공통 컴포넌트에 전달하여 실제 React server renderer(`renderToStaticMarkup`)의 HTML을 확인한다. 이는 Pi의 운영 HTTP 서버·브라우저 화면을 검증한 결과와 구분한다. Vite production build, 새 helper/test의 lint와 `git diff --check`도 통과했으며 기존 500 kB 초과 bundle 경고는 남는다.

정확한 실행 명령·출력 원문·exit code는 개인 보관 `output/phase9-resume-20261011/isolation-followup-validation-20261011.json`에 기록한다. 첫 실행의 전체 원문을 재구성하지 않고 동일 검증을 다시 실행해 기록했다. 임시 로컬 DB·가짜 runtime과 로컬 렌더/빌드의 근거이며 **운영 미배포** 상태다. 이 검증 중 Pi 설치·차단·운영 migration·서비스 정지·재부팅은 실행하지 않았다.

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

이 결과는 운영 Pi의 특권 Wrapper 보호 파일·실제 Pi 주소 검사·sudoers·Worker/DB 상태 전이·물리 장비·DHCP·재부팅 검증을 대신하지 않는다. 해당 항목과 운영 Migration/배포는 여전히 미검증이다. WSL 시험 이후 2026/10/9에 Pi SSH를 다시 연결해 읽기 전용 준비 상태와 운영 DB 사본을 확인했다. Pi의 일반 관리자 명령에는 비밀번호가 필요하고, 비대화형 권한은 기존 설치 Wrapper에 한정된다. 이후 관리자 권한으로 Pi 임시 namespace 통신 시험을 실행해 아래 결과를 확인했다. 운영 보호 파일 설치·sudoers·Worker/DB 상태 전이·실물 기기·DHCP·재부팅은 여전히 별도 검증 대상이다.

이후 실제 운영 시험은 보호 경계·별도 시험 근거·운영 백업 확인 후 진행한다. 실제 장비 접근, DHCP 이동, 서비스/보드 재시작, Pi 재부팅 후 복원과 운영 DB 마이그레이션은 각각 별도 검증 상태로 기록한다. 통신이 멈춘 사실만으로 전체 격리·설치 펌웨어·모델 추론·공식 정상 자료 편입을 인증하지 않는다.

### 별도 root Wrapper 보호 시험 — 2026/10/9

앞의 70개 통신 시험과 별도로, 제품 소스 밖에서 검토한 시험 스크립트로 WSL Ubuntu의 새 익명 mount·network namespace에서 Wrapper를 실제 실행했다. `HANIUM_FW_DRY_RUN`을 지정하지 않고 고정 `ip`·`stat`·`iptables` 경로를 사용했다. 이 시험은 보호 조건에 따른 삽입 거부와 정확한 규칙 존재·삭제를 확인하며, 패킷 송수신 시험은 아니다. 환경은 Python 3.14.4, kernel `6.18.33.1-microsoft-standard-WSL2`, iptables `1.8.11 (nf_tables)`, euid 0이었다.

namespace inode가 host와 다르고 생성 당시 값과 같은지 확인한 뒤, private mount propagation과 namespace 안의 `/etc`·`/run` tmpfs를 검증했다. 보호 파일·소유권·권한 변경은 이 tmpfs 안에서만 수행했다. 시험용 Pi 주소 `10.253.95.1`, 대상 `10.253.95.2`, 관리 주소 `10.253.95.254`는 운영 주소가 아니다. 파일 누락·빈 파일·잘못된 주소·소유권·쓰기 권한·심볼릭링크·부모 경로 문제, 관리 주소·로컬 주소 및 삽입 후 보호 목록 변경의 15개 거부 조건을 두 scope에서 확인했다. 정상 insert/check 4개, 보호 대상의 legacy 규칙만 삭제하며 wide 규칙 보존, 보호 파일이 없어진 뒤 wide 규칙 정확한 삭제까지 **36개 모두 PASS**였다. 각 거부는 exit 65와 INPUT 규칙 불변을 함께 확인했다.

전체 결과는 exit 0, `status=PASS`, `child_process_gone=true`, `cleanup_errors=[]`, `observation_errors=[]`이며, 자식 namespace의 마지막 INPUT은 `-P INPUT ACCEPT`였다. host의 `iptables-save`, link/route fingerprint와 `/etc`·`/etc/hanium`·보호 파일·`/run` 메타데이터의 전후 관측은 같았다. Wrapper 소스도 바뀌지 않았다. 익명 namespace와 tmpfs는 자식 종료로 소멸하며, 자식 시험 실행에는 120초 제한과 종료·회수 처리를 두었다. 이 결과는 해당 실행의 관측·정리 근거이며 전원 중단 등 모든 중단 상황의 정리를 인증하지 않는다.

사용한 Wrapper SHA256은 `19e4d9632ef431df32b7ec799f69c86cf3d46e044854deae95bf5007be08f5fb`, 개인 보관 시험 스크립트 SHA256은 `4e30c331cc0e4130fb20f504c2925c183a80ac83b22b741b84dc85ec381b504a`, 원본 결과 JSON SHA256은 `75f23bb2d92c37e17efa223b4b107f7d4d0e5ed2ee15cfed99cec830030ad4aa`다. 개인 시험 스크립트·로그는 PR에 포함하지 않는다. 운영 Pi의 설치 파일 소유권·sudoers·서비스 권한·Worker/DB 상태 전이·실제 기기 통신·DHCP·재부팅은 이 시험으로 검증되지 않았다.

### Historical: Pi 준비 점검과 운영 DB 사본 — 2026/10/9

이 절의 Commit·Boot·Session·HOLD와 미실행 복구 상태는 **2026/10/9 당시 기록**이다. 2026/10/11 현재 복구 상태는 다음 절과 구분한다.

Pi 운영 코드와 원격 develop은 `53ec270219692784ce8864976511a52c962cec35`, Boot ID는 `5f5fc610-af8f-4437-9e2c-ccf2af422c91`다. 수집·특징·탐지·방화벽 관련 기존 서비스 6개가 active였고, API의 `NoNewPrivileges=yes`를 확인했다. 관리자 `192.168.0.3`, 공유기 `192.168.0.1`, Pi `192.168.0.20`을 읽기 관측으로 다시 확인했다. 이 값은 이후 설치 직전에 다시 확인한다.

설치 Wrapper와 `/usr/local/sbin` 부모 경로는 root 소유이고 다른 사용자에게 쓰기를 허용하지 않았다. 설치 파일 SHA256은 `417b567ff27757db93fceeb4609525232298488c9474d1940f263e20e9aad321`이며 아직 기존 MQTT 전용이다. `/etc/hanium`과 새 보호 파일은 없었다. `sudo -n true`는 비밀번호 요구로 거부됐고, 허용된 기존 Wrapper의 `list`는 읽기 성공했다. 당시 실제 INPUT은 기본 ACCEPT이며 관리 규칙은 없었다. snapshot timer는 active, v1 snapshot은 available·error 없음·빈 managed_rules로 최신 관측을 기록했다.

세 센서의 최근 3분 MQTT에는 JSON·토픽 오류가 없었고, ESP32는 메시지당 57바이트, Pico는 129~132바이트였다. 초기 준비 점검에서는 MQTT/Packet 특징과 Packet Rule·IF·Trust 처리 시각이 전진했다. 이 관측은 공식 학습 편입·펌웨어 설치 해시·정상 허용 범위 승인 결과가 아니다.

검토된 `94eecaf186cc826fe6b8efcf9932e6dedc5ff1dd`의 최소 소스만 Pi 별도 시험 폴더에 전달했다. TAR SHA256은 `f10ec790772611183593df0fb5d71290f48c23a9d31fd15b28f2b56e5ce524a8`이며 신규 도구의 단위 검증은 Python 3.10.11에서 **41 passed in 0.22s**, 기본 실행은 DRY_RUN이었다. 이 41개는 가짜 실행기를 사용하는 시험이며 Pi root namespace 실행 결과가 아니다.

**Pi 임시 namespace 실제 시험 — 통과:** 같은 `94eecaf186cc826fe6b8efcf9932e6dedc5ff1dd` 최소 소스로 관리자 권한의 실제 실행을 진행했다. 사후 읽기 확인한 환경은 Python 3.10.11, kernel `6.18.29+rpt-rpi-2712`, iptables `1.8.11 (nf_tables)`다. 7단계 × 2개 source × 5개 probe의 70개 기대 결과를 모두 만족했고 차단 단계의 DROP counter 증가도 확인했다. 결과는 exit 0, `status=PASS`, `host_links_routes_unchanged=true`, `server_reaped=true`, `remaining_owned_namespaces=[]`, `unconfirmed_namespace_creations=[]`, `cleanup_errors=[]`였다. 마지막 단계에는 두 source의 모든 통신이 정상이고 관리 규칙은 없었다. 별도 `ip netns list`도 비어 있었고 기존 운영 Commit·Boot ID·수집 서비스는 유지됐다.

이 실행도 Wrapper dry-run의 고정 match를 새 namespace의 실제 iptables에 적용하는 구조다. 사용 Wrapper SHA256은 `19e4d9632ef431df32b7ec799f69c86cf3d46e044854deae95bf5007be08f5fb`, 개인 보관 결과 JSON SHA256은 `6d4a069cd3893730d3ca886135fc74d3dc74483d4e4d5b420b99c812c26f83f4`다. 관리자 직접 실행의 출력은 별도 개인 기록으로 보관했다. 운영 host INPUT 관측·인증, 특권 Wrapper 보호 파일 검사·설치 sudoers, Worker/DB 상태 전이, 실물 기기·DHCP·재부팅은 이 시험에 포함되지 않는다.

22:42 KST에 운영 DB를 읽기 전용 연결의 SQLite 온라인 backup으로 별도 파일에 보관하고, 그 사본을 다시 복제해 Migration 011을 시험했다. 원본 backup 140,869,632바이트의 SHA256은 `b8e480f570f886a9aee6b56f7396053c3d1c7bf0eada5003cf17bc98abcf689a`다. 사본에서 기존 19개 테이블의 원래 컬럼·모든 행 digest, 방화벽 20행·해제 16행·sequence 20·기존 Migration 기록이 보존됐다. 기존 모든 방화벽 범위는 MQTT로 유지됐다. integrity/FK 검사와 두 번째 Migration no-op·사본 파일 SHA 불변도 통과했다. 보관 원본 SHA는 그대로였고 운영 DB 스키마는 10을 유지했다. 운영 DB 원본·사본과 개인 로그는 PR에 첨부하지 않는다.

이 사본 검증은 운영 Migration 적용·서비스 릴리스·rollback 실행 검증이 아니다. 당시 Migration 번호 조율은 남아 있었으며 위 2026/10/11 병합 전 대조에서 011 배정을 확인했다. 실제 배포 직전의 새 일관된 백업·현재 상태 확인은 남아 있다.

후속 조회에서는 **22:42:30~22:42:40 KST의 10초 구간**이 `FAILED/LATE_CAPTURE`로 확인됐다. 캡처 시작이 1.30814초 지연되어 Session 108이 FAILED로 마감됐고, Session 109에서 수집을 이어가고 있다. 해당 실패 segment에는 캡처 파일·특징 데이터가 없다. MQTT 수신과 이후 Packet 수집·특징 처리는 계속되지만 Packet Rule·IF·Trust의 처리 경계는 22:42:30에서 HOLD 중이다. 서비스가 active라는 사실만으로 탐지 전진을 정상으로 표시하지 않는다.

이 실패는 DB backup·사본 검증 작업과 같은 시간대에 발생했다. 당시 DB commit과 sidecar 저장 지연도 관측됐지만, 시험 작업이 캡처 지연에 기여했는지는 확인되지 않았다. 손실 구간을 자동 승인하거나 캡처 지연 기준을 완화하지 않았다. 첫 운영 core dry-run은 보호된 `data/recovery/planned` 경로의 권한 오류로 거부됐으며 `database_committed=false`였다. 이후 관리자 권한의 읽기 전용 조회에서 Rule·IF 모두 `can_execute=true`·차단 사유 없음, ID 유지와 경계 `22:42:30 → 22:42:40 KST`를 확인했다. 계획은 손실 승인 전 초안으로 기록했고 실제 복구는 실행하지 않았다. 정확한 손실 구간 승인 이후 복구와 실제 Rule·IF·Trust 전진 확인은 남아 있다.

### 2026/10/11 복구 완료의 읽기 근거

보관한 공식 pair status는 Session 109와 110 정상 prefix의 두 replay에서 `REPLAY_COMPLETE`, 이어서 Session 110 → 111의 live 복구에서 progress `0 → 1 → 2`, `COMPLETE`를 기록한다. live 적용 감사는 68/69이며 원본 실패 tail 49639의 `FAILED/LATE_CAPTURE`, 파일 없음·캡처 시간 없음은 보존됐다. 실패 데이터를 성공 자료로 바꾸거나 공식 QC·학습에 편입했다는 뜻은 아니다.

개인 보관 `final-live-evidence-audit-20261011.json`은 **89 checks / 0 failures**, SHA256 `128643f1bdb46117d541a9859271646c87911547584956b03c4f697d444c22a5`다. 최종 freshness 관측의 실제 UTC는 `2026-10-11T05:21:44.494114Z`이며 파일명의 0522는 라벨이다. 당시 Boot는 `ce3207f0-991b-4252-9da4-d1f90e25f5dd`, Pi Commit은 `542455f397588b97eb21fa075de70bbd470c3893`, Session 111은 RUNNING이다. 다섯 처리 checkpoint는 05:21:30Z, MQTT builder는 05:21:40Z, 세 기기 MQTT는 최신이며 추가 FAILED는 없었다. 수집·Subscriber·Broker는 기존 PID를 유지했다. active/pending 방화벽 규칙은 0개였다.

이것은 보관한 관측 시점의 근거이며 설치 직전의 새 조회를 대신하지 않는다. 원격 DB·PCAP·backup 바이트의 운영 사후 SHA를 인증하지도 않는다. 복구에 사용한 Subscriber 6회와 writer 누적 151.171591초/180초 승인은 완료됐고 **새 배포·서비스 정지·재부팅에 재사용하지 않는다**.

현재 광역 승인 UI는 구현하지 않았다. 기존 Devices와 Isolation의 상세·해제·이력 화면은 `PI_INPUT_IPV4_ALL`의 NULL protocol/port를 `전체 IPv4` / `모든 포트`로 표시하고, scope 없는 legacy 응답의 TCP 1883 표시는 유지한다. Devices·Isolation과 같은 trigger event의 이력은 REMOVED보다 미해제 규칙을 우선 선택한다. 한쪽 scope만 해제하면 남은 규칙의 ID가 다음 해제 대상이며, APPLIED/FAILED에 대해서만 해당 ID의 확인 문구로 요청할 수 있다. 기존 정확한 해제 UI와 서버의 관리자 승인 API를 구분한다. 전체 한글 상태 번역은 별도 후속 범위다.

## 이후 운영 설치 순서

다음은 검토용 준비 순서이며 지금 운영에 적용하지 않는다.

최종 candidate·읽기 preflight·설치 경로·조건부 명령은 [운영 활성화 준비](phase9-pi-input-isolation-activation.md)에 정리한다. PR111은 develop에서 분리된 격리 브랜치다. 2026/10/11 15:03 KST에 적용한 Pi API 코드 `ffa82c00b31ebdfcd621b83aa13d1597bd02b26c`와 PR111 구현을 모두 포함하는 통합 candidate를 검토한 뒤 배포해야 한다. 설치 직전의 새 HEAD와 실행 경로도 확인한다. 2026/10/11 read-only remote 조회의 develop은 여전히 `53ec270219692784ce8864976511a52c962cec35`였으며, 이는 Pi HEAD와 다르다.

1. 원래 서비스별 active 상태와 일시정지 계획을 기록한다. 쓰기 서비스 정지 또는 기존 SQLite 온라인 백업 절차로 일관된 DB 사본과 필요한 WAL·현재 방화벽 규칙을 보관한다. 별도 DB 사본에서 migration 011의 FK/integrity/원래 ID·높은 sequence 보존을 확인한다.
2. 실제 관리자·라우터·Pi IPv4를 재확인하고 root 소유 보호 디렉토리/파일을 먼저 준비한다. 새 Wrapper에서는 기존 MQTT insert도 이 보호 파일의 영향을 받는다. 이후 root:root 0755 Wrapper와 `NOSETENV` sudoers를 검토·설치하고 `visudo`로 확인한다. 관리 API의 기존 `NoNewPrivileges=true`는 유지한다.
3. 모든 scope의 저장·조회·Worker·snapshot·release를 함께 읽을 수 있는 정합 릴리스를 준비한다. 운영 DB migration과 서비스 배포는 별도 실제 검증 대상으로 기록하고, 사본 테스트 통과만으로 완료 처리하지 않는다.
4. 원래 active였던 서비스만 복귀시켜 읽기 전용 list/snapshot과 기존 MQTT 경로를 확인한다. 그 근거 이후 별도 광역 차단·정확한 해제·DHCP/재시작/재부팅 시험을 진행하고 각각 실제 실행 여부를 남긴다.
