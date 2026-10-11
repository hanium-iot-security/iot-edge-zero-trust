# Pi IPv4 INPUT 격리 운영 활성화 준비

이 문서는 명령 검토용이다. 작성·로컬 검증 중 Pi 설치, host 방화벽 변경, 운영 DB migration, 서비스 정지와 재부팅은 실행하지 않았다. 10/9 임시 namespace 시험과 DB 사본 검증은 [기존 문서의 Historical 기록](phase9-pi-input-isolation.md)을 참고한다.

2026/10/11 로컬 승인 준비에서 API·repository·worker·recovery·migration·wrapper·snapshot 회귀 **242개**, 프론트 **13개**(광역/legacy/missing 응답의 shared React render 계약 3개 포함)가 통과했다. 19개 업무 테이블 집합 보존을 추가한 기존 migration 시험도 재실행해 통과했다. Vite production build, 새 helper/test 정적 검사와 `git diff --check`가 통과했다. 임시 로컬 DB·가짜 Worker·dry-run 및 로컬 화면 빌드의 결과이며 운영 설치·차단 완료를 인증하지 않는다.

## 최종 릴리스 조건

- 통합 candidate가 2026/10/11 15:03 KST에 적용한 Pi API 코드 `ffa82c00b31ebdfcd621b83aa13d1597bd02b26c`(복구 `542455f`·조회 경합 수정 `d87bfd4` 포함)와 PR111 구현을 모두 포함해야 한다. 설치 직전 새 Pi HEAD와 서비스 실행 경로를 다시 대조해 이후 변경도 보존한다. PR111 단독 HEAD를 운영 checkout하지 않는다. base develop과 현재 Pi HEAD가 다른 상태를 먼저 해결한다.
- merge 직전 모든 migration 파일의 번호가 유일·연속인지, 실제 `schema_migrations`의 이름과 번호가 일치하는지 확인한다. 현재 PR111만 011을 추가하며 조회한 sibling API/model·normal-pilot 작업 트리에는 001..010만 있었다. 다른 PR의 미래 011 예약을 확정하지는 못한다. 충돌하면 SQL 파일 번호, runner의 `FOREIGN_KEY_REBUILD_MIGRATIONS`, `firewall_repository.has_scope_schema`의 버전 경계, 문서·시험을 함께 조정한 candidate를 다시 검증한다. runner는 적용된 번호를 건너뛰므로 파일 번호 검사만으로 이미 적용된 다른 migration 이름과의 충돌을 탐지했다고 간주하지 않는다.
- 설치 전 예상 운영 schema는 001..010, 기존 업무 테이블 집합은 19개다(`schema_migrations`, `sqlite_sequence` 제외). migration은 기존 firewall table을 교체하며 permanent table을 추가하지 않는다. 새 일관된 **사본**에서 기존 컬럼의 모든 행·ID, sqlite_sequence, release FK와 테이블 집합을 비교하고 FK/integrity 및 두 번째 no-op을 확인한다. 실제 운영 적용 완료는 별도 사후 근거로 기록한다.
- 새 작업의 서비스 중단·손실·복귀 조건을 별도로 승인하고 원래 active 서비스 목록을 기록한다. 완료된 복구의 6회 Subscriber/180초 writer 승인을 재사용하지 않는다. Capture·Subscriber·Broker·reboot는 설치에 자동 포함되지 않는다.

## 설치 직전 읽기 preflight

검토한 candidate의 SHA와 원격 상태를 새 파일에 기록한다. 아래는 값 조회 명령이며 비밀 키나 `.env` 내용을 출력하지 않는다.

```sh
cd /home/pi/iot-edge-zero-trust
git rev-parse HEAD
git status --porcelain
cat /proc/sys/kernel/random/boot_id
/usr/sbin/ip -o -4 addr show
/usr/sbin/ip -4 route show
systemctl show packet-capture.service mqtt-subscriber.service mosquitto.service detection-orchestrator.service mqtt-feature-builder.service firewall-worker.service --property=ActiveState,MainPID,LoadState
systemctl show packet-feature-extractor.timer firewall-runtime-snapshot.timer --property=ActiveState,LoadState
systemctl show iot-edge-api.service --property=NoNewPrivileges,User,Group,ActiveState
sudo -n /usr/local/sbin/hanium-firewall-rule list
```

API unit 명칭이 실제 설치와 다르면 먼저 `systemctl list-unit-files`에서 확인해 그 고정 명칭을 사용한다. 위 예시 unit 존재 여부를 추정해 stop/restart하지 않는다. DB는 `file:...?...mode=ro`와 `PRAGMA query_only=ON`의 짧은 조회 후 닫는다. 읽기 대상은 schema 버전/이름·테이블 목록, 최신 capture session/FAILED, 필요한 checkpoint·세 기기 freshness, PENDING/APPLIED firewall 및 PENDING release다. 운영 원본에 integrity/전체 scan을 실행하지 않고 사본에서 수행한다.

새 관리자 워크스테이션·라우터·게이트웨이 및 Pi 주소를 실제 연결/주소 정보와 대조한다. 10/9의 관리자 `.3`, 라우터 `.1`, Pi `.20`을 승인된 현재 allowlist로 자동 간주하지 않는다. API 관리자 키는 서버 설정에서 존재 여부만 확인하며 프론트 빌드·공개 응답·명령 로그에 넣지 않는다.

## 승인 이후 설치 명령 템플릿

검토한 root 소유 staging 디렉토리의 `release`에 candidate와 hash manifest가 있고, `approved-protected-ipv4.conf`에 **재확인·승인한** RFC1918 IPv4가 하나 이상 기록된 경우에만 사용한다. 보호 파일에는 관리자·라우터·신뢰 gateway를 한 줄에 하나씩 넣는다. Pi의 로컬 IPv4는 wrapper가 추가 보호한다. 비어 있는 example을 그대로 설치하면 기존 MQTT insert까지 거부된다.

```sh
sudo install -d -o root -g root -m 0755 /etc/hanium
sudo install -o root -g root -m 0644 /run/phase9-isolation-stage/approved-protected-ipv4.conf /etc/hanium/firewall-protected-ipv4.conf
sudo install -o root -g root -m 0755 /run/phase9-isolation-stage/release/infra/scripts/hanium-firewall-rule /usr/local/sbin/hanium-firewall-rule
sudo visudo -cf /run/phase9-isolation-stage/release/infra/sudoers/hanium-firewall-worker
sudo install -o root -g root -m 0440 /run/phase9-isolation-stage/release/infra/sudoers/hanium-firewall-worker /etc/sudoers.d/hanium-firewall-worker
sudo visudo -c
sudo stat -c '%U:%G %a %n' /etc /etc/hanium /etc/hanium/firewall-protected-ipv4.conf /usr/local/sbin /usr/local/sbin/hanium-firewall-rule /etc/sudoers.d/hanium-firewall-worker
sudo sha256sum /usr/local/sbin/hanium-firewall-rule /etc/hanium/firewall-protected-ipv4.conf /etc/sudoers.d/hanium-firewall-worker
```

staging 및 설치 경로는 regular file, symlink 없음, root 소유, group/other 쓰기 없음이 조건이다. 기존 privileged 파일·unit의 내용/hash와 active 상태도 변경 전에 보관한다. sudoers는 `pi`에게 이 고정 wrapper만 `NOPASSWD: NOSETENV`로 허용한다. 임의 iptables·shell·사용자 선택 바이너리를 허용하지 않는다. API의 `NoNewPrivileges=true`를 유지하며 API는 승인 PENDING 행만 저장한다.

보호 디렉토리를 먼저 만든 후 검토한 unit을 설치한다. 새 worker/snapshot unit은 `/etc/hanium`을 read-only mount하므로 이 경로가 없으면 서비스 시작이 실패할 수 있다.

```sh
sudo install -o root -g root -m 0644 /run/phase9-isolation-stage/release/infra/systemd/firewall-worker.service /etc/systemd/system/firewall-worker.service
sudo install -o root -g root -m 0644 /run/phase9-isolation-stage/release/infra/systemd/firewall-runtime-snapshot.service /etc/systemd/system/firewall-runtime-snapshot.service
sudo install -o root -g root -m 0644 /run/phase9-isolation-stage/release/infra/systemd/firewall-runtime-snapshot.timer /etc/systemd/system/firewall-runtime-snapshot.timer
sudo systemd-analyze verify /etc/systemd/system/firewall-worker.service /etc/systemd/system/firewall-runtime-snapshot.service /etc/systemd/system/firewall-runtime-snapshot.timer
```

코드 교체·운영 migration `venv/bin/python -m db.migration_runner`·`systemctl daemon-reload` 및 worker/API/timer 재시작은 승인된 정지/복귀 절차에 포함한 뒤 실행한다. 신·구 API/Worker/snapshot/DB가 섞인 상태에서 writer를 복귀시키지 않는다. 기존 코드로 단순 checkout하는 DB rollback을 하지 않는다. 실패 시 원래 active 서비스만 복구하는 계획과 DB/schema 호환성을 먼저 확정한다.

## 광역 확장과 정확한 해제의 조건

2026/10/11 15:04 KST 관측에서 세 기기는 정상 수신 중이고 active/pending 규칙은 0개였다. 지금 확장할 원본 규칙이 있다는 뜻이 아니다. 정상 기기의 최초 격리 관리자 API/CLI는 현재 없다. 실제 탐지 대표 이벤트와 v2 Trust 판단으로 격리된 뒤 Worker가 원래 MQTT 규칙을 적용하는 경로를 사용한다. 실장비 시험은 대상·펌웨어·전송/공격 범위·시각·정상 대조 기기를 별도로 확인한 뒤 진행한다. 시험 전에 같은 대상의 MQTT와 확인할 TCP/UDP/ICMP 통신 성공을 확보한다. 임의 DB 상태·Trust 점수·정책 변경으로 확장 조건을 만들지 않는다. 별도로 승인된 실제 MQTT 격리에서 다음 값을 읽어 고정해야 한다.

1. 원본 Rule은 동일 device/IP의 `MQTT_IPV4_TCP_1883`, `DROP`, `APPLIED`이며 정확한 runtime match가 있다.
2. 기기는 현재 `isolated`, IP ownership 일치, 정책 ACTIVE 및 revision 일치, PENDING DISABLED/해제 없음이다.
3. 신규 wide PENDING/APPLIED/FAILED가 없으며 원본 규칙·정책·기기/IP를 다시 확인한다.
4. `POST /api/firewall-rules/{source_rule_id}/scope-extension-requests`의 scope·UUID4·reason·confirmation을 검토한다. `requested_by`는 인증된 서버 principal이며 요청자가 지정하지 않는다. 동일 요청 UUID 재시도는 같은 행을 반환한다.

API가 201/PENDING을 반환한 것만으로 차단 완료로 표시하지 않는다. Worker의 exact match 후 APPLIED와 runtime snapshot v2를 함께 확인한다. wide는 Pi의 INPUT IPv4 전체이며 IPv6·FORWARD·다른 서버 통신을 인증하지 않는다. 넓은 규칙 해제는 해당 wide Rule ID의 `release-requests`와 감사·runtime 부재 확인을 사용한다. 기존 MQTT 규칙은 별개이며 자동 해제되지 않는다.

광역 승인 입력 UI, 관리자 정책 revision 선택/confirmation 화면은 아직 없다. 기존 정확한 해제/이력 화면과 NULL 필드 표시만 호환된다. 실제 차단·정확한 해제·DHCP 이동·서비스 재시작·재부팅 복원은 각각 별도 승인·증거가 필요하다.
