# Firewall Worker 운영 가이드

Phase 4 세부계획 §2.6 / P4-6-01 기준. Trust Score가 격리를 결정하면 `firewall_rules`에
`PENDING` Row가 남고, 이 Worker가 실제 iptables에 TCP 1883 DROP Rule을 적용한다.

## 1. 목적과 책임 경계

| 구분 | 담당 | 내용 |
|---|---|---|
| DB 상태·Repository | 정현수 | `firewall_rules` 상태 전이, `firewall_release_requests` queue, 조회/요청 API |
| iptables Worker·운영 | 원우민 | 실제 Rule 적용·해제·Release Request 처리·Reconciliation, sudoers, systemd, 실기기 검증 |

**`devices.status=isolated`는 Trust 정책의 격리 "결정" 상태이고,
`firewall_rules.status=APPLIED`가 실제 네트워크 차단 "적용" 상태다.**
공식 격리 성공은 `APPLIED` + 실제 MQTT 연결·Publish 실패가 모두 확인된 경우에만 인정한다.

## 2. 사전 조건

- [ ] Migration 006까지 적용된 DB (`firewall_release_requests` 테이블과 partial unique index)
- [ ] 테스트 Device(ESP32 #2)가 공유기 DHCP 예약 또는 고정 Lease로 IP 고정
- [ ] `devices.ip_address`와 실제 Device IP 일치 확인

```bash
sqlite3 backend/data/iot_security.db \
  "SELECT device_id, ip_address, status, trust_score FROM devices;"
ping -c 1 192.168.0.5
```

- [ ] `.env`의 `FIREWALL_PROTECTED_IPS`에 Broker·관리자 노트북 IP 등록
      (Pi #1 = `CAPTURE_INTERFACE_IP`는 자동 포함되지만 명시해도 무방)
- [ ] `iptables` 설치 확인 (`which iptables` → Wrapper 기본값 `/usr/sbin/iptables`)

> **Protected IP를 반드시 확인할 것.** 관리자 노트북 IP가 빠진 상태에서 그 IP로 Rule이
> 생성되면 SSH·Dashboard 접근이 끊길 수 있다. Worker는 Protected IP Rule을 즉시
> `FAILED`로 만들고 iptables까지 보내지 않는다.

## 3. 설치

### Rule Wrapper + sudoers

방화벽 명령은 root 소유 Wrapper 하나만 거친다. `iptables`를 sudoers로 직접 허용하지
않는다.

```bash
# 1) Wrapper 설치 (root 소유, pi가 수정할 수 없어야 함)
sudo install -o root -g root -m 0755 \
  infra/scripts/hanium-firewall-rule /usr/local/sbin/hanium-firewall-rule

# 2) sudoers 설치
sudo cp infra/sudoers/hanium-firewall-worker /etc/sudoers.d/hanium-firewall-worker
sudo chmod 0440 /etc/sudoers.d/hanium-firewall-worker
sudo visudo -c -f /etc/sudoers.d/hanium-firewall-worker   # 반드시 문법 검사

# 3) 동작 확인 (비밀번호 없이 실행되어야 함)
sudo -n /usr/local/sbin/hanium-firewall-rule list

# 4) 조립되는 Rule 규격 확인 (실행하지 않음)
sudo -n HANIUM_FW_DRY_RUN=1 /usr/local/sbin/hanium-firewall-rule insert 192.168.0.5 1
#   또는 로컬에서: HANIUM_FW_DRY_RUN=1 bash infra/scripts/hanium-firewall-rule insert 192.168.0.5 1

# 5) 권한 확인 — root 소유이고 pi 쓰기 권한이 없어야 함
ls -l /usr/local/sbin/hanium-firewall-rule
```

**왜 Wrapper인가**: sudoers 와일드카드는 인자를 강제할 수 없다. `iptables -A INPUT *`를
허용하면 pi 계정이 Worker를 거치지 않고 임의의 INPUT Rule을 root 권한으로 추가할 수
있다(예: SSH 차단, 통제를 무력화하는 ACCEPT). Python의 `validate_rule_row()`는 직접
실행한 sudo 명령을 막지 못한다. Wrapper는 Operation·Source IP·Rule ID만 받고
Chain·Port·Target·Comment를 스스로 조립하므로 호출자가 규격을 바꿀 수 없다.

Wrapper가 허용하는 것은 4개뿐이다: `check`, `insert`, `delete`, `list`.
사설 IPv4가 아닌 Source IP나 숫자가 아닌 Rule ID는 Wrapper에서 거부된다(종료 코드 65).

> **Wrapper 파일 권한이 이 통제의 전제다.** pi가 Wrapper를 수정할 수 있으면 sudoers
> 제한이 무의미해진다. 반드시 root 소유이고 다른 사용자에게 쓰기 권한이 없어야 한다.

> **계정 권한도 함께 확인할 것.** Raspberry Pi OS 기본 설정에서 `pi` 계정은
> `/etc/sudoers.d/010_pi-nopasswd` 등으로 모든 명령에 sudo 권한을 갖는 경우가 많다.
> 그 상태라면 Wrapper 제한은 "Worker가 실수로 잘못된 Rule을 넣는 것"만 막고, 계정
> 탈취에 대한 방어는 되지 않는다. 가능하면 서비스 전용 계정(예: `hanium`)을 만들고
> blanket sudo 없이 Wrapper만 허용한 뒤 systemd Unit의 `User=`를 바꾼다.
> (Phase 4에서는 폐쇄형 테스트베드 기준으로 `pi` 계정을 사용한다.)

### systemd

```bash
sudo cp infra/systemd/firewall-worker.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now firewall-worker
systemctl status firewall-worker
journalctl -u firewall-worker -f
```

> Unit은 `NoNewPrivileges=false`다. `sudo`가 setuid 바이너리라 `true`로 두면 모든
> iptables 호출이 실패한다. 대신 sudoers로 명령 범위를 좁혀 위험을 줄인다.

## 4. Phase 6-B 배포 순서

새 API와 Worker는 `firewall_release_requests` 테이블을 조회한다. Pi 배포 때 코드가
Migration보다 먼저 올라가면 `no such table: firewall_release_requests` 오류가 날 수
있으므로 다음 순서를 지킨다.

1. DB Backup 생성
2. Migration 006 적용
3. `firewall_release_requests` 테이블과 `uq_firewall_release_requests_pending_rule`,
   `idx_firewall_release_requests_status_requested` index 확인
4. 코드 배포
5. Backend API와 Firewall Worker 재시작
6. Release Request API 생성, Worker 처리, Recovery Preflight Gate smoke test

## 5. 상태 전이

| 상태 | 의미 | 다음 |
|---|---|---|
| `PENDING` | Trust가 격리를 결정, 아직 미적용 | Worker가 적용 → `APPLIED` |
| `APPLIED` | 실제 iptables Rule 존재 | 해제 → `REMOVED` |
| `FAILED` | Validation 오류 또는 일시 오류 3회 초과 | 관리자 명령으로만 `PENDING` 복귀 |
| `REMOVED` | 차단 해제 완료 | 종료 상태 |

- **Validation 오류**(Protected IP, 비사설 IP, 잘못된 Protocol·Port·Action)는
  재시도해도 결과가 같으므로 **즉시 `FAILED`**.
- **일시 오류**(iptables 실행 실패·Timeout)는 `retry_count`를 올리며 최대 **3회**까지만
  자동 재시도하고, 그 뒤에는 자동 재시도하지 않는다. `next_retry_at` 이전에는 다시
  집어가지 않는다.
- Phase 6-B부터 공식 Release는 Backend API가 `firewall_release_requests`에
  `PENDING` 요청을 만들고, Worker가 해당 요청을 처리해 `SUCCEEDED` 또는 `FAILED`로
  종료하는 흐름을 사용한다. Backend API는 sudo/iptables를 직접 실행하지 않는다.
  Worker Reconciliation은 `PENDING` Release Request가 있는 `APPLIED` Rule을 복구하지
  않는다.

## 6. 수동 Smoke Test

```bash
cd /home/pi/iot-edge-zero-trust
source venv/bin/activate

# 1) 실행 예정 명령만 확인 (DB·OS 미변경)
python -m edge.trust.run_firewall_worker --dry-run

# 2) 한 Cycle 실행 (Reconciliation 포함)
python -m edge.trust.run_firewall_worker --once

# 3) 실제 Rule 확인 (Wrapper 경유 — Worker와 같은 권한 경로)
sudo -n /usr/local/sbin/hanium-firewall-rule list | grep hanium-firewall

# 4) DB 상태 확인
sqlite3 backend/data/iot_security.db \
  "SELECT id, device_id, source_ip, status, retry_count, applied_at, last_error
     FROM firewall_rules ORDER BY id DESC LIMIT 5;"

# 5) Rule이 INPUT Chain 맨 앞에 있는지 확인 (선행 ACCEPT보다 앞이어야 함)
sudo iptables -L INPUT -n --line-numbers | head -5
```

**실제 차단 확인은 반드시 차단 대상 Device 자신에서 해야 합니다.**

Pi에서 `mosquitto_pub`을 실행하면 Source IP가 Pi(=Protected IP)이므로 차단 대상이
아니고, 검증이 되지 않습니다. 세부계획도 Payload의 `device_id`만 바꾼 결과는 등록
Device 격리 증거로 인정하지 않습니다.

올바른 검증 방법 두 가지:

```bash
# (A) 실제 ESP32 #2에서 확인 — 공식 E2E 방식
#     ESP32 #2를 공격 Test Mode로 실행한 뒤 Serial 로그에서 MQTT 연결·Publish 실패 확인
#     (firmware/esp32/ 참고)

# (B) 임시 확인 — 차단 대상 IP를 가진 장비에서 직접 실행
#     예: esp32_02와 같은 192.168.0.5를 쓰는 장비에서
mosquitto_pub -h 192.168.0.20 -t iot/esp32_02/sensor -m '{"device_id":"esp32_02"}'
# → 연결 Timeout 또는 Publish 실패가 나와야 정상
```

기대 결과: `hanium-firewall:{id}` Comment가 붙은 Rule이 **INPUT Chain 1번 위치**에
존재하고, DB `status=APPLIED`, 해당 Device의 MQTT 연결·Publish 실패.

> **Rule 위치가 중요합니다.** DROP Rule은 `-I INPUT 1`로 Chain 맨 앞에 삽입합니다.
> 뒤에 붙이면 앞선 ACCEPT Rule(특히 `--ctstate ESTABLISHED,RELATED`)에서 판정이
> 끝나, 진행 중인 MQTT 연결이 계속 통과하면서 DB만 `APPLIED`가 되는 상태가 됩니다.

## 7. 격리 해제

```bash
python -m edge.trust.run_firewall_worker --release <RULE_ID>
sudo iptables -S INPUT | grep hanium-firewall   # 사라졌는지 확인
```

동일한 Match Specification으로 `-C` 확인 후 `-D` 삭제하고 `REMOVED`로 기록한다.
실제 Rule이 이미 없어도 DB는 `REMOVED`로 정리된다(경고 로그 남음).

## 8. 3회 실패한 Rule 재시도 (관리자 전용)

자동 무한 재시도는 하지 않는다. 원인을 먼저 확인하고 명시적으로 되돌린다.

```bash
# 1) 원인 확인
sqlite3 backend/data/iot_security.db \
  "SELECT id, source_ip, retry_count, last_error FROM firewall_rules WHERE status='FAILED';"

# 2) 원인 제거 후 재전환 (확인 토큰 필수)
python -m edge.trust.run_firewall_worker \
  --admin-reset-failed <RULE_ID> --confirm RESET-FIREWALL-RULE
```

Protected IP 때문에 실패한 Rule은 되돌리지 말 것. 그 Rule은 애초에 만들어지면 안 되는
Rule이며, Trust 쪽 Device·IP 매핑을 확인해야 한다.

## 9. Reconciliation·재부팅

Worker는 기동 후 첫 Cycle에서 자동으로 Reconciliation을 수행한다. 수동 실행:

```bash
python -m edge.trust.run_firewall_worker --reconcile-only
```

- `APPLIED`인데 실제 Rule이 없으면 → **동일 Specification으로 재적용**하고 경고 로그
- 실제 Rule은 있는데 DB에 활성 Row가 없으면 → **자동 삭제하지 않고** Comment와 전체
  Specification을 경고 로그로 남긴다. 관리자가 직접 판단한다

재부팅 검증:

```bash
sudo reboot
# 재부팅 후
systemctl status firewall-worker
journalctl -u firewall-worker | grep -i reconcil
sudo iptables -S INPUT | grep hanium-firewall
```

`iptables` Rule은 재부팅으로 사라지므로, 재부팅 후 첫 Cycle에서 `restored`로 복구되는
것이 정상 동작이다.

## 10. 단일 실행 Lock

DB 상태와 실제 iptables를 함께 바꾸는 명령은 모두 같은 Lock을 거칩니다
(`<db>.firewall.lock`, `FIREWALL_LOCK_PATH`로 변경 가능).

- Lock 대상: `--loop`의 각 Cycle, `--once`, `--release`, `--reconcile-only`,
  `--admin-reset-failed`
- Lock 없이 실행: `--dry-run`, `--status` (상태를 바꾸지 않음)

상시 서비스는 **Cycle 단위로만** Lock을 잡고 Cycle 사이에는 놓습니다. 그래서 서비스가
돌고 있어도 관리자 명령을 실행할 수 있습니다. 관리자 명령은 최대
`FIREWALL_LOCK_WAIT_SECONDS`(기본 15초)까지 기다립니다.

```bash
# 서비스 실행 중에도 해제 명령이 동작한다
python -m edge.trust.run_firewall_worker --release 12
# Lock 획득 실패 시 종료 코드 3
```

Lock이 없으면 다음 경합이 발생합니다:
- 같은 Comment의 DROP Rule이 중복 생성
- `--release`로 지운 Rule을 서비스의 Reconciliation이 곧바로 되살림
- DB 상태와 실제 Rule 불일치

## 11. 문제 해결

| 증상 | 확인 |
|---|---|
| `sudo: a password is required` | sudoers 미설치 또는 사용자 불일치. `sudo -n /usr/local/sbin/hanium-firewall-rule list` |
| 모든 Rule이 즉시 FAILED | `last_error` 확인. Protected IP·비사설 IP·Port 불일치 여부 |
| `PENDING`인데 처리 안 됨 | `next_retry_at`이 미래인지, `retry_count`가 3인지 확인 |
| APPLIED인데 차단 안 됨 | `sudo iptables -S INPUT`에 Rule이 있는지, Device 실제 IP가 `source_ip`와 같은지 |
| Rule은 있는데 DB가 PENDING | 정상. 다음 Cycle의 `-C`가 기존 Rule을 찾아 APPLIED로 수렴한다 |
| Wrapper 없음 | `FIREWALL_WRAPPER_PATH`와 `/usr/local/sbin/hanium-firewall-rule` 설치 확인 |
| Wrapper가 종료 코드 65 | Source IP가 사설 IPv4가 아니거나 Rule ID가 숫자가 아니다 |

## 12. 안전 규칙

- 허용 범위는 **등록된 사설 IPv4 / TCP / 목적지 Port 1883 / INPUT DROP**뿐이다
- sudoers는 root 소유 Wrapper 하나만 허용한다. `iptables`를 직접 허용하지 않는다
- Wrapper는 root 소유 0755여야 한다. pi가 수정 가능하면 통제가 무너진다
- `shell=True`를 사용하지 않는다. 항상 인자 배열로 실행한다
- Pi #1·Broker·관리자 IP는 Protected IP로 차단하지 않는다
- DB에 없는 `hanium-firewall:` Rule을 자동 삭제하지 않는다
- 적용·확인·삭제·Reconciliation은 항상 동일한 Match Specification을 쓴다
  (`edge/trust/firewall_worker.py`의 `build_match_args()` 한 곳에서 생성)
- DROP Rule은 `-I INPUT 1`로 Chain 맨 앞에 넣는다
- Reconciliation의 Rule 복원도 새 차단과 동일한 검증(Protected IP 포함)을 거친다
- 상태를 바꾸는 명령은 모두 단일 실행 Lock을 거친다
