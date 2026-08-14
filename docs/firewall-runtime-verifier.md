# Phase 6-A Runtime Firewall Verifier

## 1. 목적

Recovery Preflight는 DB의 `firewall_rules.status=REMOVED`만으로 실제 iptables Rule이
해제됐다고 판단하지 않는다. 실제 Raspberry Pi INPUT Chain을 최근에 관찰한 증적이
있고, 대상 Device IP에 대한 `hanium-firewall:<rule_id>` DROP Rule이 없을 때만 Runtime
Firewall Gate를 통과한다.

이 기능은 **read-only verifier**다. Firewall Rule을 생성·삭제·해제하지 않는다.
Firewall Release는 기존 Firewall Worker의 승인된 관리자 명령 경계를 그대로 사용한다.

## 2. 권한 경계

`iot-edge-api.service`는 기존처럼 `NoNewPrivileges=true`를 유지한다. FastAPI가
`sudo`, `iptables`, `/usr/local/sbin/hanium-firewall-rule`을 직접 실행하지 않는다.

대신 별도 oneshot 서비스 `firewall-runtime-snapshot.service`가 기존 Firewall Worker와
동일한 root-owned Wrapper 경계를 사용하되 코드상 `list` Operation만 호출한다. Timer가
기본 5초마다 이 서비스를 실행한다.

```text
iptables INPUT Chain
        |
        | sudo -n /usr/local/sbin/hanium-firewall-rule list
        v
firewall-runtime-snapshot.service
        |
        | atomic JSON replace
        v
data/runtime/firewall-runtime.json
        |
        | read-only
        v
FastAPI Recovery Preflight
```

API 권한을 넓히기 위해 `iot-edge-api.service`의 `NoNewPrivileges`를 `false`로 변경하면
안 된다.

## 3. Snapshot 계약

기본 경로:

```text
data/runtime/firewall-runtime.json
```

기본 Freshness Gate:

```text
FIREWALL_RUNTIME_SNAPSHOT_MAX_AGE_SECONDS=15
```

정상 Snapshot 예시:

```json
{
  "available": true,
  "error": null,
  "managed_rules": [
    {
      "rule_id": 12,
      "source_ip": "192.168.0.5"
    }
  ],
  "observed_at": "2026-08-14T07:30:00Z",
  "schema_version": "firewall-runtime-snapshot-v1"
}
```

Snapshot에는 Credential, Password, MQTT Payload 등 비밀정보를 기록하지 않는다.
관리 대상 Firewall Rule의 ID, Source IP, 관찰시각만 기록한다.

다음 경우 Recovery Runtime Gate는 모두 fail-closed `UNAVAILABLE` / `HOLD`다.

- Snapshot 파일 없음
- JSON 또는 Schema 손상
- 관찰 실패(`iptables list` 실패 포함)
- Snapshot이 Freshness 제한보다 오래됨
- 관찰시각이 허용 Clock Skew보다 미래임
- `hanium-firewall:` Comment가 있는 Rule이 기대한 INPUT/TCP/1883/DROP/단일 IPv4 Host
  규격과 맞지 않음
- 대상 Device에 유효한 IPv4 주소가 없음

Fresh Snapshot에서 대상 Device IP의 관리 Rule이 하나 이상 남아 있으면 `ACTIVE` /
`HOLD`다. 하나도 없을 때만 `VERIFIED_RELEASED`가 된다.

## 4. Raspberry Pi 배포

코드 Merge 후 실제 Pi의 현재 상태를 read-only로 확인한 다음 아래 Unit을 설치한다.
운영 Pi의 다른 설정을 추측해서 덮어쓰지 않는다.

```bash
cd /home/pi/iot-edge-zero-trust

git status --short
git rev-parse HEAD

sudo install -m 0644 \
  infra/systemd/firewall-runtime-snapshot.service \
  /etc/systemd/system/firewall-runtime-snapshot.service

sudo install -m 0644 \
  infra/systemd/firewall-runtime-snapshot.timer \
  /etc/systemd/system/firewall-runtime-snapshot.timer

sudo systemctl daemon-reload
sudo systemctl enable --now firewall-runtime-snapshot.timer
```

서비스/Timer 상태 확인:

```bash
systemctl is-enabled firewall-runtime-snapshot.timer
systemctl is-active firewall-runtime-snapshot.timer
systemctl status firewall-runtime-snapshot.timer --no-pager
systemctl status firewall-runtime-snapshot.service --no-pager
journalctl --utc -u firewall-runtime-snapshot.service -n 100 --no-pager
```

Snapshot 확인은 읽기 전용으로 수행한다.

```bash
python - <<'PY'
import json
from pathlib import Path

path = Path("data/runtime/firewall-runtime.json")
print(path.resolve())
print(json.dumps(json.loads(path.read_text()), indent=2))
PY
```

직접 Runtime 증적이 필요할 때는 기존 승인된 Wrapper의 read-only `list`만 사용한다.

```bash
sudo -n /usr/local/sbin/hanium-firewall-rule list
```

이 명령은 확인용이며 `insert`, `delete`를 대신 실행하지 않는다.

## 5. Recovery Preflight 판정

Recovery Backend의 기존 Gate와 함께 적용된다.

```text
Device isolated
+ expected Trust Score 일치
+ 활성 Firewall DB Rule 없음
+ 미처리 Detection Event 없음
+ Backup 경로 사용 가능
+ Runtime Snapshot fresh/valid
+ 대상 IP의 Runtime 관리 DROP Rule 0건
= can_execute=true
```

DB Rule이 `REMOVED`여도 Runtime Snapshot에 같은 Source IP의 관리 DROP Rule이 남아 있으면
`can_execute=false`다.

Snapshot을 읽을 수 없거나 stale이면 Rule이 없다고 추정하지 않고 `HOLD`한다.

## 6. Rollback

이 기능 자체는 iptables를 변경하지 않는다. 문제가 있으면 Snapshot Timer만 중지할 수
있다.

```bash
sudo systemctl disable --now firewall-runtime-snapshot.timer
```

Timer 중지 후 Snapshot은 곧 stale해지고 Recovery Preflight는 자동으로 `HOLD`로
수렴한다. `iot-edge-api.service`의 권한을 변경하거나 DB를 수동 UPDATE해서 Gate를
우회하지 않는다.
