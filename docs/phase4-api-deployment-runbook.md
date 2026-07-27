# Phase 4 IoT Edge API 배포 Runbook

## 1. 목적과 적용 범위

`iot-edge-api.service`는 Raspberry Pi #1에서 전체 FastAPI Backend를 실행한다.
MQTT, Packet, Gateway, Detection, Trust, Isolation, Firewall, Device, Health
Router가 모두 `backend.app.main:app` 한 프로세스에 포함된다. 별도 MQTT API
서비스는 만들지 않는다.

이 서비스는 사설 LAN 전용이다. 공유기의 Port Forwarding이나 공인망 노출을
구성하지 않는다. Phase 4의 인증 없는 조회 API를 인터넷에 공개해서는 안 된다.

기본 배포 경로:

```text
/home/pi/iot-edge-zero-trust
```

기본 장비 주소 예시:

```text
Pi #1 API:       http://192.168.0.20:8000
Dashboard Origin: http://192.168.0.3:5173
```

실제 IP가 다르면 아래 명령과 `.env`를 실제 값으로 바꾼다.

## 2. 배포 전 점검

```bash
cd /home/pi/iot-edge-zero-trust
git status --short
git rev-parse --short HEAD

test -x venv/bin/python
test -r .env
sudo -u pi test -r /home/pi/iot-edge-zero-trust/.env

venv/bin/python -m uvicorn --version
sqlite3 backend/data/iot_security.db \
  "PRAGMA integrity_check; PRAGMA foreign_key_check;"
```

기대 결과:

- Worktree에 의도하지 않은 변경이 없다.
- 가상환경 Python과 Uvicorn을 실행할 수 있다.
- `integrity_check`가 `ok`이고 `foreign_key_check` 결과가 비어 있다.

## 3. `.env` 설정

Pi의 `/home/pi/iot-edge-zero-trust/.env`에서 다음 값을 확인한다.

```env
API_HOST=0.0.0.0
API_PORT=8000
API_ALLOWED_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://192.168.0.3:5173
API_ALLOW_CREDENTIALS=true
DATABASE_URL=sqlite:///./backend/data/iot_security.db
```

`API_ALLOWED_ORIGINS`에는 브라우저에서 Dashboard를 실제로 여는 Origin을
정확히 입력한다. `http://192.168.0.3:5173`으로 열면 해당 값을 포함하고,
`http://localhost:5173`으로 열면 localhost Origin을 포함한다.

Credential을 허용하는 현재 설정에서는 Wildcard `*`를 사용하지 않는다.
공유기 DHCP로 노트북 IP가 바뀌면 실제 Dashboard Origin도 갱신하고 서비스를
재시작한다.

환경 파일은 비밀정보를 포함할 수 있으므로 Git에 커밋하지 않는다.

```bash
chmod 600 /home/pi/iot-edge-zero-trust/.env
chown pi:pi /home/pi/iot-edge-zero-trust/.env
```

## 4. Unit 설치와 최초 기동

```bash
cd /home/pi/iot-edge-zero-trust

sudo install -m 0644 infra/systemd/iot-edge-api.service /etc/systemd/system/iot-edge-api.service
sudo systemctl daemon-reload
sudo systemctl enable --now iot-edge-api.service
```

상태 확인:

```bash
systemctl is-enabled iot-edge-api.service
systemctl is-active iot-edge-api.service
sudo systemctl status iot-edge-api.service --no-pager
journalctl --utc -u iot-edge-api.service -n 100 --no-pager
```

기대 결과:

- `is-enabled`: `enabled`
- `is-active`: `active`
- 반복되는 Import·DB·CORS 설정 오류가 없다.

## 5. Health 검증

### 5.1 Pi 내부

```bash
curl --fail --silent --show-error http://127.0.0.1:8000/api/health
```

정상 예시:

```json
{
  "status": "ok",
  "database": "ok",
  "db_connected": true,
  "server_time": "2026-07-27T00:00:00Z"
}
```

`status=degraded`, `database=error` 또는 `db_connected=false`이면 API
프로세스가 실행 중이어도 배포 성공으로 판정하지 않는다.

### 5.2 같은 LAN의 Windows 노트북

```powershell
Invoke-RestMethod http://192.168.0.20:8000/api/health
```

연결되지 않으면 Pi의 실제 IP, 서비스 상태, 포트와 사설 LAN 연결을 확인한다.
문제 해결을 위해 공유기 Port Forwarding을 열지 않는다.

## 6. CORS 검증

Pi 또는 같은 LAN의 Shell에서 실제 Dashboard Origin으로 Preflight 요청을 보낸다.

```bash
curl -i -X OPTIONS http://192.168.0.20:8000/api/health \
  -H "Origin: http://192.168.0.3:5173" \
  -H "Access-Control-Request-Method: GET"
```

응답에 다음 Header가 있어야 한다.

```text
Access-Control-Allow-Origin: http://192.168.0.3:5173
Access-Control-Allow-Credentials: true
```

허용되지 않은 Origin을 사용한 요청에는 해당 Origin의
`Access-Control-Allow-Origin` Header가 없어야 한다.

Dashboard의 실제 API 설정 예시:

```env
VITE_API_BASE_URL=http://192.168.0.20:8000/api
VITE_USE_MOCK=false
```

브라우저 개발자 도구에서 CORS 오류가 없고 `/api/health`,
`/api/gateway-metrics`, `/api/packet-feature-logs` 요청이 정상 응답하는지
확인한다.

## 7. 서비스 갱신·재시작

Unit 또는 `.env`를 변경한 경우:

```bash
cd /home/pi/iot-edge-zero-trust
sudo install -m 0644 infra/systemd/iot-edge-api.service /etc/systemd/system/iot-edge-api.service
sudo systemctl daemon-reload
sudo systemctl restart iot-edge-api.service

systemctl is-active iot-edge-api.service
curl --fail --silent --show-error http://127.0.0.1:8000/api/health
journalctl --utc -u iot-edge-api.service -n 100 --no-pager
```

재시작 후 Health와 CORS를 다시 검증한다.

## 8. 재부팅 자동 기동 검증

다른 Phase 4 서비스가 안전하게 중단될 수 있는 시점에만 재부팅한다.

```bash
sudo reboot
```

Pi가 다시 연결된 후:

```bash
systemctl is-enabled iot-edge-api.service
systemctl is-active iot-edge-api.service
curl --fail --silent --show-error http://127.0.0.1:8000/api/health
journalctl --utc -u iot-edge-api.service -b --no-pager
```

부팅 후 자동 기동과 DB 연결을 모두 확인해야 한다.

## 9. 장애 확인

```bash
sudo systemctl status iot-edge-api.service --no-pager
journalctl --utc -u iot-edge-api.service -n 100 --no-pager

cd /home/pi/iot-edge-zero-trust
sudo -u pi test -r .env
venv/bin/python -m uvicorn --version
```

주요 확인 항목:

- `.env` 누락 또는 읽기 권한 오류
- `API_HOST`, `API_PORT` 누락
- 잘못된 `API_ALLOWED_ORIGINS`
- SQLite 경로·권한 또는 Migration 누락
- 8000 Port를 사용하는 다른 프로세스

Port 확인:

```bash
sudo ss -ltnp | grep ':8000'
```

## 10. Rollback

Unit 배포를 되돌리고 수동 Uvicorn으로 임시 복구할 때:

```bash
sudo systemctl disable --now iot-edge-api.service
sudo rm -f /etc/systemd/system/iot-edge-api.service
sudo systemctl daemon-reload
sudo systemctl reset-failed

cd /home/pi/iot-edge-zero-trust
source venv/bin/activate
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```

수동 프로세스는 SSH 연결 종료나 Pi 재부팅 시 중지된다. 장애 원인을 해결한 뒤
Unit을 다시 설치하고 Health·CORS·재부팅 검증을 반복한다. 운영 환경에서
`--reload`를 사용하지 않는다.

## 11. 결과 기록

PR 본문과 Notion 검증 페이지에 다음을 실제 실행 결과로 기록한다.

- Git Commit SHA
- Pi OS·Python 버전
- Unit 설치 시각과 `enabled`·`active`
- Pi 내부·노트북 Health 결과
- 실제 Dashboard Origin과 CORS 결과
- 재시작·재부팅 결과
- Journal 오류 유무
- 미실행 항목과 사유

실제 Pi에서 실행하지 않은 검증은 완료로 표시하지 않는다.

