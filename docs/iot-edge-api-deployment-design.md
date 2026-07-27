# IoT Edge API systemd 배포 설계

## 목적

Raspberry Pi에서 전체 FastAPI Backend를 수동 Uvicorn 명령이 아닌
`iot-edge-api.service`로 실행한다. 이 서비스 하나가 MQTT, Packet, Gateway,
Detection, Trust, Isolation, Firewall, Device, Health API를 모두 제공한다.

## 범위

포함:

- `infra/systemd/iot-edge-api.service`
- 필수 `.env` 기반 Host, Port, CORS, DB 설정
- 실패 시 제한된 자동 재시작과 SIGTERM 정상 종료
- 사설 LAN Health·CORS 검증 및 운영·복구 Runbook
- 기존 문서의 로컬 개발 실행과 Pi 운영 실행 구분
- systemd Unit과 Runbook의 자동 계약 테스트

제외:

- API Router와 응답 Schema 변경
- 별도 MQTT API 또는 Packet API 프로세스
- 인증·인가 추가
- 공유기 Port Forwarding 또는 공인망 노출
- 이 개발 환경에서의 실제 Pi 설치·재부팅 검증

## 대안 검토

### A. systemd에서 Uvicorn 직접 실행 — 채택

`EnvironmentFile`로 `.env`를 읽고 프로젝트 가상환경의 Python으로
`python -m uvicorn backend.app.main:app`을 실행한다. 기존 설정과 배포 구조를
그대로 사용하며 새 Runtime 코드가 필요 없다.

### B. Python API Runner 추가

`backend.app.config.settings`를 읽는 별도 실행 모듈을 만들 수 있지만, 현재
Uvicorn CLI와 systemd 환경변수로 해결되는 문제에 새로운 운영 코드를 추가하게 된다.

### C. Shell Wrapper 추가

환경 검증과 명령 조립은 쉽지만 Shell 계층이 추가되고 프로세스·Signal 추적이
복잡해진다. 현재 API에는 Root 권한이나 사전 작업이 필요하지 않으므로 사용하지 않는다.

## systemd 계약

- Unit 이름: `iot-edge-api.service`
- 실행 계정: `pi:pi`
- 작업 경로: `/home/pi/iot-edge-zero-trust`
- 환경 파일: `/home/pi/iot-edge-zero-trust/.env` 필수
- 실행기: `/home/pi/iot-edge-zero-trust/venv/bin/python`
- App: `backend.app.main:app`
- Host·Port: `.env`의 `API_HOST`, `API_PORT`
- 개발 전용 `--reload` 미사용
- `Restart=on-failure`, `RestartSec=5`
- Start Limit: 300초 동안 최대 5회
- 종료: `SIGTERM`, 최대 15초
- 로그: systemd Journal, `SyslogIdentifier=iot-edge-api`
- 부팅 자동 시작: `multi-user.target`

## CORS·네트워크 계약

`API_ALLOWED_ORIGINS`에는 Dashboard를 실제로 여는 Origin만 쉼표로 나열한다.
Credential 허용 시 Wildcard `*`는 사용하지 않는다. 예를 들어 노트북에서
`http://192.168.0.3:5173`으로 Dashboard를 열면 해당 Origin을 Pi `.env`에
추가한다. API는 사설 LAN에서만 사용하고 공유기 Port Forwarding과 공인망 노출은
금지한다.

## 운영 흐름

```text
Pi 부팅
→ systemd가 .env 로드
→ Uvicorn/FastAPI 시작
→ Pi 내부 /api/health 확인
→ 노트북에서 /api/health 및 CORS 확인
→ Dashboard가 전체 Backend API 사용
```

프로세스가 비정상 종료되면 systemd가 제한된 횟수로 재시작한다. `.env`가 없거나
잘못된 CORS 설정으로 App Import가 실패하면 Service는 실패 상태와 Journal 오류를
남긴다.

## 검증

자동 검증:

- Unit 실행 경로·계정·환경 파일·재시작·종료·로그·자동 시작 계약
- `--reload` 미사용
- Runbook의 설치·Health·CORS·재시작·재부팅·Rollback 절차

Pi 후속 검증:

- `systemctl enable --now iot-edge-api.service`
- Pi 내부와 노트북에서 `/api/health` 200
- 허용 Origin의 CORS Header
- 재시작과 재부팅 후 자동 복구
- Journal에 반복 오류가 없음
- Dashboard의 실제 API 조회
