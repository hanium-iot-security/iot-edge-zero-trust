# 로컬 통합 테스트 결과

작성일: 2026-06-29
기준 브랜치: `develop`
테스트 유형: 로컬 Windows 환경 사전 통합 테스트

## 1. 목적

이 문서는 `develop` 브랜치 기준으로 MVP 주요 모듈이 하나의 실행 흐름으로 연결되는지 로컬 Windows 환경에서 검증한 결과를 정리한다.

검증 흐름은 다음과 같다.

```txt
DB 초기화
-> seed_devices
-> MQTT Subscriber 실행
-> Feature Collector 실행
-> 공격 스크립트 실행
-> mqtt_logs 저장
-> feature_logs 생성
-> Rule detector 실행
-> AI detector 실행
-> detection_events 저장
-> Trust Score update 실행
-> devices.trust_score / devices.status 변경
-> isolation_history 저장
-> FastAPI API 조회
-> React Dashboard 표시
```

이번 테스트는 실제 Raspberry Pi + ESP32 기반 최종 E2E 검증 전, 로컬 Windows 환경에서 진행한 사전 통합 테스트이다.

## 2. 테스트 환경

| 항목 | 내용 |
| --- | --- |
| OS | Windows |
| 기준 브랜치 | `develop` |
| Python 실행 환경 | `venv` |
| MQTT Broker | 로컬 Windows Mosquitto |
| FastAPI 주소 | `http://127.0.0.1:8000` |
| React Dashboard 주소 | `http://localhost:5173` |
| MQTT Host | `localhost` |
| MQTT Port | `1883` |
| MQTT Subscribe Topic | `#` |
| AI 모델 파일 | `ai/models/isolation_forest.joblib` |

아래 파일은 로컬 실행 산출물이며 Git에 올리지 않는다.

```txt
.env
backend/data/iot_security.db
backend/data/iot_security.db-wal
backend/data/iot_security.db-shm
ai/models/isolation_forest.joblib
data/exports/train_normal_850_features.csv
node_modules/
```

## 3. 실행 전 확인

Mosquitto 실행 상태와 MQTT 1883 포트 연결을 확인했다.

```powershell
Get-Service mosquitto
Test-NetConnection localhost -Port 1883
```

확인 결과:

```txt
mosquitto = Running
TcpTestSucceeded = True
```

## 4. 실행 명령어

### 4.1 DB 초기화 및 seed

```powershell
venv\Scripts\python.exe -m db.reset_db
venv\Scripts\python.exe -m db.create_tables
venv\Scripts\python.exe -m db.seed_devices
```

### 4.2 MQTT Subscriber

```powershell
venv\Scripts\python.exe -m edge.mqtt.subscriber
```

### 4.3 Feature Collector loop

```powershell
venv\Scripts\python.exe -m edge.features.collect_feature_logs --loop --interval 5
```

### 4.4 공격 스크립트

```powershell
venv\Scripts\python.exe -m attacks.flooding_attack --count 30 --interval 0.2
venv\Scripts\python.exe -m attacks.large_payload_attack --count 3
venv\Scripts\python.exe -m attacks.malformed_payload_attack --count 5
venv\Scripts\python.exe -m attacks.abnormal_topic_attack --count 5
venv\Scripts\python.exe -m attacks.unknown_device_attack --count 4
venv\Scripts\python.exe -m attacks.device_id_mismatch_attack --count 4
```

공격 스크립트 실행 후 마지막 공격 window가 `feature_logs`에 반영될 수 있도록 최소 10초 이상 대기했다.

### 4.5 Rule / AI / Trust Score

```powershell
venv\Scripts\python.exe -m edge.detection.run_rule_detector
venv\Scripts\python.exe -m edge.detection.run_ai_detector
venv\Scripts\python.exe -m edge.trust.run_trust_score_update
```

### 4.6 FastAPI

```powershell
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --log-level debug
```

### 4.7 React Dashboard

```powershell
cd frontend
npm install
npm run dev
```

프론트엔드 `.env` 설정은 아래 기준으로 확인했다.

```env
VITE_API_BASE_URL=http://127.0.0.1:8000/api
VITE_USE_MOCK=false
```

## 5. 통합 실행 결과 요약

로컬 Windows 환경에서 아래 흐름까지 정상 연결되는 것을 확인했다.

```txt
MQTT 메시지 수집
-> mqtt_logs 저장
-> 10초 window feature_logs 생성
-> Rule / AI 탐지 실행
-> detection_events 저장
-> Trust Score update
-> devices 상태 변경
-> isolation_history 저장
-> FastAPI 조회
-> React Dashboard 표시
```

로컬 기준으로 6/28~6/29 모듈 연결 단계는 성공한 것으로 판단한다.

## 6. DB 결과

### 6.1 devices 결과

```txt
esp32_01 | trust_score 25 | status isolated
esp32_02 | trust_score 0  | status isolated
```

### 6.2 주요 테이블 row count

```txt
mqtt_logs = 56
feature_logs = 9
detection_events = 20
```

### 6.3 detection_events event type별 개수

```txt
AI   AI_ANOMALY              4
RULE ABNORMAL_PUBLISH_RATE  3
RULE ABNORMAL_TOPIC         1
RULE DEVICE_ID_MISMATCH     4
RULE LARGE_PAYLOAD          2
RULE MALFORMED_PAYLOAD      1
RULE UNKNOWN_DEVICE         5
```

### 6.4 isolation_history 결과

```txt
esp32_01 | ISOLATED | Trust Score below threshold
esp32_02 | ISOLATED | Trust Score below threshold
```

## 7. 중복 저장 방지 확인

Rule detector와 AI detector를 한 번 더 실행했을 때 `detection_events` 총 개수는 20개로 유지되었다.

따라서 같은 `feature_log_id` 또는 `mqtt_log_id` 기준으로 같은 이벤트가 중복 저장되지 않는 것을 확인했다.

## 8. FastAPI API 확인 결과

Health Check는 아래 명령으로 확인했다.

```powershell
Invoke-RestMethod http://127.0.0.1:8000/api/health
```

확인 결과:

```txt
status = ok
db_connected = True
```

확인한 주요 API는 다음과 같다.

```txt
/api/health
/api/devices
/api/mqtt-logs
/api/feature-logs
/api/detection-events
/api/trust-score/summary
/api/isolation/history
```

## 9. React Dashboard 확인 결과

아래 화면이 실제 API 기반으로 표시되는 것을 확인했다.

```txt
Dashboard Home
Devices
MQTT Logs
Events
Isolation
```

Dashboard Home 결과:

```txt
전체 기기: 2
정상: 0
주의: 0
위험: 0
격리: 2
```

Trust Score Summary:

```txt
esp32_01 | trust_score 25 | isolated
esp32_02 | trust_score 0  | isolated
```

MQTT Logs에서 확인한 로그 유형:

```txt
정상 MQTT 메시지
비정상 topic 메시지
unknown device 메시지
device_id mismatch 메시지
malformed payload 메시지
large payload 메시지
```

Events Page에서 확인한 이벤트 유형:

```txt
AI_ANOMALY
ABNORMAL_PUBLISH_RATE
LARGE_PAYLOAD
MALFORMED_PAYLOAD
ABNORMAL_TOPIC
UNKNOWN_DEVICE
DEVICE_ID_MISMATCH
```

Isolation Page에서 현재 격리된 기기와 격리 이력이 표시되는 것을 확인했다.

## 10. 통합 성공 기준 체크

| 구분 | 항목 | 결과 |
| --- | --- | --- |
| DB | `esp32_01`, `esp32_02` seed 확인 | 성공 |
| DB | `unknown_01` 미등록 확인 | 성공 |
| MQTT | 정상 메시지 `mqtt_logs` 저장 | 성공 |
| MQTT | 공격 메시지 `mqtt_logs` 저장 | 성공 |
| Feature | 10초 window `feature_logs` 생성 | 성공 |
| Rule | `ABNORMAL_PUBLISH_RATE` 저장 | 성공 |
| Rule | `LARGE_PAYLOAD` 저장 | 성공 |
| Rule | `MALFORMED_PAYLOAD` 저장 | 성공 |
| Rule | `ABNORMAL_TOPIC` 저장 | 성공 |
| Rule | `UNKNOWN_DEVICE` 저장 | 성공 |
| Rule | `DEVICE_ID_MISMATCH` 저장 | 성공 |
| AI | `AI_ANOMALY` 저장 | 성공 |
| Trust Score | Trust Score 감소 확인 | 성공 |
| Trust Score | `UNKNOWN_DEVICE` 감점 제외 확인 | 성공 |
| Trust Score | 동일 window 중복 감점 방지 확인 | 성공 |
| Trust Score | `applied_to_score` 처리 확인 | 성공 |
| Isolation | 30 미만 시 `isolated` 변경 | 성공 |
| Isolation | `isolation_history` 저장 | 성공 |
| API | 주요 FastAPI API 응답 확인 | 성공 |
| Dashboard | 실제 API 기반 화면 표시 | 성공 |

## 11. 발견된 이슈 및 후속 작업

### 11.1 Dashboard 시간 표시 기준 통일

일부 화면에서는 시간 값이 UTC처럼 보이고, 일부 화면에서는 한국 시간처럼 표시되는 문제가 확인되었다.

예시:

```txt
Events Page Detected At
Isolation Page Created At
```

후속 작업:

```txt
Dashboard에서 시간 표시를 한국 시간 기준으로 통일
Detected At / Created At 표시 방식 점검
```

### 11.2 Feature Graph 시간 표시 및 가시성 개선 필요

Feature Graph에서 x축 날짜/시간 표시가 길게 출력되어 가시성이 떨어지는 것을 확인했다.

여러 feature 값이 한 화면에 함께 표시되면서 일부 구간에서는 그래프 변화 흐름을 직관적으로 파악하기 어렵다.

후속 작업:

```txt
Feature Graph x축 시간 표시 간소화
Feature Graph 시간 오름차순 정렬
Feature Graph가 더 가시성 있게 표시되도록 화면 구성 개선
```

### 11.3 isolated 이후 Trust Score 추가 감점 정책 확인 필요

> 최신 `develop` 기준으로는 이후 PR에서 격리 이후 Trust Score 추가 감점 방지 정책이 반영되었습니다. 이 섹션은 2026-06-29 로컬 통합 테스트 당시 발견한 이슈 기록입니다.

현재 결과에서는 `isolated` 이후에도 추가 이벤트가 반영되어 현재 Trust Score가 더 낮아질 수 있음을 확인했다.

예시:

```txt
isolation_history에는 격리 당시 Trust Score가 저장됨
devices 테이블에는 이후 추가 감점이 반영된 현재 Trust Score가 저장됨
```

정책 확인 필요 사항:

```txt
isolated 이후에도 Trust Score를 계속 감점할 것인지
isolated 이후에는 detection_events만 저장하고 Trust Score 추가 감점은 중단할 것인지
isolation_history에는 격리 당시 점수를 저장하는 정책을 유지할 것인지
```

### 11.4 Windows cp949 출력 인코딩 문제

일부 공격 스크립트에서 MQTT publish는 성공했지만, Windows 콘솔 출력 과정에서 cp949 인코딩 오류가 발생했다.

원인:

```txt
공격 스크립트 완료 메시지에 em dash(U+2014) 문자가 포함됨
Windows 기본 콘솔 cp949에서 출력 실패
```

영향:

```txt
MQTT publish 및 DB 저장에는 영향 없음
다만 스크립트 종료 코드가 1로 끝날 수 있어 시연/자동화에는 좋지 않음
```

후속 작업:

```txt
공격 스크립트 출력 문자를 ASCII 기반으로 변경
em dash(U+2014)를 '-'로 변경
```

## 12. 다음 단계

### 12.1 실제 Raspberry Pi + ESP32 기반 E2E 검증

확인 대상:

```txt
Raspberry Pi Mosquitto Broker
Raspberry Pi FastAPI 실행
ESP32 정상 publish
ESP32 또는 Python 공격 시나리오 실행
React Dashboard에서 실제 장비 데이터 표시
```

### 12.2 Dashboard UI 보완

우선순위:

```txt
1. 시간 표시 한국 기준 통일
2. Feature Graph x축 시간 표시 개선
3. Feature Graph 가시성 개선
```

### 12.3 Trust Score 정책 반영 기록

> 최신 `develop` 기준으로는 격리 이후 추가 감점 방지 정책이 반영되었습니다. 이미 `isolated` 상태인 기기의 후속 대표 이벤트는 추가 감점 없이 처리 완료 상태로 마감됩니다.

현재 반영된 정책:

```txt
격리 이후에는 후속 대표 이벤트를 추가 감점하지 않는다.
이미 isolated 상태인 기기의 후속 대표 이벤트는 applied_to_score=1, score_delta=0으로 마감한다.
isolation_history는 최초 격리 시점에만 1회 저장한다.
```

해당 정책은 MVP 안정성을 위해 반영되었으며, 고도화 단계에서는 cooldown/window 묶기 정책을 추가로 검토할 수 있다.

## 13. 결론

로컬 Windows 환경에서 `develop` 기준 MVP 주요 모듈 연결이 정상적으로 동작하는 것을 확인했다.

통합 흐름:

```txt
MQTT 수집
-> Feature 생성
-> Rule / AI 탐지
-> detection_events 저장
-> Trust Score update
-> 자동 격리
-> FastAPI 조회
-> React Dashboard 표시
```

따라서 로컬 기준으로는 6/28~6/29 모듈 연결 단계가 완료된 것으로 판단한다.

향후 통합 작업은 실제 Raspberry Pi + ESP32 기반 E2E 검증과 Dashboard 표시 개선이다. Trust Score 격리 이후 추가 감점 방지 정책은 이후 PR에서 반영되었다.
