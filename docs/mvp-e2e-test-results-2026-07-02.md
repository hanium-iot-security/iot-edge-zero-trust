# MVP E2E 테스트 결과 - 2026-07-02

작성일: 2026-07-02
테스트 유형: 실제 장비 기반 MVP E2E 테스트
기준 브랜치: `develop`

## 테스트 목적

Raspberry Pi와 ESP32 기반 실제 장비 환경에서 MVP E2E 흐름이 정상 동작하는지 검증했다.

검증 범위:

```txt
MQTT 수집
-> SQLite 저장
-> Feature 생성
-> Rule-based 탐지
-> AI 이상 탐지
-> Trust Score 반영
-> 격리 상태 변경
-> FastAPI API 응답
-> React Dashboard 표시
```

## 테스트 환경

| 항목 | 값 |
| --- | --- |
| Gateway | Raspberry Pi |
| Gateway IP | `192.168.0.20` |
| MQTT Broker | Mosquitto |
| MQTT Port | `1883` |
| Backend | FastAPI |
| Frontend | React Dashboard |
| DB | SQLite |
| 정상 기기 | `esp32_01` |
| 공격 테스트 기기 | `esp32_02` |

## 최종 E2E 검증 흐름

```txt
ESP32 esp32_01 정상 publish
-> Raspberry Pi Mosquitto MQTT Broker 수신
-> Python Subscriber가 mqtt_logs 저장
-> Feature Collector가 10초 window 기준 feature_logs 생성
-> 공격 스크립트로 esp32_02 및 비정상 트래픽 발생
-> Rule Detector가 detection_events 생성
-> Isolation Forest 기반 AI Detector가 AI_ANOMALY 생성
-> Trust Score Update 실행
-> 기기 상태 normal / warning / danger / isolated 변경
-> FastAPI API 응답 확인
-> React Dashboard에서 결과 확인
```

## Rule-based 탐지 결과

| 시나리오 | 탐지 이벤트 | 저장 기준 | 결과 |
| --- | --- | --- | --- |
| Malformed Payload | `MALFORMED_PAYLOAD` | `feature_log_id` | 성공 |
| Abnormal Topic | `ABNORMAL_TOPIC` | `feature_log_id` | 성공 |
| Device ID Mismatch | `DEVICE_ID_MISMATCH` | `mqtt_log_id` | 성공 |

확인 내용:

- Malformed Payload는 10초 window 내 malformed payload 5건으로 이벤트 생성에 성공했다.
- Abnormal Topic은 비정상 topic 5건으로 이벤트 생성에 성공했다.
- Device ID Mismatch는 topic device_id와 payload device_id 불일치 메시지로 이벤트 생성에 성공했다.
- Device ID Mismatch는 topic 기준 device_id에 따라 `esp32_01`과 `esp32_02` 이벤트가 모두 생성될 수 있음을 확인했다.

## AI 이상 탐지 결과

AI Detector 입력 feature는 아래 5개이다.

```txt
publish_count
avg_payload_size
max_payload_size
avg_message_interval
min_message_interval
```

Flooding 공격 window에서 확인한 주요 feature 값은 다음과 같다.

| 항목 | 값 |
| --- | --- |
| device_id | `esp32_02` |
| publish_count | `30` |
| avg_payload_size | `65.7` |
| max_payload_size | `66` |
| avg_message_interval | `0.206` |
| min_message_interval | `0.0` |

정상 publish 패턴은 10초 window 기준 1~3개 수준인데, 해당 window에서는 10초 동안 30개의 메시지가 발생했고 평균 메시지 간격도 약 0.2초로 감소했다.

Isolation Forest는 해당 window를 정상 분포에서 벗어난 통신 행위로 판단하여 `AI_ANOMALY`로 탐지했다.

## AI 탐지 해석 및 오탐 가능성

Isolation Forest는 정상 분포 이탈을 탐지하는 방식이므로, 일부 정상 등록 기기의 window도 `AI_ANOMALY`로 분류될 수 있음을 확인했다.

예시로 정상 등록 기기의 일부 window가 아래와 같은 값을 가질 수 있다.

```txt
publish_count=3
avg_message_interval=3.0~3.5
min_message_interval=1.0~3.0
```

이 값은 Rule-based 공격 기준에는 해당하지 않지만, 학습된 정상 데이터 분포보다 메시지 간격이 짧으면 Isolation Forest가 정상 분포 이탈로 판단할 수 있다.

제로 트러스트 관점에서는 등록 기기라도 행위가 기준에서 벗어나면 의심 대상으로 탐지하는 것이 가능하다. 다만 실험 라벨 기준에서는 오탐 가능성이 있으므로 정상 데이터 다양화와 모델 민감도 조정이 필요하다.

## Trust Score 반영 결과

Trust Score update 실행 후 `detection_events.applied_to_score` 값이 갱신되는 것을 확인했다.

상태 기준:

| Trust Score | Status |
| --- | --- |
| 80~100 | `normal` |
| 60~79 | `warning` |
| 30~59 | `danger` |
| 0~29 | `isolated` |

확인 내용:

- 탐지 이벤트가 Trust Score 계산에 반영되었다.
- 반영된 이벤트는 `applied_to_score=1`로 변경되었다.
- `UNKNOWN_DEVICE`는 등록 기기 Trust Score 감점 대상이 아니므로 `score_delta=0`으로 처리된다.
- 동일 feature window에서 이미 다른 이벤트가 점수에 반영된 경우 일부 이벤트는 `Applied=no` 상태로 남을 수 있다.
- Trust Score가 30 미만이 된 기기는 `isolated` 상태로 변경된다.
- `isolation_history`는 최초 격리 시점의 이력을 저장한다.

격리 정책 요약:

```txt
격리 전 이벤트:
detection_events 저장 + Trust Score 감점

격리 상태:
devices.status = isolated
feature_logs 생성 대상에서 제외
isolation_history는 최초 격리 시점에 저장
```

## Dashboard 확인 결과

| 페이지 | 확인 결과 |
| --- | --- |
| Devices Page | 기기별 IP, status, trust_score, last_seen 표시 |
| Detection Events Page | Rule / AI 이벤트, severity, score_delta, applied 여부 표시 |
| MQTT Logs Page | 원본 MQTT 메시지 표시 |
| Isolation Page | 격리 이력 표시 |
| Dashboard Home | 요약 정보 및 feature graph 표시 |

Detection Events Page에서 `AI_ANOMALY`, `DEVICE_ID_MISMATCH` 이벤트가 표시되었고, Trust Score update 이후 Applied 상태가 변경되는 것을 확인했다.

## 테스트 중 확인한 주의사항

- Detection Events Page는 제한된 개수의 최근 이벤트만 표시하므로 이전 이벤트가 화면에서 밀릴 수 있다.
- AI Detector는 전체 `feature_logs`를 조회하므로 이전 feature window에서도 `AI_ANOMALY`가 생성될 수 있다.
- Device ID Mismatch 공격은 `esp32_01`과 `esp32_02` 양쪽 이벤트를 만들 수 있으므로 시연 중 Trust Score 테스트 해석에 주의가 필요하다.
- AI 탐지는 정상 분포 이탈을 탐지하므로 실험 기준의 오탐 가능성이 존재한다.
- 격리 상태가 된 기기는 이후 `feature_logs` 생성 대상에서 제외된다.

## 향후 개선 방향

### AI Detector 실행 범위 개선

현재 AI Detector는 전체 `feature_logs`를 대상으로 실행될 수 있다. 향후에는 이미 처리한 row를 제외하거나 특정 실행 범위를 지정할 수 있는 방식을 검토한다.

### Trust Score 적용 상태 표시 개선

Trust Score update 이후 일부 이벤트는 점수에 반영되지 않고 `Applied=no` 상태로 남을 수 있다.

예를 들어 `UNKNOWN_DEVICE`는 등록 기기의 Trust Score 감점 대상이 아니므로 `score_delta=0`으로 처리된다. 또한 동일 feature window에서 이미 다른 이벤트가 점수에 반영된 경우 일부 이벤트는 `Applied=no` 상태로 남을 수 있다.

현재 Dashboard에서는 `score_delta=0` 또는 `Applied=no`가 된 사유가 직접 표시되지 않아 테스트 결과 해석이 어려울 수 있다.

향후에는 Trust Score 적용 여부와 미적용 사유를 Dashboard에서 더 명확하게 설명할 수 있도록 개선을 검토한다.

### Dashboard 표시 설정 개선

현재 Dashboard는 이벤트와 로그를 제한된 개수만 표시한다. 이벤트나 로그가 많아질 경우 이전 데이터가 화면에서 밀릴 수 있다.

이는 기능 오류라기보다는 대시보드 표시 정책의 문제이다.

향후 톱니바퀴 설정 메뉴에서 사용자가 이벤트, MQTT 로그, Feature 로그의 표시 개수와 자동 새로고침 주기를 조절할 수 있도록 개선을 검토한다.

## 결론

2026-07-02 테스트를 통해 MQTT 수집, feature 생성, Rule-based 탐지, Isolation Forest 기반 AI 탐지, Trust Score 반영, 격리 상태 변경, FastAPI API 응답, React Dashboard 표시까지 MVP 통합 E2E 흐름이 정상적으로 연결됨을 확인했다.

AI 탐지는 Flooding 공격 feature를 `AI_ANOMALY`로 탐지하여 기능적으로 정상 동작함을 확인했다. 동시에 일부 정상 window가 AI 이상으로 분류될 수 있음을 확인하여, 후속 단계에서 정상 데이터 다양화와 모델 민감도 조정이 필요함도 확인했다.
