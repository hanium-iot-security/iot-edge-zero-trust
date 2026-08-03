# Trust Score 정책

Trust Score 처리는 `edge/trust`에서 실행합니다.

```txt
초기값: 100
최소값: 0
최대값: 100

80-100: normal
60-79: warning
30-59: danger
0-29: isolated
격리 조건: trust_score < 30
```

격리 상태와 격리 이력 action은 다음처럼 구분합니다.

```txt
status: isolated
action: ISOLATED
```

`devices.status`는 현재 기기 상태이므로 소문자 `isolated`를 사용합니다.
`isolation_history.action`은 격리 이력 action 코드이므로 대문자 `ISOLATED`를 사용합니다.
향후 격리 해제 기능을 추가하면 action 값으로 `RELEASED`를 사용할 수 있습니다.

환경 변수:

```env
INITIAL_TRUST_SCORE=100
ISOLATION_THRESHOLD=30
```

같은 window 규칙: 하나의 feature window에서 여러 detection event가 발생하면 가장 큰 감점만 적용합니다. 나머지 event는 `applied_to_score = 0`으로 유지합니다.

## 격리 이후 Trust Score 정책

MVP에서는 기기가 `isolated` 상태가 된 이후 추가 보안 이벤트가 발생하더라도 Trust Score를 추가 감점하지 않습니다.

추가 이벤트는 `detection_events`에 계속 저장하여 이상 행위 추적성은 유지하되, `devices.trust_score`는 최초 격리 시점의 점수로 고정합니다.

`isolation_history`는 최초로 `isolated` 상태에 진입한 시점에만 1회 저장합니다.

이미 `isolated`인 기기의 후속 대표 이벤트는 Trust Score updater에서 처리 완료로 보고 `applied_to_score = 1`, `score_delta = 0`으로 마감합니다.

격리 해제, 재격리, cooldown, 일정 시간 내 감점 제한, window 기반 묶기 정책은 MVP 이후 고도화 항목으로 분리합니다.

이벤트별 Trust Score 변화량은 `severity`가 아니라 `event_type` 기준으로 고정합니다. `severity`는 API와 대시보드 표시용으로 사용합니다.

| event_type | score_delta | 비고 |
| --- | ---: | --- |
| `DEVICE_ID_MISMATCH` | -25 | 기기 신원 불일치 |
| `ABNORMAL_PUBLISH_RATE` | -20 | 10초 Window의 `publish_count > 15` |
| `ABNORMAL_TOPIC` | -20 | 허용되지 않은 topic 접근 |
| `LARGE_PAYLOAD` | -15 | payload 크기 초과 |
| `AI_ANOMALY` | -15 | Isolation Forest 이상 탐지 |
| `MALFORMED_PAYLOAD` | -10 | 깨진 JSON 또는 필수 필드 누락 |
| `UNKNOWN_DEVICE` | 0 | Trust Score 계산 대상 아님 |

예시:

```txt
DEVICE_ID_MISMATCH -25
ABNORMAL_PUBLISH_RATE -20
AI_ANOMALY -15
```

이 window에서는 `-25`만 적용합니다.

Trust Score DB 갱신은 `edge.trust.run_trust_score_update`에서 수행합니다.

```bash
python -m edge.trust.run_trust_score_update
```
