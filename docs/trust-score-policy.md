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

이벤트별 Trust Score 변화량은 `severity`가 아니라 `event_type` 기준으로 고정합니다. `severity`는 API와 대시보드 표시용으로 사용합니다.

| event_type | score_delta | 비고 |
| --- | ---: | --- |
| `DEVICE_ID_MISMATCH` | -25 | 기기 신원 불일치 |
| `ABNORMAL_PUBLISH_RATE` | -20 | 과도한 publish 또는 짧은 메시지 간격 |
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

TODO: `edge/trust`에 DB 갱신 로직을 구현합니다.
