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

환경 변수:

```env
INITIAL_TRUST_SCORE=100
ISOLATION_THRESHOLD=30
```

같은 window 규칙: 하나의 feature window에서 여러 detection event가 발생하면 가장 큰 감점만 적용합니다. 나머지 event는 `applied_to_score = 0`으로 유지합니다.

예시:

```txt
DEVICE_ID_MISMATCH -25
ABNORMAL_PUBLISH_RATE -20
AI_ANOMALY -15
```

이 window에서는 `-25`만 적용합니다.

TODO: `edge/trust`에 DB 갱신 로직을 구현합니다.
