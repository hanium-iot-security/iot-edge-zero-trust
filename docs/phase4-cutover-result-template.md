# Phase 4 Cutover·Rollback 결과 — YYYY-MM-DD

> **상태:** 미실행 / Smoke Test 완료 / Cutover 완료 / 자동 Rollback / 수동 Rollback
>
> **주의:** 예상값과 실제 관측값을 구분하고, 실행하지 않은 항목은 `미검증`으로 남긴다.

## 1. 실행 기준

| 항목 | 실제 결과 |
| --- | --- |
| 실행 시각 UTC·KST |  |
| 작업자 |  |
| `develop` Commit SHA |  |
| 운영 DB 경로 |  |
| Migration Version |  |
| Cutover 결과 JSON |  |
| Rollback 결과 JSON |  |

## 2. Backup

| 항목 | 실제 결과 |
| --- | --- |
| Backup 파일 |  |
| SHA256 Manifest |  |
| SHA256 |  |
| Windows·외부 복사 위치 |  |

## 3. 서비스 전환

| 항목 | 실행 전 | 실행 후 |
| --- | --- | --- |
| 기존 Detector·Trust Cron/Service |  |  |
| Detection Orchestrator |  |  |
| Firewall Worker |  |  |

## 4. DB 검증

| 검증 | Migration 전 | Migration 후 | Rollback 후 |
| --- | --- | --- | --- |
| `PRAGMA integrity_check` |  |  |  |
| `PRAGMA foreign_key_check` |  |  |  |
| `schema_migrations` |  |  |  |
| Segment Row·ID |  |  |  |
| Packet Feature FK |  |  |  |

## 5. Cutover Checkpoint

| Detector Key | `last_processed_id` | `last_completed_window_end` | 계산 근거 |
| --- | ---: | --- | --- |
| `mqtt_feature_builder + mqtt_logs` |  |  |  |
| `mqtt_feature_rule + feature_logs` |  |  |  |
| `mqtt_message_rule + mqtt_logs` |  |  |  |
| `mqtt_if + feature_logs` |  |  |  |
| `packet_rule + packet_feature_logs` |  |  |  |
| `packet_if + packet_feature_logs` |  |  |  |
| `trust_score_v2 + detection_events` |  |  |  |

## 6. 관측 결과

- 실제 실행 명령:
- 예상 결과:
- 실제 결과:
- 오류·경고:
- 자동 Rollback 여부:
- 수동 조치:
- 남은 미검증 항목:

## 7. 최종 판단

- [ ] Cutover 성공
- [ ] Rollback 성공
- [ ] FK 위반 없음
- [ ] Integrity `ok`
- [ ] 기존 데이터·ID·FK 보존
- [ ] Cutover 이전 Event 재감점 없음
- [ ] 신규 서비스 정상 시작
- [ ] 기존 Cron과 신규 Orchestrator 동시 실행 없음

**판단:** 진행 / Rollback 유지 / 추가 수정 필요
