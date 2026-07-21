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
| 수동 Rollback 직전 보존 Backup·SHA256 |  |
| Windows·외부 복사 위치 |  |

## 3. 서비스 전환

| 항목 | 실행 전 | 실행 후 |
| --- | --- | --- |
| 기존 Detector·Trust Cron/Service |  |  |
| Detection Orchestrator |  |  |
| Firewall Worker |  |  |
| Packet Capture·Feature Writer |  |  |
| Gateway Metrics·MQTT Producer |  |  |

## 4. Smoke 원본 보존 증적

| 항목 | 실행 전 | 실행 후 |
| --- | --- | --- |
| 운영 원본 논리 Snapshot 경로 |  |  |
| 운영 원본 논리 Snapshot SHA256 Manifest |  |  |
| 운영 원본 논리 Snapshot SHA256 |  |  |
| 운영 원본 Table별 Row 수 |  |  |
| Smoke DB SHA256 | Migration 전 | Migration 후 |
| Segment ID Digest |  |  |
| Packet Feature Row·고아 FK |  |  |
| Detection Event Row |  |  |
| 기존 Detection Event ID 부분집합 보존 |  |  |
| 기존 Detection Event 불변 핵심 값 보존 |  |  |
| 신규 Detection Event ID·`event_type` (`LEGACY_MIGRATION`만 허용) |  |  |
| Checkpoint 초기화 후 `smoke_final` 보존 검사 |  |  |

## 5. DB 검증

| 검증 | Migration 전 | Migration 후 | Rollback 후 |
| --- | --- | --- | --- |
| `PRAGMA integrity_check` |  |  |  |
| `PRAGMA foreign_key_check` |  |  |  |
| `schema_migrations` |  |  |  |
| Segment Row·ID |  |  |  |
| Packet Feature FK |  |  |  |

## 6. Cutover Checkpoint

| Detector Key | `last_processed_id` | `last_completed_window_end` | 계산 근거 |
| --- | ---: | --- | --- |
| `mqtt_feature_builder + mqtt_logs` |  |  |  |
| `mqtt_feature_rule + feature_logs` |  |  |  |
| `mqtt_message_rule + mqtt_logs` |  |  |  |
| `mqtt_if + feature_logs` |  |  |  |
| `packet_rule + packet_feature_logs` |  |  |  |
| `packet_if + packet_feature_logs` |  |  |  |
| `trust_score_v2 + detection_events` |  |  |  |

## 7. 관측 결과

- 실제 실행 명령:
- 예상 결과:
- 실제 결과:
- 오류·경고:
- 실패 단계(`failure_stage`):
- 최초 오류(`primary_error`):
- 자동 Rollback 시도(`rollback_attempted`):
- 자동 Rollback 성공(`rollback_succeeded`):
- 자동 Rollback 오류(`rollback_error`):
- Rollback 후 실제 Unit 상태와 기대 상태 비교:
- 수동 조치:
- 남은 미검증 항목:

## 8. 최종 판단

- [ ] Cutover 성공
- [ ] Rollback 성공
- [ ] FK 위반 없음
- [ ] Integrity `ok`
- [ ] 기존 데이터·ID·FK 보존
- [ ] Cutover 이전 Event 재감점 없음
- [ ] 신규 서비스 정상 시작
- [ ] Writer 서비스 작업 전 상태 복구
- [ ] 반환 Checkpoint와 DB 7개 Row 일치
- [ ] Smoke 원본 논리 Snapshot SHA256·Row 수 불변
- [ ] 기존 Cron과 신규 Orchestrator 동시 실행 없음

**판단:** 진행 / Rollback 유지 / 추가 수정 필요
