# Phase 5 Raspberry Pi Scenario Hook Implementation Plan

> **For agentic workers:** Implement this plan task-by-task with TDD. Every production change must be preceded by a focused failing test.

**Goal:** Phase 5 Scenario Runner가 동일 Run Context를 Baseline·Cleanup Hook에 전달하고, Raspberry Pi에서 읽기 전용 Baseline 점검과 공격 프로세스 잔존 확인을 수행하도록 한다.

**Architecture:** `ScenarioHookContext`를 불변 dataclass로 추가하고 Runner가 실제 실행 직전에 한 번 생성해 두 Hook에 동일 객체를 전달한다. Pi Baseline은 SQLite read-only 조회와 systemd/process 상태 확인만 수행하며, Cleanup은 공격 프로세스 잔존 여부만 확인한다. Trust Score·Device 상태·Firewall·iptables를 변경하는 자동 복구는 포함하지 않는다.

**Tech Stack:** Python 3.10+, stdlib `dataclasses`, `sqlite3`, `subprocess`, `pathlib`, pytest

## Global Constraints

- 기준 브랜치: `develop` HEAD `7d288776e9560adcb2fd3c72664ba9e7e5108c6e`
- 작업 브랜치: `feature/woomin-phase5-pi-scenario-hooks`
- 설계 문서: `docs/specs/2026-08-06-phase5-pi-scenario-hooks-design.md`
- DB·API·Frontend·Firmware·Migration 계약은 변경하지 않는다.
- `detection_events`, `trust_score_history`, `isolation_history`, `firewall_rules` 기존 Row를 UPDATE/DELETE하지 않는다.
- `devices.status`, `devices.trust_score`, iptables Rule을 자동 복구하지 않는다.
- Dry-run에서는 Hook을 호출하지 않는다.
- 실제 실행에서 기본 no-op Hook은 계속 거부한다.
- `scenario-result.jsonl`, Run Manifest, Dataset v2 계약을 유지한다.

---

### Task 1: Hook Context 계약

- [x] RED: `ScenarioHookContext` 불변성과 필드 계약 테스트를 추가한다.
- [x] RED: 실제 실행에서 Baseline·Cleanup에 동일 Context 객체가 전달되는 테스트를 추가한다.
- [x] RED: Dry-run에서 두 Hook이 호출되지 않는 테스트를 추가한다.
- [x] GREEN: Context와 Protocol 시그니처를 최소 구현한다.
- [x] GREEN: Runner가 최종 `evaluation_scope` 확정 뒤 Context를 한 번 생성하고 두 Hook에 전달한다.
- [x] REFACTOR: 기존 테스트용 no-arg Hook 호환 경로를 제한적으로 유지한다.

### Task 2: Pi 읽기 전용 Baseline Hook

- [x] RED: `DATABASE_URL`이 절대경로 SQLite가 아니면 실패하는 계약을 추가한다.
- [x] RED: 대상 Device 없음·`status != normal`·활성 `PENDING/APPLIED` Firewall Rule을 거부하는 계약을 추가한다.
- [x] RED: 실제 iptables에 대상 Source IP의 `hanium-firewall:` Rule이 남아 있으면 거부하는 계약을 추가한다.
- [x] RED: Firewall inventory를 읽을 수 없으면 fail-closed 하는 계약을 추가한다.
- [x] RED: `session_id`가 있으면 해당 `packet_capture_sessions` Row가 `RUNNING`이고 `ended_at IS NULL`이어야 하는 계약을 추가한다.
- [x] RED: 필수 systemd 서비스 비활성·Capture 서비스 상태 불일치·충돌 프로세스 존재를 거부하는 계약을 추가한다.
- [x] GREEN: URI read-only SQLite 연결과 parameter binding으로 조회를 구현한다.
- [x] GREEN: systemd·iptables inventory·프로세스 조회를 인자 배열과 `shell=False`로 구현한다.

### Task 3: Pi Cleanup Hook

- [x] RED: 프로젝트 공격 모듈 프로세스가 남아 있으면 실패하는 테스트를 추가한다.
- [x] RED: Trust·Device·Firewall·iptables 변경 명령을 호출하지 않는 계약 테스트를 추가한다.
- [x] GREEN: 공격·수동 Detector·Recovery 프로세스 잔존 여부만 읽기 전용으로 확인한다.
- [x] GREEN: 잔존 프로세스가 없으면 성공하고, 있으면 PID·명령을 포함한 사유를 반환한다.

### Task 4: 실행 가이드와 회귀 검증

- [x] 문서에서 Hook 미구현 TODO를 제거하고 Pi Hook의 책임·제한을 기록한다.
- [x] Pi 운영 DB 절대경로 `DATABASE_URL` 설정을 기록한다.
- [x] `session_id`가 있는 공식 Capture 실행과 없는 Detection-only 실행의 Capture service 조건을 기록한다.
- [x] 자동 Firewall Release·Trust Recovery가 없으며 Observation 후 승인 절차를 사용한다고 기록한다.
- [x] Scenario Runner·Cleanup 집중 테스트를 실행한다.
- [x] Windows 비-Linux 전체 회귀를 실행한다.
- [x] Raspberry Pi에서 기존 Firewall Wrapper Linux 테스트를 실행한다.
- [x] `python -m compileall -q backend edge tests`와 `git diff --check`를 실행한다.
- [ ] Feature 브랜치의 Pi Hook 읽기 전용 Smoke는 PR 리뷰 후 실제 장비에서 수행한다.
- [ ] 실제 공격·ESP32·FULL_E2E 실행은 별도 승인된 Pilot 단계에서 수행한다.
