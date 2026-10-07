# Phase 8 — Packet Rule·차단·복구

작업: P8-05 검토 지원, P8-10 검토 지원, P8-11 인계(Packet·차단·복구 해석)
기준: 작업 시작 시점의 `develop` 최신 Commit(PR #104 이후, PR에 실제 해시 기록) / 브랜치: `feature/sunwoo-phase8-packet-review`

이 문서는 구현 담당자의 변경을 **검토**한 결과다. 구현 코드는 수정하지 않았다.
검토 의견은 해당 구현 담당자가 반영한다. 추가한 코드는 검토용 테스트와 읽기 전용 검토 도구뿐이다.

## 1. 추가한 산출물

| 파일 | 용도 |
| --- | --- |
| `tests/test_phase8_sunwoo_packet_rule_review.py` | P8-05 Packet Rule 기기별 임계값·경계·근거 반례 (V05·V06·V07·V10·V11) |
| `tests/test_phase8_sunwoo_packet_scenarios.py` | P8-10 Packet 공격/회귀 시나리오: MQTT Rule·Packet Rule → Trust → Firewall 기대 결과 (V08·V09·V12·V23) |
| `tests/packet_review_support.py` | 위 두 테스트의 Migration 기반 임시 DB Fixture 보조 함수 |
| `edge/scenarios/packet_review_report.py` | 복사 DB에서 Packet Event·정책 revision·Trust 이력·차단 요청을 대조하는 읽기 전용 CLI |

## 2. 검토 의견

| ID | 등급 | 대상 | 내용 | 제안 |
| --- | --- | --- | --- | --- |
| SW-P8-01 | 낮음 (수정 권장) | `edge/detection/packet_rule_detector.py` `detect_packet_rules()` | `packet_count / captured_duration_seconds`를 float로 나눈 뒤 `>`로 비교한다. 115 packets / 9.2 s는 수학적으로 정확히 12.5 pps지만 `12.500000000000002`가 되어 상한 12.5에서 **탐지**된다. V06 "정확한 상한은 비탐지" 계약과 어긋난다. 기본값 10.0·2500.0에서는 9.0~10.0초(0.1초 단위) 분모로 재현되지 않았고, 관리자가 소수 임계값을 넣을 때 드러난다. | 비교만 `Decimal(str(값))`으로 하거나 `math.isclose`로 같은 값을 비탐지 처리하고, evidence의 관측값은 그대로 둔다. `Fraction(9.2)`처럼 float를 그대로 넣으면 이미 이진 근사값이라 **해결되지 않는다**(확인함). 판정식 변경이므로 Packet Rule `version` 상향 여부를 판단한다. 재현: `test_review_finding_exact_rational_boundary_is_not_detected`(xfail strict) — 수정되면 XPASS로 실패하므로 마커를 제거한다.|
| SW-P8-02 | 정보 | `edge/scenarios/compare_events.py` | 기존 비교 도구는 Event Type 일치만 본다. 기기 revision·임계값·단위·실제 Trust 반영·대표 감점은 확인하지 않는다. | 실기기 시험 결과에는 `packet_review_report`를 함께 실행해 첨부한다(3절).|
| SW-P8-03 | 정보 | `edge/scenarios/packet_scenarios.py` | 시나리오 설명의 "packet_rate_threshold(기본 10.0)"는 Phase 8 이후 대상 기기 revision 값으로 바뀐다. | 시험 기록에 대상 기기의 `device_policy_revision`과 Packet/Byte 상한을 함께 적는다. 코드 변경은 요구하지 않는다.|
| SW-P8-04 | 정보 (테스트 이식성) | `tests/test_packet_segment_gap_cli.py`, `tests/test_planned_maintenance_cli.py` | Windows에서 사용자 폴더에 한글이 있으면 실패한다. 앞의 파일은 UTF-8로 쓴 plan을 `read_text()`(cp949)로 읽고, 뒤의 파일은 `.env`를 `write_text()`(cp949)로 쓴 뒤 pydantic이 UTF-8로 읽는다. 운영 Pi(Linux, UTF-8)에는 영향이 없다. | `read_text/write_text(encoding="utf-8")` 명시. 임시 회피: `PYTHONUTF8=1` 또는 `--basetemp`를 영문 경로로 지정.|
| SW-P8-05 | 정보 (기존 실패) | `tests/test_normal_collection_export.py` 외 2개 | 테스트 DB 옆에 `-wal`/`-shm` 파일이 남아 `snapshot_not_standalone`으로 HOLD되거나 `immutable=1` 기대가 깨진다. 변경 전 기준 코드에서도 Linux·Windows 모두 같은 실패가 났다. | Fixture의 WAL checkpoint·연결 종료 순서를 확인한다. 이번 PR과 무관. /(Export)·(Recovery·Maintenance) |

확인 결과 계약대로 동작한 항목(테스트로 고정):

- 동일 Feature를 두 기기의 서로 다른 상한으로 판정하고, evidence의 임계값·단위·revision이 판정에 쓴 정책 객체와 같다. 기기 revision은 전역 `policy_version`을 바꾸지 않는다.
- 분모는 실제 `captured_duration_seconds`다(96 packets / 9.5 s = 10.105 pps 탐지). 낮은 기기 상한도 `LATE_CAPTURE`·`PARTIAL_CAPTURE`·9초 미만 수집 제외를 우회하지 못한다.
- 늦게 처리한 Window는 `window_start` 당시 revision을 쓰고, 재실행·정책 변경만으로 Event가 늘거나 checkpoint가 초기화되지 않는다.
- 등록 효력 이전 Window의 Packet IP는 새 기기에 소급 귀속하지 않는다(후보 `device_id`는 evidence에 보존).
- 미등록 IP는 전역 v3 상한(10 pps / 2500 B/s)으로 Event만 저장하고 점수에 반영하지 않는다.
- 정책 누락 ACTIVE 기기는 Rate를 기본값으로 대신 판정하지 않고 `POLICY_UNAVAILABLE`을 남기며, Port Scan 탐지는 유지하되 감점 0이다.
- 관리 IP 제외(`PACKET_RULE_EXCLUDED_PEER_IPS`)는 등록 기기 정책보다 우선한다. 기기 정책은 Rate 2종만 바꾸고 Port Scan·Broker DoS 기준은 전역을 유지한다.
- 같은 Window의 **실제 MQTT Feature Rule**(40건/10초) + Packet Rate + Byte Rate는 FLOODING 대표 −20 한 건이다(100→80, 제어 기기 100 유지). Broker DoS가 섞이면 대표 −25다.
- SCAN + FLOODING 동시(−45)는 −30 cap, 50→20에서 격리 1건과 `tcp/1883 DROP` PENDING 요청 1건을 만든다. 격리 뒤 다음 Window 공격은 `ALREADY_ISOLATED`로 처리되어 중복 차단 요청이 없다. 다른 Window 반복은 누적된다(100→80→60).
- PENDING 기기의 공격은 4종 Event와 후보 감점을 보존하되 `PENDING_AT_WINDOW`로 처리 완료되고, ACTIVE 전환 뒤에도 소급 감점·차단이 없다.
- DISABLED 구간의 Packet 이상은 UNKNOWN이 아니라 같은 기기 통신으로 기록되고 `DISABLED_AT_WINDOW`로 감점·차단이 제외된다.
- 비활성화 예약 접수 뒤에는 효력 시점 전이라도 `DISABLE_REQUESTED_OR_DISABLED`로 새 감점·차단을 만들지 않는다.
- 같은 Window에 Rule과 Packet IF AI Event가 함께 있으면 Rule 대표만 반영한다. `observe`에서는 AI가 `AI_OBSERVATION_ONLY`·감점 0, `enforce`에서는 `NOT_REPRESENTATIVE`다.

## 3. 실기기·복사 DB 결과 검토 방법

운영 DB에서 직접 실행하지 않는다. 시험 후 SQLite Backup API로 만든 복사본을 받아 실행한다.
도구는 `mode=ro`로 열어 DB 내용을 바꾸지 않는다. WAL 형식 복사본은 같은 폴더에 `-shm`/`-wal`
보조 파일이 생길 수 있으므로 복사본 전용 폴더에서 실행한다.

```bash
python -m edge.scenarios.packet_review_report \
  --db /path/to/review-copy.db \
  --from 2026-10-06T01:00:00Z --to 2026-10-06T01:10:00Z \
  --device-id esp32_02 \
  --json-out output/review/p8-10-flooding-esp32_02.json
```

- 종료 코드 0 = FAIL 없음, 1 = FAIL 존재, 2 = 입력·DB 오류.
- 시간은 UTC다(`+09:00`처럼 오프셋을 붙이면 UTC로 변환). `--from`은 포함, `--to`는 미포함이며 `analysis_window_start` 기준이다.
- `output/` 결과는 Git에 올리지 않는다. PR·인계 문서에는 요약(Event 수·대표 감점·FAIL/WARN)만 남긴다.

검사 항목:

| check | 내용 |
| --- | --- |
| `RATE_RECOMPUTE` | 관측값 = 원시 수 / 실제 수집 시간, 그리고 `>` 상한. 부동소수점 오차로만 초과하면 WARN(SW-P8-01) |
| `RATE_UNIT` | `packets/second`·`bytes/second` |
| `POLICY_REVISION` | evidence revision·임계값 = `window_start` 당시 저장 revision. 해석할 수 없는 Window도 FAIL |
| `RESPONSE_GATE` | 점수 반영 Event와 Trust 이력이 당시 ACTIVE·정책 유효 기기의 것. 처리 시점에 비활성화 예약이 있었는데 반영돼도 FAIL |
| `WINDOW_HISTORY` | 같은 Window 이력 1건, `capped_delta` ≥ −30 |
| `FAMILY_REPRESENTATIVE` | 같은 Incident Family 대표 1건 |
| `ISOLATION_LINK` | 차단 요청은 score < 30 이력의 대표 Event(MQTT 포함)에서만 생성 |
| `UNPROCESSED` | Trust 미처리 Packet Event (WARN) |

## 4. P8-10 실기기 시험 기대값 (검토 기준)

| 시나리오 | 대상 | 기대 Event | 기대 Trust·차단 | 중단 조건 |
| --- | --- | --- | --- | --- |
| 같은 Window MQTT 과다 + UDP Packet/Byte Rate | ESP32 #2 (ACTIVE) | `ABNORMAL_PUBLISH_RATE`·`PACKET_RATE_ANOMALY`·`BYTE_RATE_ANOMALY` | 이력 1건, 대표 −20, 100→80, 격리 없음. 제어 기기 100 유지 | 이력 2건 이상 또는 −40 이상 감점 |
| Broker DoS 동반 | ESP32 #2 | 위 + `BROKER_DOS_SUSPECTED` | 대표 −25 | FLOODING 대표 2건 |
| Port Scan + Broker DoS | 시험 기기 | `PORT_SCAN`·`BROKER_DOS_SUSPECTED` | −45 → −30 cap. 30 미만이면 `isolated`·`tcp/1883 DROP` 1건 | cap 초과, 30 이상에서 차단 요청, 격리 후 중복 요청 |
| PENDING 기기 공격 | Pico (PENDING) | Event·후보 감점 저장 | 감점·이력·차단 0, `PENDING_AT_WINDOW` | 점수 변동 또는 Firewall 요청 생성 |
| 비활성화 예약 후 공격 | 시험 기기 | Event 저장 | `DISABLE_REQUESTED_OR_DISABLED`, 감점·차단 0 | 예약 이후 새 차단 요청 |

공식 해제·복구 후에는 `firewall_rules` 상태, 실제 DROP 규칙, 점수·상태, 정상 수신 재개가 일치하는지
Recovery 결과(V15·V22)와 함께 확인한다. 이 문서의 로컬 PASS는 Pi 실기기·운영 DB 결과를 대신하지 않는다.

## 5. 실행한 검증

```bash
python -m pytest -q tests/test_phase8_sunwoo_packet_rule_review.py tests/test_phase8_sunwoo_packet_scenarios.py
python -m pytest -q tests backend/tests
```

- 신규 검토 테스트: **31 passed, 1 xfailed**(SW-P8-01 재현, strict), Linux 기준. Windows에서는 첫 버전(25 passed, 1 xfailed)만 확인했으므로 보강본은 재실행이 필요하다.
- 전체 회귀
  - Linux(Python 3.13, scikit-learn 1.9.1): 신규 테스트 외 40건 실패. 변경 전 기준 코드에서도 같은 40건(SW-P8-05 및 환경 버전 차이).
  - Windows(Python 3.12, 사용자 경로 한글): SW-P8-05 묶음 + SW-P8-04 인코딩 실패(로그에서 확인한 8건). 모두 기존 테스트이며 신규 파일과 무관.
  - PR에는 실제 실행한 `pytest` 마지막 줄(passed/failed/skipped/warnings)을 그대로 기록한다.

## 6. 미검증·인계

| 항목 | 사유 | 시점 |
| --- | --- | --- |
| 고정 버전 환경 전체 회귀 | 로컬 환경 버전 차이 | 병합 전 |
| Pi 복사 DB에서 P8-10 대표 시험 결과 검토 도구 실행 | 복사본 수령 필요 | 배포 전 |
| SW-P8-01 수정 여부와 Packet Rule version 결정 | 구현 담당 판단 | Phase 9 이전 |
| SW-P8-04·05 테스트 수정 | 기존 테스트 범위 | Phase 9 초반 |
| standalone Packet runner와 Orchestrator 결과 일치(P8-05 완료 근거) | 이번 테스트는 Stage를 직접 호출. 정책 공유는 기존 `test_packet_rule_management_exclusion.py`가 확인 | 배포 전 |
