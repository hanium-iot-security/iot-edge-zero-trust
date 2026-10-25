# Pi IPv4 입력 전체 격리 검증 — 2026/10/25~26

## 구현과 운영 범위

격리 대상 source IPv4에서 Pi INPUT으로 들어오는 모든 프로토콜·포트를 차단한다. Pi가 라우터가 아닌 같은 LAN의 호스트인 현재 구성에서 검증했다. IPv6, FORWARD, 다른 LAN 호스트와 인터넷 접근 차단은 포함하지 않는다.

기준 develop은 `b5349bee80a0a1890bbe8bc7cf3582c10a6d0e73`이다. 검증한 런타임 변경은 `827c807`과 `85c69af`에 있다. 새 migration·API 형식·프런트 변경은 없다. 모델·임계값·Trust 판단 기준도 바꾸지 않았다.

- 기본값 `FIREWALL_AUTO_SCOPE=MQTT_IPV4_TCP_1883`은 기존 동작을 유지한다. 이번 Pi 운영값은 `PI_INPUT_IPV4_ALL`이다.
- Worker는 APPLIED MQTT 원본에서 별도 광역 행을 예약하고 다음 cycle에 다시 검증해 적용한다. isolated 전이와 실제 광역 적용 사이의 대기 시간을 0으로 보장하지 않는다.
- 현재 ACTIVE 정책·revision·등록 IP·보호 주소·미처리 해제를 확인한다. 같은 원본에 광역 이력이 있으면 FAILED·REMOVED 이후에도 자동으로 되살리지 않는다.
- 원본 MQTT 행은 보존한다. 규칙별 해제는 정확한 ID로 감사하며, 광역 하나만 해제하면 MQTT 차단이 남을 수 있다. 전체 통신 복귀에는 남은 모든 규칙의 정확한 해제가 필요하다.
- 정상 복구는 현재 IP와 대상 소유의 미해결 FAILED 과거 IP에 남은 DROP과 runtime freshness를 확인한다. 과거 IP의 다른 기기 행·처리된 해제 활동도 freshness에 포함한다.

## 코드 검증

| 환경 | 대상 | 실제 결과 |
|---|---|---|
| Windows / Python 3.10.11 | 자동 확장, 기존 Worker·Trust, repository·API·해제·runtime·복구·Wrapper 관련 회귀 | 447 passed, 95.92초 |
| Windows / Python 3.10.11 | 과거 FAILED IP와 freshness 복구 보호 및 기존 baseline 회귀 | 중간 검증 351 passed. 위 통합 결과와 중복되므로 합산하지 않음 |
| Pi / Python 3.10.11 | 격리된 임시 소스의 UDP 응답기·프로토콜 파서 | 19 passed, 2.48초. UDP는 loopback 임시 포트, ICMP는 C++ fixture이며 실물 차단 결과와 구분 |
| 정적 확인 | 변경 Python 구문·diff 공백 검사 | 통과. 저장소에 별도 Python lint/type 명령은 확인되지 않음 |

자동 확장의 기본값·감사 actor·현재 정책·source/IP·보호 주소·해제 경합·schema 불일치·유한 재시도·배치 한도·dry-run 비변경과, 과거 FAILED IP의 runtime 잔여·관측 이후 활동·실행 직전 재검증을 포함한다.

코드 검토에서 과거 IP의 다른 기기 활동과 처리된 해제 시각을 freshness에 포함하지 않던 지적을 수정한 뒤 회귀했다. 최종 자동 확장 검토는 구현자와 다른 단일 리뷰 문맥에서 수행했다. 여러 전문 리뷰어의 독립 실행은 실행기 용량 문제로 완료하지 못했고, 별도 native 체크리스트 검토를 완료했다. 이 한계를 다중 독립 검토 통과로 표현하지 않는다.

## Pi 적용

새 조회에서 migration 011은 `2026-10-12 04:19:40`에 이미 적용되어 있었고 schema는 001..016이었다. 기존 보호 파일·Wrapper도 설치되어 있었다. 10/11의 미설치 기록을 현재 상태로 사용하지 않았다.

최신 develop과 Pi 기존 변경을 대조해 `backend/app/config.py`, `edge/trust/firewall_worker.py`, `edge/trust/run_firewall_worker.py`, `edge/trust/automatic_scope_extension.py`, `edge/trust/baseline_recovery.py`의 필요한 차이만 반영했다. Pi의 다른 미커밋 변경과 설정은 보존했다. `.env`에는 운영 scope 설정만 추가했다. 원래 파일과 설정의 비공개 복구 사본을 Pi의 별도 rollout 디렉토리에 보관했다.

Worker와 API만 정상 재시작했고 API `NoNewPrivileges=true`를 유지했다. Capture·Subscriber·Orchestrator의 PID/InvocationID와 Boot ID는 유지됐다. Wrapper·sudoers·보호 파일·모델과 migration은 변경하지 않았다.

## 실제 ESP32_02 차단·해제

대상은 ESP32_02 `.5`→Pi `.20`이다. ESP32_01 `.4`, Pico `.8`와 관리자 PC를 정상 비교 대상으로 관측했다. 측정 프로토콜은 MQTT/TCP 1883, HTTP/TCP 8000, UDP 9002, ICMP echo다. 아래 결과는 각 포트를 전수 시험했다는 뜻이 아니라 전체 match 규칙과 네 대표 통신을 확인한 것이다.

| 단계 | MQTT | HTTP | UDP | ICMP | 확인한 상태 |
|---|---|---|---|---|---|
| 차단 전 | 수신 | 응답 | nonce 응답 | echo 응답 | MQTT는 Pi 원본에도 저장 |
| MQTT 원본 22만 적용 | 차단 | 응답 | 응답 | 응답 | 기존 범위 확인 |
| 자동 광역 23 적용 | 차단 | 차단 | 차단 | 차단 | actor `system:firewall-worker`, source 22, revision 1. DROP counter 0→4 |
| 광역 23만 공식 해제 | 차단 | 응답 | 응답 | 응답 | 요청 18 SUCCEEDED. MQTT 22 유지, 자동 재생성 없음 |
| 관리자 광역 24 적용 후 MQTT 22 공식 해제 | 차단 | 차단 | 차단 | 차단 | 광역 24만으로 전체 차단. 요청 19 SUCCEEDED. 이때 정상 복구 preflight DENIED |
| 광역 24 공식 해제 | 수신 | 응답 | nonce 응답 | echo 응답 | 요청 20 SUCCEEDED. 활성 규칙·대기 해제 없음 |

격리 유발 시험은 기존 정책에서 40건씩 네 번 전송한 MQTT 160건을 Pi 원본 저장과 대조했다. 실제 Rule 감점으로 100→80→60→40→20이 되어 MQTT 22가 적용됐고 자동 확장 23이 뒤따랐다. AI는 observe 모드로 유지했다.

최종 해제 후 MQTT nonce `ip4_restored_mqtt_1026a`는 Pi `mqtt_logs` ID 273983에 1건 저장됐다. UDP 응답기의 실제 응답과 ICMP echo·HTTP 응답도 확인했다. 시험용 UDP 프로세스는 종료했다.

## 시험 후 복구와 수집 상태

시험용 앱을 원래 APP 바이트로 복원하고 APP·partition·OTA 세 영역의 독립 digest 검증을 통과했다. 원래 APP SHA256은 `b8e5290ae24b6ab70f86086bdfab31f749ab0ad0a1a57c186df6b89a88251d7c`다. full flash/NVS 복원을 의미하지 않는다. 수동 조작 없는 UART의 sequence 1·2 / uptime 38·43을 Pi 원본 ID 274039·274042와 대조해 5초 송신을 확인했다.

공식 복구 `20261025T155139Z-3102b932ea94`는 SUCCESS이며 ESP32_02를 isolated·20에서 normal·100으로 돌렸다. 감사 기록과 311,230,464바이트의 사전 백업을 보관했다. Core/API에 기록된 백업 SHA256은 `41dafbf460ff435741f8a62878662d0ea6ef2fc9cb339791745ba69cbf5abff0`, 백업 및 사후 integrity는 ok, FK 위반은 0이다. 별도 읽기에서 백업의 isolated·20과 감사의 normal·100을 대조했다. 백업 바이트 전체의 추가 재해시는 수행하지 않았다.

2026/10/26 00:55:14~00:56:46 KST의 두 최종 관측에서 세 기기는 normal·100이며 실제 MQTT ID가 각각 증가했다. Capture Session 154는 계속 RUNNING이다. 필수 여섯 checkpoint가 모두 전진했고 gap 최대 ID 31은 그대로였다. 시험 시작 경계 89718 이후 90588까지 870개 capture segment는 모두 PROCESSED이며 새 불완전 상태는 없었다. 이후 관측의 최대 segment는 90592였다. INPUT은 기본 ACCEPT만 남고 활성/실패/PENDING 규칙·대기 해제·시험 UDP 프로세스는 없다.

Packet IF는 `packet-if-v2-calib-002-p99-py310`, bundle SHA256 `7713cd81066d56daf964d081a6588e967cafa2a8f5fdb64521fb7cc18a0c1f30`, observe 상태가 유지됐다. MQTT IF는 비활성이다. 재연결 학습이나 임계값 조정은 하지 않았다.

## 한계와 운영 확인

UART STATUS가 깨진 시도와 너무 빠른 초기 probe는 검증 결과에서 제외했다. 읽기 전용 STATUS 재동기화와 한 번의 ROM MAC 확인·재부팅 후 유효 응답으로만 차단 결과를 판정했다. USB 오류의 물리 원인은 확정하지 않았다. 요청한 Claude Opus 5.5/xhigh 구독 검토 한 번은 300초 만료·응답 0바이트로 유효 의견이 없었고 재시도하지 않았다.

이번 새 코드로 Pi 재부팅·DHCP 이동·관리자 장애 복구를 실제 실행하지 않았다. 기존 날짜의 namespace/재부팅 결과는 이번 실행 결과에 합산하지 않는다. 이번 namespace harness 실행은 dry-run이었다. 이 항목들은 장비 정비 시간을 따로 잡는 회귀 과제로 남긴다.

운영 확인은 현재 `.env`의 ALL 설정, 새 격리 원본과 광역 행의 source/actor/revision, Worker의 APPLIED 및 runtime DROP, 정상 기기의 원본 수신과 여섯 checkpoint 전진을 함께 읽는다. 광역 이력이 있는 동일 원본을 시험 목적으로 재생성하려 하지 않는다. 정상 기기 차단·보호 주소 규칙·새 수집 불완전 구간·지속 처리 정체가 발생하면 원인을 보존하고 운영 설정을 기본 MQTT로 되돌린 뒤 Worker를 정상 재시작한다. 설정 rollback은 기존 광역 규칙을 삭제하지 않으므로 남은 ID는 공식 API로 별도 해제한다. DB 전체 덮어쓰기나 직접 점수 변경은 복구 수단으로 사용하지 않는다.

운영 DB·설정 원본·펌웨어 바이너리·원시 패킷·개인 출력 디렉토리는 저장소와 PR에서 제외한다.
