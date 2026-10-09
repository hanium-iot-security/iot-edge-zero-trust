# P1·P2 예비 수집 결과 — 2026-10-09

ESP32 2 한 대를 `phase9-normal-pilot-v2`로 전환해 각 180초 관측했다. ESP32 1과 Pico는 기본 동작을 유지했다. Payload Schema는 `phase5-normal-payload-v1`이며, 시험 설정은 Payload 128B·MQTT Buffer 256B·P1 4~6초·P2 5초다. 수치와 정상 패턴 승인은 본 수집 전에 별도로 확정한다.

| 시험 | 시간(KST) | ESP32 1 / ESP32 2 / Pico 수신 | ESP32 2 결과 |
| --- | --- | --- | --- |
| P1 주기 변동 | 13:11:50~13:14:50 | 36 / 36 / 35건 | 원본 수신 간격 4.078~5.846초, 필수 필드만 송신 |
| P2 구성·크기 변동 | 13:18:40~13:21:40 | 36 / 36 / 36건 | 52~83B, 순번에 따른 필수 필드/RSSI/RSSI+Free Heap 세 형태 확인 |

두 Run의 기존 후보 QC와 별도 Profile 대조가 통과했다. 각 기기의 구간 내 MQTT 순번 누락·재시작·송신 실패와 탐지 이벤트는 없었다. 원본·봉인 Snapshot·MQTT/Packet Feature·18개 PCAP 및 진단 파일을 보존하고 해시를 대조했다. 활성 6개 처리 경계가 Run 종료에 도달해 전진했으며, 관측 시각 기준 45초 이내였다. 비활성 MQTT IF는 별도로 유지했다.

P1 시작 경계의 ESP32 2 순번 9는 Serial 관측 시각과 Gateway 수신 시각이 경계 양쪽에 있었다. 봉인 DB에서 시작 직전 수신과 Payload 일치를 확인했다. P2의 시작·종료 경계 사례도 DB와 Serial을 대조했다. 경계 사례를 구간 내부 손실로 세지 않았다.

Pico의 P2 수신 간격은 3.501~6.462초였다. PCAP에서 36건을 TCP 재조립해 원본과 대조했으며, 완전한 MQTT 메시지의 Pi 도착 간격도 같았다. 해당 두 메시지의 보고 가동시간 간격은 각각 5.029초다. 송신·무선 경로의 원인은 미확인으로 남긴다. `received_at`는 DB 커밋 시각을 뜻하지 않는다.

시험 후 오늘 보존한 원래 P0 실행 영역 937,984B를 복원하고 전체 바이트 해시를 검증했다. Boot에서 v1·Slot 2·Profile 0을 확인했고, 필수 필드의 5초 송신 6회를 관측했다. 복귀 조회 중 ESP32 2 수신 시각이 한 번 16.64초 뒤처졌으나 이후 최근 수신과 두 차례의 활성 6개 처리 전진을 확인했다. 초기 지연 관측도 보존했다. 등록·정책·Trust는 이전과 같고 Capture Session 108과 Pi Boot는 유지했다.

## 검증과 보관

- ESP32 Arduino Core 3.3.8·PubSubClient 2.8·`esp32:esp32:esp32`로 P0~P3 빌드 통과. 실제 연결 설정을 사용한 P1·P2도 빌드 통과.
- Payload 99B의 P2, Buffer 153B, 뒤집힌 Jitter 범위, Profile 4 설정은 빌드에서 차단.
- 기존 펌웨어 회귀 검사 11개 통과.
- 시험한 소스 SHA256: `74261f911e697bfeaf42e53fc3978c71e349c0dd0b893cbcb4bec7af6468481e`.
- 원래 P0 복원 실행 영역 SHA256: `03714a517d1c5acdd5a59ca95e03155f14eb17a04d41bb1a9668febfba957c22`.
- 로컬 보관: `output/phase9-pilots-20261009/`의 사전 조건·Serial·빌드/업로드 검증·Run 원본·평가·복귀 기록. 실제 연결 Header와 펌웨어 바이너리는 비공개 로컬 자료다.

두 Run은 Session UUID `2e72eab6-b8eb-4b5a-873e-3599b932f0e1`을 공유하며 독립 Train/Validation 그룹이 아니다. 학습·전체 Session·정상 패턴 승인은 모두 false다. Pico 설치 소스의 현재 해시 확인과 종민의 공식 데이터 편입·QC 경로가 본 수집 전에 필요하다. P1의 단일 메시지 Window에 기존 Feature가 채우는 5.0초를 실제 측정 간격으로 해석하지 않는다. MQTT Export의 고정 학습 필터와 Rule 경곗값 검토는 별도 데이터·정책 작업으로 이어간다.
