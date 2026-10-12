# Pico 현재 설치 소스 확인

2026/10/9 16:18:40 KST에 실제 보드에서 공개 파일 6개의 SHA256을 읽어 저장소 기준과 대조했다. 이전 긴 조회의 실패 기록과 별도의 후속 증거다. 현재 공개 파일 일치는 확인했지만, 과거 150분·P0/P1/P2 수집 시점의 전체 설치 상태를 소급 인증하지 않는다.

## 확인한 공개 파일

| 보드 경로 | 실제 SHA256 = 저장소 SHA256 |
| --- | --- |
| `main.py` | `5f0b82e426e31c4da14610176cd699707886529f87b4827097a686e83f46f393` |
| `telemetry_sender.py` | `f8711c0deadc209e4e26147db26f48e481eb7473127f3f37f68a5d678fe181f4` |
| `bme280.py` | `4d66dcfd1672158514349a0dba0f4dd38266053a8657909e5d55a01fa9e1851a` |
| `lib/umqtt/__init__.py` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `lib/umqtt/simple.py` | `5458b97fc074db01263e82ae898727aee2a15079ea5cff9d2f6d6abbea8ea217` |
| `lib/umqtt/LICENSE.txt` | `64558603da1d7566531844f30cde7adbc047ae91fdb01658442e32812c21b381` |

대조 기준은 `develop 53ec270219692784ce8864976511a52c962cec35`의 `firmware/pico_wh_bme280` 공개 파일이다. `config.py`와 비공개 설정은 조회하지 않았고, 파일·설정에 쓰는 명령이나 앱 모듈 import를 실행하지 않았다. MicroPython 런타임 전체·모든 설치 파일·설정값까지 인증한 결과는 아니다.

## 조회와 복귀 검증

각 파일에 174~188B의 단일 명령과 서로 다른 요청 nonce를 사용했다. 각 응답에서 현재 nonce·64자리 SHA256·ACK·두 종료 구분자·Raw REPL prompt를 확인했고 송신 전과 응답 뒤 잔여 바이트는 모두 0이었다. 여섯 해시가 전부 일치했으며 stderr는 없었다. 요청 ID는 `28eda6a5de404a879497d7848d37b2f0`이다.

조회 후 일반 REPL 복귀·soft reset·새 sender_start·로컬 송신을 확인했다. 이후 Gateway의 실제 메시지 12개(순번 2~13, UTC 07:18:45.734884~07:19:41.170675)를 별도로 검사했다. 기기·Topic·정규 본문·크기·순번·uptime 검사가 통과했고 Payload 최대는 127B, sender 간격 중앙값은 5.028초, 도착 간격 중앙값은 5.032122초였다. 이 관측값은 새 정상 상한이 아니다.

16:19:56 KST의 Pi 읽기 확인에서 세 기기는 ACTIVE·최근 수신 상태였다. Commit·Boot·Session 108·IP·정책 revision·Trust가 조회 전과 같았고, 활성 MQTT Feature/Rule·Packet Rule/IF·Trust의 6개 처리 단계가 전진했다. 비활성 MQTT IF의 예전 Checkpoint를 처리 장애로 바꾸어 해석하지 않았다.

진단·복귀 구간은 Session 108의 개발 기록으로 남긴다. 기존 후보 원본과 학습·전체 Session 승인 false는 보존한다. 현재 소스 확인이 공식 편입·품질·그룹 검증이나 모델 학습 승인을 대신하지 않는다.

## 별도 보관 근거

`output/phase9-normal-range-20261009`에 조회 결과 JSON, 조회 도구 동결 해시, Gateway 후속 검사, Pi 전후 관측과 불변·전진 검사를 보관한다. UART 원문·원격 traceback·파일 내용·비공개 설정은 결과에 담지 않는다.

동결 조회 도구 SHA256: `d5709997d7c57c9fe05b17de2c4c8083a2568cc8993044cbcd441b4d8ac5ad08`. 장비 접근 없는 오류·분할·잔여 응답·복귀 검사 29개를 통과하고 독립 검토 후 실제 조회를 실행했다.

관련 문서: [정상 운용 기준 v1](phase9-normal-operating-range.md), [메시지 규격](phase9-message-contract.md), [본 수집 준비](phase9-collection-readiness.md).
