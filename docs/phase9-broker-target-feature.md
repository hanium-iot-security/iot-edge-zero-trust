# Broker 목적지 SYN Feature 연결

Migration 013은 Packet Rule v4의 `BROKER_DOS_SUSPECTED`에 필요한 실제 수집 근거를
PCAP 추출·DB·조회 API·Rule evidence에 연결한다. 코드 연결과 운영 Pi 검증은 구분한다.

## 설정과 집계

- `BROKER_TARGET_IP` 기본값은 빈 값이다. 운영에서 확인한 Broker IPv4를 명시하며
  `CAPTURE_INTERFACE_IP`와 일치해야 한다.
- `BROKER_TARGET_PORT` 기본값은 `1883`이고 현재 지원하는 유일한 포트다.
  9001·IPv6·다른 Pi 주소·잘못된 설정은 추출 시작 전에 거부한다.
- 빈 IP와 기본 포트는 미설정이다. 일반 Feature 처리는 계속하되 새 세 필드는 모두 NULL이다.
- 원래 `[window_start, window_end)` 10초 Window에서 목적지 IP·TCP 1883이 일치하는
  INBOUND SYN=1/ACK=0 패킷 수를 센다. 재전송도 포함하며 고유 연결 수를 뜻하지 않는다.
- 설정된 대상에서 해당 SYN이 없으면 0이다. 다른 포트 SYN·SYN/ACK·OUTBOUND는 세지 않는다.
- `broker_target_ip`, `broker_target_port`, `broker_target_syn_count`를 함께 저장한다.
  조회·Rule evidence는 저장 당시 endpoint를 사용하고 현재 환경변수로 과거 행을 보충하지 않는다.

기존 `tcp_syn_count`, TCP 출발지/목적지 1883 기반 `mqtt_related_packet_count`, CSV 형식,
Packet IF의 6개 Feature와 모델 Artifact는 변경하지 않는다. Broker 의심 판정은 기존 정책의
Broker 전용 SYN 임계값과 MQTT packet 임계값을 모두 엄격히 초과할 때 발생한다.
SYN 없는 publish flood는 이 규칙의 대상이 아니며 기존 packet/byte rate 규칙을 따른다.

## 이관과 운영 적용

기존 DB에는 Migration 013을 명시적으로 적용해야 한다. 과거 행은 모두 NULL이며 재계산하거나
0으로 채우지 않는다. 미설정 상태에서는 이전 스키마에서도 일반 추출·조회가 가능하다.
Broker 설정을 켰는데 스키마가 없으면 파일 재정리·이동 또는 Segment 상태 변경 전에 중단한다.
설정 변경으로 같은 Segment를 다시 처리해도 기존 Feature 행을 덮어쓰지 않는다.

병합 전 #127의 기존 013/014는 각각 **014 AI 실행 근거 / 015 AI 활성화**로 조정한다.
최종 적용 순서는 012 → 013 Broker → 014 실행 근거 → 015 활성화다.
이전 PR 번호 배치로 만든 DB는 자동 재번호화하지 않는다. Migration runner는 같은 버전의
저장 이름이 현재 파일 이름과 다르면 적용을 거부한다. 해당 DB·이력을 보존하고 별도 이관을
검토해야 하며, 자료가 필요 없는 일회성 시험 DB에 한해서만 새로 만들 수 있다.

운영에서는 백업 후 DB Migration, 실제 Broker/Pi IPv4·1883 확인, 명시적 설정,
`PACKET_RULE_POLICY_VERSION=packet-rule-policy-v4` 및 승인 임계값 확인이 필요하다.
빈 설정으로 돌아가면 이후 수집분은 NULL이 되지만 이미 저장한 근거·Event·Trust는 유지된다.
DB 자체의 되돌리기는 검증한 백업 복구 절차를 사용한다.

## 검증 범위

로컬 시험은 합성 PCAP과 임시 SQLite로 정상 연결·재접속, 다른 포트 스캔+MQTT,
Broker SYN 집중, SYN 없는 publish flood, 임계값 경계, NULL/0, 저장 endpoint,
Rule/Trust 연결과 기존 모델 입력의 보존을 확인한다. 결과 수치는 PR 검증 표를 따른다.
실제 Pi PCAP 품질·부하·운영 Migration·실제 공격/차단 검증은 별도다.
