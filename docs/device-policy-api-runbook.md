# 기기 정책 API 운영 확인

P8-04의 로컬 API 구현을 운영에 적용할 때 사용한다. 이 API는 Broker 계정·ACL을
생성하거나 장비를 설정하지 않는다. 상세 요청·오류는 [API 명세](api-spec.md),
저장·이관은 [DB 명세](db-schema.md)를 따른다.

## 적용 순서

1. **의존 코드 통합:** P8-03 저장소·Migration 007과 P8-05/06의 당시 정책 조회 및
   PENDING/DISABLED Trust·Worker 보호를 먼저 통합한다. 초기 의존 PR은 #87, #88이다.
   API만 먼저 배포해 신규 기기를 등록하지 않는다.
2. **백업·이관:** 서비스를 멈춰 일관된 운영 DB·코드·설정을 보존한다. 운영 DB 복사본에서
   기존 IP 충돌 진단, Migration, 실제 운영 임계값으로 backfill dry-run을 수행한다.
   통과 후 운영에 적용하고 기존 점수·차단·감사 이력이 보존됐는지 대조한다.
   `registration_effective_from=null`인 기존 기기는 초기 등록 시각을 새로 만들어 덮어쓰지 않는다.
3. **경로·권한:** API·Rule/Trust·Worker가 동일한 SQLite를 사용하도록 확인한다.
   API와 Worker/Recovery가 동일한 `FIREWALL_LOCK_PATH`를 사용하며 해당 파일·디렉터리에
   필요한 쓰기 권한이 있어야 한다. 비활성화에는 별도
   `firewall-runtime-snapshot.service/timer`가 만든 fresh Runtime snapshot이 필요하다.
   [Runtime 관측 서비스 배포 절차](firewall-runtime-verifier.md)에 따라 서비스·타이머를
   설치하고 API와 같은 snapshot 경로 및 관측 유효 시간을 확인한다.
   API에 sudo/iptables 실행 권한을 추가하지 않는다.
4. **등록 설정:** 실제 DHCP 예약 LAN을 `DEVICE_REGISTRATION_CIDR`에 지정한다.
   Pi/관리 주소는 `CAPTURE_INTERFACE_IP`, `FIREWALL_PROTECTED_IPS`,
   `PACKET_RULE_EXCLUDED_PEER_IPS`와 함께 확인한다. 공란/잘못된 설정은 두 POST가 503,
   조회는 유지되는지 확인한다. 관리자 요청은 SSH 포워딩 loopback 또는 HTTPS에서 보낸다.
5. **PENDING 검증:** 새 기기를 등록해 초기 revision과 자기 Topic이 생성되는지 확인한다.
   수동으로 Broker credential·ACL을 준비하고 본인 Topic 허용/타 Topic 거부, 실제 수신을
   확인한다. Rule·AI 이상 이벤트를 발생시켜도 PENDING에서 새 감점·차단이 없는지 확인한다.
6. **ACTIVE·변경 검증:** 확인한 증적 ID를 reason에 기록해 ACTIVE revision을 요청한다.
   효력 경계 후 GET으로 확인하고 다른 두 기기의 동일 입력·다른 임계값, 과거 Window의
   당시 revision 사용, pending 중 재변경 409를 검증한다.
7. **비활성화·회귀:** 진행 중/잔존 차단 또는 오래된 관측에서 DISABLED 요청이 409인지,
   차단 해제 확인 후에만 수락되는지 검증한다. 수락 직후부터 새 자동 대응이 제외되고
   기존 점수·이력이 보존돼야 한다. FAILED 차단의 관리자 재시도가 PENDING·예약/효력
   DISABLED·정책 오류에서 거부되고, Worker의 새 적용과 Reconciliation 복원도 제외되는지
   확인한다. API의 `auto_response_eligible`과 Worker가 같은 현재/예정 정책을 사용해야 한다.
   ESP32 두 대와 Pico의 정상 수신·기존 Recovery도 확인한다.

문제가 생기면 변경 요청을 중단하고 서비스를 멈춘 뒤 호환되는 코드·DB·설정 백업을
함께 복원한다. Migration 007은 down migration이 없다. 초기 PENDING과 기존 ACTIVE의
표시/감점 보호가 확인되기 전까지 운영 등록을 재개하지 않는다.

## 프론트 연동

- Devices 목록/상세의 기존 Trust status와 점수는 유지하고 등록 상태·현재/예정 정책을 별도 표시한다.
- 폼에서 숫자를 명시적으로 변환하고 서버 소유 Topic·revision·효력 시점은 편집하지 않는다.
- 두 POST만 관리자 키를 요구한다. 키는 메모리에 두고 모달 종료/기기 전환 시 폐기한다.
- 201은 저장 완료다. POST의 server_time은 접수 시각이므로 저장 후/효력 경계 후 GET으로 재조회한다.
- 409와 결과 불명 네트워크 오류는 초안을 보존해 먼저 재조회하며 자동 재전송하지 않는다.
  기존 인증 문자열, 업무 오류 객체, 422 배열을 각각 표시한다. 정책 GET의 503도 운영 오류로 표시한다.
- PENDING의 100점은 검증 완료를 뜻하지 않는다. eligible은 정책상 자격이며 차단 권한을 대신하지 않는다.

## 테스트 등록 삭제·목록 정리

Migration 019와 호환 API/프런트엔드를 함께 사용한다. 상세 조건은
[기기 관리 계약](contracts/device-management-v1.md)을 따른다. 운영 Pi 적용은 별도 확인이며,
로컬 합성 DB의 성공을 운영 기기 삭제 성공으로 보고하지 않는다.

1. 기기 상세의 **등록 정리**에서 서버 조회가 완료됐는지 확인한다. 최초 등록 이외의
   정책 변경·통신·탐지·점수·차단·복구 이력이 있으면 테스트 등록 삭제를 허용하지 않는다.
2. 미사용 등록은 삭제 동작을 선택하고 사유·관리자 인증키·표시된 기기 ID를 입력해 확인한다.
   삭제 후 목록과 상세를 다시 확인한다. 감사는 보존하며, 같은 ID의 재등록은 새 등록 준비로
   시작한다. 이전 창의 요청은 등록 단위가 달라 충돌로 거부돼야 한다.
3. 사용한 기기는 기존 규칙 폼에서 관리 비활성을 저장한다. 효력 적용과 실제 차단 해제를
   확인한 뒤 목록 숨김을 실행한다. 숨김만으로 실제 통신을 차단하거나 해제하지 않는다.
4. **숨긴 기기 포함**으로 조회한 뒤 목록에 다시 표시할 수 있다. 정책·점수·이력은 유지하며
   관리 비활성 상태도 그대로다.
5. 인증 실패·409·결과 불명 오류에서는 자동 재전송하지 않는다. 최신 상태를 다시 조회하고
   작업을 새로 선택·확인한다. 조회 실패 상태에서는 실행 버튼을 사용할 수 없어야 한다.

운영 적용 전에는 복사 DB에서 Migration 019의 재실행·기존 데이터 보존과 테스트용 등록의
삭제/같은 ID 재등록을 확인한다. 실제 기기는 사용자 확인 없이 삭제하거나 숨기지 않는다.
API에는 sudo/iptables/Mosquitto 관리 권한을 추가하지 않는다.
