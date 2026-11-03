# 기기 등록 삭제·목록 숨김 계약

이 기능은 대시보드의 기기 등록 정리만 담당한다. MQTT 계정·ACL 생성/삭제, 펌웨어,
점수 초기화, 방화벽 해제, 탐지·통신 이력 삭제를 수행하지 않는다.

## 동작

- `DELETE_UNUSED`: 최초 `PENDING` 등록 정보와 자동 생성된 최초 AI `OFF` 정책만 있으며,
  수신·분석·탐지·신뢰점수·방화벽·복구 이력이 없는 기기의 등록을 삭제한다.
- `HIDE`: 기존 규칙 정책 명령으로 이미 `DISABLED`가 적용된 기기를 기본 기기 목록에서
  숨긴다. 정책이나 보안 상태를 변경하지 않는다.
- `RESTORE`: 숨긴 기기를 목록에 다시 표시한다. 관리 비활성을 해제하지 않는다.

기존 기기의 활성화/비활성화는 규칙 정책 변경 API를 그대로 사용한다. 숨김은 해당 정책의
효력 확인 후에만 허용한다. 적용 예정 규칙/AI 정책 또는 미확인·잔존 방화벽 작업은
숨김을 막으며, 기존 최신 방화벽 관측 검사도 유지한다.

## HTTP

`GET /api/devices/{device_id}/management`는 일반 기기 정보와 같은 읽기 권한으로 제공한다.
응답의 가능 여부는 조회 시점의 안내이며 명령 실행 시 다시 검사한다.

```json
{
  "device_id": "fixture_pending",
  "expected_instance_id": "opaque-registration-instance",
  "expected_revision": 1,
  "expected_ai_revision": 1,
  "hidden_at": null,
  "can_delete": true,
  "can_hide": false,
  "can_restore": false,
  "delete_blockers": [],
  "hide_blockers": ["NOT_DISABLED"]
}
```

`POST /api/devices/{device_id}/management`는 기존 `X-Recovery-Admin-Key` 인증을 요구한다.
사유와 현재 등록 식별자(`expected_instance_id`), 두 정책 버전 및 숨김 시각을 전달한다.
등록 식별자는 불투명 문자열이며 이관 전 기기는 null일 수 있다. 필드는 생략하지 않는다.
클라이언트가 이력 없음을 선언하는 우회 플래그는 받지 않는다.

```json
{
  "action": "DELETE_UNUSED",
  "expected_instance_id": "opaque-registration-instance",
  "expected_revision": 1,
  "expected_ai_revision": 1,
  "expected_hidden_at": null,
  "reason": "사용하지 않은 테스트 등록 취소"
}
```

성공은 `200 {device_id,action,operation_id,hidden_at,deleted}`다. 삭제 이후 기기 상세는
404이며, 삭제 감사는 별도 보존한다. 요청 결과가 불명확하면 자동 재전송하지 않고 먼저
목록과 상세를 재조회한다. 명령은 동시에 들어온 정책·숨김 변경을 409로 거부한다.

| 상태 | 의미 |
| --- | --- |
| 401 / 503 기존 인증 오류 | 관리자 인증 실패 / 서버 인증 미설정 |
| 404 | 기기 없음 |
| 409 `MANAGEMENT_CONFLICT` | 등록 식별자·규칙·AI 버전 또는 숨김 상태가 조회 이후 변경됨 |
| 409 `MANAGEMENT_ACTION_BLOCKED` | 현재 상태·이력이 선택한 동작을 허용하지 않음 |
| 503 `DEVICE_MANAGEMENT_UNAVAILABLE` | 필요한 Migration/스키마가 없어 안전하게 처리할 수 없음 |

`GET /api/devices`는 기본적으로 숨긴 기기를 제외한다. `include_hidden=true`이면 포함하며,
동일 조건을 `items`와 `total`에 적용한다. `DeviceItem.hidden_at`은 숨김 UTC 시각 또는 null이다.
숨긴 기기의 직접 상세·이력 조회는 유지한다. 기존 스키마에서 일반 목록 조회는 유지하지만,
관리 명령은 필요한 스키마 없이 실행되지 않는다.

## 삭제 판정과 보존

서버는 최초 등록 경계·등록 생성자·시각과 최초 규칙/AI 정책을 대조한다. 추가 정책 revision,
기존 이관 기기, 마지막 수신 시각, 정상/100 이외 상태, 숨김 이력이 있으면 삭제하지 않는다.
이력 검사는 기기 ID만 보지 않고 MQTT 토픽/본문 기기 ID, 패킷 peer IP, 탐지 subject IP,
방화벽 source IP와 AI 완료/경고 등 실제 식별 근거도 확인한다. 다른 기기에 매핑됐거나
아직 기기 ID가 없는 같은 IP의 이력도 삭제 판정을 막는다.

삭제·숨김·다시 표시 명령은 운영자·사유·대상·이전 상태를 `device_management_audits`에
남긴다. 감사 테이블은 기기 삭제로 함께 사라지지 않으며 수정·삭제·REPLACE를 거부한다.
기존 정책 이력의 삭제 금지는 초기 미사용 등록에 대한 정확한 감사 증거가 있는 경우만
예외로 한다. 실제 사용한 정책·보안·통신 자료에는 삭제 예외나 CASCADE를 추가하지 않는다.

명령은 기존 공용 방화벽 명령 잠금을 먼저 얻고 `BEGIN IMMEDIATE` 안에서 재검증·감사·변경을
원자적으로 처리한다. 실패 시 모두 rollback한다. 이 파일 잠금이 MQTT/패킷 수집까지
직렬화한다고 주장하지 않는다. 수집기가 이미 읽은 식별 정보로 삭제 이후 원본을 저장하는
경우에도 원본 저장을 막거나 버리지 않는다.

사용하지 않은 테스트 등록을 삭제한 뒤 같은 ID로 다시 등록할 수 있다. 재등록은 새
`PENDING` 등록과 최초 정책으로 시작한다. 서버는 등록 단위의 식별자를 구분해 이전 삭제
감사가 새 등록의 정책 삭제를 허용하는 증거로 재사용되지 않게 한다. 재등록 시에도 삭제된
ID·MQTT 식별 정보·관련 IP의 수신 및 보안 이력을 다시 검사한다. 삭제 후 뒤늦게 원본이
저장됐다면 재등록을 거부하고 해당 이력을 보존한다.

네트워크에 남아 있다가 재등록 이후 도착한 메시지의 실제 송신 세대까지 이 기능이 판별하는
것은 아니다. 같은 ID의 재등록은 새 기기와 계정·토픽·IP를 대조하고 정상 수신을 확인한 뒤
별도로 활성화한다. 브로커 설정이나 펌웨어에 수신 세대 표식을 자동 추가하지 않는다.

기존 규칙·AI 정책 GET도 `expected_instance_id`를 반환하며, 해당 POST는 조회한 값을 함께
받는다. 재등록된 ID에서는 이 값이 없거나 다르면 `REGISTRATION_INSTANCE_CONFLICT`(409)다.
처음 등록한 ID와 019 이전 DB에 대한 기존 클라이언트의 생략 요청은 유지한다. 명시한 값이
현재 등록과 다르면 처음 등록한 ID라도 거부한다. 검사와 정책 쓰기는 같은 쓰기 트랜잭션에
있다. 화면에서 조회한 등록 단위가 바뀌면 기존 규칙·AI 초안·사유·관리자 키를 비우고 다시
입력받으며, 이전 초안을 새 등록 식별자에 자동 연결하지 않는다.

## 로컬 검증과 Pi 확인 구분

로컬에서는 임시 SQLite와 합성 방화벽 관측 자료만 사용해 삭제/숨김/복원·인증·충돌·이력
보존을 검증한다. 실제 Pi의 기기나 MQTT 계정에는 적용하지 않는다. Pi가 연결됐다는 사용자
안내 후 코드·DB 호환성, 운영 DB 백업과 복사본 Migration, 원본 기기 이력 보존을 먼저
검토한다. 테스트용 `pico_02`도 사용자의 실제 조작 없이 삭제하지 않는다.
