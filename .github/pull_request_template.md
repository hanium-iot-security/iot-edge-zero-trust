## 작업 내용

-

## 테스트 방법

-

## 영향 범위

- DB 변경: 있음 / 없음
- API 변경: 있음 / 없음
- Frontend 영향: 있음 / 없음

## 체크리스트

- [ ] DB schema 변경 시 `docs/db-schema.md`와 `db/migrations/`를 함께 수정했습니다.
- [ ] API 변경 시 `docs/api-spec.md`를 함께 수정했습니다.
- [ ] MVP 상수 변경 시 `README.md`, `docs/`, `.env.example`, DB schema를 함께 확인했습니다.
- [ ] Raspberry Pi 실행 방식 또는 Mosquitto 설정 영향 여부를 확인했습니다.
- [ ] `backend`에는 탐지/Trust Score 판단 로직을 넣지 않았고, 실제 판단 로직은 `edge` 기준으로 유지했습니다.
- [ ] 실제 DB 파일, 모델 파일, 수집 데이터 파일, `.env`가 Git에 포함되지 않았는지 확인했습니다.

## 스크린샷 또는 로그
