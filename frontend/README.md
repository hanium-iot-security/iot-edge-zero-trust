# Frontend 예약 구조

프론트엔드는 React + Vite 기반 대시보드로 구현할 예정입니다. JavaScript 또는 TypeScript 사용 여부는 아직 확정하지 않았으며, 프론트 담당자와 협의한 뒤 결정합니다.

## 스캐폴딩 방법

JavaScript로 확정하는 경우:

```bash
npm create vite@latest frontend -- --template react
```

TypeScript로 확정하는 경우:

```bash
npm create vite@latest frontend -- --template react-ts
```

## 폴더 역할

```txt
src/api         FastAPI 호출 함수
src/pages       Dashboard, Devices, Logs, Events, Isolation 화면
src/components  공통 UI 컴포넌트
src/styles      전역 스타일
```

React Dashboard는 FastAPI API를 호출해서 기기 상태, MQTT 로그, feature 로그, 탐지 이벤트, Trust Score, 격리 이력을 표시합니다.

## 이전 임시 스캐폴딩 참고

이전에 임시로 만든 프론트엔드 스캐폴딩은 React + Vite + TypeScript 기반이었습니다. 기술 선택이 확정되지 않았으므로 해당 파일들은 제거했습니다.

참고할 값:

```env
VITE_API_BASE_URL=http://localhost:8000/api
```

이전 임시 API client는 `/api/health`를 호출하는 `getHealth()` 함수만 포함했습니다.
