#pragma once

// MQTT Broker Credential (esp32_02 전용)

// 사용법:
//   1. 이 파일을 mqtt_credentials.h로 복사한다(같은 디렉터리, Git 제외 대상).
//   2. Mosquitto Password File(infra/mosquitto/passwd.example 참고)에 등록한 esp32_02 Principal의 실제 Password로 MQTT_PASSWORD 값을 채운다.
//   3. mqtt_credentials.h를 절대 커밋하지 않는다(.gitignore에 등록됨).

// Broker가 아직 allow_anonymous true인 전환 기간에는 이 파일을 만들지 않아도 된다.
// — attack_sender.ino는 mqtt_credentials.h가 없으면 기존처럼 익명으로 연결한다.
// Broker가 인증을 강제(allow_anonymous false)한 뒤에는 반드시 이 파일을 채워야 연결이 유지된다.

#define MQTT_USERNAME "esp32_02"
#define MQTT_PASSWORD "REPLACE_WITH_MQTT_PASSWORD"