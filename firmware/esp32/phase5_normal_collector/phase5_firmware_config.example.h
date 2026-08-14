#pragma once

#define PHASE5_CONFIGURED 0
#define PHASE5_DEVICE_SLOT 1
#define PHASE5_NORMAL_PROFILE 0

#define PHASE5_WIFI_SSID "REPLACE_WITH_WIFI_SSID"
#define PHASE5_WIFI_PASSWORD "REPLACE_WITH_WIFI_PASSWORD"

#define PHASE5_MQTT_BROKER "192.168.0.20"
#define PHASE5_MQTT_PORT 1883

// MQTT Broker Credential. Username은 DEVICE_ID를 그대로 사용하므로 여기서 별도로 설정하지 않는다.
// Broker가 아직 allow_anonymous true인 전환 기간에는 PHASE5_MQTT_PASSWORD를 빈 문자열로 두면 기존처럼 익명 연결한다.
// Broker 인증이 강제된 뒤에는 실제 Password File(infra/mosquitto/passwd.example 참고)과 일치하는 값으로 채운다.
#define PHASE5_MQTT_PASSWORD ""