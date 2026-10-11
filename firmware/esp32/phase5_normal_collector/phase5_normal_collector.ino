#include <WiFi.h>
#include <PubSubClient.h>
#include <esp_system.h>

#if __has_include("phase5_firmware_config.h")
#include "phase5_firmware_config.h"
#else
#error "Copy phase5_firmware_config.example.h to phase5_firmware_config.h before compiling."
#endif

#if PHASE5_CONFIGURED != 1
#error "Set PHASE5_CONFIGURED to 1 after reviewing the local firmware configuration."
#endif

#if PHASE5_NORMAL_PROFILE < 0 || PHASE5_NORMAL_PROFILE > 3
#error "PHASE5_NORMAL_PROFILE must be between 0 and 3."
#endif

// Defaults also support local configuration headers created before Phase 9.
#ifndef PHASE5_PAYLOAD_MAX_BYTES
#define PHASE5_PAYLOAD_MAX_BYTES 128
#endif
#ifndef PHASE5_MQTT_BUFFER_BYTES
#define PHASE5_MQTT_BUFFER_BYTES 256
#endif
#ifndef PHASE5_FIXED_PUBLISH_INTERVAL_MS
#define PHASE5_FIXED_PUBLISH_INTERVAL_MS 5000UL
#endif
#ifndef PHASE5_JITTER_MIN_MS
#define PHASE5_JITTER_MIN_MS 4000UL
#endif
#ifndef PHASE5_JITTER_MAX_MS
#define PHASE5_JITTER_MAX_MS 6000UL
#endif

// ESP32: sequence/free_heap have 10 digits, uptime_s has 7, RSSI has 4.
// Both supported device IDs have 8 bytes and their sensor topics have 19.
static_assert(sizeof(unsigned long) == 4, "Payload bounds require 32-bit unsigned long.");
#if PHASE5_NORMAL_PROFILE == 2 || PHASE5_NORMAL_PROFILE == 3
#define PHASE5_CANONICAL_PAYLOAD_MAX_BYTES 100
#else
#define PHASE5_CANONICAL_PAYLOAD_MAX_BYTES 65
#endif

#if PHASE5_PAYLOAD_MAX_BYTES < PHASE5_CANONICAL_PAYLOAD_MAX_BYTES
#error "PHASE5_PAYLOAD_MAX_BYTES cannot fit this profile's canonical payload."
#endif
#if PHASE5_MQTT_BUFFER_BYTES <= 0 || PHASE5_MQTT_BUFFER_BYTES > 65535
#error "PHASE5_MQTT_BUFFER_BYTES must fit PubSubClient's uint16_t buffer size."
#endif
#if PHASE5_MQTT_BUFFER_BYTES < MQTT_MAX_HEADER_SIZE + 2 + 19 + PHASE5_PAYLOAD_MAX_BYTES
#error "PHASE5_MQTT_BUFFER_BYTES must fit the MQTT header, topic and payload limit."
#endif
#if PHASE5_FIXED_PUBLISH_INTERVAL_MS <= 0 || PHASE5_FIXED_PUBLISH_INTERVAL_MS > 0xFFFFFFFFUL
#error "PHASE5_FIXED_PUBLISH_INTERVAL_MS must be a positive uint32_t interval."
#endif
#if PHASE5_JITTER_MIN_MS <= 0 || PHASE5_JITTER_MIN_MS > PHASE5_JITTER_MAX_MS || PHASE5_JITTER_MAX_MS >= 0x7FFFFFFFUL
#error "Jitter bounds must be positive, ordered and allow an exclusive random(long) upper bound."
#endif

#if PHASE5_DEVICE_SLOT == 1
const char* DEVICE_ID = "esp32_01";
#elif PHASE5_DEVICE_SLOT == 2
const char* DEVICE_ID = "esp32_02";
#else
#error "PHASE5_DEVICE_SLOT must be 1 or 2."
#endif

// MQTT Username은 DEVICE_ID를 그대로 사용한다.
// 기존에 이미 만들어둔 로컬 phase5_firmware_config.h에 PHASE5_MQTT_PASSWORD가 없어도 컴파일이 깨지지 않도록 기본값(빈 문자열 = 익명 연결)을 둔다.
#ifndef PHASE5_MQTT_PASSWORD
#define PHASE5_MQTT_PASSWORD ""
#endif
const char* MQTT_USERNAME = DEVICE_ID;
const char* MQTT_PASSWORD = PHASE5_MQTT_PASSWORD;

const char* FIRMWARE_VERSION = "phase9-normal-pilot-v2";
const char* FIRMWARE_LIMITS_VERSION = "phase9-normal-limits-v1";
const char* PAYLOAD_SCHEMA_VERSION = "phase5-normal-payload-v1";

String MQTT_TOPIC = String("iot/") + DEVICE_ID + "/sensor";
String MQTT_CLIENT_ID = String("p5-") + DEVICE_ID + "-v1";

const unsigned long FIXED_PUBLISH_INTERVAL_MS = PHASE5_FIXED_PUBLISH_INTERVAL_MS;
const unsigned int MAX_PAYLOAD_BYTES = PHASE5_PAYLOAD_MAX_BYTES;
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000UL;
const unsigned long WIFI_RETRY_INTERVAL_MS = 5000UL;
const unsigned long MQTT_RETRY_INTERVAL_MS = 5000UL;
const unsigned int MQTT_SOCKET_TIMEOUT_SECONDS = 3;

WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);
bool mqttBufferReady = false;

unsigned long sequenceNumber = 0;
unsigned long lastPublishAtMs = 0;
unsigned long nextPublishIntervalMs = FIXED_PUBLISH_INTERVAL_MS;
unsigned long lastWifiAttemptAtMs = 0;
unsigned long lastMqttAttemptAtMs = 0;

bool profileUsesPayloadVariation() {
  return PHASE5_NORMAL_PROFILE == 2 || PHASE5_NORMAL_PROFILE == 3;
}

unsigned long chooseNextPublishIntervalMs() {
  if (PHASE5_NORMAL_PROFILE == 0 || PHASE5_NORMAL_PROFILE == 2) {
    return FIXED_PUBLISH_INTERVAL_MS;
  }
  return static_cast<unsigned long>(random(PHASE5_JITTER_MIN_MS, PHASE5_JITTER_MAX_MS + 1UL));
}

String buildCanonicalPayload(unsigned long sequence) {
  String payload = String("{\"device_id\":\"") + DEVICE_ID +
                   "\",\"sequence\":" + sequence +
                   ",\"uptime_s\":" + (millis() / 1000UL);

  if (!profileUsesPayloadVariation()) {
    return payload + "}";
  }

  unsigned long variation = sequence % 3;
  if (variation >= 1) {
    payload += String(",\"rssi\":") + WiFi.RSSI();
  }
  if (variation == 2) {
    payload += String(",\"free_heap\":") +
               static_cast<unsigned long>(ESP.getFreeHeap());
  }
  return payload + "}";
}

const char* profileName() {
  switch (PHASE5_NORMAL_PROFILE) {
    case 0:
      return "normal_stable";
    case 1:
      return "normal_interval_jitter";
    case 2:
      return "normal_payload_variation";
    case 3:
      return "normal_combined_variation";
    default:
      return "invalid";
  }
}

void printBootContract() {
  Serial.println("phase5_normal_collector_boot");
  Serial.print("firmware_version=");
  Serial.println(FIRMWARE_VERSION);
  Serial.print("payload_schema_version=");
  Serial.println(PAYLOAD_SCHEMA_VERSION);
  Serial.print("firmware_limits_version=");
  Serial.println(FIRMWARE_LIMITS_VERSION);
  Serial.print("payload_max_bytes=");
  Serial.println(MAX_PAYLOAD_BYTES);
  Serial.print("canonical_payload_max_bytes=");
  Serial.println(PHASE5_CANONICAL_PAYLOAD_MAX_BYTES);
  Serial.print("mqtt_buffer_bytes_configured=");
  Serial.println(PHASE5_MQTT_BUFFER_BYTES);
  Serial.print("fixed_publish_interval_ms=");
  Serial.println(FIXED_PUBLISH_INTERVAL_MS);
  Serial.print("jitter_min_ms=");
  Serial.println(PHASE5_JITTER_MIN_MS);
  Serial.print("jitter_max_ms=");
  Serial.println(PHASE5_JITTER_MAX_MS);
  Serial.print("device_id=");
  Serial.println(DEVICE_ID);
  Serial.print("device_slot=");
  Serial.println(PHASE5_DEVICE_SLOT);
  Serial.print("normal_profile=");
  Serial.println(PHASE5_NORMAL_PROFILE);
  Serial.print("profile_name=");
  Serial.println(profileName());
  Serial.print("mqtt_topic=");
  Serial.println(MQTT_TOPIC);
  Serial.print("mqtt_client_id=");
  Serial.println(MQTT_CLIENT_ID);
  Serial.print("mqtt_broker=");
  Serial.print(PHASE5_MQTT_BROKER);
  Serial.print(":");
  Serial.println(PHASE5_MQTT_PORT);

  if (PHASE5_NORMAL_PROFILE == 3) {
    Serial.println(
        "profile_3_requires_profile_1_and_2_pilot_approval");
  }
}

bool connectWifiWithTimeout() {
  if (WiFi.status() == WL_CONNECTED) {
    return true;
  }

  Serial.println("wifi_connect_started");
  WiFi.mode(WIFI_STA);
  WiFi.begin(PHASE5_WIFI_SSID, PHASE5_WIFI_PASSWORD);

  unsigned long startedAtMs = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - startedAtMs < WIFI_CONNECT_TIMEOUT_MS) {
    delay(250);
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("wifi_connect_timeout");
    return false;
  }

  Serial.print("wifi_connected ip=");
  Serial.println(WiFi.localIP());
  return true;
}

bool connectMqttOnce() {
  if (mqttClient.connected()) {
    return true;
  }
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }

  Serial.print("mqtt_connect_started client_id=");
  Serial.println(MQTT_CLIENT_ID);
  bool connected = (strlen(MQTT_PASSWORD) > 0)
      ? mqttClient.connect(MQTT_CLIENT_ID.c_str(), MQTT_USERNAME, MQTT_PASSWORD)
      : mqttClient.connect(MQTT_CLIENT_ID.c_str());
  if (!connected) {
    Serial.print("mqtt_connect_failed state=");
    Serial.println(mqttClient.state());
    return false;
  }

  Serial.println("mqtt_connected");
  return true;
}

bool publishNormalTelemetry() {
  unsigned long nextSequence = sequenceNumber + 1UL;
  String payload = buildCanonicalPayload(nextSequence);

  if (payload.length() > MAX_PAYLOAD_BYTES) {
    Serial.print("payload_rejected reason=over_configured_limit size=");
    Serial.print(payload.length());
    Serial.print(" limit=");
    Serial.println(MAX_PAYLOAD_BYTES);
    return false;
  }

  unsigned long packetBytes = MQTT_MAX_HEADER_SIZE + 2UL + MQTT_TOPIC.length() + payload.length();
  if (!mqttBufferReady || packetBytes > mqttClient.getBufferSize()) {
    Serial.print("payload_rejected reason=mqtt_packet_budget required=");
    Serial.print(packetBytes);
    Serial.print(" buffer=");
    Serial.println(mqttClient.getBufferSize());
    return false;
  }

  bool published = mqttClient.publish(MQTT_TOPIC.c_str(), payload.c_str());
  if (!published) {
    Serial.print("mqtt_publish_failed state=");
    Serial.println(mqttClient.state());
    return false;
  }

  sequenceNumber = nextSequence;
  Serial.print("mqtt_publish_succeeded sequence=");
  Serial.print(sequenceNumber);
  Serial.print(" interval_ms=");
  Serial.print(nextPublishIntervalMs);
  Serial.print(" payload_size=");
  Serial.print(payload.length());
  Serial.print(" topic=");
  Serial.print(MQTT_TOPIC);
  Serial.print(" payload=");
  Serial.println(payload);
  return true;
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  printBootContract();

  randomSeed(esp_random());
  mqttClient.setServer(PHASE5_MQTT_BROKER, PHASE5_MQTT_PORT);
  mqttBufferReady = mqttClient.setBufferSize(PHASE5_MQTT_BUFFER_BYTES) &&
                    mqttClient.getBufferSize() == PHASE5_MQTT_BUFFER_BYTES;
  Serial.print("mqtt_buffer_bytes_actual=");
  Serial.println(mqttClient.getBufferSize());
  if (!mqttBufferReady) {
    Serial.println("mqtt_buffer_allocation_failed");
    return;
  }
  mqttClient.setSocketTimeout(MQTT_SOCKET_TIMEOUT_SECONDS);

  connectWifiWithTimeout();
  lastWifiAttemptAtMs = millis();
  if (WiFi.status() == WL_CONNECTED) {
    connectMqttOnce();
    lastMqttAttemptAtMs = millis();
  }

  nextPublishIntervalMs = chooseNextPublishIntervalMs();
  lastPublishAtMs = millis();
}

void loop() {
  if (!mqttBufferReady) {
    delay(250);
    return;
  }
  unsigned long currentTimeMs = millis();

  if (WiFi.status() != WL_CONNECTED) {
    if (currentTimeMs - lastWifiAttemptAtMs >= WIFI_RETRY_INTERVAL_MS) {
      connectWifiWithTimeout();
      lastWifiAttemptAtMs = millis();
    }
    return;
  }

  if (!mqttClient.connected()) {
    if (currentTimeMs - lastMqttAttemptAtMs >= MQTT_RETRY_INTERVAL_MS) {
      connectMqttOnce();
      lastMqttAttemptAtMs = millis();
    }
    return;
  }

  mqttClient.loop();
  if (currentTimeMs - lastPublishAtMs < nextPublishIntervalMs) {
    return;
  }

  bool published = publishNormalTelemetry();
  lastPublishAtMs = currentTimeMs;
  if (published) {
    nextPublishIntervalMs = chooseNextPublishIntervalMs();
  }
}
