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

#if PHASE5_DEVICE_SLOT == 1
const char* DEVICE_ID = "esp32_01";
#elif PHASE5_DEVICE_SLOT == 2
const char* DEVICE_ID = "esp32_02";
#else
#error "PHASE5_DEVICE_SLOT must be 1 or 2."
#endif

const char* FIRMWARE_VERSION = "phase5-normal-pilot-v1";
const char* PAYLOAD_SCHEMA_VERSION = "phase5-normal-payload-v1";

String MQTT_TOPIC = String("iot/") + DEVICE_ID + "/sensor";
String MQTT_CLIENT_ID = String("p5-") + DEVICE_ID + "-v1";

const unsigned long FIXED_PUBLISH_INTERVAL_MS = 5000UL;
const unsigned int MAX_PAYLOAD_BYTES = 100;
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000UL;
const unsigned long WIFI_RETRY_INTERVAL_MS = 5000UL;
const unsigned long MQTT_RETRY_INTERVAL_MS = 5000UL;
const unsigned int MQTT_SOCKET_TIMEOUT_SECONDS = 3;

WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);

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
  return static_cast<unsigned long>(random(4000, 6001));
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
  bool connected = mqttClient.connect(MQTT_CLIENT_ID.c_str());
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
    Serial.print("payload_rejected reason=over_100_bytes size=");
    Serial.println(payload.length());
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
  mqttClient.setBufferSize(256);
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
