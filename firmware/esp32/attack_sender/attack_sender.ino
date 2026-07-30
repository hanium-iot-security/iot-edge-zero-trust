#include <WiFi.h>
#include <PubSubClient.h>

const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

const bool ATTACK_TEST_ENABLED = false;
const char* MQTT_BROKER = "192.168.0.20";
const int MQTT_PORT = 1883;
const char* DEVICE_ID = "esp32_02";
const char* MQTT_TOPIC = "iot/esp32_02/sensor";

const unsigned int MESSAGES_PER_BURST = 40;
const unsigned int MAX_BURSTS = 4;
const unsigned long PUBLISH_INTERVAL_MS = 50;
const unsigned long BURST_START_INTERVAL_MS = 10000;
const unsigned long MAX_TEST_DURATION_MS = 45000;
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;
const unsigned long MQTT_CONNECT_TIMEOUT_MS = 10000;

WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);

bool testExecuted = false;
unsigned long sequenceNumber = 0;

bool isPrivateBrokerAddress() {
  IPAddress brokerAddress;
  if (!brokerAddress.fromString(MQTT_BROKER)) {
    return false;
  }

  const uint8_t first = brokerAddress[0];
  const uint8_t second = brokerAddress[1];
  return first == 10 ||
         (first == 172 && second >= 16 && second <= 31) ||
         (first == 192 && second == 168);
}

bool connectWiFiWithTimeout() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  const unsigned long startedAt = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - startedAt < WIFI_CONNECT_TIMEOUT_MS) {
    delay(250);
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("[ABORT] Wi-Fi connection timeout");
    return false;
  }

  Serial.print("[READY] ESP32 IP: ");
  Serial.println(WiFi.localIP());
  return true;
}

bool connectMqttWithTimeout() {
  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setBufferSize(256);

  const unsigned long startedAt = millis();
  while (!mqttClient.connected() &&
         millis() - startedAt < MQTT_CONNECT_TIMEOUT_MS) {
    mqttClient.connect("phase4_attack_esp32_02");
    if (!mqttClient.connected()) {
      delay(500);
    }
  }

  if (!mqttClient.connected()) {
    Serial.print("[ABORT] MQTT connection timeout, state=");
    Serial.println(mqttClient.state());
    return false;
  }

  Serial.println("[READY] MQTT connected");
  return true;
}

String buildAttackPayload(
    unsigned int burstIndex,
    unsigned long sequence) {
  const float temperature = 25.0 + ((sequence % 10) * 0.1);
  const float humidity = 50.0 + (sequence % 5);

  return String("{\"device_id\":\"") + DEVICE_ID +
         "\",\"temperature\":" + String(temperature, 1) +
         ",\"humidity\":" + String(humidity, 1) +
         ",\"sequence\":" + sequence +
         ",\"burst\":" + (burstIndex + 1) + "}";
}

bool waitForBurstStart(
    unsigned long testStartedAt,
    unsigned int burstIndex) {
  const unsigned long targetOffset =
      burstIndex * BURST_START_INTERVAL_MS;

  while (millis() - testStartedAt < targetOffset) {
    if (millis() - testStartedAt >= MAX_TEST_DURATION_MS) {
      return false;
    }
    mqttClient.loop();
    delay(10);
  }
  return true;
}

void runBoundedFloodTest() {
  const unsigned long testStartedAt = millis();
  unsigned int publishedCount = 0;
  unsigned int failedCount = 0;

  Serial.println("[TEST] Limited MQTT Flood test started");

  for (unsigned int burstIndex = 0;
       burstIndex < MAX_BURSTS;
       burstIndex++) {
    if (!waitForBurstStart(testStartedAt, burstIndex) ||
        millis() - testStartedAt >= MAX_TEST_DURATION_MS) {
      Serial.println("[STOP] Maximum test duration reached");
      break;
    }

    if (!mqttClient.connected()) {
      Serial.println(
          "[STOP] MQTT connection unavailable; possible isolation");
      break;
    }

    Serial.print("[BURST] start ");
    Serial.println(burstIndex + 1);

    for (unsigned int messageIndex = 0;
         messageIndex < MESSAGES_PER_BURST;
         messageIndex++) {
      if (millis() - testStartedAt >= MAX_TEST_DURATION_MS) {
        Serial.println("[STOP] Maximum test duration reached");
        break;
      }

      sequenceNumber++;
      const String payload =
          buildAttackPayload(burstIndex, sequenceNumber);
      const bool published =
          mqttClient.publish(MQTT_TOPIC, payload.c_str());

      if (published) {
        publishedCount++;
      } else {
        failedCount++;
      }

      mqttClient.loop();
      delay(PUBLISH_INTERVAL_MS);
    }

    Serial.print("[BURST] end ");
    Serial.print(burstIndex + 1);
    Serial.print(", published=");
    Serial.print(publishedCount);
    Serial.print(", failed=");
    Serial.println(failedCount);
  }

  mqttClient.disconnect();
  WiFi.disconnect(false);

  Serial.print("[DONE] published=");
  Serial.print(publishedCount);
  Serial.print(", failed=");
  Serial.print(failedCount);
  Serial.print(", elapsed_ms=");
  Serial.println(millis() - testStartedAt);
  Serial.println("[DONE] Restore normal_sender.ino before normal operation");
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  if (!ATTACK_TEST_ENABLED) {
    Serial.println(
        "[DISABLED] Set ATTACK_TEST_ENABLED=true only for the approved test");
    return;
  }

  if (testExecuted) {
    return;
  }
  testExecuted = true;

  if (!isPrivateBrokerAddress()) {
    Serial.println("[ABORT] MQTT broker must be an RFC1918 private IPv4 address");
    return;
  }

  if (!connectWiFiWithTimeout() || !connectMqttWithTimeout()) {
    return;
  }

  runBoundedFloodTest();
}

void loop() {
  if (testExecuted) {
    delay(1000);
    return;
  }

  delay(1000);
}
