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
const unsigned long OBSERVATION_TIMEOUT_MS = 45000;
const unsigned long OBSERVATION_PROBE_INTERVAL_MS = 5000;
const unsigned int MAX_OBSERVATION_PROBES = 9;
const unsigned int OBSERVATION_CONNECT_TIMEOUT_SECONDS = 5;
const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000;
const unsigned long MQTT_CONNECT_TIMEOUT_MS = 10000;
const unsigned int MQTT_CONNECT_SOCKET_TIMEOUT_SECONDS = 3;
const unsigned int MQTT_CONNECT_MAX_ATTEMPTS = 2;

WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);

bool testExecuted = false;
unsigned long runStartedAt = 0;

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
  mqttClient.setSocketTimeout(MQTT_CONNECT_SOCKET_TIMEOUT_SECONDS);

  const unsigned long startedAt = millis();
  unsigned int mqttConnectAttempt = 0;
  while (!mqttClient.connected() &&
         millis() - startedAt < MQTT_CONNECT_TIMEOUT_MS &&
         mqttConnectAttempt < MQTT_CONNECT_MAX_ATTEMPTS) {
    mqttConnectAttempt++;
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

String buildCanonicalPayload() {
  return String("{\"device_id\":\"") + DEVICE_ID + "\"}";
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
  runStartedAt = millis();
  const unsigned long testStartedAt = runStartedAt;
  unsigned int publishedCount = 0;
  unsigned int failedCount = 0;

  Serial.print("[TEST] run_started_at_device_ms=");
  Serial.println(runStartedAt);
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

      const String payload = buildCanonicalPayload();
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

  Serial.print("[DONE] published=");
  Serial.print(publishedCount);
  Serial.print(", failed=");
  Serial.print(failedCount);
  Serial.print(", elapsed_ms=");
  Serial.println(millis() - testStartedAt);
}

void logFirstObservationFailure(
    unsigned long observationStartedAt,
    const char* failureKind,
    const char* publishResult) {
  Serial.print("[OBSERVE] first_failure_run_elapsed_ms=");
  Serial.print(millis() - runStartedAt);
  Serial.print(", observation_elapsed_ms=");
  Serial.print(millis() - observationStartedAt);
  Serial.print(", failure_kind=");
  Serial.print(failureKind);
  Serial.print(", mqtt_state=");
  Serial.print(mqttClient.state());
  Serial.print(", publish_result=");
  Serial.println(publishResult);
}

void runBoundedIsolationObservation() {
  const unsigned long observationStartedAt = millis();
  unsigned long lastProbeAt = observationStartedAt;
  unsigned int observationProbeCount = 0;
  bool firstFailureRecorded = false;

  Serial.println("[OBSERVE] bounded isolation observation started");

  while (millis() - observationStartedAt < OBSERVATION_TIMEOUT_MS &&
         observationProbeCount < MAX_OBSERVATION_PROBES) {
    mqttClient.loop();

    if (!mqttClient.connected()) {
      logFirstObservationFailure(
          observationStartedAt,
          "connection_lost",
          "not_attempted");
      firstFailureRecorded = true;
      break;
    }

    if (millis() - lastProbeAt >= OBSERVATION_PROBE_INTERVAL_MS) {
      const String payload = buildCanonicalPayload();
      const bool publishResult =
          mqttClient.publish(MQTT_TOPIC, payload.c_str());
      observationProbeCount++;
      lastProbeAt = millis();

      Serial.print("[OBSERVE] probe=");
      Serial.print(observationProbeCount);
      Serial.print(", elapsed_ms=");
      Serial.print(millis() - observationStartedAt);
      Serial.print(", mqtt_state=");
      Serial.print(mqttClient.state());
      Serial.print(", publish_result=");
      Serial.println(publishResult ? "success" : "failed");

      if (!publishResult) {
        logFirstObservationFailure(
            observationStartedAt,
            "probe_publish_failed",
            "failed");
        firstFailureRecorded = true;
        break;
      }
    }

    delay(50);
  }

  if (!firstFailureRecorded) {
    Serial.println("[OBSERVE] no failure before observation timeout");
  }

  if (mqttClient.connected()) {
    mqttClient.disconnect();
  }

  mqttClient.setSocketTimeout(OBSERVATION_CONNECT_TIMEOUT_SECONDS);
  const bool reconnectResult =
      mqttClient.connect("phase4_observation_esp32_02");
  Serial.print("[OBSERVE] reconnect_run_elapsed_ms=");
  Serial.print(millis() - runStartedAt);
  Serial.print(", observation_elapsed_ms=");
  Serial.print(millis() - observationStartedAt);
  Serial.print(", mqtt_state=");
  Serial.print(mqttClient.state());
  Serial.print(", reconnect_result=");
  Serial.println(reconnectResult ? "success" : "failed");

  if (reconnectResult) {
    mqttClient.disconnect();
  }
  WiFi.disconnect(false);

  Serial.println("[OBSERVE] bounded isolation observation finished");
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
  runBoundedIsolationObservation();
}

void loop() {
  if (testExecuted) {
    delay(1000);
    return;
  }

  delay(1000);
}
