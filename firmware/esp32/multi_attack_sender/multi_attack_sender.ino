#include <WiFi.h>
#include <WiFiUdp.h>
#include <PubSubClient.h>
#include <errno.h>
#include <time.h>

#if __has_include("multi_attack_firmware_config.h")
#include "multi_attack_firmware_config.h"
#else
#error "Copy multi_attack_firmware_config.example.h to multi_attack_firmware_config.h before compiling."
#endif

#if MULTI_ATTACK_CONFIGURED != 1
#error "Set MULTI_ATTACK_CONFIGURED to 1 after reviewing the local firmware configuration."
#endif

#if __has_include("mqtt_credentials.h")
#include "mqtt_credentials.h"
#else
#define MQTT_USERNAME ""
#define MQTT_PASSWORD ""
#endif

const char* FIRMWARE_VERSION = "phase6b-multi-attack-sender-v1";
const char* DEVICE_ID = "esp32_02";
const char* SPOOFED_DEVICE_ID = "esp32_01";
const char* EXPECTED_LOCAL_IP_TEXT = "192.168.0.5";
const char* TARGET_IP_TEXT = "192.168.0.20";
const char* MQTT_TOPIC = "iot/esp32_02/sensor";
const uint16_t MQTT_PORT = 1883U;
const uint16_t TARGET_UDP_PORT = 19999U;
const uint16_t LOCAL_UDP_PORT = 42100U;

const char* NTP_SERVER = "pool.ntp.org";
const time_t MIN_VALID_EPOCH = 1700000000;
const unsigned long ANALYSIS_WINDOW_SECONDS = 10UL;
const unsigned long WINDOW_START_OFFSET_SECONDS = 1UL;
const unsigned long TIME_SYNC_TIMEOUT_MS = 15000UL;

const unsigned int IDENTITY_MISMATCH_MESSAGE_COUNT = 1U;
const unsigned int MALFORMED_MESSAGE_COUNT = 3U;
const char* MALFORMED_PAYLOAD = "{\"device_id\":";
const unsigned long MQTT_STAGE_INTERVAL_MS = 100UL;

const unsigned long PACKET_RATE_PPS = 20UL;
const unsigned long PACKET_RATE_DURATION_SECONDS = 6UL;
const size_t PACKET_RATE_PAYLOAD_BYTES = 64U;
const unsigned long MAX_PACKET_RATE_PPS = 100UL;
const unsigned long MAX_PACKET_RATE_DURATION_SECONDS = 15UL;
const size_t MAX_PACKET_PAYLOAD_BYTES = 1400U;
const unsigned long MIN_PACKET_RATE_SENT = 100UL;

const unsigned int MQTT_FLOOD_MESSAGE_COUNT = 40U;
const unsigned long MQTT_FLOOD_INTERVAL_MS = 50UL;

const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000UL;
const unsigned long MQTT_CONNECT_TIMEOUT_MS = 10000UL;
const unsigned int MQTT_CONNECT_SOCKET_TIMEOUT_SECONDS = 3U;
const unsigned int MQTT_CONNECT_MAX_ATTEMPTS = 2U;
const unsigned long OBSERVATION_TIMEOUT_MS = 45000UL;
const unsigned long OBSERVATION_PROBE_INTERVAL_MS = 5000UL;
const unsigned int MAX_OBSERVATION_PROBES = 9U;
const unsigned int OBSERVATION_CONNECT_TIMEOUT_SECONDS = 5U;
const size_t MAX_SERIAL_LINE_LENGTH = 96U;

WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);
WiFiUDP udp;
IPAddress expectedLocalIp;
IPAddress targetIp;

bool expectedLocalIpValid = false;
bool targetIpValid = false;
bool udpStarted = false;
bool utcTimeSynchronized = false;
bool demoActive = false;
bool demoExecuted = false;
bool abortRequested = false;
String serialLine;
bool serialLineOverflow = false;
String busySerialLine;
bool busySerialLineOverflow = false;
const char* currentStage = "IDLE";
unsigned long demoStartedAtMs = 0UL;

bool isPrivateIpv4(const IPAddress& address) {
  const uint8_t first = address[0];
  const uint8_t second = address[1];
  return first == 10 ||
         (first == 172 && second >= 16 && second <= 31) ||
         (first == 192 && second == 168);
}

bool expectedLocalIpMatches() {
  return expectedLocalIpValid &&
         WiFi.status() == WL_CONNECTED &&
         WiFi.localIP() == expectedLocalIp;
}

void printBoolean(bool value) {
  Serial.println(value ? "true" : "false");
}

void printHelp() {
  Serial.println("multi_attack_sender_help");
  Serial.println("RUN_DEMO");
  Serial.println("RUN IDENTITY_MISMATCH");
  Serial.println("RUN MALFORMED_PAYLOAD");
  Serial.println("RUN PACKET_RATE");
  Serial.println("RUN MQTT_FLOOD");
  Serial.println("STATUS");
  Serial.println("ABORT");
  Serial.println("HELP");
}

void printBootContract() {
  Serial.println("multi_attack_sender_boot");
  Serial.print("firmware_version=");
  Serial.println(FIRMWARE_VERSION);
  Serial.print("device_id=");
  Serial.println(DEVICE_ID);
  Serial.print("expected_local_ip=");
  Serial.println(EXPECTED_LOCAL_IP_TEXT);
  Serial.print("target_ip=");
  Serial.println(TARGET_IP_TEXT);
  Serial.print("mqtt_topic=");
  Serial.println(MQTT_TOPIC);
  Serial.print("target_udp_port=");
  Serial.println(TARGET_UDP_PORT);
  Serial.println("auto_start=false");
  Serial.println("demo_runs_per_boot=1");
}

void printStatus() {
  Serial.println("multi_attack_sender_status");
  Serial.print("firmware_version=");
  Serial.println(FIRMWARE_VERSION);
  Serial.print("wifi_connected=");
  printBoolean(WiFi.status() == WL_CONNECTED);
  Serial.print("local_ip=");
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("0.0.0.0");
  }
  Serial.print("expected_local_ip_match=");
  printBoolean(expectedLocalIpMatches());
  Serial.print("mqtt_connected=");
  printBoolean(mqttClient.connected());
  Serial.print("utc_time_synchronized=");
  printBoolean(utcTimeSynchronized);
  Serial.print("demo_active=");
  printBoolean(demoActive);
  Serial.print("demo_executed=");
  printBoolean(demoExecuted);
  Serial.print("abort_requested=");
  printBoolean(abortRequested);
  Serial.print("current_stage=");
  Serial.println(currentStage);
}

void pollSerialForAbort() {
  while (Serial.available() > 0) {
    const char input = static_cast<char>(Serial.read());
    if (input == '\r') {
      continue;
    }
    if (input == '\n') {
      if (busySerialLineOverflow) {
        Serial.println("command_rejected reason=serial_line_too_long");
      } else {
        busySerialLine.trim();
        busySerialLine.toUpperCase();
        if (busySerialLine == "ABORT") {
          abortRequested = true;
          Serial.println("demo_aborted reason=operator_request");
        } else if (busySerialLine == "STATUS") {
          printStatus();
        } else if (busySerialLine.length() > 0U) {
          Serial.println("command_rejected reason=demo_active_only_ABORT_or_STATUS_allowed");
        }
      }
      busySerialLine = "";
      busySerialLineOverflow = false;
      continue;
    }
    if (busySerialLineOverflow) {
      continue;
    }
    if (busySerialLine.length() >= MAX_SERIAL_LINE_LENGTH) {
      busySerialLineOverflow = true;
      continue;
    }
    busySerialLine += input;
  }
}

bool runtimeHealthy(bool requireMqtt) {
  pollSerialForAbort();
  if (abortRequested) {
    return false;
  }
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("demo_aborted reason=wifi_disconnected");
    return false;
  }
  if (!expectedLocalIpMatches()) {
    Serial.println("demo_aborted reason=local_ip_changed");
    return false;
  }
  if (requireMqtt) {
    mqttClient.loop();
    if (!mqttClient.connected()) {
      Serial.println("demo_aborted reason=mqtt_disconnected_before_isolation_stage");
      return false;
    }
  }
  return true;
}

bool connectWifiWithTimeout() {
  if (WiFi.status() == WL_CONNECTED) {
    return expectedLocalIpMatches();
  }

  WiFi.mode(WIFI_STA);
  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  WiFi.begin(MULTI_ATTACK_WIFI_SSID, MULTI_ATTACK_WIFI_PASSWORD);

  const unsigned long startedAtMs = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - startedAtMs < WIFI_CONNECT_TIMEOUT_MS) {
    pollSerialForAbort();
    if (abortRequested) {
      return false;
    }
    delay(250);
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("preflight_failed reason=wifi_connect_timeout");
    return false;
  }

  Serial.print("wifi_connected local_ip=");
  Serial.println(WiFi.localIP());
  if (!expectedLocalIpMatches()) {
    Serial.print("preflight_failed reason=local_ip_mismatch expected=");
    Serial.print(EXPECTED_LOCAL_IP_TEXT);
    Serial.print(" actual=");
    Serial.println(WiFi.localIP());
    return false;
  }
  return true;
}

bool mqttConnectWithCredentials(const char* clientId) {
  if (strlen(MQTT_USERNAME) > 0U) {
    return mqttClient.connect(clientId, MQTT_USERNAME, MQTT_PASSWORD);
  }
  return mqttClient.connect(clientId);
}

bool connectMqttWithTimeout() {
  if (mqttClient.connected()) {
    return true;
  }

  mqttClient.setServer(TARGET_IP_TEXT, MQTT_PORT);
  mqttClient.setBufferSize(256U);
  mqttClient.setSocketTimeout(MQTT_CONNECT_SOCKET_TIMEOUT_SECONDS);

  const unsigned long startedAtMs = millis();
  unsigned int attempts = 0U;
  while (!mqttClient.connected() &&
         millis() - startedAtMs < MQTT_CONNECT_TIMEOUT_MS &&
         attempts < MQTT_CONNECT_MAX_ATTEMPTS) {
    attempts++;
    mqttConnectWithCredentials("phase6b_multi_attack_esp32_02");
    if (!mqttClient.connected()) {
      delay(500);
    }
  }

  if (!mqttClient.connected()) {
    Serial.print("preflight_failed reason=mqtt_connect_timeout state=");
    Serial.println(mqttClient.state());
    return false;
  }
  return true;
}

bool startUdpSocket() {
  if (udpStarted) {
    return true;
  }
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }
  udpStarted = udp.begin(LOCAL_UDP_PORT) == 1;
  if (!udpStarted) {
    Serial.println("preflight_failed reason=udp_start_failed");
  }
  return udpStarted;
}

bool syncUtcTimeWithTimeout() {
  const time_t existingEpoch = time(nullptr);
  if (existingEpoch >= MIN_VALID_EPOCH) {
    utcTimeSynchronized = true;
    return true;
  }

  configTime(0, 0, NTP_SERVER);
  const unsigned long startedAtMs = millis();
  while (time(nullptr) < MIN_VALID_EPOCH &&
         millis() - startedAtMs < TIME_SYNC_TIMEOUT_MS) {
    pollSerialForAbort();
    if (abortRequested) {
      return false;
    }
    mqttClient.loop();
    delay(100);
  }

  utcTimeSynchronized = time(nullptr) >= MIN_VALID_EPOCH;
  if (!utcTimeSynchronized) {
    Serial.println("preflight_failed reason=time_sync_unavailable");
  }
  return utcTimeSynchronized;
}

bool waitForNextAnalysisWindow(const char* nextStage) {
  if (!utcTimeSynchronized) {
    Serial.println("demo_aborted reason=time_sync_unavailable");
    return false;
  }

  const time_t currentEpoch = time(nullptr);
  const time_t targetEpoch =
      ((currentEpoch / ANALYSIS_WINDOW_SECONDS) + 1) *
          ANALYSIS_WINDOW_SECONDS +
      WINDOW_START_OFFSET_SECONDS;

  Serial.print("[WAIT] next_stage=");
  Serial.print(nextStage);
  Serial.print(" target_epoch=");
  Serial.println(static_cast<unsigned long>(targetEpoch));

  while (time(nullptr) < targetEpoch) {
    if (!runtimeHealthy(true)) {
      return false;
    }
    delay(20);
  }
  return true;
}

bool runPreflight() {
  Serial.println("[DEMO] Preflight started");
  if (MULTI_ATTACK_TEST_ENABLED != 1) {
    Serial.println("preflight_failed reason=test_not_enabled");
    return false;
  }
  if (!expectedLocalIpValid || !targetIpValid || !isPrivateIpv4(targetIp)) {
    Serial.println("preflight_failed reason=invalid_private_lab_configuration");
    return false;
  }
  if (!connectWifiWithTimeout()) {
    return false;
  }
  if (!expectedLocalIpMatches()) {
    Serial.println("preflight_failed reason=local_ip_mismatch");
    return false;
  }
  if (!connectMqttWithTimeout()) {
    return false;
  }
  if (!startUdpSocket()) {
    return false;
  }
  if (!syncUtcTimeWithTimeout()) {
    return false;
  }
  Serial.println("preflight_result=PASS");
  return true;
}

bool publishMqttMessages(
    const char* stageName,
    const String& payload,
    unsigned int count,
    unsigned long intervalMs) {
  unsigned int published = 0U;
  unsigned int failed = 0U;
  for (unsigned int index = 0U; index < count; index++) {
    if (!runtimeHealthy(true)) {
      return false;
    }
    const bool result = mqttClient.publish(MQTT_TOPIC, payload.c_str());
    if (result) {
      published++;
    } else {
      failed++;
    }
    mqttClient.loop();
    if (index + 1U < count) {
      delay(intervalMs);
    }
  }

  Serial.print("[STAGE] name=");
  Serial.print(stageName);
  Serial.print(" published=");
  Serial.print(published);
  Serial.print(" failed=");
  Serial.println(failed);
  return published == count && failed == 0U;
}

String buildDevicePayload(const char* deviceId) {
  return String("{\"device_id\":\"") + deviceId + "\"}";
}

bool runIdentityMismatchAttack() {
  currentStage = "IDENTITY_MISMATCH";
  Serial.println("[DEMO 1/4] IDENTITY_MISMATCH started");
  const bool result = publishMqttMessages(
      currentStage,
      buildDevicePayload(SPOOFED_DEVICE_ID),
      IDENTITY_MISMATCH_MESSAGE_COUNT,
      MQTT_STAGE_INTERVAL_MS);
  Serial.println(result ?
      "[DEMO 1/4] IDENTITY_MISMATCH completed" :
      "[DEMO 1/4] IDENTITY_MISMATCH failed");
  return result;
}

bool runMalformedPayloadAttack() {
  currentStage = "MALFORMED_PAYLOAD";
  Serial.println("[DEMO 2/4] MALFORMED_PAYLOAD started");
  const bool result = publishMqttMessages(
      currentStage,
      String(MALFORMED_PAYLOAD),
      MALFORMED_MESSAGE_COUNT,
      MQTT_STAGE_INTERVAL_MS);
  Serial.println(result ?
      "[DEMO 2/4] MALFORMED_PAYLOAD completed" :
      "[DEMO 2/4] MALFORMED_PAYLOAD failed");
  return result;
}

bool runPacketRateAttack() {
  currentStage = "PACKET_RATE";
  Serial.println("[DEMO 3/4] PACKET_RATE started");

  if (PACKET_RATE_PPS > MAX_PACKET_RATE_PPS ||
      PACKET_RATE_DURATION_SECONDS > MAX_PACKET_RATE_DURATION_SECONDS ||
      PACKET_RATE_PAYLOAD_BYTES > MAX_PACKET_PAYLOAD_BYTES ||
      !startUdpSocket()) {
    Serial.println("[DEMO 3/4] PACKET_RATE failed reason=safety_contract");
    return false;
  }

  uint8_t payload[PACKET_RATE_PAYLOAD_BYTES];
  memset(payload, 'P', sizeof(payload));
  const char prefix[] = "esp32_02_packet_rate";
  memcpy(payload, prefix, sizeof(prefix) - 1U);

  const unsigned long packetIntervalUs = 1000000UL / PACKET_RATE_PPS;
  const unsigned long startedAtMs = millis();
  unsigned long nextPacketAtUs = micros();
  unsigned long sentPackets = 0UL;
  unsigned long failedPackets = 0UL;

  while (millis() - startedAtMs < PACKET_RATE_DURATION_SECONDS * 1000UL) {
    if (!runtimeHealthy(true)) {
      return false;
    }

    const unsigned long nowUs = micros();
    if (static_cast<int32_t>(nowUs - nextPacketAtUs) < 0) {
      delay(1);
      continue;
    }

    const int beginResult = udp.beginPacket(targetIp, TARGET_UDP_PORT);
    if (beginResult != 1) {
      failedPackets++;
    } else {
      const size_t written = udp.write(payload, sizeof(payload));
      const int endResult = udp.endPacket();
      const int endErrno = errno;
      if (written == sizeof(payload) && endResult == 1) {
        sentPackets++;
      } else {
        failedPackets++;
        Serial.print("packet_send_failure errno=");
        Serial.println(endErrno);
      }
    }

    nextPacketAtUs += packetIntervalUs;
    const unsigned long afterSendUs = micros();
    if (static_cast<int32_t>(afterSendUs - nextPacketAtUs) >= 0) {
      nextPacketAtUs = afterSendUs + packetIntervalUs;
    }
  }

  Serial.print("[STAGE] name=PACKET_RATE sent=");
  Serial.print(sentPackets);
  Serial.print(" failed=");
  Serial.println(failedPackets);
  const bool result = sentPackets >= MIN_PACKET_RATE_SENT;
  Serial.println(result ?
      "[DEMO 3/4] PACKET_RATE completed" :
      "[DEMO 3/4] PACKET_RATE failed reason=insufficient_packets");
  return result;
}

bool runMqttFloodAttack() {
  currentStage = "MQTT_FLOOD";
  Serial.println("[DEMO 4/4] MQTT_FLOOD started");
  unsigned int published = 0U;
  unsigned int failed = 0U;
  const String payload = buildDevicePayload(DEVICE_ID);

  for (unsigned int messageIndex = 0U;
       messageIndex < MQTT_FLOOD_MESSAGE_COUNT;
       messageIndex++) {
    pollSerialForAbort();
    if (abortRequested || WiFi.status() != WL_CONNECTED ||
        !expectedLocalIpMatches() || !mqttClient.connected()) {
      break;
    }
    if (mqttClient.publish(MQTT_TOPIC, payload.c_str())) {
      published++;
    } else {
      failed++;
    }
    mqttClient.loop();
    delay(MQTT_FLOOD_INTERVAL_MS);
  }

  Serial.print("[STAGE] name=MQTT_FLOOD published=");
  Serial.print(published);
  Serial.print(" failed=");
  Serial.println(failed);
  const bool result = !abortRequested && published > 15U;
  Serial.println(result ?
      "[DEMO 4/4] MQTT_FLOOD completed" :
      "[DEMO 4/4] MQTT_FLOOD failed reason=threshold_not_reached");
  return result;
}

void logObservationFailure(
    unsigned long observationStartedAtMs,
    const char* failureKind,
    const char* publishResult) {
  Serial.print("[OBSERVE] first_failure_demo_elapsed_ms=");
  Serial.print(millis() - demoStartedAtMs);
  Serial.print(" observation_elapsed_ms=");
  Serial.print(millis() - observationStartedAtMs);
  Serial.print(" failure_kind=");
  Serial.print(failureKind);
  Serial.print(" mqtt_state=");
  Serial.print(mqttClient.state());
  Serial.print(" publish_result=");
  Serial.println(publishResult);
}

void runBoundedIsolationObservation() {
  currentStage = "ISOLATION_OBSERVATION";
  const unsigned long observationStartedAtMs = millis();
  unsigned long lastProbeAtMs = observationStartedAtMs;
  unsigned int observationProbeCount = 0U;
  bool failureObserved = false;

  Serial.println("[OBSERVE] bounded isolation observation started");
  while (millis() - observationStartedAtMs < OBSERVATION_TIMEOUT_MS &&
         observationProbeCount < MAX_OBSERVATION_PROBES &&
         !abortRequested) {
    pollSerialForAbort();
    mqttClient.loop();

    if (!mqttClient.connected()) {
      logObservationFailure(
          observationStartedAtMs,
          "connection_lost",
          "not_attempted");
      failureObserved = true;
      break;
    }

    if (millis() - lastProbeAtMs >= OBSERVATION_PROBE_INTERVAL_MS) {
      const String payload = buildDevicePayload(DEVICE_ID);
      const bool publishResult = mqttClient.publish(MQTT_TOPIC, payload.c_str());
      observationProbeCount++;
      lastProbeAtMs = millis();
      Serial.print("[OBSERVE] probe=");
      Serial.print(observationProbeCount);
      Serial.print(" publish_result=");
      Serial.println(publishResult ? "success" : "failed");
      if (!publishResult) {
        logObservationFailure(
            observationStartedAtMs,
            "probe_publish_failed",
            "failed");
        failureObserved = true;
        break;
      }
    }
    delay(50);
  }

  if (!failureObserved && !abortRequested) {
    Serial.println("[OBSERVE] no failure before observation timeout");
  }

  if (mqttClient.connected()) {
    mqttClient.disconnect();
  }
  mqttClient.setSocketTimeout(OBSERVATION_CONNECT_TIMEOUT_SECONDS);
  const bool reconnectResult =
      mqttConnectWithCredentials("phase6b_multi_attack_observation");
  Serial.print("[OBSERVE] reconnect_result=");
  Serial.println(reconnectResult ? "success" : "failed");
  if (reconnectResult) {
    mqttClient.disconnect();
  }
  if (udpStarted) {
    udp.stop();
    udpStarted = false;
  }
  WiFi.disconnect(false);
  Serial.println("[OBSERVE] bounded isolation observation finished");
  Serial.println("[DONE] Restore normal_sender firmware before normal operation");
}

void runDemoSequence() {
  if (demoActive) {
    Serial.println("demo_rejected reason=already_active");
    return;
  }
  if (demoExecuted) {
    Serial.println("demo_rejected reason=already_executed_this_boot");
    return;
  }

  demoExecuted = true;
  demoActive = true;
  abortRequested = false;
  demoStartedAtMs = millis();
  currentStage = "PREFLIGHT";

  if (!runPreflight()) {
    Serial.println("demo_finished result=PREFLIGHT_FAILED");
    demoActive = false;
    currentStage = "IDLE";
    return;
  }

  if (!waitForNextAnalysisWindow("IDENTITY_MISMATCH") ||
      !runIdentityMismatchAttack()) {
    Serial.println("demo_finished result=IDENTITY_MISMATCH_FAILED");
    demoActive = false;
    currentStage = "IDLE";
    return;
  }

  if (!waitForNextAnalysisWindow("MALFORMED_PAYLOAD") ||
      !runMalformedPayloadAttack()) {
    Serial.println("demo_finished result=MALFORMED_PAYLOAD_FAILED");
    demoActive = false;
    currentStage = "IDLE";
    return;
  }

  if (!waitForNextAnalysisWindow("PACKET_RATE") ||
      !runPacketRateAttack()) {
    Serial.println("demo_finished result=PACKET_RATE_FAILED");
    demoActive = false;
    currentStage = "IDLE";
    return;
  }

  if (!waitForNextAnalysisWindow("MQTT_FLOOD") ||
      !runMqttFloodAttack()) {
    Serial.println("demo_finished result=MQTT_FLOOD_FAILED");
    demoActive = false;
    currentStage = "IDLE";
    return;
  }

  runBoundedIsolationObservation();
  Serial.print("demo_finished result=");
  Serial.println(abortRequested ? "ABORTED" : "SEQUENCE_COMPLETE");
  demoActive = false;
  currentStage = "IDLE";
}

void runIndividualAttack(const String& mode) {
  if (demoActive) {
    Serial.println("run_rejected reason=demo_active");
    return;
  }
  abortRequested = false;
  if (!runPreflight()) {
    Serial.println("run_finished result=PREFLIGHT_FAILED");
    currentStage = "IDLE";
    return;
  }

  bool result = false;
  if (mode == "IDENTITY_MISMATCH") {
    result = runIdentityMismatchAttack();
  } else if (mode == "MALFORMED_PAYLOAD") {
    result = runMalformedPayloadAttack();
  } else if (mode == "PACKET_RATE") {
    result = runPacketRateAttack();
  } else if (mode == "MQTT_FLOOD") {
    result = runMqttFloodAttack();
  } else {
    Serial.print("run_rejected reason=unknown_mode value=");
    Serial.println(mode);
    currentStage = "IDLE";
    return;
  }

  Serial.print("run_finished mode=");
  Serial.print(mode);
  Serial.print(" result=");
  Serial.println(result ? "COMPLETED" : "FAILED");
  currentStage = "IDLE";
}

void processSerialCommand(String command) {
  command.trim();
  if (command.length() == 0U) {
    return;
  }
  command.toUpperCase();

  if (command == "HELP") {
    printHelp();
    return;
  }
  if (command == "STATUS") {
    printStatus();
    return;
  }
  if (command == "ABORT") {
    if (demoActive) {
      abortRequested = true;
      Serial.println("demo_aborted reason=operator_request");
    } else {
      Serial.println("abort_ignored reason=no_active_demo");
    }
    return;
  }
  if (command == "RUN_DEMO") {
    runDemoSequence();
    return;
  }
  if (command.startsWith("RUN ")) {
    const String mode = command.substring(4);
    runIndividualAttack(mode);
    return;
  }

  Serial.print("command_rejected reason=unknown_command value=");
  Serial.println(command);
  printHelp();
}

void handleSerialInput() {
  while (Serial.available() > 0) {
    const char input = static_cast<char>(Serial.read());
    if (input == '\r') {
      continue;
    }
    if (input == '\n') {
      if (serialLineOverflow) {
        Serial.println("command_rejected reason=serial_line_too_long");
      } else {
        processSerialCommand(serialLine);
      }
      serialLine = "";
      serialLineOverflow = false;
      continue;
    }
    if (serialLineOverflow) {
      continue;
    }
    if (serialLine.length() >= MAX_SERIAL_LINE_LENGTH) {
      serialLineOverflow = true;
      continue;
    }
    serialLine += input;
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  printBootContract();

  expectedLocalIpValid = expectedLocalIp.fromString(EXPECTED_LOCAL_IP_TEXT);
  targetIpValid = targetIp.fromString(TARGET_IP_TEXT);
  if (!expectedLocalIpValid) {
    Serial.println("configuration_error reason=invalid_expected_local_ip");
  }
  if (!targetIpValid || !isPrivateIpv4(targetIp)) {
    Serial.println("configuration_error reason=invalid_private_target_ip");
  }
  if (MULTI_ATTACK_TEST_ENABLED != 1) {
    Serial.println("[DISABLED] Set MULTI_ATTACK_TEST_ENABLED=1 only for the approved lab test");
  }

  printHelp();
  Serial.println("multi_attack_sender_ready");
}

void loop() {
  handleSerialInput();
  if (mqttClient.connected()) {
    mqttClient.loop();
  }
  delay(1);
}
