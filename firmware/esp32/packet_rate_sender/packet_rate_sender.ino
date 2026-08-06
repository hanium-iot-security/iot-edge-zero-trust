#include <WiFi.h>
#include <WiFiUdp.h>

#if __has_include("packet_rate_firmware_config.h")
#include "packet_rate_firmware_config.h"
#else
#error "Copy packet_rate_firmware_config.example.h to packet_rate_firmware_config.h before compiling."
#endif

#if PACKET_RATE_CONFIGURED != 1
#error "Set PACKET_RATE_CONFIGURED to 1 after reviewing the local firmware configuration."
#endif

#if PACKET_RATE_DEVICE_SLOT != 2
#error "PACKET_RATE_DEVICE_SLOT must be 2. This firmware is restricted to esp32_02."
#endif

#if PACKET_RATE_TARGET_PORT < 1 || PACKET_RATE_TARGET_PORT > 65535
#error "PACKET_RATE_TARGET_PORT must be between 1 and 65535."
#endif

#if PACKET_RATE_LOCAL_UDP_PORT < 1 || PACKET_RATE_LOCAL_UDP_PORT > 65535
#error "PACKET_RATE_LOCAL_UDP_PORT must be between 1 and 65535."
#endif

const char* DEVICE_ID = "esp32_02";
const char* FIRMWARE_VERSION = "phase5-packet-rate-sender-v1";

const unsigned long MIN_RATE_PPS = 1UL;
const unsigned long MAX_RATE_PPS = 100UL;
const unsigned long MIN_DURATION_SECONDS = 1UL;
const unsigned long MAX_DURATION_SECONDS = 15UL;
const unsigned long MIN_PAYLOAD_BYTES = 1UL;
const unsigned long MAX_PAYLOAD_BYTES = 1400UL;

const unsigned long WIFI_CONNECT_TIMEOUT_MS = 15000UL;
const unsigned long WIFI_RETRY_INTERVAL_MS = 5000UL;
const size_t MAX_SERIAL_LINE_LENGTH = 96U;

WiFiUDP udp;
IPAddress expectedLocalIp;
IPAddress targetIp;

bool expectedLocalIpValid = false;
bool targetIpValid = false;
bool udpStarted = false;

String serialLine;
bool serialLineOverflow = false;
unsigned long lastWifiAttemptAtMs = 0UL;

bool attackActive = false;
unsigned long attackRatePps = 0UL;
unsigned long attackDurationSeconds = 0UL;
unsigned long attackPayloadBytes = 0UL;
unsigned long attackStartedAtMs = 0UL;
unsigned long attackIntervalUs = 0UL;
unsigned long nextPacketAtUs = 0UL;
unsigned long sentPackets = 0UL;
unsigned long failedPackets = 0UL;
uint8_t payloadBuffer[MAX_PAYLOAD_BYTES];

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
  Serial.println("packet_rate_sender_help");
  Serial.println("START <pps> <duration_sec> <payload_bytes>");
  Serial.println("STATUS");
  Serial.println("HELP");
  Serial.println("example_smoke=START 10 3 64");
  Serial.println("example_offline_test=START 80 12 64");
  Serial.print("limits pps=");
  Serial.print(MIN_RATE_PPS);
  Serial.print("-");
  Serial.print(MAX_RATE_PPS);
  Serial.print(" duration_sec=");
  Serial.print(MIN_DURATION_SECONDS);
  Serial.print("-");
  Serial.print(MAX_DURATION_SECONDS);
  Serial.print(" payload_bytes=");
  Serial.print(MIN_PAYLOAD_BYTES);
  Serial.print("-");
  Serial.println(MAX_PAYLOAD_BYTES);
}

void printBootContract() {
  Serial.println("packet_rate_sender_boot");
  Serial.print("firmware_version=");
  Serial.println(FIRMWARE_VERSION);
  Serial.print("device_id=");
  Serial.println(DEVICE_ID);
  Serial.print("device_slot=");
  Serial.println(PACKET_RATE_DEVICE_SLOT);
  Serial.print("expected_local_ip=");
  Serial.println(PACKET_RATE_EXPECTED_LOCAL_IP);
  Serial.print("target_ip=");
  Serial.println(PACKET_RATE_TARGET_IP);
  Serial.print("target_port=");
  Serial.println(PACKET_RATE_TARGET_PORT);
  Serial.print("local_udp_port=");
  Serial.println(PACKET_RATE_LOCAL_UDP_PORT);
  Serial.print("safety_max_pps=");
  Serial.println(MAX_RATE_PPS);
  Serial.print("safety_max_duration_sec=");
  Serial.println(MAX_DURATION_SECONDS);
  Serial.print("safety_max_payload_bytes=");
  Serial.println(MAX_PAYLOAD_BYTES);
  Serial.println("auto_start=false");
  Serial.println("serial_commands=START <pps> <duration_sec> <payload_bytes>|STATUS|HELP");
}

bool startUdpSocket() {
  if (udpStarted) {
    return true;
  }
  if (WiFi.status() != WL_CONNECTED) {
    return false;
  }

  udpStarted = udp.begin(PACKET_RATE_LOCAL_UDP_PORT) == 1;
  if (!udpStarted) {
    Serial.print("udp_start_failed local_port=");
    Serial.println(PACKET_RATE_LOCAL_UDP_PORT);
    return false;
  }

  Serial.print("udp_ready local_port=");
  Serial.println(PACKET_RATE_LOCAL_UDP_PORT);
  return true;
}

void stopUdpSocket() {
  if (!udpStarted) {
    return;
  }
  udp.stop();
  udpStarted = false;
}

bool connectWifiWithTimeout() {
  if (WiFi.status() == WL_CONNECTED) {
    return startUdpSocket();
  }

  stopUdpSocket();
  Serial.println("wifi_connect_started");
  WiFi.mode(WIFI_STA);
  WiFi.begin(PACKET_RATE_WIFI_SSID, PACKET_RATE_WIFI_PASSWORD);

  const unsigned long startedAtMs = millis();
  while (WiFi.status() != WL_CONNECTED &&
         millis() - startedAtMs < WIFI_CONNECT_TIMEOUT_MS) {
    delay(250);
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("wifi_connect_timeout");
    return false;
  }

  Serial.print("wifi_connected local_ip=");
  Serial.println(WiFi.localIP());
  Serial.print("expected_local_ip_match=");
  printBoolean(expectedLocalIpMatches());

  if (!expectedLocalIpMatches()) {
    Serial.print("warning reason=local_ip_mismatch expected=");
    Serial.print(PACKET_RATE_EXPECTED_LOCAL_IP);
    Serial.print(" actual=");
    Serial.println(WiFi.localIP());
  }

  return startUdpSocket();
}

void printStatus() {
  Serial.println("packet_rate_sender_status");
  Serial.print("firmware_version=");
  Serial.println(FIRMWARE_VERSION);
  Serial.print("device_id=");
  Serial.println(DEVICE_ID);
  Serial.print("wifi_connected=");
  printBoolean(WiFi.status() == WL_CONNECTED);
  Serial.print("local_ip=");
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("0.0.0.0");
  }
  Serial.print("expected_local_ip=");
  Serial.println(PACKET_RATE_EXPECTED_LOCAL_IP);
  Serial.print("expected_local_ip_match=");
  printBoolean(expectedLocalIpMatches());
  Serial.print("target_ip=");
  Serial.println(PACKET_RATE_TARGET_IP);
  Serial.print("target_port=");
  Serial.println(PACKET_RATE_TARGET_PORT);
  Serial.print("udp_ready=");
  printBoolean(udpStarted);
  Serial.print("attack_active=");
  printBoolean(attackActive);
  Serial.print("requested_pps=");
  Serial.println(attackRatePps);
  Serial.print("duration_sec=");
  Serial.println(attackDurationSeconds);
  Serial.print("payload_bytes=");
  Serial.println(attackPayloadBytes);
  Serial.print("sent=");
  Serial.println(sentPackets);
  Serial.print("failed=");
  Serial.println(failedPackets);
  if (attackActive) {
    Serial.print("elapsed_ms=");
    Serial.println(millis() - attackStartedAtMs);
  }
}

void finishAttack(const char* reason) {
  if (!attackActive) {
    return;
  }

  const unsigned long elapsedMs = millis() - attackStartedAtMs;
  attackActive = false;

  const float elapsedSeconds = elapsedMs / 1000.0F;
  const float averagePps =
      elapsedSeconds > 0.0F ? sentPackets / elapsedSeconds : 0.0F;

  Serial.println("packet_rate_attack_finished");
  Serial.print("reason=");
  Serial.println(reason);
  Serial.print("firmware_version=");
  Serial.println(FIRMWARE_VERSION);
  Serial.print("device_id=");
  Serial.println(DEVICE_ID);
  Serial.print("local_ip=");
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("0.0.0.0");
  }
  Serial.print("target_ip=");
  Serial.println(PACKET_RATE_TARGET_IP);
  Serial.print("target_port=");
  Serial.println(PACKET_RATE_TARGET_PORT);
  Serial.print("requested_pps=");
  Serial.println(attackRatePps);
  Serial.print("duration_sec=");
  Serial.println(attackDurationSeconds);
  Serial.print("payload_bytes=");
  Serial.println(attackPayloadBytes);
  Serial.print("started_at_ms=");
  Serial.println(attackStartedAtMs);
  Serial.print("sent=");
  Serial.println(sentPackets);
  Serial.print("failed=");
  Serial.println(failedPackets);
  Serial.print("attempted=");
  Serial.println(sentPackets + failedPackets);
  Serial.print("elapsed_ms=");
  Serial.println(elapsedMs);
  Serial.print("average_pps=");
  Serial.println(averagePps, 2);
}

bool validateStartArguments(
    unsigned long ratePps,
    unsigned long durationSeconds,
    unsigned long payloadBytes) {
  if (ratePps < MIN_RATE_PPS || ratePps > MAX_RATE_PPS) {
    Serial.print("start_rejected reason=pps_out_of_range min=");
    Serial.print(MIN_RATE_PPS);
    Serial.print(" max=");
    Serial.print(MAX_RATE_PPS);
    Serial.print(" actual=");
    Serial.println(ratePps);
    return false;
  }

  if (durationSeconds < MIN_DURATION_SECONDS ||
      durationSeconds > MAX_DURATION_SECONDS) {
    Serial.print("start_rejected reason=duration_out_of_range min=");
    Serial.print(MIN_DURATION_SECONDS);
    Serial.print(" max=");
    Serial.print(MAX_DURATION_SECONDS);
    Serial.print(" actual=");
    Serial.println(durationSeconds);
    return false;
  }

  if (payloadBytes < MIN_PAYLOAD_BYTES ||
      payloadBytes > MAX_PAYLOAD_BYTES) {
    Serial.print("start_rejected reason=payload_out_of_range min=");
    Serial.print(MIN_PAYLOAD_BYTES);
    Serial.print(" max=");
    Serial.print(MAX_PAYLOAD_BYTES);
    Serial.print(" actual=");
    Serial.println(payloadBytes);
    return false;
  }

  return true;
}

void startAttack(
    unsigned long ratePps,
    unsigned long durationSeconds,
    unsigned long payloadBytes) {
  if (attackActive) {
    Serial.println("start_rejected reason=attack_already_active");
    return;
  }

  if (!targetIpValid || !expectedLocalIpValid || !isPrivateIpv4(targetIp)) {
    Serial.println("start_rejected reason=invalid_private_lab_configuration");
    return;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("start_rejected reason=wifi_not_connected");
    return;
  }

  if (!expectedLocalIpMatches()) {
    Serial.print("start_rejected reason=local_ip_mismatch expected=");
    Serial.print(PACKET_RATE_EXPECTED_LOCAL_IP);
    Serial.print(" actual=");
    Serial.println(WiFi.localIP());
    return;
  }

  if (!startUdpSocket()) {
    Serial.println("start_rejected reason=udp_not_ready");
    return;
  }

  if (!validateStartArguments(ratePps, durationSeconds, payloadBytes)) {
    return;
  }

  memset(payloadBuffer, 'P', payloadBytes);
  const char payloadPrefix[] = "esp32_02_packet_rate";
  const size_t prefixBytes = sizeof(payloadPrefix) - 1U;
  const size_t copyBytes = payloadBytes < prefixBytes ? payloadBytes : prefixBytes;
  memcpy(payloadBuffer, payloadPrefix, copyBytes);

  attackRatePps = ratePps;
  attackDurationSeconds = durationSeconds;
  attackPayloadBytes = payloadBytes;
  attackIntervalUs = 1000000UL / attackRatePps;
  attackStartedAtMs = millis();
  nextPacketAtUs = micros();
  sentPackets = 0UL;
  failedPackets = 0UL;
  attackActive = true;

  Serial.println("packet_rate_attack_started");
  Serial.print("firmware_version=");
  Serial.println(FIRMWARE_VERSION);
  Serial.print("device_id=");
  Serial.println(DEVICE_ID);
  Serial.print("local_ip=");
  Serial.println(WiFi.localIP());
  Serial.print("target_ip=");
  Serial.println(PACKET_RATE_TARGET_IP);
  Serial.print("target_port=");
  Serial.println(PACKET_RATE_TARGET_PORT);
  Serial.print("requested_pps=");
  Serial.println(attackRatePps);
  Serial.print("duration_sec=");
  Serial.println(attackDurationSeconds);
  Serial.print("payload_bytes=");
  Serial.println(attackPayloadBytes);
  Serial.print("started_at_ms=");
  Serial.println(attackStartedAtMs);
}

void sendScheduledPacket() {
  const int beginResult = udp.beginPacket(targetIp, PACKET_RATE_TARGET_PORT);
  if (beginResult != 1) {
    failedPackets++;
    return;
  }

  const size_t written = udp.write(payloadBuffer, attackPayloadBytes);
  const int endResult = udp.endPacket();

  if (written == attackPayloadBytes && endResult == 1) {
    sentPackets++;
  } else {
    failedPackets++;
  }
}

void updateAttack() {
  if (!attackActive) {
    return;
  }

  if (WiFi.status() != WL_CONNECTED) {
    finishAttack("wifi_disconnected");
    stopUdpSocket();
    return;
  }

  if (!expectedLocalIpMatches()) {
    finishAttack("local_ip_changed");
    return;
  }

  const unsigned long elapsedMs = millis() - attackStartedAtMs;
  if (elapsedMs >= attackDurationSeconds * 1000UL) {
    finishAttack("duration_completed");
    return;
  }

  const unsigned long nowUs = micros();
  if (static_cast<int32_t>(nowUs - nextPacketAtUs) < 0) {
    return;
  }

  sendScheduledPacket();

  // Advance from the previous schedule. If the loop was delayed, skip missed
  // slots rather than sending a catch-up burst above the requested rate.
  nextPacketAtUs += attackIntervalUs;
  const unsigned long afterSendUs = micros();
  if (static_cast<int32_t>(afterSendUs - nextPacketAtUs) >= 0) {
    nextPacketAtUs = afterSendUs + attackIntervalUs;
  }
}

void processSerialCommand(String command) {
  command.trim();
  if (command.length() == 0U) {
    return;
  }

  const int firstSpace = command.indexOf(' ');
  String verb = firstSpace < 0 ? command : command.substring(0, firstSpace);
  verb.toUpperCase();

  if (verb == "HELP") {
    printHelp();
    return;
  }

  if (verb == "STATUS") {
    printStatus();
    return;
  }

  if (verb != "START") {
    Serial.print("command_rejected reason=unknown_command value=");
    Serial.println(command);
    printHelp();
    return;
  }

  unsigned long ratePps = 0UL;
  unsigned long durationSeconds = 0UL;
  unsigned long payloadBytes = 0UL;
  char extraToken[2] = {0};
  const int parsed = sscanf(
      command.c_str(),
      "%*s %lu %lu %lu %1s",
      &ratePps,
      &durationSeconds,
      &payloadBytes,
      extraToken);

  if (parsed != 3) {
    Serial.println(
        "start_rejected reason=invalid_syntax expected=START_<pps>_<duration_sec>_<payload_bytes>");
    return;
  }

  startAttack(ratePps, durationSeconds, payloadBytes);
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

void maintainWifi() {
  if (WiFi.status() == WL_CONNECTED) {
    if (!udpStarted) {
      startUdpSocket();
    }
    return;
  }

  stopUdpSocket();
  const unsigned long currentTimeMs = millis();
  if (currentTimeMs - lastWifiAttemptAtMs < WIFI_RETRY_INTERVAL_MS) {
    return;
  }

  lastWifiAttemptAtMs = currentTimeMs;
  connectWifiWithTimeout();
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  printBootContract();

  expectedLocalIpValid =
      expectedLocalIp.fromString(PACKET_RATE_EXPECTED_LOCAL_IP);
  targetIpValid = targetIp.fromString(PACKET_RATE_TARGET_IP);

  if (!expectedLocalIpValid) {
    Serial.println("configuration_error reason=invalid_expected_local_ip");
  }
  if (!targetIpValid) {
    Serial.println("configuration_error reason=invalid_target_ip");
  } else if (!isPrivateIpv4(targetIp)) {
    Serial.println("configuration_error reason=target_ip_not_private");
  }

  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  connectWifiWithTimeout();
  lastWifiAttemptAtMs = millis();

  printHelp();
  Serial.println("packet_rate_sender_ready");
}

void loop() {
  handleSerialInput();
  updateAttack();
  maintainWifi();
  delay(1);
}
