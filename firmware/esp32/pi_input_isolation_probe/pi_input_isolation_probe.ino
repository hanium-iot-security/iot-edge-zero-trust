#include <WiFi.h>
#include <WiFiUdp.h>
#include <PubSubClient.h>
#include <cJSON.h>
#include <lwip/sockets.h>
#include <esp_random.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "isolation_probe_protocol.h"

#if __has_include("isolation_probe_config.h")
#include "isolation_probe_config.h"
#else
#error "Copy isolation_probe_config.example.h to isolation_probe_config.h locally."
#endif
#if ISOLATION_PROBE_CONFIGURED != 1
#error "Review the physical test configuration before setting ISOLATION_PROBE_CONFIGURED=1."
#endif
#if __has_include("mqtt_credentials.h")
#include "mqtt_credentials.h"
#else
#error "Copy mqtt_credentials.example.h to mqtt_credentials.h locally."
#endif

const char* FIRMWARE_VERSION = "phase9-pi-input-isolation-probe-v1";
const char* DEVICE_ID = "esp32_02";
const char* MQTT_TOPIC = "iot/esp32_02/sensor";
const IPAddress EXPECTED_LOCAL_IP(192, 168, 0, 5);
const IPAddress PI_IP(192, 168, 0, 20);
const uint16_t MQTT_PORT = 1883;
const uint16_t HTTP_PORT = 8000;
const uint16_t UDP_PORT = 9002;
const uint16_t LOCAL_UDP_PORT = 42100;
const unsigned long MIN_RUN_INTERVAL_MS = 10000;
const unsigned long ARM_LIFETIME_MS = 15000;
const unsigned long CONNECT_TIMEOUT_MS = 2000;
const unsigned long RESPONSE_TIMEOUT_MS = 2000;
const size_t MAX_SERIAL_BYTES = 96;
const size_t MAX_HTTP_BYTES = 1536;
const size_t MAX_UDP_BYTES = 128;
const unsigned int FLOOD_COUNT = 40;
const unsigned long FLOOD_INTERVAL_MS = 50;

WiFiClient mqttTransport;
PubSubClient mqttClient(mqttTransport);
String commandLine;
bool lineOverflow = false;
bool busy = false;
bool abortRequested = false;
bool hasRun = false;
unsigned long lastRunAt = 0;
unsigned long sequenceNumber = 0;
String lastNonce;
String armedNonce;
unsigned long armedAt = 0;
bool floodArmed = false;
const char* mqttFailure = "NO_ACCEPTED_CONNACK";

void printStatus() {
  Serial.print("status firmware_version="); Serial.print(FIRMWARE_VERSION);
  Serial.print(" device_id="); Serial.print(DEVICE_ID);
  Serial.print(" local_ip="); Serial.print(WiFi.localIP());
  Serial.print(" target_ip="); Serial.print(PI_IP);
  Serial.print(" expected_local_ip_match=");
  Serial.print(WiFi.status() == WL_CONNECTED && WiFi.localIP() == EXPECTED_LOCAL_IP);
  Serial.print(" busy="); Serial.print(busy);
  Serial.print(" flood_armed="); Serial.print(floodArmed);
  Serial.println(" auto_probe=false auto_flood=false auto_normal_publish=false");
}

void help() {
  Serial.println("CONNECT | STATUS | HELP | ABORT");
  Serial.println("PROBE MQTT <nonce> | PROBE TCP <nonce> | PROBE UDP <nonce> | PROBE ICMP <nonce>");
  Serial.println("ARM MQTT_FLOOD <nonce> | RUN MQTT_FLOOD");
  Serial.println("nonce=8..32_ASCII_letters_digits_underscore_hyphen; use a fresh nonce for each command");
}

bool validNonce(const String& nonce) {
  if (nonce.length() < 8 || nonce.length() > 32 || nonce == lastNonce) return false;
  for (size_t i = 0; i < nonce.length(); ++i) {
    const char c = nonce[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
  }
  return true;
}

void processCommand(String command);

void readSerial() {
  while (Serial.available()) {
    const char c = Serial.read();
    if (c == '\r') continue;
    if (c != '\n') {
      if (commandLine.length() >= MAX_SERIAL_BYTES) lineOverflow = true;
      if (!lineOverflow) commandLine += c;
      continue;
    }
    String completed = commandLine;
    commandLine = "";
    const bool overflow = lineOverflow;
    lineOverflow = false;
    completed.trim();
    if (overflow) Serial.println("command_rejected reason=serial_line_too_long");
    else if (busy) {
      if (completed == "ABORT") abortRequested = true;
      else if (completed == "STATUS") printStatus();
      else if (completed.length()) Serial.println("command_rejected reason=busy");
    } else if (completed.length()) processCommand(completed);
  }
}

bool healthy() {
  readSerial();
  return !abortRequested && WiFi.status() == WL_CONNECTED &&
         WiFi.localIP() == EXPECTED_LOCAL_IP;
}

void result(const char* protocol, const String& nonce, const char* outcome) {
  if (abortRequested) outcome = "ABORTED";
  else if (WiFi.status() != WL_CONNECTED || WiFi.localIP() != EXPECTED_LOCAL_IP)
    outcome = "LOCAL_LINK_CHANGED";
  Serial.print("probe_result protocol="); Serial.print(protocol);
  Serial.print(" nonce="); Serial.print(nonce);
  Serial.print(" outcome="); Serial.println(outcome);
}

bool authorizeRun(const String& nonce) {
  if (ISOLATION_PROBE_TEST_ENABLED != 1) {
    Serial.println("command_rejected reason=test_not_enabled"); return false;
  }
  if (!validNonce(nonce)) {
    Serial.println("command_rejected reason=invalid_or_repeated_nonce"); return false;
  }
  if (WiFi.status() != WL_CONNECTED || WiFi.localIP() != EXPECTED_LOCAL_IP) {
    Serial.println("command_rejected reason=wifi_or_local_ip_mismatch"); return false;
  }
  if (hasRun && millis() - lastRunAt < MIN_RUN_INTERVAL_MS) {
    Serial.println("command_rejected reason=ten_second_cooldown"); return false;
  }
  lastNonce = nonce;
  hasRun = true;
  lastRunAt = millis();
  abortRequested = false;
  busy = true;
  Serial.print("probe_started nonce="); Serial.print(nonce);
  Serial.print(" local_ip="); Serial.print(WiFi.localIP());
  Serial.print(" target_ip="); Serial.println(PI_IP);
  return true;
}

void connectWifi() {
  if (ISOLATION_PROBE_TEST_ENABLED != 1) {
    Serial.println("command_rejected reason=test_not_enabled"); return;
  }
  abortRequested = false; busy = true;
  WiFi.mode(WIFI_STA);
  WiFi.begin(ISOLATION_PROBE_WIFI_SSID, ISOLATION_PROBE_WIFI_PASSWORD);
  const unsigned long started = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - started < 15000) {
    readSerial();
    if (abortRequested) break;
    delay(20);
  }
  busy = false;
  printStatus();
  if (abortRequested) Serial.println("connect_result=ABORTED");
  else if (WiFi.status() != WL_CONNECTED) Serial.println("connect_result=TIMEOUT");
  else if (WiFi.localIP() != EXPECTED_LOCAL_IP) Serial.println("connect_result=LOCAL_IP_MISMATCH");
  else Serial.println("connect_result=EXPECTED_WIFI_IP");
}

bool connectMqtt() {
  mqttFailure = "NO_ACCEPTED_CONNACK";
  mqttTransport.stop();
  mqttTransport.setConnectionTimeout(CONNECT_TIMEOUT_MS);
  mqttClient.setServer(PI_IP, MQTT_PORT);
  mqttClient.setSocketTimeout(2);
  if (strcmp(MQTT_USERNAME, DEVICE_ID) != 0 || strlen(MQTT_PASSWORD) == 0 ||
      strcmp(MQTT_PASSWORD, "REPLACE_WITH_MQTT_PASSWORD") == 0) {
    mqttFailure = "LOCAL_CONFIGURATION_ERROR";
    Serial.println("mqtt_local_error=missing_or_wrong_device_credentials"); return false;
  }
  if (!mqttClient.setBufferSize(512)) {
    mqttFailure = "LOCAL_ALLOCATION_ERROR";
    Serial.println("mqtt_local_error=buffer_allocation_failed"); return false;
  }
  const bool connack = mqttClient.connect("phase9_isolation_probe_esp32_02", MQTT_USERNAME, MQTT_PASSWORD);
  Serial.print("mqtt_connack_accepted="); Serial.print(connack);
  Serial.print(" client_state="); Serial.println(mqttClient.state());
  if (!connack && mqttClient.state() > 0) mqttFailure = "CONNACK_REJECTED";
  if (connack && mqttTransport.remoteIP() != PI_IP) mqttFailure = "PEER_MISMATCH";
  return connack && mqttTransport.remoteIP() == PI_IP && healthy();
}

String mqttPayload(const String& nonce) {
  ++sequenceNumber;
  return String("{\"device_id\":\"esp32_02\",\"sequence\":") + sequenceNumber +
         ",\"uptime_s\":" + millis() / 1000UL + ",\"probe_nonce\":\"" + nonce + "\"}";
}

void closeMqtt() {
  mqttClient.disconnect();
  mqttTransport.stop();
}

void probeMqtt(const String& nonce) {
  if (!connectMqtt()) {
    result("MQTT", nonce, mqttFailure);
    closeMqtt(); return;
  }
  const String payload = mqttPayload(nonce);
  const bool queued = mqttClient.publish(MQTT_TOPIC, payload.c_str());
  Serial.print("mqtt_publish_queued="); Serial.print(queued);
  Serial.print(" sequence="); Serial.print(sequenceNumber);
  Serial.print(" payload="); Serial.println(payload);
  Serial.println("mqtt_broker_received=UNVERIFIED; compare the nonce in Pi mqtt_logs separately");
  result("MQTT", nonce, queued ? "CONNACK_AND_LOCAL_PUBLISH" : "CONNACK_PUBLISH_FAILED");
  closeMqtt();
}

void probeTcp(const String& nonce) {
  WiFiClient client;
  if (!client.connect(PI_IP, HTTP_PORT, CONNECT_TIMEOUT_MS)) {
    result("TCP", nonce, "CONNECTION_FAILED"); client.stop(); return;
  }
  if (client.remoteIP() != PI_IP || !healthy()) {
    result("TCP", nonce, abortRequested ? "ABORTED" : "PEER_OR_WIFI_MISMATCH");
    client.stop(); return;
  }
  const String request = String("GET /api/health HTTP/1.1\r\nHost: 192.168.0.20\r\n") +
                         "X-Isolation-Probe-Nonce: " + nonce + "\r\nConnection: close\r\n\r\n";
  if (client.write(reinterpret_cast<const uint8_t*>(request.c_str()), request.length()) != request.length()) {
    result("TCP", nonce, "REQUEST_WRITE_FAILED"); client.stop(); return;
  }
  String response;
  const unsigned long started = millis();
  while (millis() - started < RESPONSE_TIMEOUT_MS && healthy()) {
    while (client.available() && response.length() < MAX_HTTP_BYTES) response += static_cast<char>(client.read());
    if (response.length() >= MAX_HTTP_BYTES || (!client.connected() && !client.available())) break;
    delay(2);
  }
  client.stop();
  const int split = response.indexOf("\r\n\r\n");
  const bool http200 = response.startsWith("HTTP/1.1 200 ") || response.startsWith("HTTP/1.0 200 ");
  String header = split >= 0 ? response.substring(0, split + 2) : "";
  header.toLowerCase();
  const String body = split >= 0 ? response.substring(split + 4) : "";
  const String lengthPrefix = "\r\ncontent-length:";
  const int lengthAt = header.indexOf(lengthPrefix);
  unsigned int expectedLength = 0;
  bool validLength = lengthAt >= 0 && header.indexOf(lengthPrefix, lengthAt + 1) < 0;
  if (validLength) {
    const int valueAt = lengthAt + lengthPrefix.length();
    String length = header.substring(valueAt, header.indexOf("\r\n", valueAt));
    length.trim();
    validLength = length.length() > 0 && length.length() <= 4;
    for (size_t i = 0; validLength && i < length.length(); ++i) {
      validLength = length[i] >= '0' && length[i] <= '9';
      if (validLength) expectedLength = expectedLength * 10 + length[i] - '0';
    }
    validLength = validLength && expectedLength > 0 && expectedLength < MAX_HTTP_BYTES;
  }
  const bool jsonType = header.indexOf("\r\ncontent-type: application/json\r\n") >= 0 ||
                        header.indexOf("\r\ncontent-type: application/json;") >= 0;
  const bool complete = validLength && body.length() == expectedLength &&
                        header.indexOf("\r\ntransfer-encoding:") < 0;
  bool healthOk = false, healthDegraded = false;
  if (complete && jsonType) {
    const char* parseEnd = nullptr;
    cJSON* json = cJSON_ParseWithLengthOpts(body.c_str(), body.length() + 1, &parseEnd, true);
    if (json && parseEnd == body.c_str() + body.length() && cJSON_IsObject(json)) {
      const cJSON* status = cJSON_GetObjectItemCaseSensitive(json, "status");
      const cJSON* database = cJSON_GetObjectItemCaseSensitive(json, "database");
      const cJSON* connected = cJSON_GetObjectItemCaseSensitive(json, "db_connected");
      const cJSON* time = cJSON_GetObjectItemCaseSensitive(json, "server_time");
      if (cJSON_IsString(status) && cJSON_IsString(database) && cJSON_IsBool(connected) &&
          cJSON_IsString(time) && time->valuestring[0]) {
        healthOk = strcmp(status->valuestring, "ok") == 0 &&
                   strcmp(database->valuestring, "ok") == 0 && cJSON_IsTrue(connected);
        healthDegraded = strcmp(status->valuestring, "degraded") == 0 &&
                         strcmp(database->valuestring, "error") == 0 && !cJSON_IsTrue(connected);
      }
    }
    cJSON_Delete(json);
  }
  Serial.print("tcp_peer_ip="); Serial.print(PI_IP);
  Serial.print(" http200="); Serial.print(http200);
  Serial.print(" health_ok="); Serial.print(healthOk);
  Serial.print(" health_degraded="); Serial.print(healthDegraded);
  Serial.print(" response_bytes="); Serial.println(response.length());
  // A degraded health body is still a real TCP/HTTP response, not DB health proof.
  result("TCP", nonce, abortRequested ? "ABORTED" :
         (http200 && complete && jsonType && (healthOk || healthDegraded) && response.length() < MAX_HTTP_BYTES ?
          "HTTP_RESPONSE" : (response.length() ? "INCOMPLETE_OR_INVALID_HTTP_RESPONSE" : "RESPONSE_TIMEOUT")));
}

void probeUdp(const String& nonce) {
  WiFiUDP udp;
  if (udp.begin(LOCAL_UDP_PORT) != 1) { result("UDP", nonce, "LOCAL_SOCKET_ERROR"); return; }
  const String request = "P9UDP:" + nonce;
  const String expected = "P9UDP-ACK:" + nonce;
  if (udp.beginPacket(PI_IP, UDP_PORT) != 1 || udp.write(reinterpret_cast<const uint8_t*>(request.c_str()), request.length()) != request.length() ||
      udp.endPacket() != 1) {
    result("UDP", nonce, "LOCAL_SEND_ERROR"); udp.stop(); return;
  }
  const unsigned long started = millis();
  unsigned int received = 0;
  const char* outcome = "RESPONSE_TIMEOUT";
  while (millis() - started < RESPONSE_TIMEOUT_MS && healthy() && received < 4) {
    const int size = udp.parsePacket();
    if (size > 0) {
      ++received;
      const IPAddress peer = udp.remoteIP();
      const uint16_t peerPort = udp.remotePort();
      char bytes[MAX_UDP_BYTES + 1];
      const int read = udp.read(reinterpret_cast<uint8_t*>(bytes), MAX_UDP_BYTES);
      if (read >= 0) bytes[read] = '\0';
      if (peer == PI_IP && peerPort == UDP_PORT) {
        outcome = size == static_cast<int>(expected.length()) && read == size &&
                  String(bytes) == expected ? "NONCE_RESPONSE" : "INVALID_NONCE_RESPONSE";
        Serial.print("udp_peer_ip="); Serial.print(peer);
        Serial.print(" peer_port="); Serial.print(peerPort);
        Serial.print(" response_bytes="); Serial.println(size);
        break;
      }
    }
    delay(2);
  }
  udp.stop();
  result("UDP", nonce, abortRequested ? "ABORTED" : outcome);
}

void probeIcmp(const String& nonce) {
  // The IDF ping-session delete API is asynchronous. Own one raw lwIP socket
  // directly so timeout, abort and cleanup have one finite lifetime.
  const int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (fd < 0) { result("ICMP", nonce, "LOCAL_SOCKET_ERROR"); return; }
  auto finish = [&](const char* outcome) {
    const int closed = close(fd);
    Serial.print("icmp_close_rc="); Serial.println(closed);
    result("ICMP", nonce, closed == 0 ? outcome : "LOCAL_CLEANUP_ERROR");
  };
  if (fd >= FD_SETSIZE) { finish("LOCAL_DESCRIPTOR_RANGE_ERROR"); return; }
  const int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    finish("LOCAL_NONBLOCK_ERROR"); return;
  }
  sockaddr_in local = {};
  local.sin_family = AF_INET;
  local.sin_addr.s_addr = static_cast<uint32_t>(EXPECTED_LOCAL_IP);
  if (bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
    finish("LOCAL_BIND_ERROR"); return;
  }
  sockaddr_in target = {};
  target.sin_family = AF_INET;
  target.sin_addr.s_addr = static_cast<uint32_t>(PI_IP);
  const String marker = "P9ICMP:" + nonce;
  uint8_t request[8 + 7 + 32] = {};
  const uint16_t id = static_cast<uint16_t>(esp_random());
  const uint16_t seq = static_cast<uint16_t>(esp_random());
  request[0] = 8;
  request[4] = id >> 8; request[5] = id & 0xff;
  request[6] = seq >> 8; request[7] = seq & 0xff;
  memcpy(request + 8, marker.c_str(), marker.length());
  const size_t size = 8 + marker.length();
  const uint16_t checksum = isolation_probe::internetChecksum(request, size);
  request[2] = checksum >> 8; request[3] = checksum & 0xff;
  const unsigned long started = millis();
  if (sendto(fd, request, size, 0, reinterpret_cast<sockaddr*>(&target), sizeof(target)) != static_cast<int>(size)) {
    finish("LOCAL_SEND_ERROR"); return;
  }
  const char* outcome = "RESPONSE_TIMEOUT";
  unsigned int unmatched = 0;
  while (millis() - started < 1000 && healthy()) {
    const unsigned long elapsed = millis() - started;
    if (elapsed >= 1000) break;
    const unsigned long remaining = 1000 - elapsed;
    timeval wait = {0, static_cast<suseconds_t>((remaining < 50 ? remaining : 50) * 1000)};
    fd_set readable;
    FD_ZERO(&readable); FD_SET(fd, &readable);
    const int ready = select(fd + 1, &readable, nullptr, nullptr, &wait);
    if (ready < 0) {
      if (errno == EINTR) continue;
      outcome = "LOCAL_SELECT_ERROR"; break;
    }
    if (!ready) continue;
    uint8_t response[512];
    sockaddr_in peer = {};
    socklen_t peerSize = sizeof(peer);
    const int bytes = recvfrom(fd, response, sizeof(response), MSG_DONTWAIT,
                               reinterpret_cast<sockaddr*>(&peer), &peerSize);
    if (bytes < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
      outcome = "LOCAL_RECEIVE_ERROR"; break;
    }
    if (millis() - started >= 1000) break;
    if (isolation_probe::validIcmpReply(response, static_cast<size_t>(bytes), request, size,
          peer.sin_family == AF_INET && peer.sin_addr.s_addr == target.sin_addr.s_addr)) {
      outcome = "ECHO_REPLY";
      Serial.print("icmp_peer_ip="); Serial.print(PI_IP);
      Serial.print(" id="); Serial.print(id);
      Serial.print(" seq="); Serial.print(seq);
      Serial.print(" rtt_ms="); Serial.println(millis() - started);
      break;
    }
    if (++unmatched >= 32) { outcome = "UNMATCHED_PACKET_LIMIT"; break; }
  }
  finish(outcome);
}

void runFlood() {
  const String nonce = armedNonce;
  const bool allowed = floodArmed && millis() - armedAt <= ARM_LIFETIME_MS;
  // Consume the arm before any network action. Retrying RUN cannot repeat a burst.
  floodArmed = false; armedNonce = "";
  if (!allowed || ISOLATION_PROBE_FLOOD_ENABLED != 1) {
    Serial.println("flood_rejected reason=not_armed_expired_or_disabled"); return;
  }
  if (!authorizeRun(nonce)) return;
  unsigned int attempted = 0, queued = 0;
  if (connectMqtt()) {
    for (unsigned int i = 0; i < FLOOD_COUNT && healthy() && mqttClient.connected(); ++i) {
      ++attempted;
      const String payload = mqttPayload(nonce);
      if (mqttClient.publish(MQTT_TOPIC, payload.c_str())) ++queued;
      mqttClient.loop();
      if (i + 1 < FLOOD_COUNT) delay(FLOOD_INTERVAL_MS);
    }
  }
  closeMqtt();
  Serial.print("flood_result nonce="); Serial.print(nonce);
  Serial.print(" attempted="); Serial.print(attempted);
  Serial.print(" publish_queued="); Serial.print(queued);
  Serial.print(" aborted="); Serial.print(abortRequested);
  Serial.println(" broker_received=UNVERIFIED detection_and_trust=UNVERIFIED arm_consumed=true");
  busy = false;
}

void processCommand(String command) {
  if (command == "HELP") { help(); return; }
  if (command == "STATUS") { printStatus(); return; }
  if (command == "CONNECT") { connectWifi(); return; }
  if (command == "ABORT") { floodArmed = false; armedNonce = ""; return; }
  if (command == "RUN MQTT_FLOOD") { runFlood(); return; }
  if (command.startsWith("ARM MQTT_FLOOD ")) {
    const String nonce = command.substring(15);
    if (ISOLATION_PROBE_TEST_ENABLED != 1 || ISOLATION_PROBE_FLOOD_ENABLED != 1 || !validNonce(nonce)) {
      Serial.println("flood_rejected reason=disabled_or_invalid_nonce"); return;
    }
    armedNonce = nonce; armedAt = millis(); floodArmed = true;
    Serial.println("flood_armed expires_ms=15000 max_messages=40 interval_ms=50 requires_RUN"); return;
  }
  if (!command.startsWith("PROBE ")) { Serial.println("command_rejected reason=unknown_command"); return; }
  const int split = command.indexOf(' ', 6);
  if (split < 0) { Serial.println("command_rejected reason=missing_nonce"); return; }
  const String protocol = command.substring(6, split);
  const String nonce = command.substring(split + 1);
  if (protocol != "MQTT" && protocol != "TCP" && protocol != "UDP" && protocol != "ICMP") {
    Serial.println("command_rejected reason=unknown_protocol"); return;
  }
  if (!authorizeRun(nonce)) return;
  if (protocol == "MQTT") probeMqtt(nonce);
  else if (protocol == "TCP") probeTcp(nonce);
  else if (protocol == "UDP") probeUdp(nonce);
  else probeIcmp(nonce);
  busy = false;
}

void setup() {
  Serial.begin(115200);
  delay(500);
  printStatus(); help();
}

void loop() {
  readSerial();
  delay(2);
}
