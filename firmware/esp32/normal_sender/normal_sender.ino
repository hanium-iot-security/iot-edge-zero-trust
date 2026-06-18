#include <WiFi.h>
#include <PubSubClient.h>

const char* WIFI_SSID = "YOUR_WIFI_SSID";
const char* WIFI_PASSWORD = "YOUR_WIFI_PASSWORD";

const char* MQTT_BROKER = "192.168.0.20";
const int MQTT_PORT = 1883;
const char* DEVICE_ID = "esp32_01";
const char* MQTT_TOPIC = "iot/esp32_01/sensor";

const int NORMAL_MODE = 1;

const unsigned long FIXED_INTERVAL_MS = 5000;
const unsigned long MIN_INTERVAL_MS = 4000;
const unsigned long MAX_INTERVAL_MS = 6000;
const unsigned int MAX_NORMAL_PAYLOAD_BYTES = 100;

WiFiClient wifiClient;
PubSubClient mqttClient(wifiClient);

unsigned long lastPublishTime = 0;
unsigned long nextPublishIntervalMs = FIXED_INTERVAL_MS;
unsigned long sequenceNumber = 0;

String buildMinimalPayload() {
  return String("{\"device_id\":\"") + DEVICE_ID + "\"}";
}

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) {
    return;
  }

  Serial.print("Connecting to WiFi: ");
  Serial.println(WIFI_SSID);

  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(1000);
  }

  Serial.println();
  Serial.println("WiFi connected");
  Serial.print("ESP32 IP address: ");
  Serial.println(WiFi.localIP());
}

void connectMQTT() {
  if (mqttClient.connected()) {
    return;
  }

  while (!mqttClient.connected()) {
    Serial.print("Attempting MQTT connection...");
    String clientId = String("normal_sender_") + DEVICE_ID;

    if (mqttClient.connect(clientId.c_str())) {
      Serial.println(" connected");
    } else {
      Serial.print(" failed, rc=");
      Serial.print(mqttClient.state());
      Serial.println(" retrying in 2 seconds");
      delay(2000);
    }
  }
}

void updateNextPublishInterval() {
  if (NORMAL_MODE == 0) {
    nextPublishIntervalMs = FIXED_INTERVAL_MS;
    return;
  }

  nextPublishIntervalMs = random(MIN_INTERVAL_MS, MAX_INTERVAL_MS + 1);
}

String buildNormalPayload() {
  if (NORMAL_MODE != 2) {
    return buildMinimalPayload();
  }

  sequenceNumber++;

  long rssi = WiFi.RSSI();
  int tempTenths = random(230, 280);
  int humTenths = random(400, 600);
  int bat = random(90, 101);
  String temp = String(tempTenths / 10.0, 1);
  String hum = String(humTenths / 10.0, 1);

  int selector = random(0, 100);

  if (selector < 20) {
    return String("{\"device_id\":\"") + DEVICE_ID +
           "\",\"seq\":" + sequenceNumber +
           ",\"rssi\":" + rssi + "}";
  }

  if (selector < 70) {
    return String("{\"device_id\":\"") + DEVICE_ID +
           "\",\"seq\":" + sequenceNumber +
           ",\"rssi\":" + rssi +
           ",\"temp\":" + temp +
           ",\"hum\":" + hum + "}";
  }

  return String("{\"device_id\":\"") + DEVICE_ID +
         "\",\"seq\":" + sequenceNumber +
         ",\"rssi\":" + rssi +
         ",\"temp\":" + temp +
         ",\"hum\":" + hum +
         ",\"bat\":" + bat +
         ",\"st\":\"ok\"}";
}

void publishNormalMessage() {
  String payload = buildNormalPayload();

  if (payload.length() > MAX_NORMAL_PAYLOAD_BYTES) {
    Serial.println("[WARN] Payload size exceeded 100 bytes. Fallback to minimal payload.");
    payload = buildMinimalPayload();
  }

  bool published = mqttClient.publish(MQTT_TOPIC, payload.c_str());

  if (published) {
    Serial.print("Published: ");
  } else {
    Serial.print("[ERROR] Publish failed: ");
  }

  Serial.print(payload);
  Serial.print(" | topic=");
  Serial.print(MQTT_TOPIC);
  Serial.print(" | payload_size=");
  Serial.print(payload.length());
  Serial.print(" bytes | interval_ms=");
  Serial.println(nextPublishIntervalMs);
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  randomSeed(analogRead(0));

  mqttClient.setServer(MQTT_BROKER, MQTT_PORT);
  mqttClient.setBufferSize(256);

  connectWiFi();
  connectMQTT();
  updateNextPublishInterval();
  lastPublishTime = millis();
}

void loop() {
  if (WiFi.status() != WL_CONNECTED) {
    connectWiFi();
  }

  if (!mqttClient.connected()) {
    connectMQTT();
  }

  mqttClient.loop();

  unsigned long currentTime = millis();
  if (currentTime - lastPublishTime >= nextPublishIntervalMs) {
    publishNormalMessage();
    lastPublishTime = currentTime;
    updateNextPublishInterval();
  }
}
