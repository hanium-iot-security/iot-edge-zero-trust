#include <WiFi.h>
#include <PubSubClient.h>

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

const unsigned long FIXED_PUBLISH_INTERVAL_MS = 5000UL;

unsigned long sequenceNumber = 0;

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
