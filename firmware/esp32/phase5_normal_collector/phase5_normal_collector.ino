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
