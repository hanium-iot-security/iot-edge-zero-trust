#pragma once

// Copy this file to packet_rate_firmware_config.h, review every value,
// then change PACKET_RATE_CONFIGURED to 1. Never commit the real password.
#define PACKET_RATE_CONFIGURED 0

// This firmware is intentionally restricted to the registered attack device.
#define PACKET_RATE_DEVICE_SLOT 2

#define PACKET_RATE_WIFI_SSID "REPLACE_WITH_WIFI_SSID"
#define PACKET_RATE_WIFI_PASSWORD "REPLACE_WITH_WIFI_PASSWORD"

// Phase 5 lab addressing contract.
#define PACKET_RATE_EXPECTED_LOCAL_IP "192.168.0.5"
#define PACKET_RATE_TARGET_IP "192.168.0.20"
#define PACKET_RATE_TARGET_PORT 19999

// Stable local UDP source port for easier packet inspection.
#define PACKET_RATE_LOCAL_UDP_PORT 42100
