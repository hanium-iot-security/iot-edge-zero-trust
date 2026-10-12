#pragma once
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace isolation_probe {

inline uint16_t internetChecksum(const uint8_t* data, size_t length) {
  uint32_t sum = 0;
  for (size_t i = 0; i < length; i += 2)
    sum += (static_cast<uint16_t>(data[i]) << 8) | (i + 1 < length ? data[i + 1] : 0);
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return static_cast<uint16_t>(~sum);
}

// IPv4 raw sockets include the IPv4 header. The caller also checks sockaddr
// source against the fixed Pi and passes that result here.
inline bool validIcmpReply(const uint8_t* response, size_t bytes,
                           const uint8_t* request, size_t requestSize,
                           bool sourceMatches) {
  if (!response || !request || !sourceMatches || bytes < 20 || requestSize < 8) return false;
  const size_t ihl = (response[0] & 0x0f) * 4;
  const size_t total = (static_cast<size_t>(response[2]) << 8) | response[3];
  return (response[0] >> 4) == 4 && ihl >= 20 && ihl <= 60 &&
         response[9] == 1 && (response[6] & 0x3f) == 0 && response[7] == 0 &&
         total == bytes && total == ihl + requestSize &&
         response[ihl] == 0 && response[ihl + 1] == 0 &&
         memcmp(response + ihl + 4, request + 4, requestSize - 4) == 0 &&
         internetChecksum(response + ihl, requestSize) == 0;
}

}  // namespace isolation_probe
