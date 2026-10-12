#include "isolation_probe_protocol.h"
#include <cstdlib>
#include <iostream>
#include <vector>

static int cases = 0;
static void check(bool condition) {
  if (!condition) std::abort();
  ++cases;
}

static void checksum(std::vector<uint8_t>& packet) {
  const size_t ihl = (packet[0] & 15) * 4;
  packet[ihl + 2] = packet[ihl + 3] = 0;
  const uint16_t value = isolation_probe::internetChecksum(packet.data() + ihl, packet.size() - ihl);
  packet[ihl + 2] = value >> 8;
  packet[ihl + 3] = value & 255;
}

static std::vector<uint8_t> reply(const std::vector<uint8_t>& request, size_t ihl = 20) {
  std::vector<uint8_t> packet(ihl + request.size(), 0);
  packet[0] = 0x40 | (ihl / 4);
  packet[2] = packet.size() >> 8;
  packet[3] = packet.size() & 255;
  packet[8] = 64;
  packet[9] = 1;
  packet[12] = 192; packet[13] = 168; packet[15] = 20;
  for (size_t i = 0; i < request.size(); ++i) packet[ihl + i] = request[i];
  packet[ihl] = 0;
  checksum(packet);
  return packet;
}

int main() {
  const uint8_t even[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};
  const uint8_t odd[] = {1, 2, 3};
  check(isolation_probe::internetChecksum(even, sizeof(even)) == 0x220d);
  check(isolation_probe::internetChecksum(odd, sizeof(odd)) == 0xfbfd);
  std::vector<uint8_t> request = {8, 0, 0, 0, 0xab, 0xcd, 0x12, 0x34,
                                 'n', 'o', 'n', 'c', 'e', '_', '0', '0', '1'};
  const std::vector<uint8_t> base = reply(request);
  auto valid = [&](const std::vector<uint8_t>& packet, bool source = true) {
    return isolation_probe::validIcmpReply(packet.data(), packet.size(), request.data(), request.size(), source);
  };
  check(valid(base));
  check(valid(reply(request, 24)));  // IPv4 options move the ICMP header.
  check(!valid(base, false));
  std::vector<uint8_t> packet = base;
  packet[20] = 8; checksum(packet); check(!valid(packet));
  packet = base; packet[21] = 1; checksum(packet); check(!valid(packet));
  packet = base; packet[24] ^= 1; checksum(packet); check(!valid(packet));
  packet = base; packet[26] ^= 1; checksum(packet); check(!valid(packet));
  packet = base; packet[28] ^= 1; checksum(packet); check(!valid(packet));
  packet = base; packet[22] ^= 1; check(!valid(packet));
  packet = base; --packet[3]; check(!valid(packet));
  packet = base; packet.pop_back(); check(!valid(packet));
  packet = base; packet.push_back('x'); ++packet[3]; checksum(packet); check(!valid(packet));
  packet = base; packet[6] = 0x20; check(!valid(packet));
  packet = base; packet[7] = 1; check(!valid(packet));
  packet = base; packet[0] = 0x65; check(!valid(packet));
  packet = base; packet[9] = 17; check(!valid(packet));
  packet = base; packet[0] = 0x4f; check(!valid(packet));
  packet = base; packet.resize(19); check(!valid(packet));
  check(!isolation_probe::validIcmpReply(base.data(), base.size(), request.data(), 7, true));
  check(!isolation_probe::validIcmpReply(base.data(), base.size(), nullptr, request.size(), true));
  check(!isolation_probe::validIcmpReply(nullptr, base.size(), request.data(), request.size(), true));
  std::cout << "ICMP_PROTOCOL_CASES=" << cases << '\n';
  return 0;
}
