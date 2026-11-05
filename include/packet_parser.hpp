#pragma once
#include <cstddef>
#include <cstdint>

// Result of parsing one captured packet.
// Pointers refer to libpcap's buffer and are valid only during the packet callback.
struct PacketInfo {
    const uint8_t* src_mac;  // 6 bytes
    uint32_t src_ip;         // host byte order
    uint32_t dst_ip;         // host byte order
    uint16_t src_port;
    uint16_t dst_port;
    const uint8_t* payload;  // TCP payload
    size_t payload_len;
};

// Parses a captured packet and fills the provided PacketInfo structure.
// Returns true if the packet was successfully parsed, false otherwise.
bool parse_packet(const uint8_t* data, size_t caplen, PacketInfo& out);