#include "packet_parser.hpp"

constexpr size_t ETHERNET_HEADER_LEN = 14;
constexpr size_t SRC_MAC_OFFSET = 6;
constexpr size_t ETHERTYPE_OFFSET = 12;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
//Combine two consecutive bytes into one big-endian 16-bit value
static uint16_t read_u16_be(const uint8_t* bytes) {
    return static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
}
    
static bool is_too_short_for_ethernet(size_t caplen) {
    return caplen < ETHERNET_HEADER_LEN;
}

static bool is_not_ipv4(const uint8_t* data) {
    return read_u16_be(data + ETHERTYPE_OFFSET) != ETHERTYPE_IPV4;
}

static bool parse_ethernet(const uint8_t* data, size_t caplen, PacketInfo& out) {
    if (is_too_short_for_ethernet(caplen)) return false;
    if (is_not_ipv4(data)) return false;
    out.src_mac = data + SRC_MAC_OFFSET;
    return true;
}

bool parse_packet(const uint8_t* data, size_t caplen, PacketInfo& out) {
    return parse_ethernet(data, caplen, out);
}