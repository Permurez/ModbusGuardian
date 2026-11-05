#include "packet_parser.hpp"
#include "byte_order.h"

constexpr size_t ETHERNET_HEADER_LEN = 14;

static bool is_too_short_for_ethernet(size_t caplen) {
    return caplen < ETHERNET_HEADER_LEN;
}

constexpr size_t ETHERTYPE_OFFSET = 12;
constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;

static bool is_not_ipv4(const uint8_t* data) {
    return read_u16_be(data + ETHERTYPE_OFFSET) != ETHERTYPE_IPV4;
}

constexpr size_t SRC_MAC_OFFSET = 6;
//Checks if the packet is an Ethernet frame with an IPv4 payload and stores the source MAC address in out.src_mac.
static bool parse_ethernet(const uint8_t* data, size_t caplen, PacketInfo& out) {
    if (is_too_short_for_ethernet(caplen)) return false;
    if (is_not_ipv4(data)) return false;
    out.src_mac = data + SRC_MAC_OFFSET;
    return true;
}

static uint8_t ipv4_version(const uint8_t* ip) {
    return ip[0] >> 4;
}

static size_t ipv4_header_len(const uint8_t* ip) {
    return (ip[0] & 0x0F) * 4;
}

constexpr uint8_t IP_VERSION_4 = 4;
constexpr size_t MIN_IPV4_HEADER_LEN = 20;
constexpr size_t IP_TOTAL_LEN_OFFSET = 2;
// Returns true if the IPv4 header is malformed or does not fit in the captured bytes.
// available is the number of captured bytes from the start of this header to the end of the packet.
static bool has_invalid_ipv4_header(const uint8_t* ip, size_t available) {
    if (ipv4_version(ip) != IP_VERSION_4) return true;
    const size_t header_len = ipv4_header_len(ip);
    if (header_len < MIN_IPV4_HEADER_LEN || header_len > available) return true;
    return read_u16_be(ip + IP_TOTAL_LEN_OFFSET) < header_len;
}

constexpr size_t IP_PROTOCOL_OFFSET = 9;
constexpr uint8_t IP_PROTOCOL_TCP = 6;
// Returns true if the IP protocol field is not TCP (6).
static bool is_not_tcp(const uint8_t* ip) {
    return ip[IP_PROTOCOL_OFFSET] != IP_PROTOCOL_TCP;
}


constexpr size_t IP_FRAGMENT_OFFSET = 6;
constexpr uint16_t IP_FRAGMENT_MASK = 0x1FFF;
// Returns true if this is a later fragment of a split packet.
static bool is_later_fragment(const uint8_t* ip) {
   return (read_u16_be(ip + IP_FRAGMENT_OFFSET) & IP_FRAGMENT_MASK) != 0;
}



constexpr size_t IP_SRC_OFFSET = 12;
constexpr size_t IP_DST_OFFSET = 16;

static bool parse_ipv4(const uint8_t* ip, size_t available, PacketInfo& out) {
    if (available < MIN_IPV4_HEADER_LEN) return false;
    if (has_invalid_ipv4_header(ip, available)) return false;
    if (is_not_tcp(ip) || is_later_fragment(ip)) return false;
    out.src_ip = read_u32_be(ip + IP_SRC_OFFSET);
    out.dst_ip = read_u32_be(ip + IP_DST_OFFSET);
    return true;
}

constexpr size_t MIN_TCP_HEADER_LEN = 20;
constexpr size_t TCP_DATA_OFFSET_BYTE =12;
static size_t tcp_header_len(const uint8_t* tcp) {
    return (tcp[TCP_DATA_OFFSET_BYTE] >> 4) * 4;
}
// Returns true if the TCP header is malformed or does not fit in the available bytes.
static bool has_invalid_tcp_header(const uint8_t* tcp, size_t available, size_t segment_len) {
    if (available < MIN_TCP_HEADER_LEN) return true;
    const size_t header_len = tcp_header_len(tcp);
    return header_len < MIN_TCP_HEADER_LEN || header_len > available || header_len > segment_len;
}

// Returns true if the segment carries no data or was cut off during capture.
static bool has_no_complete_payload(const uint8_t* tcp, size_t available, size_t segment_len) {
    return segment_len == tcp_header_len(tcp) || segment_len > available;
}

constexpr size_t TCP_SRC_PORT_OFFSET = 0;
constexpr size_t TCP_DST_PORT_OFFSET = 2;
// Stores the source and destination ports, as well as the payload pointer and length, in the PacketInfo structure.
static void store_tcp_fields(const uint8_t* tcp, size_t segment_len, PacketInfo& out) {
    out.src_port = read_u16_be(tcp + TCP_SRC_PORT_OFFSET);
    out.dst_port = read_u16_be(tcp + TCP_DST_PORT_OFFSET);
    out.payload = tcp + tcp_header_len(tcp);
    out.payload_len = segment_len - tcp_header_len(tcp);
}
static bool parse_tcp_segment(const uint8_t* tcp, size_t available, size_t segment_len, PacketInfo& out) {
    if (has_invalid_tcp_header(tcp, available, segment_len)) return false;
    if (has_no_complete_payload(tcp, available, segment_len)) return false;
    store_tcp_fields(tcp, segment_len, out);
    return true;
}
static bool parse_tcp(const uint8_t* ip, size_t available, PacketInfo& out) {
    const size_t ip_header_len = ipv4_header_len(ip);
    const size_t segment_len = read_u16_be(ip + IP_TOTAL_LEN_OFFSET) - ip_header_len;
    return parse_tcp_segment(ip + ip_header_len, available - ip_header_len, segment_len, out);
}

bool parse_packet(const uint8_t* data, size_t caplen, PacketInfo& out) {
    return parse_ethernet(data, caplen, out)
        && parse_ipv4(data + ETHERNET_HEADER_LEN, caplen - ETHERNET_HEADER_LEN, out)
        && parse_tcp(data + ETHERNET_HEADER_LEN, caplen - ETHERNET_HEADER_LEN, out);
}