#include <iostream>
#include <pcap.h>
#include "mbframe.h"
#include "packet_parser.hpp"

// Combines two consecutive bytes into one big-endian 16-bit value.
static uint16_t read_be16(const uint8_t* bytes) {
    return static_cast<uint16_t>((bytes[0] << 8) | bytes[1]);
}

// Prints the MBAP header fields of a Modbus TCP frame.
static void print_mbap_header(const uint8_t* mbap) {
    std::cout << "Transaction ID: " << read_be16(mbap)
              << " | Protocol ID: " << read_be16(mbap + 2)
              << " | Length: " << read_be16(mbap + 4)
              << " | Unit ID: " << static_cast<int>(mbap[6]) << std::endl;
}

void packetHandler(u_char*, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketInfo info;
    if (!parse_packet(packet, pkthdr->caplen, info)) return;
    if (info.payload_len < MBAP_HEADER_LEN) return;
    print_mbap_header(info.payload);
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline("docs/modbus-baseline.pcapng", errbuf);
    if (handle == nullptr) {
        std::cerr << "Cannot open capture: " << errbuf << std::endl;
        return 1;
    }

    pcap_loop(handle, 0, packetHandler, nullptr);
    pcap_close(handle);
    return 0;
}