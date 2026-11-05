#include <iostream>
#include <string>
#include "cli_options.hpp"
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
// Opens a capture source (live interface or pcap file) based on the provided options.
static pcap_t* open_capture(const CliOptions& options, char* errbuf) {
    if (!options.pcap_path.empty()) return pcap_open_offline(options.pcap_path.c_str(), errbuf);
    return pcap_open_live(options.iface.c_str(), 65535, 1, 1000, errbuf);
}

static bool is_ethernet(pcap_t* handle) {
    return pcap_datalink(handle) == DLT_EN10MB;
}
// Applies a BPF filter to capture only TCP packets on the specified port.
static bool apply_port_filter(pcap_t* handle, int port) {
    bpf_program program;
    if (pcap_compile(handle, &program, ("tcp port " + std::to_string(port)).c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) return false;
    const bool applied = pcap_setfilter(handle, &program) == 0;
    pcap_freecode(&program);
    return applied;
}
// Prepares the capture handle by checking the link type and applying the port filter.
static bool prepare_capture(pcap_t* handle, int port) {
    if (!is_ethernet(handle)) return false;
    return apply_port_filter(handle, port);
}
// Runs the packet capture loop, invoking the packetHandler for each captured packet.
static int run_capture(const CliOptions& options) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = open_capture(options, errbuf);
    if (handle == nullptr) { std::cerr << errbuf << std::endl; return 1; }
    const bool ready = prepare_capture(handle, options.port);
    if (ready) pcap_loop(handle, 0, packetHandler, nullptr);
    else std::cerr << "Unsupported link type or invalid filter" << std::endl;
    pcap_close(handle);
    return ready ? 0 : 1;
}

int main(int argc, char* argv[]) {
    const auto options = parse_cli_options(argc, argv);
    if (options) return run_capture(*options);
    std::cerr << "Usage: modbus-guardian (--iface <name> | --pcap <file>) [--port <1-65535>]" << std::endl;
    return 2;
}