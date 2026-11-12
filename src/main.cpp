#include <iostream>
#include <string>
#include "cli_options.hpp"
#include <pcap.h>
#include "mbframe.h"
#include "byte_order.h"
#include "packet_parser.hpp"
 
 
static const char* function_name(uint8_t code) {
    switch (code & 0x7F) {
        case MB_FC_READ_COILS: return "Read Coils";
        case MB_FC_READ_DISCRETE_INPUTS: return "Read Discrete Inputs";
        case MB_FC_READ_HOLDING_REGS: return "Read Holding Registers";
        case MB_FC_READ_INPUT_REGS: return "Read Input Registers";
        case MB_FC_WRITE_SINGLE_COIL: return "Write Single Coil";
        case MB_FC_WRITE_SINGLE_REG: return "Write Single Register";
        case MB_FC_WRITE_MULTIPLE_COILS: return "Write Multiple Coils";
        case MB_FC_WRITE_MULTIPLE_REGS: return "Write Multiple Registers";
        default: return "Unknown";
    }
}
 
// A request travels from the client to the server port.
static bool is_request(const PacketInfo& info, int server_port) {
    return info.dst_port == server_port;
}
 
// The function code says how the data bytes are laid out. Only these requests put a 2-byte start address first, followed by a 2-byte quantity or value. Error responses (code + 0x80) are not on the list, so they are rejected too.
static bool request_starts_with_address(uint8_t code) {
    switch (code) {
        case MB_FC_READ_COILS:
        case MB_FC_READ_DISCRETE_INPUTS:
        case MB_FC_READ_HOLDING_REGS:
        case MB_FC_READ_INPUT_REGS:
        case MB_FC_WRITE_SINGLE_COIL:
        case MB_FC_WRITE_SINGLE_REG:
        case MB_FC_WRITE_MULTIPLE_COILS:
        case MB_FC_WRITE_MULTIPLE_REGS:
            return true;
        default:
            return false;
    }
}
 
// Checks that the address and quantity can be read safely:
// the frame type has them, and the frame is long enough to hold them.
static bool has_request_fields(const MbFrame& frame) {
    return request_starts_with_address(frame.function_code) && frame.data_len >= 4;
}
 
// Prints the start address (bytes 0-1) and the quantity or written value (bytes 2-3).
static void print_request_fields(const MbFrame& frame) {
    std::cout << " | Address: " << read_u16_be(frame.data)
              << " | Quantity/Value: " << read_u16_be(frame.data + 2);
}
 
// Responses reuse the request's function code, but their data bytes mean
// something else, so the address is printed only for requests.
static void print_frame(const MbFrame& frame, bool is_request_frame) {
    std::cout << "Transaction ID: " << frame.transaction_id
              << " | Unit ID: " << static_cast<int>(frame.unit_id)
              << " | Function: " << static_cast<int>(frame.function_code)
              << " (" << function_name(frame.function_code) << ")"
              << " | Data bytes: " << frame.data_len;
    if (is_request_frame && has_request_fields(frame)) print_request_fields(frame);
    std::cout << std::endl;
}
 
// A single TCP segment can carry several Modbus frames.
static void print_frames(const uint8_t* payload, size_t payload_len, bool is_request_frame) {
    size_t offset = 0;
    while (offset < payload_len) {
        MbFrame frame;
        const int size = mb_parse_frame(payload + offset, payload_len - offset, &frame);
        if (size <= 0) return;
        print_frame(frame, is_request_frame);
        offset += static_cast<size_t>(size);
    }
}
 
void packetHandler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketInfo info;
    if (!parse_packet(packet, pkthdr->caplen, info)) return;
    // user_data points to the server port (int) passed to pcap_loop in capture_packets.
    const int server_port = *reinterpret_cast<const int*>(user_data);
    print_frames(info.payload, info.payload_len, is_request(info, server_port));
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
// Runs the capture loop; returns false and prints the reason on failure.
static bool capture_packets(pcap_t* handle, int port) {
    if (!prepare_capture(handle, port)) {
        std::cerr << "Unsupported link type or invalid filter" << std::endl;
        return false;
    }
    // Pass the server port to packetHandler as user_data.
    if (pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(&port)) != PCAP_ERROR) return true;
    std::cerr << "Capture failed: " << pcap_geterr(handle) << std::endl;
    return false;
}
 
static int run_capture(const CliOptions& options) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = open_capture(options, errbuf);
    if (handle == nullptr) { std::cerr << errbuf << std::endl; return 1; }
    const bool succeeded = capture_packets(handle, options.port);
    pcap_close(handle);
    return succeeded ? 0 : 1;
}
 
int main(int argc, char* argv[]) {
    const auto options = parse_cli_options(argc, argv);
    if (options) return run_capture(*options);
    std::cerr << "Usage: modbus-guardian (--iface <name> | --pcap <file>) [--port <1-65535>]" << std::endl;
    return 2;
}