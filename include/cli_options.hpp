#pragma once
#include <optional>
#include <string>

// Program settings chosen on the command line.
struct CliOptions {
    std::string iface;      // Live network interface; empty if not used
    std::string pcap_path;  // Capture file; empty if not used
    int port = 502;         // TCP port carrying Modbus traffic
};

// Returns the options, or nothing if the command line is invalid.
std::optional<CliOptions> parse_cli_options(int argc, char* argv[]);