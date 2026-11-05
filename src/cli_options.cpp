#include "cli_options.hpp"
#include <cstdlib>
#include <getopt.h>

static bool is_valid_port(const char* text) {
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    return end != text && *end == '\0' && value >= 1 && value <= 65535;
}

// Stores one option; returns false if its value is invalid.
static bool store_option(int option, const char* value, CliOptions& out) {
    if (option == 'i') out.iface = value;
    else if (option == 'f') out.pcap_path = value;
    else if (option == 'p' && is_valid_port(value)) out.port = std::atoi(value);
    else return false;
    return true;
}

static bool has_exactly_one_source(const CliOptions& options) {
    return (options.iface.empty() && !options.pcap_path.empty())
        || (!options.iface.empty() && options.pcap_path.empty());
}

std::optional<CliOptions> parse_cli_options(int argc, char* argv[]) {
    static const option long_options[] = {
        {"iface", required_argument, nullptr, 'i'},
        {"pcap", required_argument, nullptr, 'f'},
        {"port", required_argument, nullptr, 'p'},
        {nullptr, 0, nullptr, 0},
    };
    CliOptions options;
    int option_code;
    while ((option_code = getopt_long(argc, argv, "", long_options, nullptr)) != -1) {
        if (!store_option(option_code, optarg, options)) return std::nullopt;
    }
    if (optind != argc || !has_exactly_one_source(options)) return std::nullopt;
    return options;
}