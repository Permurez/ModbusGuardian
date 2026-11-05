# ModbusGuardian
A lightweight intrusion detection system for Modbus TCP traffic.

## Targets

- **modbus-guardian** (`src/main.cpp`, `src/packet_parser.cpp`, `src/cli_options.cpp`) —
  passive Modbus TCP sniffer built on libpcap. Locates the Modbus data by reading the
  IP and TCP header lengths, and checks every read against the captured length. It reads
  a live interface or a capture file; detection rules are in progress.
- **mbgen** (`src/mbgen.c`) — Modbus TCP test client. Builds requests with the `mbframe`
  library, sends them to a server, and prints the responses as hex.
- **mbframe** (`src/mbframe.c`, `include/mbframe.h`) — shared, I/O-free static library
  for building and parsing Modbus TCP frames.

## Building

Requires CMake 3.20+, a C/C++ compiler and libpcap (`libpcap-dev` on Debian/Ubuntu).

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Running

```sh
# From a capture file
./build/modbus-guardian --pcap docs/modbus-baseline.pcapng --port 5020

# From a live interface
sudo ./build/modbus-guardian --iface lo --port 5020
```

Choose exactly one of `--pcap` and `--iface`. The default port is 502.

## Test server

`tools/mbserver.py` runs a pymodbus-based Modbus TCP test server on
`127.0.0.1:5020` with 100 holding registers (`register[i] == i * 10`) and
100 coils, for exercising `mbgen` against a real Modbus endpoint: