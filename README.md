# ModbusGuardian
Lekki system IDS monitorujący ruch Modbus TCP

## Targets

- **modbus-guardian** (`src/main.cpp`) — passive Modbus TCP sniffer / IDS built on
  libpcap. Captures traffic on a chosen network interface, filters on TCP port 502,
  and parses the Modbus TCP MBAP header of each packet.
- **mbgen** (`src/mbgen.c`) — Modbus TCP traffic generator / client used for testing.
  Builds a Modbus request frame using the `mbframe` library, sends it over a TCP
  socket to a target server, and prints the response. Currently scaffolded with
  TODOs — the frame encoding/decoding logic and socket I/O are not yet implemented.
- **mbframe** (`src/mbframe.c`, `include/mbframe.h`) — shared, I/O-free static
  library for building and parsing Modbus TCP ADUs, used by both `mbgen` and
  future tooling.

## Building

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Test server

`tools/mbserver.py` runs a pymodbus-based Modbus TCP test server on
`127.0.0.1:5020` with 100 holding registers (`register[i] == i * 10`) and
100 coils, for exercising `mbgen` against a real Modbus endpoint:

```sh
python tools/mbserver.py
```
