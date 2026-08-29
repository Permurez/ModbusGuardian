#!/usr/bin/env python3
"""Standalone Modbus TCP test server for exercising the mbgen traffic generator.

Listens on 127.0.0.1:5020 and exposes:
  - 100 holding registers, register[i] preloaded with the value i * 10
  - 100 coils, all initialized to off
"""

from pymodbus.datastore import (
    ModbusDeviceContext,
    ModbusSequentialDataBlock,
    ModbusServerContext,
)
from pymodbus.server import StartTcpServer

HOST = "127.0.0.1"
PORT = 5020
REGISTER_COUNT = 100
COIL_COUNT = 100


def build_context() -> ModbusServerContext:
    holding_registers = ModbusSequentialDataBlock(1, [i * 10 for i in range(REGISTER_COUNT)])
    coils = ModbusSequentialDataBlock(1, [False] * COIL_COUNT)

    device_context = ModbusDeviceContext(
        di=ModbusSequentialDataBlock(1, [False] * COIL_COUNT),
        co=coils,
        ir=ModbusSequentialDataBlock(1, [0] * REGISTER_COUNT),
        hr=holding_registers,
    )
    return ModbusServerContext(devices=device_context, single=True)


def main() -> None:
    context = build_context()
    print(f"Starting Modbus TCP test server on {HOST}:{PORT}")
    StartTcpServer(context=context, address=(HOST, PORT))


if __name__ == "__main__":
    main()
