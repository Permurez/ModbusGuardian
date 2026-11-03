#pragma once
#include <cstdint>

#pragma pack(push, 1)

// Nagłówek MBAP (7 bajtów)
struct MbapHeader {
    uint16_t transaction_id;
    uint16_t protocol_id;   
    uint16_t length;        
    uint8_t  unit_id;       
};

// Struktura standardowego zapytania Modbus TCP (np. dla funkcji 0x01, 0x03, 0x05, 0x06)
struct ModbusStandardRequest {
    MbapHeader mbap;
    uint8_t    function_code;
    uint16_t   address;       // Adres początkowy rejestru/cewki (Big-Endian)
    uint16_t   value_or_qty;  // Zapisywana wartość LUB ilość rejestrów do odczytu (Big-Endian)
};

#pragma pack(pop)