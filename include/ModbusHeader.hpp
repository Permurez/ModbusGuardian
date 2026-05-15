#include <cstdint>

#pragma pack(push, 1) // Zakazujemy kompilatorowi dodawania "luzów" między bajtami
struct ModbusTCPHeader {
    uint16_t transactionId; // ID transakcji (porządek bajtów: Big Endian)
    uint16_t protocolId;    // Zawsze 0 dla Modbus
    uint16_t length;        // Ile bajtów leci dalej
    uint8_t  unitId;        // Adres urządzenia (Slave ID)
    uint8_t  functionCode;  // Co chcemy zrobić? (np. 3 = Read, 5 = Write)
};
#pragma pack(pop)