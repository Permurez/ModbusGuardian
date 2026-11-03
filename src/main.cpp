#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>
#include <winsock2.h> // Potrzebne do ntohs

#include "AlertLogger.hpp"
#include "ModbusHeader.hpp"

// KONFIGURACJA REGUL IDS (Polityka bezpieczeństwa sieci)
const uint8_t ALLOWED_UNIT_ID = 1; // Nasz prawowity sterownik ma ID = 1

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    auto* logger = reinterpret_cast<AlertLogger*>(userData);
    unsigned int network_offset = 54; // Ethernet (14B) + IP (20B) + TCP (20B)

    // Sprawdzamy, czy pakiet ma rozmiar pozwalający na pełne zapytanie z payloadem (54B sieci + 7B MBAP + 1B funkcja + 4B dane = 66 bajtów)
    if (pkthdr->len >= (network_offset + sizeof(ModbusStandardRequest))) {
        
        // Rzutujemy wskaźnik na naszą rozbudowaną strukturę zapytania
        const ModbusStandardRequest* req = reinterpret_cast<const ModbusStandardRequest*>(packet + network_offset);

        // Konwersja z formatu sieciowego (Big-Endian) na format procesora
        uint16_t trans_id  = ntohs(req->mbap.transaction_id);
        uint8_t  unit_id   = req->mbap.unit_id;
        uint8_t  func_code = req->function_code;
        uint16_t address   = ntohs(req->address);
        uint16_t val_qty   = ntohs(req->value_or_qty);

        std::cout << "[IDS - DEEP PACKET INSPECTION]" << std::endl;
        std::cout << "      [MBAP] Transakcja: " << trans_id << " | Unit ID: " << (int)unit_id << std::endl;

        // --- REGULA 1: Weryfikacja Unit ID (Skanowanie sieci / Fałszywe zapytania) ---
        if (unit_id != ALLOWED_UNIT_ID) {
            if (logger != nullptr) {
                logger->logAlert("CRITICAL",
                                 "Wykryto zapytanie do nieautoryzowanego Unit ID. Możliwy atak Reconnaissance!",
                                 trans_id,
                                 unit_id);
            }
            std::cout << "      [KRYTYCZNY ALARM] Wykryto zapytanie do nieautoryzowanego Unit ID: " 
                      << (int)unit_id << "! Możliwy atak Reconnaissance!" << std::endl;
        }

        // --- REGULA 2: Głęboka analiza kodu funkcji i payloadu ---
        switch (func_code) {
            case 0x01:
                std::cout << "      [INFO] Odczyt cewek (Coils). Adres startowy: " << address 
                          << ", Ilość: " << val_qty << std::endl;
                break;
            case 0x03:
                std::cout << "      [INFO] Odczyt rejestrów (Holding Registers). Adres startowy: " << address 
                          << ", Ilość: " << val_qty << std::endl;
                break;
            case 0x05:
                if (logger != nullptr) {
                    logger->logAlert("ALARM",
                                     "Próba zapisu cewki.",
                                     trans_id,
                                     unit_id);
                }
                std::cout << "      [ALARM] Próba zapisu cewki! Adres: " << address 
                          << " | Wartość wymuszana: " << (val_qty == 0xFF00 ? "ON" : "OFF") << std::endl;
                break;
            case 0x06:
                if (logger != nullptr) {
                    logger->logAlert("CRITICAL",
                                     "Modyfikacja rejestru sterującego.",
                                     trans_id,
                                     unit_id);
                }
                std::cout << "      [ALARM KRYTYCZNY] Modyfikacja rejestru sterującego! Adres: " << address 
                          << " | Zapisywana wartość: " << val_qty << std::endl;
                break;
            default:
                std::cout << "      [OSTRZEŻENIE] Nietypowy kod funkcji: 0x" << std::hex << (int)func_code << std::dec << std::endl;
                break;
        }
        std::cout << "-----------------------------------------------------" << std::endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Blad findalldevs: " << errbuf << std::endl;
        return 1;
    }

    std::vector<pcap_if_t*> devs;
    int i = 0;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << (d->description ? d->description : d->name) << std::endl;
        devs.push_back(d);
    }

    std::cout << "\nWybierz karte sieciowa: ";
    int choice;
    std::cin >> choice;

    if (choice < 1 || choice > i) {
        std::cout << "Nieprawidlowy wybor." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_t *handle = pcap_open_live(devs[choice - 1]->name, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Nie udalo sie otworzyc karty: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    struct bpf_program fp;
    char filter_exp[] = "tcp port 502";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Blad kompilacji filtra: " << pcap_geterr(handle) << std::endl;
        return 1;
    }
    pcap_setfilter(handle, &fp);

    AlertLogger logger;

    std::cout << "\n[IDS DPI ACTIVE] Strażnik analizuje zawartość payloadu..." << std::endl;
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(&logger));

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}