#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>

// Rozbudowana procedura obsługi pakietów (callback)
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Odcinamy nagłówki sieciowe: Ethernet (14B) + IP (20B) + TCP (20B) = 54 bajty
    // Używamy 'unsigned int', żeby dopasować typ do pkthdr->len i uniknąć warningów
    unsigned int network_offset = 54;

    // Sprawdzamy, czy pakiet ma w ogóle dane poza nagłówkami sieciowymi
    if (pkthdr->len > network_offset) {
        // Ustawiamy wskaźnik bezpośrednio na początek nagłówka Modbus TCP (MBAP)
        const u_char* modbus = packet + network_offset;

        // Składanie bajtów (Big-Endian): przesunięcie bitowe o 8 pozycji w lewo i suma logiczna OR (|)
        unsigned short transaction_id = (modbus[0] << 8) | modbus[1];
        unsigned short protocol_id    = (modbus[2] << 8) | modbus[3];
        unsigned short length         = (modbus[4] << 8) | modbus[5];
        unsigned char unit_id         = modbus[6]; // 7. bajt nagłówka MBAP

        std::cout << "[IDS] Analiza nagłówka Modbus TCP (MBAP):" << std::endl;
        std::cout << "      Transaction ID: " << transaction_id << std::endl;
        std::cout << "      Protocol ID:    " << protocol_id << " (0 = Modbus TCP)" << std::endl;
        std::cout << "      Długość reszty: " << length << " bajtów" << std::endl;
        std::cout << "      Unit ID:        " << (int)unit_id << std::endl;
        std::cout << "-----------------------------------------------" << std::endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    // Pobranie listy dostępnych kart sieciowych
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Błąd findalldevs: " << errbuf << std::endl;
        return 1;
    }

    std::vector<pcap_if_t*> devs;
    int i = 0;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::cout << ++i << ". " << (d->description ? d->description : d->name) << std::endl;
        devs.push_back(d);
    }

    std::cout << "\nWybierz kartę sieciową: ";
    int choice;
    std::cin >> choice;

    if (choice < 1 || choice > i) {
        std::cout << "Nieprawidłowy wybór." << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Otwarcie wybranej karty w trybie promiscuous (uchwyt 'handle')
    pcap_t *handle = pcap_open_live(devs[choice - 1]->name, 65535, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Nie udało się otworzyć karty: " << errbuf << std::endl;
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Kompilacja i nakładanie filtra BPF na port 502
    struct bpf_program fp;
    char filter_exp[] = "tcp port 502";

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Błąd kompilacji filtra: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Błąd nakładania filtra: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        pcap_freealldevs(alldevs);
        return 1;
    }

    std::cout << "\n[NASŁUCH] Filtr aktywny. Czekam na pakiety Modbus..." << std::endl;
    
    // Pętla przechwytywania działająca w nieskończoność
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Czyszczenie zasobów po wyjściu z pętli (choć pcap_loop tu działa bez końca)
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}