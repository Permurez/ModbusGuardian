#include <iostream>
#include <pcap.h>

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    // 1. Pobierz listę dostępnych urządzeń
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Błąd przy wyszukiwaniu kart: " << errbuf << std::endl;
        return 1;
    }

    // 2. Wypisz je na ekran
    std::cout << "Dostępne karty sieciowe:" << std::endl;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
        std::cout << "Nazwa: " << d->name << std::endl;
        if (d->description) std::cout << " Opis: " << d->description << std::endl;
    }

    // 3. Posprzątaj
    pcap_freealldevs(alldevs);
    return 0;
}