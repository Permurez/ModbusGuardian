#include <iostream>
#include <pcap.h>
#include <vector>
#include <string>

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    std::cout << "[IDS] Wykryto ruch na porcie 502! Rozmiar: " << pkthdr->len << " bajtów" << std::endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {// Pobierz listę interfejsów sieciowych
        std::cerr << "Błąd: " << errbuf << std::endl;
        return 1;
    }

    std::vector<pcap_if_t*> devs;//wskanziki do interfejsów
    int i = 0;
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {// Wyświetl dostępne interfejsy
        std::cout << ++i << ". " << (d->description ? d->description : d->name) << std::endl;
        devs.push_back(d);
    }

    std::cout << "\nWybierz kartę: ";
    int choice;
    std::cin >> choice;

    pcap_t *handle = pcap_open_live(devs[choice - 1]->name, 65535, 1, 1000, errbuf);// Otwórz wybrany interfejs


    struct bpf_program fp;
    char filter_exp[] = "tcp port 502"; // Tylko Modbus TCP

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Błąd filtra: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "Błąd nakładania filtra: " << pcap_geterr(handle) << std::endl;
        return 1;
    }

    std::cout << "\n[NASŁUCH] Filtr aktywny (port 502). Czekam na pakiety..." << std::endl;
    pcap_loop(handle, 0, packetHandler, nullptr);

    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}