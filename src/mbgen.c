#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include "mbframe.h"
//Read exactly 'need' bytes from fd into fub, looping until complete.
//TCP is a byte stream so single recv() may return partial frame.

static int recv_exact(int fd, uint8_t *buf, size_t need) {
    size_t got = 0;
    while (got < need) {
        ssize_t n = recv(fd, buf + got, need - got, 0);
        if (n == 0) {
            fprintf(stderr, "connection closed mid-frame\n");
            return -1;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;//Interrupted by a signal, not a real error
            }
            perror("recv");
            return -1;
        }
        got += (size_t)n;
    }
    return 0;
}
int main(void) {

    /* 1. Build a Modbus TCP "Read Holding Registers" request frame using mbframe. */
    printf("mbgen: start\n");
    uint8_t req[MB_MAX_ADU];
    int req_len = mb_build_read_holding(req, sizeof(req), 1, 1, 0, 2);
    if (req_len < 0) {
        perror ("mb_build_read_holding");
        return 1;
    }
    /* 2. Create a TCP socket (AF_INET, SOCK_STREAM). */
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror ("socket");
        return 1;
    }
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5020);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        perror ("inet_pton failed\n");
        close(fd);
        return 1;
    }
    /* 3. Connect the socket to the target Modbus server (address, port 502/5020). */

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) <0){
        perror ("connect");
        close(fd);
        return 1;
    }
    /* 4. Send the encoded frame over the socket. */

    if (send(fd, req, (size_t)req_len, 0) <0 ) {
        perror ("send");
        close(fd);
        return 1;
    }
    /* 5. Receive the response into a buffer. */
    uint8_t resp[MB_MAX_ADU];

    /* MBAP: tid(2) + proto(2) + len(2) — fixed size, read it first */
    if (recv_exact(fd, resp, 6) < 0) {
        close(fd);
        return 1;
    }

    uint16_t len = (uint16_t)(((uint16_t)resp[4] << 8) | resp[5]);

    /* Length comes from the wire — never trust it */
    if (len < 2 || len > MB_MAX_PDU) {
        fprintf(stderr, "invalid MBAP length: %u\n", len);
        close(fd);
        return 1;
    }

    if (recv_exact(fd, resp + 6, len) < 0) {
        close(fd);
        return 1;
    }

    size_t total = 6 + (size_t)len;

    /* 6. Hex dump the received bytes for inspection. */
    for (size_t i = 0; i < total; i++) {
        printf("%02X ", resp[i]);
    }
    printf("\n");


    req_len = mb_build_read_coils(req, sizeof(req), 2, 1, 0, 8);
    if (req_len < 0) {
        fprintf(stderr, "mb_build_read_coils failed\n");
        close(fd);
        return 1;
    }

    if (send(fd, req, (size_t)req_len, 0) < 0) {
        perror("send");
        close(fd);
        return 1;
    }

    if (recv_exact(fd, resp, 6) < 0) {
        close(fd);
        return 1;
    }

    len = (uint16_t)(((uint16_t)resp[4] << 8) | resp[5]);

    if (len < 2 || len > MB_MAX_PDU) {
        fprintf(stderr, "invalid MBAP length: %u\n", len);
        close(fd);
        return 1;
    }

    if (recv_exact(fd, resp + 6, len) < 0) {
        close(fd);
        return 1;
    }

    total = 6 + (size_t)len;

    for (size_t i = 0; i < total; i++) {
        printf("%02X ", resp[i]);
    }
    printf("\n");
    /* 7. Close the socket. */
    close(fd);
    return 0;
}
