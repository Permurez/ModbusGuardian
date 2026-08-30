#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "mbframe.h"

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
    ssize_t n = recv(fd, resp, sizeof(resp), 0);
    if ( n < 0 ) {
        perror ("recv");
        close(fd);
        return 1;
    }
    if (n==0){
        fprintf(stderr, "connection closed by peer\n");
        close(fd);
        return 1;
    }
    /* 6. Hex dump the received bytes for inspection. */
    for (ssize_t i = 0; i < n; i++) {
        printf("%02X ", resp[i]);
    }
 printf("\n");
    /* 7. Close the socket. */
    close(fd);
    return 0;
}
