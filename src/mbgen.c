#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "mbframe.h"

int main(void) {
    printf("mbgen: start\n");

    /* 1. Build a Modbus TCP "Read Holding Registers" request frame using mbframe. */

    /* 2. Create a TCP socket (AF_INET, SOCK_STREAM). */

    /* 3. Connect the socket to the target Modbus server (address, port 502/5020). */

    /* 4. Send the encoded frame over the socket. */

    /* 5. Receive the response into a buffer. */

    /* 6. Hex dump the received bytes for inspection. */

    /* 7. Close the socket. */

    return 0;
}
