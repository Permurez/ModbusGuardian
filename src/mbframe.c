#include "mbframe.h"
#define MB_FC_03_REQ_LEN (MBAP_HEADER_LEN+5)


//encodes an MBAP header + Read Holding Registers (FC 0x03) request into buf.
int mb_build_read_holding(uint8_t *buf, size_t buflen, uint16_t tid,
                          uint8_t uid, uint16_t addr, uint16_t qty) {
    const uint16_t pdu_len = 1+1+2+2;
    if (buf==NULL||buflen < MB_FC_03_REQ_LEN) {return -1;}
    if (qty < 1 || qty> 125) {return -1;}
    buf[0] = (uint8_t)(tid>>8);//moved by 8 to right
    buf[1] = (uint8_t)(tid & 0xff); // only 8 bottom bits
    buf[2] = 0;
    buf[3] = 0;
    buf[4] =(uint8_t)(pdu_len>>8);//length
    buf[5] =(uint8_t)(pdu_len & 0xff);
    buf[6] = (uint8_t)(uid);
    buf[7] = MB_FC_READ_HOLDING_REGS;
    buf[8] = (uint8_t)(addr >> 8);
    buf[9] =(uint8_t)(addr & 0xff);
    buf[10] = (uint8_t)(qty >> 8);
    buf[11] = (uint8_t)(qty & 0xff);
    return (MB_FC_03_REQ_LEN);
}

int mb_parse_response_header(const uint8_t *buf, size_t len,
                              uint16_t *out_tid, uint16_t *out_len) {
    if (buf == NULL ||out_len == NULL || out_tid == NULL || len < MBAP_HEADER_LEN) {return -1;}
    *out_len=(uint16_t)(((uint16_t)buf[4]<<8)|buf[5]);
    *out_tid=(uint16_t)(((uint16_t)buf[0]<<8)|buf[1]);
    return 0;
}
