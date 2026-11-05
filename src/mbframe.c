#include "mbframe.h"
#include "byte_order.h"
#define MB_READ_REQ_LEN (MBAP_HEADER_LEN+5)


//encodes an MBAP header + Read Holding Registers (FC 0x03) request into buf.
int mb_build_read_holding(uint8_t *buf, size_t buflen, uint16_t tid,
                          uint8_t uid, uint16_t addr, uint16_t qty) {
    const uint16_t pdu_len = 1+1+2+2;
    if (buf==NULL||buflen < MB_READ_REQ_LEN) {return -1;}
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
    return (MB_READ_REQ_LEN);
}

int mb_parse_response_header(const uint8_t *buf, size_t len,
                              uint16_t *out_tid, uint16_t *out_len) {
    if (buf == NULL ||out_len == NULL || out_tid == NULL || len < MBAP_HEADER_LEN) {return -1;}
    *out_len=(uint16_t)(((uint16_t)buf[4]<<8)|buf[5]);
    *out_tid=(uint16_t)(((uint16_t)buf[0]<<8)|buf[1]);
    return 0;
}
int mb_build_read_coils(uint8_t *buf, size_t buflen, uint16_t tid, uint8_t uid, uint16_t addr, uint16_t qty) {
    const uint16_t pdu_len = 1+1+2+2;
    if (buf==NULL||buflen < MB_READ_REQ_LEN) {return -1;}
    if (qty < 1 || qty> 2000) {return -1;}
    buf[0] = (uint8_t)(tid>>8);//moved by 8 to right
    buf[1] = (uint8_t)(tid & 0xff); // only 8 bottom bits
    buf[2] = 0;
    buf[3] = 0;
    buf[4] =(uint8_t)(pdu_len>>8);//length
    buf[5] =(uint8_t)(pdu_len & 0xff);
    buf[6] = (uint8_t)(uid);
    buf[7] =MB_FC_READ_COILS;
    buf[8] = (uint8_t)(addr >> 8);
    buf[9] =(uint8_t)(addr & 0xff);
    buf[10] = (uint8_t)(qty >> 8);
    buf[11] = (uint8_t)(qty & 0xff);
    return (MB_READ_REQ_LEN);
}

static size_t frame_size(uint16_t length_field) {
    return 6u + length_field;
}

static int is_invalid_length(uint16_t length_field) {
    return length_field < MB_MIN_LENGTH_FIELD || length_field > MB_MAX_LENGTH_FIELD;
}

static void fill_frame(const uint8_t *buf, uint16_t length_field, MbFrame *out) {
    out->transaction_id = read_u16_be(buf);
    out->protocol_id = read_u16_be(buf + 2);
    out->length = length_field;
    out->unit_id = buf[6];
    out->function_code = buf[7];
    out->data =  buf + 8;
    out->data_len = length_field - 2u;
}

int mb_parse_frame(const uint8_t *buf, size_t len, MbFrame *out) {
    if (buf == NULL || out == NULL || len < 6) return MB_FRAME_INCOMPLETE;
    const uint16_t length_field = read_u16_be(buf + 4);
    if (is_invalid_length(length_field)) return MB_FRAME_INVALID_LENGTH;
    if (len < frame_size(length_field)) return MB_FRAME_INCOMPLETE;
    fill_frame(buf, length_field, out);
    return (int)frame_size(length_field);
}