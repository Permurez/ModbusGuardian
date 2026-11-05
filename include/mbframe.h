#ifndef MBFRAME_H
#define MBFRAME_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MBAP header length in bytes (Transaction ID, Protocol ID, Length, Unit ID). */
#define MBAP_HEADER_LEN 7

/* Maximum size of a Modbus PDU (function code + data). */
#define MB_MAX_PDU 253

/* Maximum size of a full Modbus TCP ADU (MBAP header + PDU). */
#define MB_MAX_ADU 260

/* Modbus function codes used by this project. */
#define MB_FC_READ_COILS            0x01
#define MB_FC_READ_DISCRETE_INPUTS  0x02
#define MB_FC_READ_HOLDING_REGS     0x03
#define MB_FC_READ_INPUT_REGS       0x04
#define MB_FC_WRITE_SINGLE_COIL     0x05
#define MB_FC_WRITE_SINGLE_REG      0x06

#define MB_FC_WRITE_MULTIPLE_COILS  0x0F
#define MB_FC_WRITE_MULTIPLE_REGS   0x10
/* Set on the function code of a Modbus exception response. */
#define MB_FC_ERROR_BIT 0x80

/* Allowed values of the MBAP Length field: Unit ID + PDU. */
#define MB_MIN_LENGTH_FIELD 2
#define MB_MAX_LENGTH_FIELD 254

/* Special results of mb_parse_frame. */
#define MB_FRAME_INCOMPLETE 0
#define MB_FRAME_INVALID_LENGTH (-1)

/* One decoded Modbus TCP frame. Pointers refer to the input buffer. */
typedef struct {
    uint16_t transaction_id;
    uint16_t protocol_id;
    uint16_t length;
    uint8_t unit_id;
    uint8_t function_code;
    const uint8_t *data;
    size_t data_len;
} MbFrame;

/**
 * Build a Modbus TCP "Read Holding Registers" (FC 03) request frame.
 *
 * @param buf     Destination buffer for the encoded ADU.
 * @param buflen  Size of buf in bytes.
 * @param tid     Transaction identifier to place in the MBAP header.
 * @param uid     Unit identifier (slave address).
 * @param addr    Starting register address.
 * @param qty     Quantity of registers to read.
 *
 * @return Number of bytes written to buf on success, or a negative value
 *         if buf is NULL or buflen is too small to hold the encoded frame.
 */
int mb_build_read_holding(uint8_t *buf, size_t buflen, uint16_t tid,
                           uint8_t uid, uint16_t addr, uint16_t qty);
int mb_build_read_coils(uint8_t *buf, size_t buflen, uint16_t tid, uint8_t uid, uint16_t addr, uint16_t qty);

/**
 * Parse the MBAP header of a Modbus TCP response and extract key fields.
 *
 * @param buf      Buffer containing the received ADU.
 * @param len      Number of valid bytes in buf.
 * @param out_tid  Output parameter receiving the transaction identifier.
 * @param out_len  Output parameter receiving the MBAP "length" field.
 *
 * @return 0 on success, or a negative value if buf/out_tid/out_len is NULL
 *         or len is smaller than MBAP_HEADER_LEN.
 */
int mb_parse_response_header(const uint8_t *buf, size_t len,
                              uint16_t *out_tid, uint16_t *out_len);

/**
 * Decodes the frame at the start of buf.
 *
 * @return Frame size in bytes, MB_FRAME_INCOMPLETE if more bytes are needed,
 *         or MB_FRAME_INVALID_LENGTH if the Length field is out of range.
 */
int mb_parse_frame(const uint8_t *buf, size_t len, MbFrame *out);

#ifdef __cplusplus
}
#endif

#endif /* MBFRAME_H */