#ifndef BYTE_ORDER_H
#define BYTE_ORDER_H

#include <stdint.h>

/* Combines two consecutive bytes into one big-endian 16-bit value. */
static inline uint16_t read_u16_be(const uint8_t *bytes) {
    return (uint16_t)((bytes[0] << 8) | bytes[1]);
}

/* Combines four consecutive bytes into one big-endian 32-bit value. */
static inline uint32_t read_u32_be(const uint8_t *bytes) {
    return ((uint32_t)read_u16_be(bytes) << 16) | read_u16_be(bytes + 2);
}

#endif /* BYTE_ORDER_H */