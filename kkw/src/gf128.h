#ifndef GF128_H
#define GF128_H

/* Polynomial-basis GF(2^128) with little-endian bytes and 32-bit limbs. */

#include <stdint.h>

void gf128_word_shift_xor(uint32_t acc[8], uint32_t word, int pos);

void gf128_reduce(const uint32_t acc[8], uint32_t out[4]);

void gf128_mul_words(const uint32_t X[4], const uint32_t Y[4], uint32_t out[4]);

void gf128_load(uint32_t w[4], const uint8_t b[16]);
void gf128_store(uint8_t b[16], const uint32_t w[4]);
void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t z[16]);

#endif
