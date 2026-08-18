#ifndef COMMITMENT_H
#define COMMITMENT_H

/* Halevi–Micali commitment over GF(2^128), (n,s,k) = (128,2,6).
 * The wire encoding is a || b || y with little-endian field elements. */

#include <stdint.h>

#define HM_NONCES 6
#define HM_LINES 2
#define HM_ELT 16
#define HM_R_BYTES (HM_NONCES * HM_ELT)
#define HM_A_BYTES (HM_LINES * HM_NONCES * HM_ELT)
#define HM_B_BYTES (HM_LINES * HM_ELT)
#define HM_Y_BYTES 32
#define HM_COM_BYTES (HM_A_BYTES + HM_B_BYTES + HM_Y_BYTES)
#define HM_OPEN_BYTES (HM_R_BYTES + HM_A_BYTES)

void hm_y(const uint8_t r[HM_R_BYTES], uint8_t y[HM_Y_BYTES]);

void hm_lines(const uint8_t m_hat[32], const uint8_t a[HM_A_BYTES], const uint8_t r[HM_R_BYTES],
              uint8_t b[HM_B_BYTES]);

void hm_commitment(const uint8_t a[HM_A_BYTES], const uint8_t b[HM_B_BYTES], const uint8_t y[HM_Y_BYTES],
                   uint8_t com[HM_COM_BYTES]);

void hm_digest(const uint8_t com[HM_COM_BYTES], uint8_t d[32]);

void hm_commit(const uint8_t m_hat[32], const uint8_t r[HM_R_BYTES], const uint8_t a[HM_A_BYTES],
               uint8_t com[HM_COM_BYTES], uint8_t d[32]);

#endif
