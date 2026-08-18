#ifndef KKW_PROVE_H
#define KKW_PROVE_H

#include "shared.h"
#include "xmss.h"
#include <stdint.h>
#include <stdio.h>

extern int kkw_verbose;

int kkw_prove(const unsigned char *input  ,
              const unsigned char m_hat[32],
              const unsigned char pk_seed[XMSS_PK_SEED_BYTES],
              const uint32_t pubout[8],
              FILE *out);

#endif
