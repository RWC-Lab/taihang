// curve operations

#ifndef __MONT25519_2x1_H__
#define __MONT25519_2x1_H__

#include "crypto_uint64_vec2x1.h"

#define CRYPTO_BYTES 32

#define mladder_2x1 CRYPTO_SHARED_NAMESPACE(mladder_2x1)
#define crypto_nP_2x1 CRYPTO_NAMESPACE(crypto_nP_2x1)

extern void mladder_2x1(crypto_uint64_vec2x1 *, const crypto_uint64_vec2x1 *, const crypto_uint64_vec2x1 *);
int crypto_nP_2x1(unsigned char [2][CRYPTO_BYTES], const unsigned char [2][CRYPTO_BYTES], const unsigned char [2][CRYPTO_BYTES]);

#endif


