#ifndef		__CRYPTO_HASH_SHA512__H
#define 	__CRYPTO_HASH_SHA512__H

/*#include "stddef.h"*/
/*#include "stdint.h"*/
/*#include "stdlib.h"*/


#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif



#define crypto_sign_ed25519_BYTES 64U

#define crypto_hash_sha512_BYTES 64U

#define crypto_sign_BYTES crypto_sign_ed25519_BYTES


typedef struct crypto_hash_sha512_state {
    uint64_t state[8];
    uint64_t count[2];
    uint8_t  buf[128];
} crypto_hash_sha512_state;

typedef struct crypto_sign_ed25519ph_state {
    crypto_hash_sha512_state hs;
} crypto_sign_ed25519ph_state;

typedef crypto_sign_ed25519ph_state crypto_sign_state;

int
crypto_hash_sha512_init(crypto_hash_sha512_state *state);

int
crypto_hash_sha512_update(crypto_hash_sha512_state *state,
                          const unsigned char *in, unsigned long long inlen);

int
crypto_hash_sha512_final(crypto_hash_sha512_state *state, unsigned char *out);

int
_crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                     const unsigned char *m,
                                     unsigned long long   mlen,
                                     const unsigned char *pk,
                                     int prehashed);

#ifdef __cplusplus
}
#endif

#endif 
