#ifndef	__25519__H
#define	__25519__H

#include "crypto_common.h"


#ifdef HAVE_TI_MODE
typedef uint64_t fe25519[5];
#else
typedef int32_t fe25519[10];
#endif
#define crypto_verify_32_BYTES 32U


typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
} ge25519_p2;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519_p3;

typedef struct {
    fe25519 X;
    fe25519 Y;
    fe25519 Z;
    fe25519 T;
} ge25519_p1p1;

typedef struct {
    fe25519 yplusx;
    fe25519 yminusx;
    fe25519 xy2d;
} ge25519_precomp;

typedef struct {
    fe25519 YplusX;
    fe25519 YminusX;
    fe25519 Z;
    fe25519 T2d;
} ge25519_cached;


int
sc25519_is_canonical(const unsigned char *s);

int
ge25519_is_canonical(const unsigned char *s);


int
ge25519_has_small_order(const unsigned char s[32]);

int
ge25519_frombytes_negate_vartime(ge25519_p3 *h, const unsigned char *s);

void
sc25519_reduce(unsigned char *s);

void
ge25519_double_scalarmult_vartime(ge25519_p2 *r, const unsigned char *a,
                                  const ge25519_p3 *A, const unsigned char *b);
void
ge25519_tobytes(unsigned char *s, const ge25519_p2 *h);

int
crypto_verify_32(const unsigned char *x, const unsigned char *y);



#endif

