#ifndef UBOOT_EdDSA_COMMON_H
#define UBOOT_EdDSA_COMMON_H

/*#include "stdint.h"*/
/*#include "string.h"*/
#include <common.h>

/*typedef long unsigned int size_t;
typedef long long int int64_t;
typedef unsigned long long int uint64_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef short int int16_t;
typedef unsigned short int uint16_t;
typedef char int8_t;
typedef unsigned char uint8_t;*/

typedef signed char int_fast8_t;  
typedef unsigned char uint_fast8_t;  
typedef short  int_fast16_t;  
typedef unsigned short  uint_fast16_t;  
typedef int  int_fast32_t;  
typedef unsigned  int  uint_fast32_t;  

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;

#ifndef CRYPTO_ALIGN
# if defined(__INTEL_COMPILER) || defined(_MSC_VER)
#  define CRYPTO_ALIGN(x) __declspec(align(x))
# else
#  define CRYPTO_ALIGN(x) __attribute__ ((aligned(x)))
# endif
#endif



#define MD5_LENGTH 16
#endif //UBOOT_EdDSA_COMMON_H
