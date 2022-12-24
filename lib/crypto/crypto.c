/*#include "stdio.h"*/

/*#include "sys/types.h"
#include "sys/stat.h"
#include "unistd.h"*/

#include "crypto_common.h"
#include "crypto_hash_sha512.h"


#define MD5_LEN 16

#define CRC32_LEN 4

#if defined (CONFIG_PRODUCT_ATOM)
static const unsigned char eddsa_pkey[] = "\xef\x09\xb7\xaf\xad\x80\xa4\xc3\x1e\x4a\xf8\x26\x86\x72\x7d\x30\x11\x55\xc3\x37\x3a\x41\x13\xa0\xbe\x7c\x3b\xa1\x19\xa5\xd9\xa4";
#elif defined (CONFIG_PRODUCT_AZARTON)
static const unsigned char eddsa_pkey[] = "";
#elif defined (CONFIG_PRODUCT_SMARTLAB)
static const unsigned char eddsa_pkey[] = "";
#elif defined (CONFIG_PRODUCT_WYZEV3)
static const unsigned char eddsa_pkey[] = "\xd1\x96\x9b\x89\x48\xd8\x19\x8d\x10\x93\x8d\x06\xdc\xae\xe8\xf5\x44\xf5\xc7\xa8\xf2\xbd\x04\x08\x85\xa6\xf9\x26\x70\x97\xb7\x73";
#elif defined (CONFIG_PRODUCT_WYZEV2PAN)
static const unsigned char eddsa_pkey[] = "\xd1\x96\x9b\x89\x48\xd8\x19\x8d\x10\x93\x8d\x06\xdc\xae\xe8\xf5\x44\xf5\xc7\xa8\xf2\xbd\x04\x08\x85\xa6\xf9\x26\x70\x97\xb7\x73";
#endif

int crypto_sign_init(crypto_sign_state *state)
{
    crypto_hash_sha512_init(&state->hs);
    return 0;
}


int crypto_sign_update(crypto_sign_state *state, const unsigned char *m,
                   unsigned long long mlen)
{
    return crypto_hash_sha512_update(&state->hs, m, mlen);
}


int crypto_sign_final_verify(crypto_sign_state *state, const unsigned char *sig,
						const unsigned char *pk)
{
  	unsigned char ph[crypto_hash_sha512_BYTES];

    crypto_hash_sha512_final(&state->hs, ph);

    return _crypto_sign_ed25519_verify_detached(sig, ph, sizeof ph, pk, 1);
}

int eddsa_verify(void *data, int len) 
{
	int remains = len - crypto_sign_BYTES;
	unsigned long long n = 0;
	unsigned char *p = (unsigned char *)data;
	const unsigned char *sig = p + remains;
	crypto_sign_state state;

	crypto_sign_init(&state);
	while (remains > 0) {
		n = 1024 * 1024;
		if (n > remains) {
			n = remains;
		}

		crypto_sign_update(&state, p, n);

		remains -= n;
		p +=n;

	}


	if (crypto_sign_final_verify(&state, sig, eddsa_pkey) != 0) {
		return -1;
	}
	return 0;
}

#if 0
#define 	FILE_NAME		"demo_hlc6.bin"
int  main (int argc ,char * argv[])
{
	char * buf = NULL;
	int ret = 0;
	struct stat	statbuf = {};
	FILE *pfd =NULL;
	if (access(FILE_NAME ,F_OK)!=0)
	{
		printf("err access.\n");
		return -1;
	}

	if(stat(FILE_NAME ,&statbuf)!=0)
	{
		printf("err stat.\n");
		return -1;
	}

	buf = malloc(statbuf.st_size);
	if(buf == NULL)
	{
		printf("err malloc.\n");
		return -1;
	}

	pfd = fopen(FILE_NAME,"r");
	if(pfd == NULL)
	{
		free(buf);
		printf("err fopen.\n");
		return -1;
	}

	ret = fread(buf ,1 ,statbuf.st_size ,pfd);
	if(ret != statbuf.st_size)
	{
		fclose(pfd);
		free(buf);
		printf("err fread.\n");
		return -1;
	}

	fclose(pfd);

	ret = eddsa_verify(buf ,statbuf.st_size);
	if(ret <0)
		printf("fail:%d.\n",ret);
	else
	printf("ret = %d.\n",ret);
	return 0;
}
#endif


