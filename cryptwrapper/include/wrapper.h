#ifndef WRAPPER_H
#define WRAPPER_H

#include <stdbool.h>

#include <sodium.h>

#define TRANS_BUFF_SIZE 500

#define DEBUG

#ifdef DEBUG
#define dbprintf(f, p...) printf(f, p)
#define dbprint(f) printf(f)
#else
#define dbprintf(f, p...) ((void)0)
#define dbprint(f) ((void)0)
#endif

static const unsigned char seed[randombytes_SEEDBYTES] = {
	"hellothereyoudingdong"
};

struct crypto_ctx {
	// Public and private key of the client
	unsigned char self_pk[crypto_kx_PUBLICKEYBYTES];
	unsigned char self_sk[crypto_kx_SECRETKEYBYTES];

	unsigned char other_pk[crypto_kx_PUBLICKEYBYTES];

	unsigned char rx[crypto_kx_SESSIONKEYBYTES];
	unsigned char tx[crypto_kx_SESSIONKEYBYTES];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
};

int send_encrypted(int sock, struct crypto_ctx *con,
		   unsigned char buff[TRANS_BUFF_SIZE]);
int recv_encrypted(int sock, struct crypto_ctx *con,
		   unsigned char buff[TRANS_BUFF_SIZE]);
int keyexchange(int sock, struct crypto_ctx *con, bool client);
#endif
