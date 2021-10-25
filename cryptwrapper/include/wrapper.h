#ifndef WRAPPER_H
#define WRAPPER_H

#include <sodium.h>

#define TRANS_BUFF_SIZE 200

static const unsigned char seed[randombytes_SEEDBYTES] = { "hellothereyoudingdong" };

struct crypto_ctx {
	unsigned char client_pk[crypto_kx_PUBLICKEYBYTES];
	unsigned char client_sk[crypto_kx_SECRETKEYBYTES];

	unsigned char server_pk[crypto_kx_PUBLICKEYBYTES];

	unsigned char rx[crypto_kx_SESSIONKEYBYTES];
	unsigned char tx[crypto_kx_SESSIONKEYBYTES];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];
};


int send_encrypted(int sock, struct crypto_ctx *con, unsigned char buff[TRANS_BUFF_SIZE]);
int recv_encrypted(int sock, struct crypto_ctx *con, unsigned char buff[TRANS_BUFF_SIZE]);
int keyexchange(int sock, struct crypto_ctx *con);
#endif
