#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>

#include <sodium.h>

#include "wrapper.h"

int send_encrypted(int sock, struct crypto_ctx *con,
		   unsigned char buff[TRANS_BUFF_SIZE])
{
	int len;
	unsigned char cipher_buff[TRANS_BUFF_SIZE + crypto_secretbox_MACBYTES];

	crypto_secretbox_easy(cipher_buff, buff, TRANS_BUFF_SIZE, con->nonce,
			      con->tx);

	len = send(sock, cipher_buff,
		   TRANS_BUFF_SIZE + crypto_secretbox_MACBYTES, 0);

  if (len > 0) { 
    sodium_increment(con->nonce, sizeof con->nonce);
  }
	return len;
}

int recv_encrypted(int sock, struct crypto_ctx *con,
		   unsigned char buff[TRANS_BUFF_SIZE])
{
	unsigned char cipher_buff[TRANS_BUFF_SIZE + crypto_secretbox_MACBYTES];
	int len;

	len = recv(sock, cipher_buff,
		   TRANS_BUFF_SIZE + crypto_secretbox_MACBYTES, 0);
	if (len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
		return len;
	}

	if (len > 0) {
		if (crypto_secretbox_open_easy(
			    buff, cipher_buff,
			    TRANS_BUFF_SIZE + crypto_secretbox_MACBYTES,
			    con->nonce, con->rx)) {
			return -2;
		}

		sodium_increment(con->nonce, sizeof con->nonce);
		return len;
	}
	return 0;
}

int keyexchange(int sock, struct crypto_ctx *con)
{
	crypto_kx_keypair(con->server_pk, con->server_pk);

	// send server public key
	if (send(sock, con->server_pk, crypto_kx_PUBLICKEYBYTES, 0) !=
	    crypto_kx_PUBLICKEYBYTES) {
		return -1;
	}

	// get client public key
	if (recv(sock, con->client_pk, crypto_kx_PUBLICKEYBYTES, 0) !=
	    crypto_kx_PUBLICKEYBYTES) {
		return -2;
	}

	// compute shared session keys
	if (crypto_kx_server_session_keys(con->rx, con->tx, con->server_pk,
					  con->server_pk, con->client_pk)) {
		return -3;
	}

	// send encrypted nonce with fixed_nonce
	randombytes_buf_deterministic(con->nonce, sizeof con->nonce, seed);

	return 0;
}
