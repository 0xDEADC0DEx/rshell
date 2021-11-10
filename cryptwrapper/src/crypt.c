#include <sys/socket.h>
#include <sys/types.h>
#include <errno.h>
#include <stdio.h>

#include <sodium.h>

#include "logger.h"
#include "wrapper.h"

void printkey(unsigned char input[], size_t len)
{
	size_t i;

	for (i = 0; i < len; i++) {
		LOG(1, "%x", input[i]);
	}
	LOG(1, "\n");
}

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
		LOG(1, "Nonce incremented!\n");
		LOG(1, "\nSent encrypted:\n{\n%s\n}\n", buff);
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
		return -1;
	}

	if (len > 0) {
		if (crypto_secretbox_open_easy(
			    buff, cipher_buff,
			    TRANS_BUFF_SIZE + crypto_secretbox_MACBYTES,
			    con->nonce, con->rx)) {
			return -2;
		}

		sodium_increment(con->nonce, sizeof con->nonce);
		LOG(1, "Nonce incremented!\n");
		LOG(1, "\nReceived encrypted:\n{\n%s\n}\n", buff);
		return len;
	}
	return 0;
}

int keyexchange(int sock, struct crypto_ctx *con, bool client)
{
	crypto_kx_keypair(con->self_pk, con->self_sk);

	// send server public key
	if (send(sock, con->self_pk, crypto_kx_PUBLICKEYBYTES, 0) !=
	    crypto_kx_PUBLICKEYBYTES) {
		return -1;
	}

	// get client public key
	if (recv(sock, con->other_pk, crypto_kx_PUBLICKEYBYTES, 0) !=
	    crypto_kx_PUBLICKEYBYTES) {
		return -2;
	}

	// compute shared session keys
	if (client) {
		if (crypto_kx_client_session_keys(con->rx, con->tx,
						  con->self_pk, con->self_sk,
						  con->other_pk)) {
			return -3;
		}
	} else {
		if (crypto_kx_server_session_keys(con->rx, con->tx,
						  con->self_pk, con->self_sk,
						  con->other_pk)) {
			return -3;
		}
	}

	LOG(1, "Self public key:");
	printkey(con->self_pk, crypto_kx_PUBLICKEYBYTES);
	LOG(1, "Self private key:");
	printkey(con->self_sk, crypto_kx_SECRETKEYBYTES);

	LOG(1, "Remote public key:");
	printkey(con->other_pk, crypto_kx_PUBLICKEYBYTES);

	LOG(1, "Session Keys:\nRx:");
	printkey(con->rx, crypto_kx_SESSIONKEYBYTES);
	LOG(1, "Tx:");
	printkey(con->tx, crypto_kx_SESSIONKEYBYTES);

	// send encrypted nonce with fixed_nonce
	randombytes_buf_deterministic(con->nonce, sizeof con->nonce, seed);

	{
		unsigned char temp[TRANS_BUFF_SIZE] = "HelloWorld";

		// Test the connection with a handshake
		// (Basically just send Hello world between client and server)
		if (client) {
			int rv;

			if (send_encrypted(sock, con, temp) < 0) {
				return -4;
			}

			rv = recv_encrypted(sock, con, temp);
			if (rv < 0) {
				ERR(rv);
				return -5;
			}

			if (temp[3] != 'l') {
				return -6;
			}
		} else {
			int rv;

			rv = recv_encrypted(sock, con, temp);
			if (rv < 0) {
				ERR(rv);
				return -4;
			}

			if (temp[3] != 'l') {
				return -5;
			}

			if (send_encrypted(sock, con, temp) < 0) {
				return -6;
			}
		}
	}

	return 0;
}
