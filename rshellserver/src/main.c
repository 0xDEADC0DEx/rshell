#include <stdbool.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <sodium.h>

#include "wrapper.h"

bool brexit = false;
uint16_t port = 6969;

struct connection {
	int sock;

	struct crypto_ctx ctx;
};

void handler(int signal)
{
	brexit = true;
}

static long int longparse(const char input[], char **end)
{
	long int num;
	errno = 0;

	num = strtol(input, end, 0);
	if (end != NULL) {
		if (*end == input) {
			return LLONG_MAX;
		}
	}

	if ((num == LLONG_MAX || num == LLONG_MIN) && errno == ERANGE) {
		return LLONG_MAX;
	}

	return num;
}

int argparse(int argc, char *argv[])
{
	int i;

	for (i = 0; i < argc; i++) {
		switch (argv[i][1]) {
		case 'p':
			if (i + 1 <= argc) {
				long int temp;

				temp = longparse(argv[i + 1], NULL);
				if (temp > UINT16_MAX || temp < 1) {
					printf("Invalid argument given to -p option\n");
					return -1;
				} else {
					port = temp;
				}
			}
			break;
		}
	}

	printf("Port: %d\n", port);
	return 0;
}

int main(int argc, char *argv[])
{
	struct connection con;
	struct sockaddr_in sin;
	int sock;

	if (sodium_init()) {
		return -1;
	}

	if (argparse(argc, argv)) {
		return -2;
	}

	// setup socket
	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket failed");
		return -3;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);

	// bind to port
	if (bind(sock, (struct sockaddr *)&sin, sizeof(sin))) {
		perror("bind failed");
		return -4;
	}
	listen(sock, 1);

	// setup signalhandler
	{
		struct sigaction action;
		action.sa_handler = handler;
		action.sa_flags = 0;
		sigemptyset(&action.sa_mask);

		if (sigaction(SIGINT, &action, NULL)) {
			perror("sigaction failed");
			return -5;
		}
	}

	if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK)) {
		perror("fcntl failed");
		return -6;
	}

	{
		// accept new connection
		socklen_t addrlen = sizeof(struct sockaddr_in);

		printf("Waiting for connection\n");

		con.sock = accept(sock, (struct sockaddr *)&sin, &addrlen);
		if (con.sock < 0) {
			perror("accept failed");
			return -7;
		}
		printf("Connected!\n");

		// exchange keys
		if (keyexchange(con.sock, &con.ctx, false)) {
			printf("keyexchange failed\n");
			return -8;
		}
		printf("Authentication Complete!\n");

		if (fcntl(con.sock, F_SETFL, O_NONBLOCK)) {
			perror("fcntl failed");
			return -9;
		}

		while (!brexit) {
			unsigned char buff[TRANS_BUFF_SIZE];
			int len;

			memset(buff, 0, TRANS_BUFF_SIZE);

			len = read(STDIN_FILENO, buff, TRANS_BUFF_SIZE);
			if (len < 0 && errno != EWOULDBLOCK &&
			    errno != EAGAIN) {
				perror("read failed");
				return -10;
			}

			if (len > 0) {
				if (send_encrypted(con.sock, &con.ctx, buff) <
				    0) {
					printf("send_encrypted failed!");
					return -11;
				}
			}

			memset(buff, 0, TRANS_BUFF_SIZE);

			len = recv_encrypted(con.sock, &con.ctx, buff);
			if (len > 0) {
				len = write(STDOUT_FILENO, buff,
					    TRANS_BUFF_SIZE);
				if (len < 0) {
					perror("write failed");
					return -12;
				}

				if (buff[0] == 'e' && buff[1] == 'x' &&
				    buff[2] == 'i' && buff[3] == 't') {
					brexit = true;
				}

			} else if (len < 0) {
				printf("recv_encrypted failed with %d!\n", len);
				return -13;
			}

			if (usleep(25000)) {
				return -14;
			}
		}

		if (close(con.sock)) {
			perror("close failed");
			return -14;
		}
	}

	if (close(sock)) {
		perror("close failed");
		return -15;
	}
	return 0;
}
