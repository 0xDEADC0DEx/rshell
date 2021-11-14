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
#include "logger.h"

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
					LOG(0,
					    "Invalid argument given to -p option\n");
					return -1;
				} else {
					port = temp;
				}
			}
			break;
		case 'v':
			if (g_loglevel <= 1) {
				g_loglevel++;
			}
			break;
		}
	}

	LOG(1, "Port: %d\n", port);
	return 0;
}

int custom_command_handler(unsigned char buff[], size_t size)
{
	if (memcmp(buff, "exit", 4) == 0) {
		brexit = true;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int rv;
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
		ERR(sock);
		return -3;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(port);

	// bind to port
	rv = bind(sock, (struct sockaddr *)&sin, sizeof(sin));
	if (rv) {
		ERR(rv);
		return -4;
	}
	listen(sock, 1);

	// setup signalhandler
	{
		struct sigaction action;
		action.sa_handler = handler;
		action.sa_flags = 0;
		sigemptyset(&action.sa_mask);

		rv = sigaction(SIGINT, &action, NULL);
		if (rv) {
			ERR(rv);
			return -5;
		}
	}

	rv = fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
	if (rv) {
		ERR(rv);
		return -6;
	}

	{
		// accept new connection
		socklen_t addrlen = sizeof(struct sockaddr_in);

		LOG(0, "Waiting for connection\n");

		con.sock = accept(sock, (struct sockaddr *)&sin, &addrlen);
		if (con.sock < 0) {
			ERR(con.sock);
			return -7;
		}
		LOG(0, "Connected!\n");

		// exchange keys
		rv = keyexchange(con.sock, &con.ctx, false);
		if (rv) {
			ERR(rv);
			return -8;
		}
		LOG(0, "Authentication Complete!\n");

		rv = fcntl(con.sock, F_SETFL, O_NONBLOCK);
		if (rv) {
			ERR(rv);
			return -9;
		}

		while (!brexit) {
			unsigned char buff[TRANS_BUFF_SIZE];
			int len;

			memset(buff, 0, TRANS_BUFF_SIZE);

			// Read a command from the prompt
			len = read(STDIN_FILENO, buff, TRANS_BUFF_SIZE);
			if (len < 0 && errno != EWOULDBLOCK &&
			    errno != EAGAIN) {
				ERR(len);
				return -10;
			}

			// Send the command over the socket to the shell
			if (len > 0) {
				rv = send_encrypted(con.sock, &con.ctx, buff);
				if (rv < 0) {
					ERR(rv);
					return -11;
				}
			}

			// Handle custom server side commands
			rv = custom_command_handler(buff, len);
			if (rv) {
				ERR(rv);
				return -12;
			}

			memset(buff, 0, TRANS_BUFF_SIZE);

			// Get some data from the socket
			len = recv_encrypted(con.sock, &con.ctx, buff);
			if (len > 0) {
				len = write(STDOUT_FILENO, buff,
					    TRANS_BUFF_SIZE);
				if (len < 0) {
					ERR(len);
					return -13;
				}

			} else if (len < 0) {
				ERR(len);
				return -14;
			}

			if (usleep(25000)) {
				return -15;
			}
		}

		rv = close(con.sock);
		if (rv) {
			ERR(rv);
			return -16;
		}
	}

	rv = close(sock);
	if (rv) {
		ERR(rv);
		return -17;
	}
	return 0;
}
