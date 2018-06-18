/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <crypto/cryptodev.h>
#include <sys/ioctl.h>

#include "socket-common.h"

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

ssize_t insist_read(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
		ret = read(fd, buf, cnt);
        if (ret < 0)
                return ret;
        buf += ret;
        cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[])
{
	int sd, port;
	ssize_t n;
	char buf[256], tmpbuff[256], iv[16];
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	
	int cfd = open("/dev/crypto", O_RDWR);
	struct session_op sess;
	struct crypt_op crypt;
	
	memset(&sess, 0, sizeof(sess));
	memset(&crypt, 0, sizeof(crypt));
	memset(iv, 0x0, sizeof(iv));
	
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = 16;
	sess.key = (unsigned char *) CRYPTOKEY;
	ioctl(cfd, CIOCGSESSION, &sess);
	crypt.ses = sess.ses;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");

	/* Be careful with buffer overruns, ensure NUL-termination */
	strncpy(buf, HELLO_THERE, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';
	
	// ENCRYPT
	crypt.len = sizeof(buf);
	crypt.src = (unsigned char *) buf;
	crypt.dst = (unsigned char *) tmpbuff;
	crypt.iv = (unsigned char *) iv;
	crypt.op = COP_ENCRYPT;
	ioctl(cfd, CIOCCRYPT, &crypt);
	// ENCRYPT
	
#ifdef DEBUG
print_encrypted(tmpbuff, sizeof(tmpbuff));
#endif

	/* Say something... */
	if (insist_write(sd, tmpbuff, sizeof(tmpbuff)) != sizeof(tmpbuff)) {
		perror("write");
		exit(1);
	}
	printf("CLIENT: %s\n", buf);
	fflush(stdout);

	/* Read answer and write it to standard output */
	char inbuf[256];
	for (;;) {
		bzero(buf, sizeof(buf));
		bzero(inbuf, sizeof(inbuf));
		bzero(tmpbuff, sizeof(tmpbuff));
		n = read(sd, buf, sizeof(buf));

		if (n < 0) {
			perror("read");
			exit(1);
		}

		if (n <= 0)
			break;
			
		// DECRYPT
		crypt.len = sizeof(buf);
		crypt.src = (unsigned char *) buf;
		crypt.dst = (unsigned char *) tmpbuff;
		crypt.iv = (unsigned char *) iv;
		crypt.op = COP_DECRYPT;
		ioctl(cfd, CIOCCRYPT, &crypt);
		// DECRYPT
		
		fprintf(stdout, "SERVER: %s", (char *) tmpbuff);
		fprintf(stdout, "CLIENT: ");
		fflush(stdout);
		n = read(0, inbuf, sizeof(inbuf));
		inbuf[sizeof(inbuf) - 1] = '\0';
		fflush(stdin);
		
		// ENCRYPT
		crypt.len = sizeof(inbuf);
		crypt.src = (unsigned char *) inbuf;
		crypt.dst = (unsigned char *) tmpbuff;
		crypt.iv = (unsigned char *) iv;
		crypt.op = COP_ENCRYPT;
		ioctl(cfd, CIOCCRYPT, &crypt);
		// ENCRYPT
		
		if (insist_write(sd, tmpbuff, sizeof(tmpbuff)) != sizeof(tmpbuff)) {
			perror("write");
			exit(1);
		}
	}

	fprintf(stderr, "\nDone.\n");
	ioctl(cfd, CIOCFSESSION);
	close(cfd);
	return 0;
}
