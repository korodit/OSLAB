/*
 * socket-common.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H

/* Compile-time options */
#define TCP_PORT    35001
#define TCP_BACKLOG 5

#define CRYPTOKEY "_Such_key_w0w_12"

#define HELLO_THERE "Initial Connection from peer!\n"


void print_encrypted(char *data, int len) {
    printf("\nEncrypted data:\n");
	int i;
	for (i = 0; i < len; i++) {
		printf("%x", data[i]);
	}
	printf("\n");
}

void print_decrypted(char *data, int len) {
    printf("\nDecrypted data:\n");
	int i;
	for (i = 0; i < len; i++) {
		printf("%c", data[i]);
	}
	printf("\n");
}


#endif /* _SOCKET_COMMON_H */

