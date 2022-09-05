#include <iostream>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#include "openssl/ssl.h"
#include "openssl/err.h"

#define PORTNUM 2001
#define USAGE(x) printf("./ser or ./cli 2000 \"127.0.0.1\" \\n");

using namespace std;


typedef struct sockaddr Sock_t;
typedef struct sockaddr_in SockIn_t;

void showCerts(SSL *ssl);

class tcplib
{
	public:
		int createSocket(void);
		int listen2Socket(int fd, SockIn_t *addr, int len);
		int tcpaccept(int fd, SockIn_t *addr);
		int tcpconnect(int fd, SockIn_t *addr);
		void closeSD(int fd);
		int tcprecv(int fd, SockIn_t *addr, char *buf, int len);
		int tcpsend(int fd, SockIn_t *addr, char *buf, int len);
};

class tlslib
{
	public:
		SSL_CTX *InitCtx(int opt);

    		void ConfigCA(SSL_CTX *ctx, char *key, char *path);
		SSL *createSession(SSL_CTX *ctx, int fd);
		int tlsConnect(SSL *ssl);
		void tlsClose(SSL *ssl, SSL_CTX *ctx, int fd);
		int tlsRead(SSL *ssl, char *buf, int len);
		int tlsWrite(SSL *ssl, char *buf, int len);
		void LoadCerts(SSL_CTX *ctx, char *cert, char *pvtkey);
		int tlsAccept(SSL *ssl);
};
