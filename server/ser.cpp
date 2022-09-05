#include "../common/common.h"
#include <signal.h>

int fd;
int clisd;

void ctrlz(int signum)
{
	close(clisd);
	close(fd);
	cout << "closed all the socket\n";
}

void segfalt(int signum)
{
	close(clisd);
	close(fd);
	cout << "closed due to segmentation fault\n";
}

int main(int argc, char **argv)
{
	class tcplib ser;
	class tlslib tls;

	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	char buf2[] = "Sent from server";
	char buf[100];
	SockIn_t seraddr, cliaddr;
	char cert[] = "./keys/server/server_cert.pem";
	char key[] = "./keys/server/server_key.pem";
	char cakey[] = "./keys/ca/ca_cert.pem";
	char capath[] = "./keys/ca/";
	int port = PORTNUM;
	char ip[20] = "127.0.0.1";


	if(argc <= 0 && argc > 3)
	{
		USAGE("cli");
		return 0;
	}
	else
	{
		port = atoi(argv[1]);
		(void)strcpy(ip, argv[2]);
		printf("IP Address: %s & Port: 0x%x\n",ip, port);
	}

	signal(SIGTSTP, ctrlz);
        signal(SIGSEGV, segfalt);	

	fd = ser.createSocket();
	if(fd <= 0)
	{
		ser.closeSD(fd);
	}
	else
	{
		ctx = tls.InitCtx(1);
		if(ctx == NULL)
		{
			return 0;
		}
		
		tls.LoadCerts(ctx, cert, key);
		tls.ConfigCA(ctx, cakey, capath);

		seraddr.sin_family = AF_INET;
		seraddr.sin_addr.s_addr = inet_addr(ip);
		seraddr.sin_port = htons(port);
		if(ser.listen2Socket(fd, &seraddr, sizeof(seraddr)) != -1)
		{
			cout << "Waiting for client\n";
			clisd = ser.tcpaccept(fd, &seraddr);
			if(clisd < 0)
			{
				return 0;
			}
			else
			{
				ssl = tls.createSession(ctx, clisd);
				if(ssl == NULL)
				{
					return 0;
				}
				if( tls.tlsAccept(ssl) == -1)
				{
					return 0;
				}

				tls.tlsRead(ssl, buf, 100);
				cout << buf << endl;
				tls.tlsWrite(ssl, buf2, strlen(buf2));
			}
		}
	}
	
	return 0;
}
