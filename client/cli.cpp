#include "../common/common.h"

int main(int argc, char **argv)
{
	class tcplib cli;
	class tlslib tls;

	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;

	char cakey[] = "./keys/ca/ca_cert.pem";
	char key[] = "./keys/client/client_key.pem";
	char cert[] = "./keys/client/client_cert.pem";
	char path[] = "./keys/ca";
	int fd;
	char buf[100] = "Sent from Client";
	SockIn_t addr;
	int port = PORTNUM;
	char ip[16] = "127.0.0.1";

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

	fd = cli.createSocket();
	if(fd <= 0)
	{
		cout << "Socket failed\n";
		return 0;
	}
	else
	{
		ctx = tls.InitCtx(0);
		if(ctx == NULL)
		{
			return 0;
		}
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = inet_addr(ip);
		addr.sin_port = htons(port);
		if(cli.tcpconnect(fd, &addr) < 0)
		{
			return 0;
		}
		else
		{
			tls.LoadCerts(ctx, cert, key);
			tls.ConfigCA(ctx, cakey,path);
			ssl = tls.createSession(ctx, fd);
			if(ssl != NULL)
			{
				if(tls.tlsConnect(ssl) == -1)
				{
					return 0;
				}
			}
			else
			{
				return 0;
			}
			tls.tlsWrite(ssl, buf, strlen(buf));
			tls.tlsRead(ssl, buf, 100);
			cout << buf << endl;
		}
	}
	return 0;
}

