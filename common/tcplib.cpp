#include "common.h"

int tcplib:: createSocket(void)
{
	return (socket(AF_INET, SOCK_STREAM, 0));
}

int tcplib::listen2Socket(int fd, SockIn_t *addr, int len)
{
	int ret = 0;
	ret = bind(fd, (Sock_t *)addr, len);
	if(ret != 0)
	{
		perror("bind");
		ret = -1;
	}
	else
	{
		if(listen(fd, 2) == -1)
		{
			perror("listen");
			ret = -1;
		}
	}
	return ret;
}

int tcplib::tcpaccept(int fd, SockIn_t *addr)
{
	int len = sizeof(Sock_t);

	int clifd = accept(fd, (Sock_t *)addr, (socklen_t *)&len);
	if(clifd == -1)
	{
		perror("accept");
	}
	return clifd;
}

int tcplib::tcpconnect(int fd, SockIn_t *addr)
{
	if(connect(fd, (Sock_t *)addr, sizeof(Sock_t)) == -1)
	{
		perror("connect");
		return -1;
	}
	else
	{
		return 0;
	}
}

void tcplib::closeSD(int fd)
{
	close(fd);
}

int tcplib::tcprecv(int fd, SockIn_t *addr, char *buf, int len)
{
	socklen_t slen = sizeof(Sock_t);
	return (recvfrom(fd, buf, len, 0, (Sock_t *)addr, &slen) );
}

int tcplib::tcpsend(int fd, SockIn_t *addr, char *buf, int len)
{
	return ( sendto(fd, buf, len, 0, (Sock_t *)addr, sizeof(Sock_t)) );
}


