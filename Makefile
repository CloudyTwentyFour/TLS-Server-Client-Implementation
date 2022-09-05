all: cli ser

ser:
	g++ ./server/ser.cpp ./common/tcplib.cpp ./common/tlslib.cpp ./common/common.h -o ser -lcrypto -lssl -fpermissive -g

cli:
	g++ ./client/cli.cpp ./common/tcplib.cpp ./common/tlslib.cpp ./common/common.h -o cli -lcrypto -lssl -fpermissive -g

clean:
	rm -rf cli ser
