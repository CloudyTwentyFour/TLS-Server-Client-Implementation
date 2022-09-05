# TLS-Server-Client-Implementation
Secure Communication using openssl(TLSv1.2) with wireshark files, key generation using openssl and much more

__Key Generation:__

First make sure to generate the keys/certificates required for secure communication such as

1. CA Keys

2. Server Public/Private Keys

3. Client Public/Private Keys

__Compilation:__

To compile the test application i.e., server and client apps 

make all

__Testing:__

__Usage:__

./ser portnumber "ipaddress"

For Ex:- ./ser 2000 "127.0.0.1"

./cli portnumber "ipaddress"

For Ex:- ./cli 2000 "127.0.0.1"



__Directory Structure:__

├── client

│   └── cli.cpp

├── common

│   ├── common.h

│   ├── tcplib.cpp

│   └── tlslib.cpp

├── key_generator.sh

├── keys

│   ├── ca

│   │   ├── ca_cert.pem

│   │   ├── ca_cert.srl

│   │   └── ca_key.pem

│   ├── client

│   │   ├── client_cert.pem

│   │   ├── client.csr

│   │   └── client_key.pem

│   └── server

│       ├── server_cert.pem

│       ├── server.csr

│       └── server_key.pem

├── logs

│   ├── One_Way_TLS.pcapng //One way authentication is captured in this log

│   └── Two_way_TLS.pcapng //Mutual Authentication or Two way authentication is captured in this log

├── Makefile

└── server

└── ser.cpp

