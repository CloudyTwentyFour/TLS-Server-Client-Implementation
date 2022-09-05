# TLS-Server-Client-Implementation
Secure Communication using openssl(TLSv1.2) with wireshark files, key generation using openssl and much more


Directory Structure:
.
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
│   ├── One_Way_TLS.pcapng
│   └── Two_way_TLS.pcapng
├── Makefile
└── server
    └── ser.cpp
