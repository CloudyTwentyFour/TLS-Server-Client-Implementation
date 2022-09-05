#/bin/sh

#Create directory to store the keys and certificate
set +p
mkdir keys
cd ./keys
mkdir ca server client

#To Create CA key and certificate:
openssl req -x509 -nodes -days 3650 -newkey rsa:4096 -keyout ca/ca_key.pem -out ca/ca_cert.pem -subj "/C=US/ST=Acme State/L=Acme City/O=Acme Inc./CN=example.com"

#Generate Server private key
openssl genrsa -out server/server_key.pem 4096

#Generate server ceritificate signing request
openssl req -new -key server/server_key.pem -out server/server.csr -subj "/C=US/ST=Acme State/L=Acme City/O=Acme Inc./CN=server.example.com"

#Generate Client private key
openssl genrsa -out client/client_key.pem 4096

#Generate client ceritificate signing request
openssl req -new -key client/client_key.pem -out client/client.csr -subj "/C=US/ST=Acme State/L=Acme City/O=Acme Inc./CN=client.example.com"

#Generate server digital signing certificate
openssl x509 -req -days 1460 -in server/server.csr -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -CAcreateserial -out server/server_cert.pem

#Generate client digital signing ceritificate
openssl x509 -req -days 1460 -in client/client.csr -CA ca/ca_cert.pem -CAkey ca/ca_key.pem -CAcreateserial -out client/client_cert.pem

#To verify if the server or client certificate is signed by CA
openssl verify -CAfile ./ca/ca_cert.pem ./client/client_cert.pem

#or

openssl verify -CAfile ./ca/ca_cert.pem ./server/server_cert.pem
