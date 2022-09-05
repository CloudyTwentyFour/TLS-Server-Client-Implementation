#include "common.h"

SSL_CTX *tlslib::InitCtx(int opt)
{
	SSL_METHOD *method = NULL;
	SSL_CTX *ctx = NULL;

	SSL_library_init();
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	if(opt == 1)
	{
		method = TLS_server_method();
	}
	else
	{
		method = TLS_client_method();
	}

	ctx = SSL_CTX_new(method);
	if(ctx == NULL)
	{
		ERR_print_errors_fp(stderr);
	}
	(void)SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
	return ctx;
}

void showCerts(SSL *ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);
	if(cert != NULL)
	{
		cout << "Server certificate\n";

		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		cout << "Subject:" << line << endl;

		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		free(line);
		
		X509_free(cert);
	}
	else
	{
		cout << "No client ceritifate configured\n";
	}
}

SSL *tlslib::createSession(SSL_CTX *ctx, int fd)
{
	SSL* ssl = NULL;
	ssl = SSL_new(ctx);

	if(ssl != NULL)
	{
		SSL_set_fd(ssl, fd);
	}
	else
	{
		cout << "SSL create session failed\n";
	}
	return ssl;
}

int tlslib::tlsConnect(SSL *ssl)
{
	if(SSL_connect(ssl) == -1)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	else
	{
		cout << "SSL COnnect success\n";
	}
	return 0;
}

void tlslib::tlsClose(SSL *ssl, SSL_CTX *ctx, int fd)
{
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(fd);
}

int tlslib::tlsRead(SSL *ssl, char *buf, int len)
{
	return SSL_read(ssl, buf, len);
}

int tlslib::tlsWrite(SSL *ssl, char *buf, int len)
{
        return SSL_write(ssl, buf, len);
}

void tlslib::ConfigCA(SSL_CTX *ctx,  char *key, char *path)
{
	if(SSL_CTX_load_verify_locations(ctx, key, path) == 0)
	{
		cout << "Could not set CA file location \n";
		cout << key << "\t" << path << endl;
	}
	else
	{
		SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(key));

		SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

		SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

		SSL_CTX_set_verify_depth(ctx, 1);
	}
}

void tlslib::LoadCerts(SSL_CTX *ctx, char *cert, char *pvtkey)
{
	
	if(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, pvtkey, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return;
	}
	if( !SSL_CTX_check_private_key(ctx))
	{
		cout << "Private key doesn't match public key certificate\n";
		return;
	}
}

int tlslib::tlsAccept(SSL *ssl)
{
	if(SSL_accept(ssl) == -1)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	else
	{
		showCerts(ssl);
		cout << "SSL Accept success\n";
	}
}


