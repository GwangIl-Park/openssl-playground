#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

int main() {
    //SSL_library_init()
    // - in v1.1.0, SSL_library_init() and OpenSSL_add_ssl_algorithms() were deprecated in OPENSSL_init_ssl()

    //SSL_load_error_strings();
    // - in v1.1.0, ERR_load_crypto_strings(), SSL_load_error_strings(), and ERR_free_strings() were deprecated in OPENSSL_init_crypto() and OPENSSL_init_ssl()
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);

    // - in v3.0.0, deprecated
    //ERR_load_BIO_strings();

    // create a new SSL_CTX object, which holds various configuration and data relevant to SSL/TLS or DTLS session establishment
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if(!ctx) {
        std::cerr << "SSL_CTX_new failed" << std::endl;
        exit(-1);
    }

    //set verification flag for ctx
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    //SSL_CTX_load_verify_locations

    int result = SSL_CTX_use_certificate_file(ctx, "test.crt", SSL_FILETYPE_PEM);
    if(result != 1) {
        std::cerr << "SSL_CTX_use_certificate_file failed : " << ERR_reason_error_string(ERR_get_error()) << std::endl;
        exit(-1);
    }

    result = SSL_CTX_use_PrivateKey_file(ctx, "test.key", SSL_FILETYPE_PEM);
    if(result != 1) {
        std::cerr << "SSL_CTX_use_PrivateKey_file failed : " << ERR_reason_error_string(ERR_get_error()) << std::endl;
        exit(-1);
    }

    result = SSL_CTX_check_private_key(ctx);
    if(result != 1) {
        std::cerr << "SSL_CTX_check_private_key failed" << ERR_reason_error_string(ERR_get_error()) << std::endl;
        exit(-1);
    }

    int serverFd = socket(AF_INET, SOCK_STREAM, 0);
    if(serverFd == -1) {
        std::cerr << "create socket failed" << std::endl;
        exit(-1);
    }

    const int port = 8986;
    
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    result = bind(serverFd, (struct sockaddr*)&serverAddr, sizeof(sockaddr_in));
    if(result < 0) {
        std::cerr << "bind failed" << std::endl;
        exit(-1);
    }

    result = listen(serverFd, 5);
    if(result == -1) {
        std::cerr << "listen failed" << std::endl;
        exit(-1);
    }

    std::cout << "Server Start (port:" << port << ")" << std::endl;

    while(true) {
        struct sockaddr_in clientAddr;
        int len = sizeof(sockaddr_in);
        int clientFd = accept(serverFd, (struct sockaddr*)&clientAddr, (socklen_t*)&len);
        if(clientFd == -1) {
            std::cerr << "accept failed" << std::endl;
        exit(-1);
        }

        //creates a new SSL structure which is needed to hold the data for a TLS/SSL connection
        SSL* ssl = SSL_new(ctx);
        if(!ssl) {
            std::cerr << "SSL_new failed" << std::endl;
        exit(-1);
        }

        result = SSL_set_fd(ssl, clientFd);
        if(result == 0) {
            std::cerr << "SSL_set_fd failed" << std::endl;
        exit(-1);
        }

        SSL_set_accept_state(ssl);
        
        // tls handshake
        result = SSL_do_handshake((ssl));
        if(result <= 0) {
            std::cerr << "SSL_do_handshake failed" << std::endl;
        exit(-1);
        }

        char buffer[BUFFER_SIZE];
        memset(buffer, 0, BUFFER_SIZE);
        SSL_read(ssl, buffer, BUFFER_SIZE);
        std::cout << "receive from client : " << buffer << std::endl;

        const char* resp = "Hello\r\n";
        SSL_write(ssl, resp, strlen(resp));

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(clientFd);
    }

    SSL_CTX_free(ctx);
    close(serverFd);

    return 0;
}