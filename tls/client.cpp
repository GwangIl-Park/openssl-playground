#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

void logErrorAndExit() {
    ERR_print_errors_fp(stderr);
    exit(-1);
}

int main() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx) {
        logErrorAndExit();
    }

    int clientFd = socket(AF_INET, SOCK_STREAM, 0);
    if(clientFd == -1) {
        logErrorAndExit();
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(8986);

    int result = connect(clientFd, (sockaddr*)&serverAddr, sizeof(sockaddr_in));
    if(result == -1) {
        logErrorAndExit();
    }

    SSL* ssl = SSL_new(ctx);
    if(!ssl) {
        logErrorAndExit();
    }
    SSL_set_fd(ssl, clientFd);

    result = SSL_connect(ssl);
    if(result == -1) {
        logErrorAndExit();
    }

    const char* msg = "Hello\r\n";

    SSL_write(ssl, msg, strlen(msg));

    char buffer[BUFFER_SIZE];
    SSL_read(ssl, buffer, BUFFER_SIZE);
    std::cout << "received from server : " << buffer << std::endl;

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(clientFd);
    SSL_CTX_free(ctx);

    return 0;
}