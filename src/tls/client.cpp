#include <iostream>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

int main() {
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if(!ctx) {
        std::cerr << "SSL_CTX_new failed" << std::endl;
        exit(-1);
    }

    int result;
    result = SSL_CTX_load_verify_locations(ctx, "rootCA.crt", nullptr);
    if(result != 1) {
        std::cerr << "SSL_CTX_load_verify_locations failed" << std::endl;
        exit(-1);
    }

    int clientFd = socket(AF_INET, SOCK_STREAM, 0);
    if(clientFd == -1) {
        std::cerr << "create socket failed" << std::endl;
        exit(-1);
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverAddr.sin_port = htons(8986);

    result = connect(clientFd, (sockaddr*)&serverAddr, sizeof(sockaddr_in));
    if(result == -1) {
        std::cerr << "connect failed" << std::endl;
        exit(-1);
    }

    SSL* ssl = SSL_new(ctx);
    if(!ssl) {
        std::cerr << "SSL_new failed" << std::endl;
        exit(-1);
    }
    SSL_set_fd(ssl, clientFd);

    result = SSL_connect(ssl);
    if(result == -1) {
        std::cerr << "SSL_connect failed" << std::endl;
        exit(-1);
    }

    result = SSL_get_verify_result(ssl);
    if(result != X509_V_OK) {
        std::cerr << "SSL_get_verify_result failed : result = " << result << " reason : " << ERR_lib_error_string(ERR_get_error()) << std::endl;
        exit(-1);
    }

    SSL_SESSION* session = SSL_get_session(ssl);
    SSL_SESSION_print_fp(stdout, session);


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