#include <openssl/ssl.h>
#include <iostream>

SSL_CTX* makeSSL_CTX() {
    const SSL_METHOD* sslMethod = TLS_method();
    SSL_CTX* sslCtx = SSL_CTX_new(sslMethod);
    if(!sslCtx) {
        return NULL;
    }

    return sslCtx;
}

void printSSLSessionNumber(SSL_CTX* sslCtx) {
    std::cout << "세션 개수 : " << SSL_CTX_sess_number(sslCtx) << std::endl;
}

int main() {
    SSL_CTX* sslCtx = makeSSL_CTX();

    printSSLSessionNumber(sslCtx);
    return 0;
}