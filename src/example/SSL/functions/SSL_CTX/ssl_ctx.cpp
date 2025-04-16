#include <ssl_ctx.h>

const SSL_METHOD* SSLCtx::getSSLMethod(int index) {
    switch(index) {
        case TLS_METHOD:
            return TLS_method();
        case TLS_SERVER_METHOD:
            return TLS_server_method();
        case TLS_CLIENT_METHOD:
            return TLS_client_method();
        default:
            return NULL;
    }
}

SSL_CTX* SSLCtx::makeNewSSLCTX(const SSL_METHOD* sslMethod) {
    SSL_CTX* sslCtx = SSL_CTX_new(sslMethod);
    if(!sslCtx) {
        return NULL;
    }

    return sslCtx;
}

void SSLCtx::freeSSLCTX(SSL_CTX* ctx) {
    SSL_CTX_free(ctx);
}

// void printSSLSessionNumber(SSL_CTX* sslCtx) {
//     std::cout << "세션 개수 : " << SSL_CTX_sess_number(sslCtx) << std::endl;
// }

// int main() {
//     SSL_CTX* sslCtx = makeSSL_CTX();

//     printSSLSessionNumber(sslCtx);
//     return 0;
// }