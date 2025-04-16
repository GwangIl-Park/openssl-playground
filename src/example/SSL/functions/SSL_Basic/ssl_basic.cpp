#include <ssl_basic.h>
#include <../SSL_CTX/ssl_ctx.h>

SSL* SSLBasic::makeNewSSL(SSL_CTX* ctx) {
    SSL* ssl = SSL_new(ctx);
    if(!ssl) {
        return NULL;
    }

    return ssl;
}

void SSLBasic::freeSSL(SSL* ssl) {
    SSL_free(ssl);
}