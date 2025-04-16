#ifndef SSL_BASIC_H_
#define SSL_BASIC_H_

#include <openssl/ssl.h>

class SSLBasic
{
    SSL*    makeNewSSL(SSL_CTX* ctx);
    void    freeSSL(SSL* ssl);
};

#endif