#ifndef X509_BASIC_H_
#define X509_BASIC_H_

#include <openssl/x509.h>

class X509Basic
{
public:
    X509*   makeNewX509();
    void    freeX509(X509* x509);
};

#endif