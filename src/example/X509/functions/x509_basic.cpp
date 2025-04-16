#include <x509_basic.h>
#include <iostream>

X509* X509Basic::makeNewX509() {
    X509* x509 = X509_new();
    if(!x509) {
        std::cerr << "x509 객체 생성 실패" << std::endl;
        return NULL;
    }

    return x509;
}

void X509Basic::freeX509(X509* x509) {
    X509_free(x509);
}