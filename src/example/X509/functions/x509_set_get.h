#ifndef X509_SET_GET_H_
#define X509_SET_GET_H_

#include <openssl/x509.h>

class X509SetGetFunc
{
public:
    //편의상 현재 시간으로 고정
    int setNotBefore(X509* x509);
    //편의상 1년 후로 고정
    int setNotAfter(X509* x509);
    int setPubkey(X509* x509, EVP_PKEY* pkey);
    int setVersion(X509* x509, long version);
    int setSerialNumber(X509* x509, const char* serialNumber);
    int setSubjectName(X509* x509, X509_NAME* subject);
    int setIssuerName(X509* x509, X509_NAME* issuer);

    ASN1_TIME* getNotBefore(X509* x509);
    ASN1_TIME* getNotAfter(X509* x509);
    EVP_PKEY* getPubkey(X509* x509);
    long getVersion(X509* x509);
    ASN1_INTEGER* getSerialNumber(X509* x509);
    

};

#endif