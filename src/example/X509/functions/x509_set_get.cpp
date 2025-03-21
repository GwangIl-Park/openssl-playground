#include <x509_set_get.h>

int X509SetGetFunc::setNotBefore(X509* x509) {
    ASN1_TIME* notBefore = ASN1_TIME_new();
    if (!notBefore) {
        return 0;
    }

    time_t notBeforeTime = time(NULL);

    if (!ASN1_TIME_set(notBefore, notBeforeTime)) {
        ASN1_TIME_free(notBefore);
        return 0;
    }

    if (!X509_set1_notBefore(x509, notBefore)) {
        ASN1_TIME_free(notBefore);
        return 0;
    }

    return 1;
}

constexpr long ONE_YEAR = 365 * 24 * 60 * 60;

int X509SetGetFunc::setNotAfter(X509* x509) {
    ASN1_TIME* notAfter = ASN1_TIME_new();
    if (!notAfter) {
        return 0;
    }

    time_t notAfterTime = time(NULL) + ONE_YEAR;

    if (!ASN1_TIME_set(notAfter,notAfterTime)) {
        ASN1_TIME_free(notAfter);
        return 0;
    }

    if (!X509_set1_notAfter(x509, notAfter)) {
        ASN1_TIME_free(notAfter);
        return 0;
    }

    return 1;
}