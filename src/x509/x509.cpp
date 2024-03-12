#include <iostream>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

int main() {
    // OpenSSL 초기화
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);

    BIO* bio = BIO_new(BIO_s_file());

    X509* rootCert = nullptr;
    BIO_read_filename(bio, (void*)"rootCA.crt");
    PEM_read_bio_X509(bio, &rootCert, NULL, NULL);

    X509_REQ* req = nullptr;
    BIO_read_filename(bio, (void*)"test.csr");
    PEM_read_bio_X509_REQ(bio, &req, NULL, NULL);

    X509* cert = X509_new();
    X509_set_version(cert, 2);

    X509_set_issuer_name(cert, X509_get_subject_name(rootCert));
    X509_set_subject_name(cert, X509_REQ_get_subject_name(req));
    EVP_PKEY* pkey = X509_REQ_get_pubkey(req);
    X509_set_pubkey(cert, pkey);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    EVP_PKEY* rootKey = nullptr;
    BIO_read_filename(bio, (void*)"rootCA.key");
    PEM_read_bio_PrivateKey(bio, &rootKey, NULL, NULL);

    X509_sign(cert, rootKey, EVP_sha256());

    BIO_write_filename(bio, (void*)"test.crt");
    PEM_write_bio_X509(bio, cert);

    // OpenSSL 정리
    OPENSSL_cleanup();

    return 0;
}
