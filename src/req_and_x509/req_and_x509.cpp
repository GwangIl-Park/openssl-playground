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

#define CSR_DEBUG

struct CertificateData {
    const unsigned char* countryName;
    const unsigned char* stateOrProvinceName;
    const unsigned char* organizationName;
    const unsigned char* localityName;
    const unsigned char* commonName;
    const char* signatureHash;
};

const EVP_MD* getMessageDigest(const char* signatureHash) {
    if(signatureHash == "SHA1") {
        return EVP_sha1();
    } else if(signatureHash == "SHA256") {
        return EVP_sha256();
    } else if(signatureHash == "SHA384") {
        return EVP_sha384();
    } else if(signatureHash == "SHA512") {
        return EVP_sha512();
    }
}

X509_REQ* makeCSR(CertificateData* certificateData) {
    X509_REQ* csr = X509_REQ_new();
    X509_NAME* subject = X509_NAME_new();

    X509_NAME_add_entry_by_txt(subject, "countryName", MBSTRING_ASC, certificateData->countryName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "stateOrProvinceName", MBSTRING_ASC, certificateData->stateOrProvinceName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "organizationName", MBSTRING_ASC, certificateData->organizationName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "localityName", MBSTRING_ASC, certificateData->localityName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "commonName", MBSTRING_ASC, certificateData->commonName, -1, -1, 0);

	X509_REQ_set_subject_name(csr, subject);
	X509_NAME_free(subject);

    STACK_OF(X509_EXTENSION*) exts = sk_X509_EXTENSION_new_null();
    sk_X509_EXTENSION_push(exts, X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "DNS:example.com"));
    sk_X509_EXTENSION_push(exts, X509V3_EXT_conf_nid(NULL, NULL, NID_subject_alt_name, "DNS:example2.com"));

    X509_REQ_add_extensions(csr, exts);

    EVP_PKEY *pkey = nullptr;

    BIO* bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, (void*)"test.key");
    PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);

	X509_REQ_set_pubkey(csr, pkey);

	const EVP_MD* message_digest = getMessageDigest(certificateData->signatureHash);

	if(!X509_REQ_sign(csr, pkey, message_digest)) {
        std::cout << "req sign fail" << std::endl;
        return NULL;
    }

    BIO_free(bio);

    return csr;
}

bool makeX509(X509_REQ* csr, CertificateData* certificateData) {
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CRYPTO_STRINGS | OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, nullptr);

    BIO* bio = BIO_new(BIO_s_file());

    X509* rootCert = nullptr;
    BIO_read_filename(bio, (void*)"rootCA.crt");
    PEM_read_bio_X509(bio, &rootCert, NULL, NULL);

    X509* cert = X509_new();
    X509_set_version(cert, 2);

    X509_set_issuer_name(cert, X509_get_subject_name(rootCert));
    X509_set_subject_name(cert, X509_REQ_get_subject_name(csr));
    EVP_PKEY* pkey = X509_REQ_get_pubkey(csr);
    X509_set_pubkey(cert, pkey);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L);

    EVP_PKEY* rootKey = nullptr;
    BIO_read_filename(bio, (void*)"rootCA.key");
    PEM_read_bio_PrivateKey(bio, &rootKey, NULL, NULL);

    // create a message digest
	const EVP_MD* message_digest = getMessageDigest(certificateData->signatureHash);

    X509_sign(cert, rootKey, message_digest);

    BIO_write_filename(bio, (void*)"test.crt");

    int ret = X509_print_ex(bio, cert, 0, 0);

    PEM_write_bio_X509(bio, cert);

    // OpenSSL 정리
    OPENSSL_cleanup();

    return true;
}

int main() {
    CertificateData certificateData;
    certificateData.commonName          = (const unsigned char*)"test.com";
    certificateData.countryName         = (const unsigned char*)"KR";
    certificateData.localityName        = (const unsigned char*)"Seoul";
    certificateData.organizationName    = (const unsigned char*)"test";
    certificateData.stateOrProvinceName = (const unsigned char*)"Seoul";
    certificateData.signatureHash       = "SHA512";
    
    X509_REQ* csr = makeCSR(&certificateData);

#ifdef CSR_DEBUG
    BIO* bio = BIO_new(BIO_s_file());
    BIO_write_filename(bio, (void*)"test.csr");

    int ret = X509_REQ_print_ex(bio, csr, 0, 0);
    if(!ret) {
        std::cout << "fail" << std::endl;
    }

    PEM_write_bio_X509_REQ(bio, csr);
#endif

    makeX509(csr, &certificateData);

    return 0;
}