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

    // 개인 키 생성
    EVP_PKEY* private_key = EVP_PKEY_new();
    EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(ec_key);
    EVP_PKEY_assign_EC_KEY(private_key, ec_key);

    // X.509 인증서 생성
    X509* x509_cert = X509_new();
    X509_set_version(x509_cert, 2); // X.509 버전 3으로 설정

    // 시리얼 넘버 설정
    ASN1_INTEGER_set(X509_get_serialNumber(x509_cert), 1);

    // 유효 기간 설정 (1년)
    X509_gmtime_adj(X509_get_notBefore(x509_cert), 0);
    X509_gmtime_adj(X509_get_notAfter(x509_cert), 31536000L);

    // 서브젝트 및 발급자 설정
    X509_NAME* name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"My Cert", -1, -1, 0);
    X509_set_subject_name(x509_cert, name);
    X509_set_issuer_name(x509_cert, name);

    // 공개 키 설정
    X509_set_pubkey(x509_cert, private_key);

    // 서명
    if (X509_sign(x509_cert, private_key, EVP_sha256())) {
        std::cerr << "Failed to sign the certificate" << std::endl;
        return 1;
    }

    // 인증서를 PEM 형식으로 출력
    BIO* bio = BIO_new(BIO_s_file());
    BIO_set_fp(bio, stdout, BIO_NOCLOSE);
    PEM_write_bio_X509(bio, x509_cert);

    // 메모리 해제
    BIO_free_all(bio);
    X509_free(x509_cert);
    EVP_PKEY_free(private_key);
    X509_NAME_free(name);

    // OpenSSL 정리
    OPENSSL_cleanup();

    return 0;
}
