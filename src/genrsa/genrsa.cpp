#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "genrsa.h"

bool genRsa(unsigned int keyLength, const char* filePath) {
    // OpenSSL 초기화
    OPENSSL_init_crypto(0, NULL);

    EVP_PKEY* pkey = nullptr;

#ifdef SIMPLE_VERSION
    pkey = EVP_RSA_gen(keyLength);
#else
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    EVP_PKEY_keygen_init(pctx);

    OSSL_PARAM osslParams[2];
    osslParams[0] = OSSL_PARAM_construct_uint("bits", &keyLength);
    osslParams[1] = OSSL_PARAM_construct_end();
    EVP_PKEY_CTX_set_params(pctx, osslParams);

    EVP_PKEY_generate(pctx, &pkey);
#endif

    // 생성된 RSA 키를 PEM 형식으로 출력
    BIO* bio = BIO_new(BIO_s_file());
    BIO_write_filename(bio, (void*)filePath);
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL);

    BIO_free(bio);

#ifndef SIMPLE_VERSION
    EVP_PKEY_CTX_free(pctx);
#endif

    // OpenSSL 정리
    OPENSSL_cleanup();

    return 0;
}

int main() {
    unsigned int keyLength = 2048;
	genRsa(keyLength, "test.key");
	return 0;
}