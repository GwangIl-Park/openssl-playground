#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main() {
    // OpenSSL 초기화
    OPENSSL_init_crypto(0, NULL);

    // RSA 키 생성
    RSA* keypair = RSA_new();
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_F4);  // RSA_F4는 65537를 의미

    // 키 길이 설정 (예: 2048비트)
    int keyLength = 2048;
    int ret = RSA_generate_key_ex(keypair, keyLength, bne, NULL);

    if (ret != 1) {
        std::cerr << "RSA key generation failed." << std::endl;
        return 1;
    }

    // 생성된 RSA 키를 PEM 형식으로 출력
    BIO* privateBio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(privateBio, keypair, NULL, NULL, 0, NULL, NULL);

    // 출력된 키를 문자열로 가져오기
    BUF_MEM* privateBioMem;
    BIO_get_mem_ptr(privateBio, &privateBioMem);

    // 출력
    std::cout << "Generated RSA Private Key:" << std::endl;
    std::cout << privateBioMem->data << std::endl;

    // 메모리 및 리소스 해제
    RSA_free(keypair);
    BN_free(bne);
    BIO_free(privateBio);

    // OpenSSL 정리
    OPENSSL_cleanup();

    return 0;
}
