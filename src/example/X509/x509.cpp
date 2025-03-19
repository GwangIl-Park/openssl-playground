#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include <iostream>

X509* callX509New() {
    X509* x509 = X509_new();
    if(!x509) {
        std::cerr << "x509 객체 생성 실패" << std::endl;
        return NULL;
    }

    return x509;
}

void callX509Free(X509* x509) {
    X509_free(x509);
}

int setNotBeforeAfter(X509* x509) {
    ASN1_TIME *notBefore = ASN1_TIME_new();
    if (!notBefore) {
        std::cerr << "notBefore 객체 생성 실패" << std::endl;
        return 0;
    }

    ASN1_TIME *notAfter = ASN1_TIME_new();
    if (!notAfter) {
        std::cerr << "notAfter 객체 생성 실패" << std::endl;
        return 0;
    }

    time_t notBeforeTime = time(NULL);
    time_t notAfterTime = notBeforeTime  + (365 * 24 * 60 * 60);

    if (!ASN1_TIME_set(notBefore, notBeforeTime)) {
        std::cerr << "notBefore 설정 실패" << std::endl;
        ASN1_TIME_free(notBefore);
        return 0;
    }

    if (!ASN1_TIME_set(notAfter, notAfterTime)) {
        std::cerr << "notAfter 설정 실패" << std::endl;
        ASN1_TIME_free(notAfter);
        return 0;
    }

    if (!X509_set1_notBefore(x509, notBefore)) {
        std::cerr << "x509에 notBefore 설정 실패" << std::endl;
        ASN1_TIME_free(notBefore);
        return 0;
    }

    if (!X509_set1_notAfter(x509, notAfter)) {
        std::cerr << "x509에 notAfter 설정 실패" << std::endl;
        ASN1_TIME_free(notAfter);
        return 0;
    }

    return 1;
}

void printNotBeforeAfter(const X509* x509) {
    const ASN1_TIME* notBefore = X509_get0_notBefore(x509);
    const ASN1_TIME* notAfter = X509_get0_notAfter(x509);

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "BIO 객체 생성 실패!" << std::endl;
        return;
    }

    if(ASN1_TIME_print(bio, notBefore) == 0) {
        std::cerr << "notBefore 출력 실패!" << std::endl;
        BIO_free(bio);
        return;
    }

    char buffer[128];
    int len = BIO_read(bio, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';  // 문자열 종료 처리
        std::cout << "notBefore: " << buffer << std::endl;
    } else {
        std::cerr << "notBefore를 읽는 데 실패했습니다." << std::endl;
    }

    if(ASN1_TIME_print(bio, notAfter) == 0) {
        std::cerr << "notAfter 출력 실패!" << std::endl;
        BIO_free(bio);
        return;
    }

    len = BIO_read(bio, buffer, sizeof(buffer) - 1);
    if (len > 0) {
        buffer[len] = '\0';  // 문자열 종료 처리
        std::cout << "notAfter: " << buffer << std::endl;
    } else {
        std::cerr << "notAfter 읽는 데 실패했습니다." << std::endl;
    }

    BIO_free(bio);  // BIO 객체 해제
}

int setPubkey(X509* x509) {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    
    if(X509_set_pubkey(x509, pkey) != 1) {
        std::cerr << "인증서에 공개키 설정 실패" << std::endl;
        return 0;
    }

    return 1;
}

void printPubkey(X509* x509) {
    EVP_PKEY* pkey = X509_get0_pubkey(x509);

    std::cout << "pubkey : ";
    BIO* outBio = BIO_new_fp(stdout, BIO_NOCLOSE);
    PEM_write_bio_PUBKEY(outBio, pkey);
}

int setSerialNumber(X509* x509) {
    ASN1_INTEGER *serialNumber = s2i_ASN1_INTEGER(NULL, "1");

    X509_set_serialNumber(x509, serialNumber);

    return 1;
}

void printSerialNumber(X509* x509) {
    ASN1_INTEGER *serialNumber = X509_get_serialNumber(x509);

    BIO* outBio = BIO_new_fp(stdout, BIO_NOCLOSE);

    std::cout << "serial number : ";
    i2a_ASN1_INTEGER(outBio, serialNumber);
    std::cout << std::endl;
}

int setVersion(X509* x509) {
    //if(!X509_set_version(x509, X509_VERSION_1)) {
    //if(!X509_set_version(x509, X509_VERSION_2)) {
    if(!X509_set_version(x509, X509_VERSION_3)) {
        std::cerr << "인증서 버전 설정 실패" << std::endl;
        return 0;
    }
    return 1;
}

void printVersion(X509* x509) {
    long version = X509_get_version(x509);

    std::cout << "인증서 버전 : " << version << std::endl;
}

int setSubjectAndIssuerName(X509* x509) {
    X509_NAME* subject = X509_NAME_new();
    X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, (unsigned char *)"KR", -1, -1, 0);  // 국가 (Country)
    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, (unsigned char *)"MyCompany", -1, -1, 0);  // 조직 (Organization)
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);  // 공통 이름 (Common Name)
    
    X509_NAME_add_entry_by_NID(subject, NID_organizationalUnitName, MBSTRING_ASC, (unsigned char *)"IT", -1, -1, 0); //조직 부서 (Organization Unit)

    X509_NAME_add_entry_by_OBJ(subject, OBJ_txt2obj("1.2.840.113549.1.9.1", 0), MBSTRING_ASC, (unsigned char *)"example@example.com", -1, -1, 0); //이메일 주소

    X509_set_subject_name(x509, subject);

    X509_set_issuer_name(x509, subject);

    return 1;
}

void printSubjectAndIssuerName(X509* x509) {
    X509_NAME* subject = X509_get_subject_name(x509);

    BIO *out = BIO_new_fp(stdout, BIO_NOCLOSE);
    std::cout << "subject 정보 : ";
    X509_NAME_print_ex(out, subject, 0, XN_FLAG_RFC2253);
    std::cout << std::endl;
    BIO_free(out);

    // for (int i = 0; i < X509_NAME_entry_count(subject); i++) {
    //     X509_NAME_ENTRY *entry = X509_NAME_get_entry(subject, i);
    //     ASN1_OBJECT *obj = X509_NAME_ENTRY_get_object(entry);
    //     ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);

    //     char obj_buf[128];
    //     OBJ_obj2txt(obj_buf, sizeof(obj_buf), obj, 0);

    //     std::cout << obj_buf << " = " << ASN1_STRING_get0_data(data) << std::endl;
    // }

    unsigned long subjectHash = X509_NAME_hash_ex(subject, NULL, NULL, NULL);
    std::cout << "Subject Hash : " << subjectHash << std::endl;
}

int main() {
    X509* x509 = callX509New();
    if(!x509) {
        return 0;
    }

    if(!setNotBeforeAfter(x509)) {
        return 0;
    }
    printNotBeforeAfter(x509);

    if(!setPubkey(x509)) {
        return 0;
    }
    printPubkey(x509);

    if(!setSerialNumber(x509)) {
        return 0;
    }
    printSerialNumber(x509);

    if(!setVersion(x509)) {
        return 0;
    }
    printVersion(x509);

    if(!setSubjectAndIssuerName(x509)) {
        return 0;
    }
    printSubjectAndIssuerName(x509);

    callX509Free(x509);
    return 0;
}