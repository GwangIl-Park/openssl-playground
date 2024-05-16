#include <iostream>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

struct CSRData {
    const unsigned char* countryName;
    const unsigned char* stateOrProvinceName;
    const unsigned char* organizationName;
    const unsigned char* localityName;
    const unsigned char* commonName;
    const char* signatureHash;
};

bool makeCSR(CSRData* csrData) {
    X509_REQ* req = X509_REQ_new();
    X509_NAME* subject = X509_NAME_new();

    X509_NAME_add_entry_by_txt(subject, "countryName", MBSTRING_ASC, csrData->countryName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "stateOrProvinceName", MBSTRING_ASC, csrData->stateOrProvinceName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "organizationName", MBSTRING_ASC, csrData->organizationName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "localityName", MBSTRING_ASC, csrData->localityName, -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "commonName", MBSTRING_ASC, csrData->commonName, -1, -1, 0);

	X509_REQ_set_subject_name(req, subject);
	X509_NAME_free(subject);

    EVP_PKEY *pkey = nullptr;

    BIO* bio = BIO_new(BIO_s_file());
    BIO_read_filename(bio, (void*)"test.key");
    PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL);

	// set certificate request public key
	X509_REQ_set_pubkey(req, pkey);

	// create a message digest
	const EVP_MD* message_digest;
    
    if(csrData->signatureHash == "SHA1") {
        message_digest = EVP_sha1();
    } else if(csrData->signatureHash == "SHA256") {
        message_digest = EVP_sha256();
    } else if(csrData->signatureHash == "SHA384") {
        message_digest = EVP_sha384();
    } else if(csrData->signatureHash == "SHA512") {
        message_digest = EVP_sha512();
    }

	// sign certificate request
	X509_REQ_sign(req, pkey, message_digest);

    BIO_write_filename(bio, (void*)"test.csr");

    int ret = X509_REQ_print_ex(bio, req, 0, 0);
    if(!ret) {
        std::cout << "fail" << std::endl;
    }

    PEM_write_bio_X509_REQ(bio, req);

    BIO_free(bio);
    OPENSSL_cleanup();

    return true;
}

int main() {
    CSRData csrData;
    csrData.commonName          = (const unsigned char*)"test.com";
    csrData.countryName         = (const unsigned char*)"KR";
//    csrData.emailAddress        = (const unsigned char*)"test@gmail.com";
    csrData.localityName        = (const unsigned char*)"Seoul";
    csrData.organizationName    = (const unsigned char*)"test";
    csrData.stateOrProvinceName = (const unsigned char*)"Seoul";
    csrData.signatureHash       = "SHA512";
    makeCSR(&csrData);
    return 0;
}