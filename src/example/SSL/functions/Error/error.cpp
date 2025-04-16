#include <openssl/ssl.h>
#include <iostream>

int main() {
    std::cout << SSL_alert_type_string(SSL_AD_DECODE_ERROR) << std::endl;
    std::cout << SSL_alert_type_string_long(SSL_AD_DECODE_ERROR) << std::endl;
    std::cout << SSL_alert_desc_string(SSL_AD_DECODE_ERROR) << std::endl;
    std::cout << SSL_alert_desc_string_long(SSL_AD_DECODE_ERROR) << std::endl;
    return 0;
}