#ifndef X509_NAME_H_
#define X509_NAME_H_

#include <array>
#include <openssl/x509.h>

enum ENTRY_FIELD_ENUM {
    COMMON_NAME,
    ORGANIZATION,
    ORGANIZATION_UNIT,
    COUNTRY_NAME,
    STATE_OR_PROVINCE,
    LOCALITY,
    EMAIL,
    ENTRY_FIELD_COUNT
};

constexpr std::array<const char*, ENTRY_FIELD_COUNT> ENTRY_FIELD_TXT = 
{
    "C",
    "O",
    "OU",
    "C",
    "ST",
    "L",
    "emailAddress"
};

constexpr std::array<const char*, ENTRY_FIELD_COUNT> ENTRY_FIELD_OID = 
{
    "2.5.4.3",
    "2.5.4.10",
    "2.5.4.11",
    "2.5.4.6",
    "2.5.4.8",
    "2.5.4.7",
    "1.2.840.113549.1.9.1"
};

constexpr std::array<int, ENTRY_FIELD_COUNT> ENTRY_FIELD_NID = 
{
    NID_commonName,
    NID_organizationName,
    NID_organizationalUnitName,
    NID_countryName,
    NID_stateOrProvinceName,
    NID_localityName,
    NID_pkcs9_emailAddress
};

class X509NameFunc
{
public:
    X509_NAME*  newX509Name();
    int         addEntryByTxt(X509_NAME* x509Name, int entryIndex);
    int         addEntryByObj(X509_NAME* x509Name, int entryIndex);
    int         addEntryByNid(X509_NAME* x509Name, int entryIndex);
};

#endif