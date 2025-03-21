#include <x509_name.h>

X509_NAME* X509NameFunc::newX509Name() {
    X509_NAME* subject = X509_NAME_new();
    if(!subject) return NULL;

    return subject;
}

int X509NameFunc::addEntryByTxt(X509_NAME* x509Name, int entryIndex) {
    if(!X509_NAME_add_entry_by_txt(x509Name, ENTRY_FIELD_TXT[entryIndex], MBSTRING_ASC, (unsigned char *)"KR", -1, -1, 0)) {
        return 0;
    }

    return 1;
}

int X509NameFunc::addEntryByObj(X509_NAME* x509Name, int entryIndex) {
    if(!X509_NAME_add_entry_by_OBJ(x509Name, OBJ_txt2obj(ENTRY_FIELD_OID[entryIndex], 0), MBSTRING_ASC, (unsigned char *)"KR", -1, -1, 0)) {
        return 0;
    }
    
    return 1;
}

int X509NameFunc::addEntryByNid(X509_NAME* x509Name, int entryIndex) {
    if(!X509_NAME_add_entry_by_NID(x509Name, ENTRY_FIELD_NID[entryIndex], MBSTRING_ASC, (unsigned char *)"KR", -1, -1, 0)) {
        return 0;
    }
    
    return 1;
}