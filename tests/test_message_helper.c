#include <check.h>
#include "scep.h"
#include "scep_tests.h"

SCEP_ERROR PKCS7_get_content(PKCS7 *p7, PKCS7 **result) {
    BIO *pkcs7bio = NULL;
    PKCS7 *content = NULL;
    SCEP_ERROR error = SCEPE_OK;

    pkcs7bio = PKCS7_dataInit(p7, NULL);
    ck_assert(pkcs7bio != NULL);

    content = d2i_PKCS7_bio(pkcs7bio, NULL);
    ck_assert(content != NULL);

    *result = content;
finally:
    if(pkcs7bio)
        BIO_free_all(pkcs7bio);
    if(error != SCEPE_OK) {
        if(content)
            PKCS7_free(content);
    }
    return error;
}

BIO *get_decrypted_data(PKCS7 *p7, X509 *enc_cacert, EVP_PKEY *enc_cakey)
{
    /*client only*/
    PKCS7 *p7enc = NULL, *p7_inner;
    BIO *outbio;
    ck_assert(PKCS7_get_content(p7, &p7enc) == SCEPE_OK);
    outbio = BIO_new(BIO_s_mem());

    // version == 0
    char *v = i2s_ASN1_INTEGER(NULL, p7enc->d.enveloped->version);
    ck_assert_str_eq("0", v);
    free(v);

    // decrypt and check content
    PKCS7_decrypt(p7enc, enc_cakey, enc_cacert, outbio, 0);
    PKCS7_free(p7enc);
    return outbio;
}

ASN1_STRING *get_attribute(PKCS7 *message, int nid) {
    STACK_OF(PKCS7_SIGNER_INFO) *sk_si = PKCS7_get_signer_info(message);
    ck_assert(sk_PKCS7_SIGNER_INFO_num(sk_si) == 1);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk_si, 0);

    ASN1_TYPE *attr = PKCS7_get_signed_attribute(si, nid);
    return attr->value.printablestring;
}

char *get_attribute_data(PKCS7 *message, int nid) {
    return ASN1_STRING_data(get_attribute(message, nid));
}