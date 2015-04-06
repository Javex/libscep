#include <check.h>
#include "scep.h"
#include "test_message_common.c"

static PKCS7 *make_message()
{
    PKCS7 *p7;
    ASN1_INTEGER *serial = X509_get_serialNumber(sig_cert);
    X509_NAME *issuer = X509_get_issuer_name(sig_cert);
    ck_assert(scep_get_cert(
        handle, sig_cert, sig_key,
        issuer, serial, enc_cacert, &p7) == SCEPE_OK);
    return p7;
}

static void setup()
{
    generic_setup();
    p7 = make_message();
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message();
}

static void teardown()
{
    PKCS7_free(p7);
    PKCS7_free(p7_nosigcert);
    generic_teardown();
}

START_TEST(test_get_cert)
{
    BIO *data = get_decrypted_data(p7, enc_cacert, enc_cakey);
    const unsigned char *data_buf;
    int data_buf_len = BIO_get_mem_data(data, &data_buf);
    ck_assert_int_ne(data_buf_len, 0);

    ck_assert_str_eq(
        SCEP_MSG_GETCERT_STR,
        get_attribute_data(p7, handle->oids->messageType));

    PKCS7_ISSUER_AND_SERIAL *ias = NULL;
    d2i_PKCS7_ISSUER_AND_SERIAL(&ias, &data_buf, data_buf_len);
    ck_assert(ias != NULL);
    char *x = X509_NAME_oneline(ias->issuer, NULL, 0);
    ck_assert_str_eq(x, "/C=DE/ST=asdf/L=asdf/O=asdf/CN=ca");
    free(x);
    x = i2s_ASN1_INTEGER(NULL, ias->serial);
    ck_assert_str_eq("1", x);
    free(x);
    PKCS7_ISSUER_AND_SERIAL_free(ias);
    BIO_free(data);
}
END_TEST

void add_get_cert(Suite *s)
{
    TCase *tc_gc_msg = tcase_create("GetCert Message");
    tcase_add_checked_fixture(tc_gc_msg, setup, teardown);
    tcase_add_test(tc_gc_msg, test_scep_message_transaction_id_getcert);
    tcase_add_test(tc_gc_msg, test_scep_message_sender_nonce);
    tcase_add_test(tc_gc_msg, test_scep_message_certificate);
    tcase_add_test(tc_gc_msg, test_get_cert);
    suite_add_tcase(s, tc_gc_msg);
}