#include <check.h>
#include "scep.h"
#include "test_message_common.c"

static PKCS7 *make_message()
{
    PKCS7 *p7;
    ck_assert(scep_get_cert_initial(
        handle, req, sig_cert, sig_key,
        sig_cacert, enc_cacert, &p7) == SCEPE_OK);
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

START_TEST(test_get_cert_initial)
{
    BIO *data = get_decrypted_data(p7, enc_cacert, enc_cakey);

    const unsigned char *data_buf;
    int data_buf_len = BIO_get_mem_data(data, &data_buf);
    ck_assert_int_ne(data_buf_len, 0);

    ck_assert_str_eq(
        SCEP_MSG_GETCERTINITIAL_STR,
        get_attribute_data(p7, handle->oids->messageType));

    PKCS7_ISSUER_AND_SUBJECT *ias = NULL;
    d2i_PKCS7_ISSUER_AND_SUBJECT(&ias, &data_buf, data_buf_len);
    ck_assert(ias != NULL);
    char *name = X509_NAME_oneline(ias->subject, NULL, 0);
    ck_assert_str_eq(name, "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=foo.bar");
    free(name);
    name = X509_NAME_oneline(ias->issuer, NULL, 0);
    ck_assert_str_eq(name, "/C=DE/ST=asdf/L=asdf/O=asdf/CN=ca");
    free(name);
    PKCS7_ISSUER_AND_SUBJECT_free(ias);
    BIO_free(data);
}
END_TEST

void add_get_cert_initial(Suite *s)
{
    TCase *tc_gci_msg = tcase_create("GetCertInitial Message");
    tcase_add_checked_fixture(tc_gci_msg, setup, teardown);
    tcase_add_test(tc_gci_msg, test_scep_message_transaction_id);
    tcase_add_test(tc_gci_msg, test_scep_message_sender_nonce);
    tcase_add_test(tc_gci_msg, test_scep_message_certificate);
    tcase_add_test(tc_gci_msg, test_get_cert_initial);
    suite_add_tcase(s, tc_gci_msg);
}