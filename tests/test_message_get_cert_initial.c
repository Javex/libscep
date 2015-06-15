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
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
}

static void setup_engine()
{
    generic_engine_setup();
    p7 = make_message();
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message();
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
}

static void teardown()
{
    PKCS7_free(p7);
    PKCS7_free(p7_nosigcert);
    generic_teardown();
}

static SCEP_DATA *make_unwrap_message()
{
    PKCS7 *p7 = NULL;
    SCEP_DATA *data;
    SCEP_ERROR error = scep_get_cert_initial(handle, req, sig_cert, sig_key, enc_cacert, enc_cacert, &p7);
    ck_assert(error == SCEPE_OK);
    ck_assert(p7 != NULL);
    ck_assert(scep_unwrap(
        handle, p7, sig_cacert, enc_cacert, enc_cakey, &data) == SCEPE_OK);
    PKCS7_free(p7);
    return data;
}

static void free_unwrap_message(SCEP_DATA *data)
{
    SCEP_DATA_free(data);
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

START_TEST(test_unwrap)
{
    SCEP_DATA *data = make_unwrap_message();
    ck_assert_int_eq(X509_NAME_cmp(data->issuer_and_subject->issuer, X509_get_subject_name(sig_cacert)), 0);
    ck_assert_int_eq(X509_NAME_cmp(data->issuer_and_subject->subject, X509_REQ_get_subject_name(req)), 0);
    free_unwrap_message(data);
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

    TCase *tc_gci_msg_engine = tcase_create("GetCertInitial Message with Engine");
    tcase_add_checked_fixture(tc_gci_msg_engine, setup_engine, teardown);
    tcase_add_test(tc_gci_msg_engine, test_scep_message_transaction_id);
    tcase_add_test(tc_gci_msg_engine, test_scep_message_sender_nonce);
    tcase_add_test(tc_gci_msg_engine, test_scep_message_certificate);
    tcase_add_test(tc_gci_msg_engine, test_get_cert_initial);
    suite_add_tcase(s, tc_gci_msg_engine);

    TCase *tc_unwrap = tcase_create("GetCertInitial Unwrapping");
    tcase_add_unchecked_fixture(tc_unwrap, setup, teardown);
    tcase_add_test(tc_unwrap, test_unwrap);
    suite_add_tcase(s, tc_unwrap);

    TCase *tc_unwrap_engine = tcase_create("GetCertInitial Unwrapping with Engine");
    tcase_add_unchecked_fixture(tc_unwrap_engine, setup_engine, teardown);
    tcase_add_test(tc_unwrap_engine, test_unwrap);
    suite_add_tcase(s, tc_unwrap_engine);
}