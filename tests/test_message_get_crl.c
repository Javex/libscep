#include <check.h>
#include "scep.h"
#include "test_message_common.c"
static PKCS7 *make_message()
{
    PKCS7 *p7;
    ck_assert(scep_get_crl(
        handle, sig_cert, sig_key,
        sig_cert, enc_cacert, &p7) == SCEPE_OK);
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

#ifdef WITH_ENGINE_TESTS
static void setup_engine()
{
    generic_engine_setup();
    p7 = make_message();
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message();
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
}
#endif /* WITH_ENGINE_TESTS */

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
    SCEP_ERROR error = scep_get_crl(
        handle, sig_cert, sig_key, sig_cert,
        enc_cacert, &p7);
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

START_TEST(test_get_crl)
{
    BIO *data = get_decrypted_data(p7, enc_cacert, enc_cakey);

    const unsigned char *data_buf;
    int data_buf_len = BIO_get_mem_data(data, &data_buf);
    ck_assert_int_ne(data_buf_len, 0);

    ck_assert_str_eq(
        SCEP_MSG_GETCRL_STR,
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

START_TEST(test_unwrap)
{
    SCEP_DATA *data = make_unwrap_message();
    ck_assert_int_eq(X509_NAME_cmp(data->issuer_and_subject->issuer, X509_get_subject_name(sig_cacert)), 0);
    ck_assert_int_eq(ASN1_INTEGER_cmp(data->issuer_and_serial->serial, X509_get_serialNumber(sig_cert)), 0);
    free_unwrap_message(data);
}
END_TEST

void add_get_crl(Suite *s)
{
    TCase *tc_gcrl_msg = tcase_create("GetCRL Message");
    tcase_add_checked_fixture(tc_gcrl_msg, setup, teardown);
    tcase_add_test(tc_gcrl_msg, test_scep_message_transaction_id_getcrl);
    tcase_add_test(tc_gcrl_msg, test_scep_message_sender_nonce);
    tcase_add_test(tc_gcrl_msg, test_scep_message_certificate);
    tcase_add_test(tc_gcrl_msg, test_get_crl);
    suite_add_tcase(s, tc_gcrl_msg);

    TCase *tc_unwrap = tcase_create("GetCRL Unwrapping");
    tcase_add_unchecked_fixture(tc_unwrap, setup, teardown);
    tcase_add_test(tc_unwrap, test_unwrap);
    tcase_add_test(tc_unwrap, test_unwrap_invalid_version);
    suite_add_tcase(s, tc_unwrap);

#ifdef WITH_ENGINE_TESTS
    /* We need a checked fixture on all engine tests, possibly because
     * the engine process cannot deal with the forking of check
     */
    TCase *tc_gcrl_msg_engine = tcase_create("GetCRL Message with Engine");
    tcase_add_checked_fixture(tc_gcrl_msg_engine, setup_engine, teardown);
    tcase_add_test(tc_gcrl_msg_engine, test_scep_message_transaction_id_getcrl);
    tcase_add_test(tc_gcrl_msg_engine, test_scep_message_sender_nonce);
    tcase_add_test(tc_gcrl_msg_engine, test_scep_message_certificate);
    tcase_add_test(tc_gcrl_msg_engine, test_get_crl);
    suite_add_tcase(s, tc_gcrl_msg_engine);

    TCase *tc_unwrap_engine = tcase_create("GetCRL Unwrapping with Engine");
    tcase_add_checked_fixture(tc_unwrap_engine, setup_engine, teardown);
    tcase_add_test(tc_unwrap_engine, test_unwrap);
    tcase_add_test(tc_unwrap_engine, test_unwrap_invalid_version);
    suite_add_tcase(s, tc_unwrap_engine);
#endif /* WITH_ENGINE_TESTS */
}