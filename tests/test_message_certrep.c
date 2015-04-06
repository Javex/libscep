#include <check.h>
#include "scep.h"
#include "test_message_common.c"

static void make_message() {
    /*build pkcsreq*/
    /*TODO: build other request types*/
    SCEP_DATA *scep_message = NULL;
    ck_assert(scep_pkcsreq(
            handle, req, sig_cert, sig_key, enc_cacert, &p7) == SCEPE_OK);

    /*pkcsreq to SCEP_DATA*/
    ck_assert(scep_unwrap(
        handle, p7, sig_cacert, enc_cacert, enc_cakey, &scep_message) == SCEPE_OK);

    /*read in the rest*/
    BIO *b;
    X509 *issuedCert = NULL;
    b = BIO_new(BIO_s_mem());
    BIO_puts(b, issuedCert_str);
    PEM_read_bio_X509(b, &issuedCert, 0, 0);
    BIO_free(b);

    own_certrep_pending = NULL;
    ck_assert(scep_certrep(handle, scep_message->transactionID, scep_message->senderNonce, SCEP_PENDING, 0,
            NULL, sig_cacert, sig_cakey, NULL, NULL, NULL,
            &own_certrep_pending) == SCEPE_OK);

    ck_assert(scep_unwrap(
        handle, own_certrep_pending, sig_cacert, enc_cert, enc_key, &unwrap_own_certrep_pending) == SCEPE_OK);

    own_certrep_failure = NULL;
    ck_assert(scep_certrep(handle, scep_message->transactionID, scep_message->senderNonce, SCEP_FAILURE, SCEP_BAD_ALG,
            NULL, sig_cacert, sig_cakey, NULL, NULL, NULL,
            &own_certrep_failure) == SCEPE_OK);

    ck_assert(scep_unwrap(
        handle, own_certrep_failure, sig_cacert, enc_cert, enc_key, &unwrap_own_certrep_failure) == SCEPE_OK);

    own_certrep_success = NULL;
    STACK_OF(X509) *cert_stack = sk_X509_new_null();
    sk_X509_push(cert_stack, sig_cacert);
    ck_assert(scep_certrep(handle, scep_message->transactionID, scep_message->senderNonce, SCEP_SUCCESS, 0,
            issuedCert, sig_cacert, sig_cakey, enc_cert, cert_stack, NULL,
            &own_certrep_success) == SCEPE_OK);
    sk_X509_free(cert_stack);

    ck_assert(scep_unwrap(
        handle, own_certrep_success, sig_cacert, enc_cert, enc_key, &unwrap_own_certrep_success) == SCEPE_OK);
    X509_REQ_free(scep_message->request);
    free(scep_message);
}

static void free_message()
{
    PKCS7_free(unwrap_own_certrep_success->messageData);
    PKCS7_free(p7);
    free(unwrap_own_certrep_pending);
    free(unwrap_own_certrep_failure);
    free(unwrap_own_certrep_success);
}

static void setup()
{
    generic_setup();
    make_message();
}

static void teardown()
{
    free_message();
    generic_teardown();
}

START_TEST(test_certrep)
{
    ck_assert_int_ne(NULL, unwrap_own_certrep_pending);
    ck_assert_str_eq(
        "2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
        unwrap_own_certrep_pending->transactionID);
    ck_assert_str_eq(SCEP_MSG_CERTREP_STR, unwrap_own_certrep_pending->messageType_str);
    ck_assert_int_eq(SCEP_MSG_CERTREP, unwrap_own_certrep_pending->messageType);
    ck_assert_int_ne(NULL, (char*)unwrap_own_certrep_pending->senderNonce);
    ck_assert_int_ne(NULL, (char*)unwrap_own_certrep_pending->recipientNonce);
    ck_assert_int_eq(SCEP_PENDING, unwrap_own_certrep_pending->pkiStatus);

    ck_assert_int_ne(NULL, unwrap_own_certrep_failure);
    ck_assert_str_eq(
        "2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
        unwrap_own_certrep_failure->transactionID);
    ck_assert_str_eq(SCEP_MSG_CERTREP_STR, unwrap_own_certrep_failure->messageType_str);
    ck_assert_int_eq(SCEP_MSG_CERTREP, unwrap_own_certrep_failure->messageType);
    ck_assert_int_ne(NULL, (char*)unwrap_own_certrep_failure->senderNonce);
    ck_assert_int_ne(NULL, (char*)unwrap_own_certrep_failure->recipientNonce);
    ck_assert_int_eq(SCEP_FAILURE, unwrap_own_certrep_failure->pkiStatus);
    ck_assert_int_eq(0, unwrap_own_certrep_failure->failInfo);

    ck_assert_int_ne(NULL, unwrap_own_certrep_success);
    ck_assert_str_eq(
        "2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
        unwrap_own_certrep_success->transactionID);
    ck_assert_str_eq(SCEP_MSG_CERTREP_STR, unwrap_own_certrep_success->messageType_str);
    ck_assert_int_eq(SCEP_MSG_CERTREP, unwrap_own_certrep_success->messageType);
    ck_assert_int_ne(NULL, (char*)unwrap_own_certrep_success->senderNonce);
    ck_assert_int_ne(NULL, (char*)unwrap_own_certrep_success->recipientNonce);
    ck_assert_int_eq(SCEP_SUCCESS, unwrap_own_certrep_success->pkiStatus);
    BIO *b = BIO_new(BIO_s_mem());
    ck_assert_int_ne(0, PEM_write_bio_PKCS7(b, unwrap_own_certrep_success->messageData));
    BIO_free(b);
}
END_TEST

void add_certrep(Suite *s)
{
    TCase *tc_certrep_msg = tcase_create("Certrep Message");
    tcase_add_checked_fixture(tc_certrep_msg, setup, teardown);
    tcase_add_test(tc_certrep_msg, test_certrep);
    suite_add_tcase(s, tc_certrep_msg);
}