/* tests/test_configuration.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"
#include "scep_tests.h"
#include "test_message_common.c"

void make_unwrap_message()
{
	scep_pkcsreq(handle, req, sig_cert, sig_key, enc_cacert, &p7);

	ck_assert(p7 != NULL);

	pkiMessage = NULL;
	ck_assert(scep_unwrap(
		handle, p7, sig_cacert, enc_cacert, enc_cakey, &pkiMessage) == SCEPE_OK);

	/*same for server response*/

	pkiMessage_certrep = NULL;
	/*complementary parameters correct?*/
	ck_assert(scep_unwrap_response(
		handle, certrep_pending, sig_cacert, enc_cert, enc_key, SCEPOP_PKCSREQ, &pkiMessage_certrep) == SCEPE_OK);

	ck_assert(scep_unwrap_response(
		handle, certrep_failure, sig_cacert, enc_cert, enc_key, SCEPOP_PKCSREQ, &pkiMessage_failure) == SCEPE_OK);

	ck_assert(scep_unwrap_response(
		handle, certrep_success, sig_cacert, enc_cert, enc_key, SCEPOP_PKCSREQ, &pkiMessage_success) == SCEPE_OK);
}

void free_unwrap_message()
{
    sk_X509_free(pkiMessage_success->certs);
    PKCS7_free(p7);
}

void make_unwrap_gci_message()
{
	scep_get_cert_initial(handle, req, sig_cert, sig_key, enc_cacert, enc_cacert, &p7);
	ck_assert(p7 != NULL);
	ck_assert(scep_unwrap(
		handle, p7, sig_cacert, enc_cacert, enc_cakey, &pkiMessage) == SCEPE_OK);
}

void free_unwrap_gci_message()
{
	PKCS7_ISSUER_AND_SUBJECT_free(pkiMessage->issuer_and_subject);
	free(pkiMessage);
	PKCS7_free(p7);
}

void make_unwrap_gc_message()
{
	ASN1_INTEGER *serial = X509_get_serialNumber(sig_cert);
	X509_NAME *issuer = X509_get_issuer_name(sig_cert);
	ck_assert(scep_get_cert(
		handle, sig_cert, sig_key,
		issuer, serial, enc_cacert, &p7) == SCEPE_OK);
	ck_assert(p7 != NULL);
	ck_assert(scep_unwrap(
		handle, p7, sig_cacert, enc_cacert, enc_cakey, &pkiMessage) == SCEPE_OK);
}

void free_unwrap_gc_message()
{
	PKCS7_ISSUER_AND_SERIAL_free(pkiMessage->issuer_and_serial);
	free(pkiMessage);
	PKCS7_free(p7);
}

void make_unwrap_gcrl_message()
{
	ck_assert(scep_get_crl(
		handle, sig_cert, sig_key,
		sig_cert, enc_cacert, &p7) == SCEPE_OK);
	ck_assert(p7 != NULL);
	ck_assert(scep_unwrap(
		handle, p7, sig_cacert, enc_cacert, enc_cakey, &pkiMessage) == SCEPE_OK);
}

void free_unwrap_gcrl_message()
{
	PKCS7_ISSUER_AND_SERIAL_free(pkiMessage->issuer_and_serial);
	free(pkiMessage);
	PKCS7_free(p7);
}

void unwrap_setup()
{
	generic_setup();
}

void unwrap_teardown()
{
	generic_teardown();
}

START_TEST(test_unwrap_message)
{
	make_unwrap_message();

	ck_assert_int_ne(NULL, pkiMessage_success);
	ck_assert_str_eq(
		"2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
		pkiMessage_success->transactionID);
	ck_assert_str_eq(SCEP_MSG_CERTREP_STR, pkiMessage_success->messageType_str);
	ck_assert_int_eq(SCEP_MSG_CERTREP, pkiMessage_success->messageType);
	ck_assert_int_ne(NULL, (char*)(pkiMessage_success->senderNonce));
	ck_assert_int_ne(NULL, (char*)(pkiMessage_success->recipientNonce));
	ck_assert_int_eq(SCEP_SUCCESS, pkiMessage_success->pkiStatus);
	/*TODO: this test should fail...*/
	ck_assert_int_eq(0, pkiMessage_success->failInfo);
	/*for every kind of request, a SUCCESS response will have a degen p7 structure */
	ck_assert_int_eq(sk_X509_num(pkiMessage_success->certs), 1);

	ck_assert_int_ne(NULL, pkiMessage_failure);
	ck_assert_str_eq(
		"2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
		pkiMessage_failure->transactionID);
	ck_assert_str_eq(SCEP_MSG_CERTREP_STR, pkiMessage_failure->messageType_str);
	ck_assert_int_eq(3, pkiMessage_failure->messageType);
	/*TODO: check improving, some values might be not NULL and still invalid*/
	ck_assert_int_ne(NULL, (char*)(pkiMessage_failure->senderNonce));
	ck_assert_int_ne(NULL, (char*)(pkiMessage_failure->recipientNonce));
	//next test shoud work on own implementation but not necessary on other ones
	//ck_assert_str_eq((char*)(pkiMessage_failure->senderNonce), (char*)(pkiMessage_failure->recipientNonce));
	ck_assert_int_eq(SCEP_FAILURE, pkiMessage_failure->pkiStatus);
	ck_assert_int_eq(0, pkiMessage_failure->failInfo);
	ck_assert_int_eq(pkiMessage_failure->certs, NULL);


	ck_assert_int_ne(NULL, pkiMessage_certrep);
	ck_assert_str_eq(
		"2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
		pkiMessage_certrep->transactionID);
	ck_assert_str_eq(SCEP_MSG_CERTREP_STR, pkiMessage_certrep->messageType_str);
	ck_assert_int_eq(3, pkiMessage_certrep->messageType);
	ck_assert_int_ne(NULL, (char*)(pkiMessage_certrep->senderNonce));
	ck_assert_int_ne(NULL, (char*)(pkiMessage_certrep->recipientNonce));
	//next test shoud work on own implementation but not necessary on other ones
	//ck_assert_str_eq((char*)(pkiMessage_certrep->senderNonce), (char*)(pkiMessage_certrep->recipientNonce));

	ck_assert_int_eq(SCEP_PENDING, pkiMessage_certrep->pkiStatus);
	ck_assert_int_eq(pkiMessage_certrep->certs, NULL);

	ck_assert_int_ne(NULL, pkiMessage);
	ck_assert_int_eq(0, pkiMessage->initialEnrollment);
	ck_assert_str_eq(
		"2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
		pkiMessage->transactionID);
	ck_assert_str_eq(SCEP_MSG_PKCSREQ_STR, pkiMessage->messageType_str);
	ck_assert_int_eq(SCEP_MSG_PKCSREQ, pkiMessage->messageType);
	ck_assert_int_ne(NULL, pkiMessage->request);
	ck_assert_int_ne(NULL, pkiMessage->senderNonce);
	ck_assert_str_eq("FOOBARTESTPWD", ASN1_STRING_data(pkiMessage->challenge_password->value.printablestring));

	free_unwrap_message();
}
END_TEST

START_TEST(test_unwrap_getcertinitial)
{
	make_unwrap_gci_message();
	ck_assert_int_eq(X509_NAME_cmp(pkiMessage->issuer_and_subject->issuer, X509_get_subject_name(sig_cacert)), 0);
	ck_assert_int_eq(X509_NAME_cmp(pkiMessage->issuer_and_subject->subject, X509_REQ_get_subject_name(req)), 0);
	free_unwrap_gci_message();
}
END_TEST

START_TEST(test_unwrap_getcert)
{
	make_unwrap_gc_message();
	ck_assert_int_eq(X509_NAME_cmp(pkiMessage->issuer_and_subject->issuer, X509_get_subject_name(sig_cacert)), 0);
	ck_assert_int_eq(ASN1_INTEGER_cmp(pkiMessage->issuer_and_serial->serial, X509_get_serialNumber(sig_cert)), 0);
	free_unwrap_gc_message();
}
END_TEST

START_TEST(test_unwrap_getcrl)
{
	make_unwrap_gcrl_message();
	ck_assert_int_eq(X509_NAME_cmp(pkiMessage->issuer_and_subject->issuer, X509_get_subject_name(sig_cacert)), 0);
	ck_assert_int_eq(ASN1_INTEGER_cmp(pkiMessage->issuer_and_serial->serial, X509_get_serialNumber(sig_cert)), 0);
	free_unwrap_gcrl_message();
}
END_TEST

START_TEST(test_invalid_sig)
{
	PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(certrep_pending), 0);
	ASN1_TYPE *t = PKCS7_get_signed_attribute(si, handle->oids->pkiStatus);
	ck_assert_int_ne(ASN1_STRING_set(t->value.printablestring, SCEP_PKISTATUS_SUCCESS, -1), 0);
	ck_assert_int_eq(scep_unwrap(
		handle, certrep_pending, sig_cacert, enc_cert, enc_key,
		&pkiMessage_certrep), SCEPE_OPENSSL);

}
END_TEST

START_TEST(test_unwrap_invalid_pkiStatus)
{
	PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(certrep_pending), 0);
	ASN1_TYPE *t = PKCS7_get_signed_attribute(si, handle->oids->pkiStatus);
	ck_assert(t != NULL);
	ck_assert_int_ne(ASN1_STRING_set(t->value.printablestring, "foobar", -1), 0);
	ck_assert_int_ne(PKCS7_SIGNER_INFO_set(si, sig_cert, sig_key, handle->configuration->sigalg), 0);
	ck_assert_int_ne(PKCS7_add_certificate(certrep_pending, sig_cert), 0);
	int res = PKCS7_SIGNER_INFO_sign(si);
	ck_assert_int_ne(res, 0);
	ck_assert_int_eq(scep_unwrap(
		handle, certrep_pending, sig_cacert, enc_cert, enc_key,
		&pkiMessage_certrep), SCEPE_PROTOCOL);
}
END_TEST


Suite * scep_message_suite(void)
{
	Suite *s = suite_create("Message");
	/*test Certrep*/
	add_certrep(s);

	/*test unwrapping*/
	TCase *tc_unwrap_msg = tcase_create("Unwrap Message");
	tcase_add_checked_fixture(tc_unwrap_msg, unwrap_setup, unwrap_teardown);
	tcase_add_test(tc_unwrap_msg, test_unwrap_getcertinitial);
	tcase_add_test(tc_unwrap_msg, test_unwrap_getcert);
	tcase_add_test(tc_unwrap_msg, test_unwrap_getcrl);
	tcase_add_test(tc_unwrap_msg, test_unwrap_message);
	tcase_add_test(tc_unwrap_msg, test_invalid_sig);
	tcase_add_test(tc_unwrap_msg, test_unwrap_invalid_pkiStatus);
	suite_add_tcase(s, tc_unwrap_msg);

	/* PKCSReq tests */
	add_pkcsreq(s);

	/* GetCertInitial tests */
	add_get_cert_initial(s);

	/* GetCert tests */
	add_get_cert(s);

	/* GetCRL tests */
	add_get_crl(s);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = scep_message_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
