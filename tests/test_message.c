/* tests/test_configuration.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"
#include "scep_tests.h"
#include "test_message_common.c"

void unwrap_setup()
{
	generic_setup();
}

void unwrap_teardown()
{
	generic_teardown();
}

#ifdef _NOTDEFINED__
START_TEST(test_unwrap_message)
{
	make_unwrap_message();

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
#endif

Suite * scep_message_suite(void)
{
	Suite *s = suite_create("Message");
	/*test Certrep*/
	add_certrep(s);

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
