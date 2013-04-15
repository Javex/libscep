/* tests/test_scep.c */

#include <check.h>
#include <stdlib.h>
#include "../src/scep.h"

#define TEST_ERRMSG(ival, sval) \
	ck_assert_str_eq(scep_strerror(ival), sval)

START_TEST(test_scep_strerror)
{
	int i;
	TEST_ERRMSG(SCEPE_OK, "No error");
	TEST_ERRMSG(SCEPE_MEMORY, "Not enough memory available");
	TEST_ERRMSG(SCEPE_INVALID_URL, "The given URL is invalid");
	TEST_ERRMSG(SCEPE_UNKNOWN_CONFIGURATION, "This configuration option is "
			"not known");
	TEST_ERRMSG(SCEPE_UNKOWN_OPERATION, "Operation is unknown or no operation "
			"specified");
	TEST_ERRMSG(SCEPE_MISSING_URL, "Missing URL configuration");
	TEST_ERRMSG(SCEPE_MISSING_CONFIG, "This operation was not configured");
	TEST_ERRMSG(SCEPE_MISSING_CSR, "You have to provide a CSR for the PKCSReq "
			"operation");
	TEST_ERRMSG(SCEPE_MISSING_REQ_KEY, "You have to provide the private key "
			"for which you want a certificate");
	TEST_ERRMSG(SCEPE_MISSING_CA_CERT, "The CA certificate is missing but is "
			"needed to encrypt the message for the server and/or extract "
			"certain values");
	TEST_ERRMSG(SCEPE_MISSING_SIGKEY, "If you provide a signature "
			"certificate, you also need to provide a signature key");
	TEST_ERRMSG(SCEPE_MISSING_SIGCERT, "If you provide a signature key, you "
			"also need to provide a signature certificate");
	TEST_ERRMSG(SCEPE_MISSING_CERT_KEY, "To request an existing certificate "
			"you need to provide the key for which it was created");
	TEST_ERRMSG(SCEPE_MISSING_CRL_CERT, "To request a CRL you need to provide "
			"the certificate which you want to validate");
	for(i=SCEPE_DUMMY_LAST_ERROR; i < 100; ++i)
		TEST_ERRMSG(i, "Unknown error");
}
END_TEST

Suite * scep_util_suite(void)
{
	Suite *s = suite_create("Util");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_scep_strerror);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = scep_util_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	srunner_set_fork_status(sr, CK_NOFORK);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
