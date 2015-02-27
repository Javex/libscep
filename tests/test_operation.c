/* tests/test_configuration.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"

SCEP *handle;
BIO *scep_log;

#define TEST_SERVER "http://demo.openxpki.org/cgi-bin/scep/scep"

#define OSSL_TEST_TYPE_ONCE(var, cfg_enum, cfg_var, type) \
	var = type ## _new(); \
	error = scep_conf_set(handle, cfg_enum, var); \
	ck_assert(error == SCEPE_OK); \
	ck_assert(cfg_var == var)

#define OSSL_TEST_TYPE(var, cfg_enum, cfg_var, type) \
		OSSL_TEST_TYPE_ONCE(var, cfg_enum, cfg_var, type); \
		OSSL_TEST_TYPE_ONCE(var, cfg_enum, cfg_var, type)

void setup()
{
	ck_assert(scep_init(&handle) == SCEPE_OK);
	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, scep_log);
	scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
	scep_conf_set(handle, SCEPCFG_URL, TEST_SERVER);
}

void teardown()
{
	scep_cleanup(handle);
	BIO_flush(scep_log);
	BIO_free(scep_log);
}

START_TEST(test_scep_operation_getcacert)
{
	STACK_OF(X509) *certs;
	X509 *cert;
	SCEP_ERROR error;
	int i;
	error = scep_operation_getcacert(handle, NULL, &certs);
	ck_assert(error == SCEPE_OK);
	ck_assert(sk_X509_num(certs) > 0);
}
END_TEST


Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Configuration");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_scep_operation_getcacert);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = scep_conf_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
