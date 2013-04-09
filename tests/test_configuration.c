#include <check.h>
#include <stdlib.h>
#include "../src/scep.h"

SCEP *handle;

void setup()
{
	handle = scep_init();
}

void teardown()
{
	scep_cleanup(handle);
}

START_TEST(test_scep_set_conf)
{
	SCEP_URL url;
	url.hostname = "example.com";
	url.path = "/path/to/scep";
	url.scheme = HTTP;
	url.port = 1337;

	scep_set_conf(handle, SCEPCFG_URL, &url);
	ck_assert_str_eq(handle->configuration->url->hostname, "example.com");
	ck_assert_str_eq(handle->configuration->url->path, "/path/to/scep");
	ck_assert(handle->configuration->url->scheme == HTTP);
	ck_assert(handle->configuration->url->port == 1337);
}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Configuration");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_scep_set_conf);

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
