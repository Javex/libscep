/* tests/test_configuration.c */

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

	/* TODO: test all paths:
	 * URL, PROXY, VERBOSITY, SIGALG, ENCALG,
	 * GETCACERT_*, PKCSREQ_*, GETCERT_*,
	 * GETCRL_*, GETNEXTCACERT_*
	 */

	scep_conf_set(handle, SCEPCFG_URL, &url);
	ck_assert_str_eq(handle->configuration->url->hostname, "example.com");
	ck_assert_str_eq(handle->configuration->url->path, "/path/to/scep");
	ck_assert(handle->configuration->url->scheme == HTTP);
	ck_assert(handle->configuration->url->port == 1337);

	url.hostname = "test.com";
	url.path = "";
	url.scheme = HTTPS;
	url.port = 8080;
	scep_conf_set(handle, SCEPCFG_PROXY, &url);
	ck_assert_str_eq(handle->configuration->proxy->hostname, "test.com");
	ck_assert_str_eq(handle->configuration->proxy->path, "");
	ck_assert(handle->configuration->proxy->scheme == HTTPS);
	ck_assert(handle->configuration->proxy->port == 8080);

	scep_conf_set(handle, SCEPCFG_ENCALG, TRIPLE_DES);
	ck_assert(handle->configuration->encalg == TRIPLE_DES);

	scep_conf_set(handle, SCEPCFG_SIGALG, MD5);
	ck_assert(handle->configuration->sigalg == MD5);

	scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
	ck_assert(handle->configuration->verbosity == DEBUG);

	scep_conf_set(handle, -1, NULL);
	//TODO: check error reporting once its implemented
}
END_TEST

START_TEST(test_scep_conf_url)
{
	SCEP_URL url;
	url.hostname = "example.com";
	url.path = "/path/to/scep";
	url.scheme = HTTP;
	url.port = 1337;

	scep_set_conf_url(handle, SCEPCFG_URL, &url);
	ck_assert_str_eq(handle->configuration->url->hostname, "example.com");
	ck_assert_str_eq(handle->configuration->url->path, "/path/to/scep");
	ck_assert(handle->configuration->url->scheme == HTTP);
	ck_assert(handle->configuration->url->port == 1337);

	// and now lets hit the default branch
	// TODO: check error reporting once its implemented
	scep_set_conf_url(handle, -1, &url);
}
END_TEST

START_TEST(test_scep_conf_encalg)
{
	scep_set_conf_encalg(handle, TRIPLE_DES);
	ck_assert(handle->configuration->encalg == TRIPLE_DES);
	scep_set_conf_encalg(handle, DES);
	ck_assert(handle->configuration->encalg == DES);
	scep_set_conf_encalg(handle, BLOWFISH);
	ck_assert(handle->configuration->encalg == BLOWFISH);
}
END_TEST

START_TEST(test_scep_conf_sigalg)
{
	scep_set_conf_sigalg(handle, MD5);
	ck_assert(handle->configuration->sigalg == MD5);
	scep_set_conf_sigalg(handle, SHA1);
	ck_assert(handle->configuration->sigalg == SHA1);
}
END_TEST

START_TEST(test_scep_conf_verbosity)
{
	scep_set_conf_verbosity(handle, FATAL);
	ck_assert(handle->configuration->verbosity == FATAL);
	scep_set_conf_verbosity(handle, ERROR);
	ck_assert(handle->configuration->verbosity == ERROR);
	scep_set_conf_verbosity(handle, WARN);
	ck_assert(handle->configuration->verbosity == WARN);
	scep_set_conf_verbosity(handle, INFO);
	ck_assert(handle->configuration->verbosity == INFO);
	scep_set_conf_verbosity(handle, DEBUG);
	ck_assert(handle->configuration->verbosity == DEBUG);
}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("Configuration");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_scep_set_conf);
	tcase_add_test(tc_core, test_scep_conf_url);
	tcase_add_test(tc_core, test_scep_conf_encalg);
	tcase_add_test(tc_core, test_scep_conf_sigalg);
	tcase_add_test(tc_core, test_scep_conf_verbosity);

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
