/* tests/test_configuration.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"

SCEP *handle;

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
}

void teardown()
{
	scep_cleanup(handle);
}

START_TEST(test_scep_set_conf)
{
	char *url_string = "http://example.com:80/path/to/scep";
	char *url_string_test;
	int url_string_length;
	SCEP_ERROR error;
	X509 *test_cert;

	// check the defaults are set
	ck_assert(handle->configuration->verbosity == DEFAULT_VERBOSITY);
	ck_assert(handle->configuration->sigalg == DEFAULT_SIGALG);
	ck_assert(handle->configuration->encalg == DEFAULT_ENCALG);

	error = scep_conf_set(handle, SCEPCFG_URL, url_string);
	ck_assert(SCEPE_OK == error);
	uriToStringCharsRequiredA(handle->configuration->url, &url_string_length);
	url_string_length++;
	url_string_test = malloc(url_string_length);
	uriToStringA(url_string_test, handle->configuration->url,
			url_string_length, NULL);
	ck_assert_str_eq(url_string_test, url_string);
	free(url_string_test);


	url_string = "https://test.com:8080";
	error = scep_conf_set(handle, SCEPCFG_PROXY, url_string);
	ck_assert(SCEPE_OK == error);
	uriToStringCharsRequiredA(handle->configuration->proxy, &url_string_length);
	url_string_length++;
	url_string_test = malloc(url_string_length);
	uriToStringA(url_string_test, handle->configuration->proxy,
			url_string_length, NULL);
	ck_assert_str_eq(url_string_test, url_string);
	free(url_string_test);

	error = scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
	ck_assert(SCEPE_OK == error);
	ck_assert(handle->configuration->verbosity == DEBUG);

	error = scep_conf_set(handle, SCEPCFG_SIGALG, EVP_md5());
	ck_assert(SCEPE_OK == error);
	ck_assert(handle->configuration->sigalg == EVP_md5());

	error = scep_conf_set(handle, SCEPCFG_ENCALG, EVP_des_ede3_cbc());
	ck_assert(SCEPE_OK == error);
	ck_assert(handle->configuration->encalg == EVP_des_ede3_cbc());

	error = scep_conf_set(handle, SCEPCFG_LOG, BIO_new(BIO_s_mem()));
	ck_assert(SCEPE_OK == error);
	ck_assert(handle->configuration->log != NULL);

	error = scep_conf_set(handle, -1, NULL);
	ck_assert(SCEPE_UNKNOWN_CONFIGURATION == error);
}
END_TEST

START_TEST(test_scep_conf_url)
{
	SCEP_ERROR error;
	char *url_string = "http://example.com/cgi-bin/scep/scep";
	char *url_string2 = "https://test-example.net/some/path";
	char *url_string_test = NULL;
	int url_string_length;

	// test setting url
	error = scep_conf_set_url(handle, SCEPCFG_URL, url_string);
	ck_assert(SCEPE_OK == error);
	uriToStringCharsRequiredA(handle->configuration->url, &url_string_length);
	url_string_length++;
	url_string_test = malloc(url_string_length);
	uriToStringA(url_string_test, handle->configuration->url,
			url_string_length, NULL);
	ck_assert_str_eq(url_string_test, url_string);
	free(url_string_test);

	error = scep_conf_set_url(handle, SCEPCFG_URL, url_string2);
	ck_assert(SCEPE_OK == error);
	uriToStringCharsRequiredA(handle->configuration->url, &url_string_length);
	url_string_length++;
	url_string_test = malloc(url_string_length);
	uriToStringA(url_string_test, handle->configuration->url,
			url_string_length, NULL);
	ck_assert_str_eq(url_string_test, url_string2);
	free(url_string_test);

	// and now the same game with proxy
	error = scep_conf_set_url(handle, SCEPCFG_PROXY, url_string);
	ck_assert(SCEPE_OK == error);
	uriToStringCharsRequiredA(handle->configuration->proxy, &url_string_length);
	url_string_length++;
	url_string_test = malloc(url_string_length);
	uriToStringA(url_string_test, handle->configuration->proxy,
			url_string_length, NULL);
	ck_assert_str_eq(url_string_test, url_string);
	free(url_string_test);

	error = scep_conf_set_url(handle, SCEPCFG_PROXY, url_string2);
	ck_assert(SCEPE_OK == error);
	uriToStringCharsRequiredA(handle->configuration->proxy, &url_string_length);
	url_string_length++;
	url_string_test = malloc(url_string_length);
	uriToStringA(url_string_test, handle->configuration->proxy,
			url_string_length, NULL);
	ck_assert_str_eq(url_string_test, url_string2);
	free(url_string_test);

	// make wrong URL
	error = scep_conf_set_url(handle, SCEPCFG_URL, NULL);
	ck_assert(error == SCEPE_INVALID_URL);

	// and now lets hit the default branch
	error = scep_conf_set_url(handle, -1, "");
	ck_assert(error == SCEPE_UNKNOWN_CONFIGURATION);
}
END_TEST

START_TEST(test_scep_conf_encalg)
{
	scep_conf_set(handle, SCEPCFG_ENCALG, EVP_des_cbc());
	ck_assert(handle->configuration->encalg == EVP_des_cbc());

	scep_conf_set(handle, SCEPCFG_ENCALG, EVP_des_ede3_cbc());
	ck_assert(handle->configuration->encalg == EVP_des_ede3_cbc());

	scep_conf_set(handle, SCEPCFG_ENCALG, EVP_bf_cbc());
	ck_assert(handle->configuration->encalg == EVP_bf_cbc());
}
END_TEST

START_TEST(test_scep_conf_sigalg)
{
	// test some commong algorithms
	scep_conf_set(handle, SCEPCFG_SIGALG, EVP_md5());
	ck_assert(handle->configuration->sigalg == EVP_md5());

	scep_conf_set(handle, SCEPCFG_SIGALG, EVP_sha1());
	ck_assert(handle->configuration->sigalg == EVP_sha1());

	scep_conf_set(handle, SCEPCFG_SIGALG, EVP_sha384());
	ck_assert(handle->configuration->sigalg == EVP_sha384());
}
END_TEST

START_TEST(test_scep_conf_verbosity)
{
	SCEP_VERBOSITY verb;
	for(verb = FATAL; verb <= DEBUG; verb++)
	{
		scep_conf_set(handle, SCEPCFG_VERBOSITY, verb);
		ck_assert(handle->configuration->verbosity == verb);
	}
}
END_TEST

START_TEST(test_scep_conf_sanity_check)
{
       ck_assert(scep_conf_sanity_check(handle) == SCEPE_MISSING_URL);
       scep_conf_set(handle, SCEPCFG_URL, "http://example.com/scep");
       ck_assert(scep_conf_sanity_check(handle) == SCEPE_OK);
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

	TCase *tc_sanity = tcase_create("Sanity Checks");
	tcase_add_checked_fixture(tc_sanity, setup, teardown);
	tcase_add_test(tc_sanity, test_scep_conf_sanity_check);

	suite_add_tcase(s, tc_core);
	suite_add_tcase(s, tc_sanity);

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
