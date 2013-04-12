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
	char *url_string = "http://example.com:80/path/to/scep";
	char *url_string_test;
	int url_string_length;
	int error;
	X509 *getcert_dummy_cert, *getcrl_dummy_cert;

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

	error = scep_conf_set(handle, SCEPCFG_GETCACERT_ISSUER, "Test Issuer");
	ck_assert(SCEPE_OK == error);
	ck_assert_str_eq(handle->configuration->getcacert->issuer, "Test Issuer");

	error = scep_conf_set(handle, SCEPCFG_PKCSREQ_POLL_INTERVAL, 15);
	ck_assert(SCEPE_OK == error);
	ck_assert(handle->configuration->pkcsreq->polling_interval == 15);

	getcert_dummy_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCERT_CERT_TARGET, getcert_dummy_cert);
	ck_assert(SCEPE_OK == error);
	ck_assert(memcmp(handle->configuration->getcert->cert_target,
					getcert_dummy_cert, sizeof(X509)) == 0);

	getcrl_dummy_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCRL_CERT, getcrl_dummy_cert);
	ck_assert(SCEPE_OK == error);
	ck_assert(memcmp(handle->configuration->getcrl->cert,
					getcrl_dummy_cert, sizeof(X509)) == 0);


	error = scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_ISSUER, "Test Issuer");
	ck_assert(SCEPE_OK == error);
	ck_assert_str_eq(handle->configuration->getnextcacert->issuer, "Test Issuer");

	error = scep_conf_set(handle, -1, NULL);
	ck_assert(SCEPE_UNKNOWN_CONFIGURATION == error);
}
END_TEST

START_TEST(test_scep_conf_url)
{
	int error;
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

START_TEST(test_scep_conf_getcacert)
{
	SCEP_ERROR error;
	X509 *cert_target;

	error = scep_conf_set(handle, SCEPCFG_GETCACERT_ISSUER, "test");
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(handle->configuration->getcacert->issuer, "test");

	error = scep_conf_set(handle, SCEPCFG_GETCACERT_ISSUER, "test2");
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(handle->configuration->getcacert->issuer, "test2");

	cert_target = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCACERT_CACERT_TARGET, cert_target);
	ck_assert(error == SCEPE_OK);
	ck_assert(cert_target == handle->configuration->getcacert->ca_cert_target);

	cert_target = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCACERT_CACERT_TARGET, cert_target);
	ck_assert(error == SCEPE_OK);
	ck_assert(cert_target == handle->configuration->getcacert->ca_cert_target);

	error = scep_conf_set_getcacert(handle, -1, NULL);
	ck_assert(error == SCEPE_UNKNOWN_CONFIGURATION);
}
END_TEST

START_TEST(test_scep_conf_pkcsreq)
{
}
END_TEST

START_TEST(test_scep_conf_getcert)
{
	int error;
	EVP_PKEY *test_key;
	X509 *test_cert;

	test_key = EVP_PKEY_new();
	error = scep_conf_set(handle, SCEPCFG_GETCERT_KEY, test_key);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcert->request_key == test_key);

	test_key = EVP_PKEY_new();
	error = scep_conf_set(handle, SCEPCFG_GETCERT_KEY, test_key);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcert->request_key == test_key);

	test_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCERT_CACERT, test_cert);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcert->ca_cert == test_cert);

	test_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCERT_CACERT, test_cert);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcert->ca_cert == test_cert);

	test_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCERT_CERT_TARGET, test_cert);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcert->cert_target == test_cert);

	test_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCERT_CERT_TARGET, test_cert);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcert->cert_target == test_cert);

	error = scep_conf_set_getcert(handle, -1, NULL);
	ck_assert(error = SCEPE_UNKNOWN_CONFIGURATION);
}
END_TEST

START_TEST(test_scep_conf_getcrl)
{
	int error;
	X509 *test_cert;
	X509_CRL *test_crl;

	test_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCRL_CERT, test_cert);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcrl->cert == test_cert);

	test_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETCRL_CERT, test_cert);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcrl->cert == test_cert);

	test_crl = X509_CRL_new();
	error = scep_conf_set(handle, SCEPCFG_GETCRL_CRL_TARGET, test_crl);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcrl->crl_target == test_crl);

	test_crl = X509_CRL_new();
	error = scep_conf_set(handle, SCEPCFG_GETCRL_CRL_TARGET, test_crl);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getcrl->crl_target == test_crl);

	error = scep_conf_set_getcrl(handle, -1, NULL);
	ck_assert(error == SCEPE_UNKNOWN_CONFIGURATION);
}
END_TEST

START_TEST(test_scep_conf_getnextcacert)
{
	int error;
	X509 *test_cert;

	error = scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_ISSUER, "test1");
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(handle->configuration->getnextcacert->issuer, "test1");

	error = scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_ISSUER, "test2");
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(handle->configuration->getnextcacert->issuer, "test2");

	test_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_CACERT_TARGET, test_cert);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getnextcacert->ca_cert_target == test_cert);

	test_cert = X509_new();
	error = scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_CACERT_TARGET, test_cert);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->getnextcacert->ca_cert_target == test_cert);

	error = scep_conf_set_getnextcacert(handle, -1, NULL);
	ck_assert(error == SCEPE_UNKNOWN_CONFIGURATION);

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
	tcase_add_test(tc_core, test_scep_conf_getcacert);
	tcase_add_test(tc_core, test_scep_conf_pkcsreq);
	tcase_add_test(tc_core, test_scep_conf_getcert);
	tcase_add_test(tc_core, test_scep_conf_getcrl);
	tcase_add_test(tc_core, test_scep_conf_getnextcacert);

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
