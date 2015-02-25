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

	error = scep_conf_set(handle, SCEPCFG_GETCACERT_ISSUER, "Test Issuer");
	ck_assert(SCEPE_OK == error);
	ck_assert_str_eq(handle->configuration->getcacert->issuer, "Test Issuer");

	error = scep_conf_set(handle, SCEPCFG_PKCSREQ_POLL_INTERVAL, 15);
	ck_assert(SCEPE_OK == error);
	ck_assert(handle->configuration->pkcsreq->polling_interval == 15);

	OSSL_TEST_TYPE(test_cert, SCEPCFG_GETCERT_CACERT,
			handle->configuration->getcert->ca_cert, X509);

	OSSL_TEST_TYPE(test_cert, SCEPCFG_GETCRL_CERT,
			handle->configuration->getcrl->cert, X509);

	error = scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_ISSUER, "Test Issuer");
	ck_assert(SCEPE_OK == error);
	ck_assert_str_eq(handle->configuration->getnextcacert->issuer, "Test Issuer");

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

	error = scep_conf_set_getcacert(handle, -1, NULL);
	ck_assert(error == SCEPE_UNKNOWN_CONFIGURATION);
}
END_TEST

START_TEST(test_scep_conf_pkcsreq)
{
	SCEP_ERROR error;
	X509_REQ *test_req;
	EVP_PKEY *test_key;
	X509 *test_cert;
	char *test_str;

	OSSL_TEST_TYPE(test_req, SCEPCFG_PKCSREQ_CSR,
		handle->configuration->pkcsreq->request, X509_REQ);

	// check the defaults are set (only exist after setting first param
	mark_point();
	ck_assert(handle->configuration->pkcsreq->polling_interval == \
			DEFAULT_POLL_INTERVAL);
	mark_point();
	ck_assert(handle->configuration->pkcsreq->maximum_poll_time == \
			DEFAULT_MAX_POLL_TIME);
	mark_point();
	ck_assert(handle->configuration->pkcsreq->maximum_poll_count == \
			DEFAULT_MAX_POLL_COUNT);
	mark_point();

	OSSL_TEST_TYPE(test_key, SCEPCFG_PKCSREQ_KEY,
		handle->configuration->pkcsreq->request_key, EVP_PKEY);

	OSSL_TEST_TYPE(test_cert, SCEPCFG_PKCSREQ_CACERT,
		handle->configuration->pkcsreq->ca_cert, X509);

	test_str = "Some Test String";
	error = scep_conf_set(handle, SCEPCFG_PKCSREQ_CHALL_PASSWD, test_str);
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(handle->configuration->pkcsreq->challenge_password, test_str);

	error = scep_conf_set(handle, SCEPCFG_PKCSREQ_CHALL_PASSWD, test_str);
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(handle->configuration->pkcsreq->challenge_password, test_str);

	OSSL_TEST_TYPE(test_key, SCEPCFG_PKCSREQ_SIGKEY,
			handle->configuration->pkcsreq->signature_key, EVP_PKEY);

	OSSL_TEST_TYPE(test_cert, SCEPCFG_PKCSREQ_SIGCERT,
			handle->configuration->pkcsreq->signature_cert, X509);

	error = scep_conf_set(handle, SCEPCFG_PKCSREQ_POLL_INTERVAL, 5);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->pkcsreq->polling_interval == 5);

	error = scep_conf_set(handle, SCEPCFG_PKCSREQ_POLL_TIME, 7);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->pkcsreq->maximum_poll_time == 7);

	error = scep_conf_set(handle, SCEPCFG_PKCSREQ_POLL_COUNT, 9);
	ck_assert(error == SCEPE_OK);
	ck_assert(handle->configuration->pkcsreq->maximum_poll_count == 9);

	error = scep_conf_set_pkcsreq(handle, -1, NULL);
	ck_assert(error == SCEPE_UNKNOWN_CONFIGURATION);
}
END_TEST

START_TEST(test_scep_conf_getcert)
{
	SCEP_ERROR error;
	EVP_PKEY *test_key;
	X509 *test_cert;

	OSSL_TEST_TYPE(test_key, SCEPCFG_GETCERT_KEY,
			handle->configuration->getcert->request_key, EVP_PKEY);

	OSSL_TEST_TYPE(test_cert, SCEPCFG_GETCERT_CACERT,
			handle->configuration->getcert->ca_cert, X509);

	error = scep_conf_set_getcert(handle, -1, NULL);
	ck_assert(error = SCEPE_UNKNOWN_CONFIGURATION);
}
END_TEST

START_TEST(test_scep_conf_getcrl)
{
	SCEP_ERROR error;
	X509 *test_cert;
	X509_CRL *test_crl;

	OSSL_TEST_TYPE(test_cert, SCEPCFG_GETCRL_CERT,
		handle->configuration->getcrl->cert, X509);

	error = scep_conf_set_getcrl(handle, -1, NULL);
	ck_assert(error == SCEPE_UNKNOWN_CONFIGURATION);
}
END_TEST

START_TEST(test_scep_conf_getnextcacert)
{
	SCEP_ERROR error;
	X509 *test_cert;

	error = scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_ISSUER, "test1");
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(handle->configuration->getnextcacert->issuer, "test1");

	error = scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_ISSUER, "test2");
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(handle->configuration->getnextcacert->issuer, "test2");

	error = scep_conf_set_getnextcacert(handle, -1, NULL);
	ck_assert(error == SCEPE_UNKNOWN_CONFIGURATION);

}
END_TEST

START_TEST(test_scep_conf_sanity_check)
{
	ck_assert(scep_conf_sanity_check(handle, -1) ==
			SCEPE_MISSING_URL);
	// need to set something so it doesn't break here
	scep_conf_set(handle, SCEPCFG_GETCACERT_ISSUER, "");
	scep_conf_set(handle, SCEPCFG_URL, "http://example.com/scep");
	ck_assert(scep_conf_sanity_check(handle, SCEPOP_GETCACERT) == SCEPE_OK);
	ck_assert(scep_conf_sanity_check(handle, -1) == SCEPE_UNKOWN_OPERATION);

	ck_assert(scep_conf_sanity_check(handle, SCEPOP_PKCSREQ) != SCEPE_OK);
	ck_assert(scep_conf_sanity_check(handle, SCEPOP_GETCERT) != SCEPE_OK);
	ck_assert(scep_conf_sanity_check(handle, SCEPOP_GETCRL) != SCEPE_OK);
	ck_assert(scep_conf_sanity_check(handle, SCEPOP_GETNEXTCACERT) ==
			SCEPE_OK);

}
END_TEST

START_TEST(test_scep_conf_sanity_check_getcacert)
{
	scep_conf_set(handle, SCEPCFG_GETCACERT_ISSUER, "");
	ck_assert(scep_conf_sanity_check_getcacert(handle) == SCEPE_OK);
}
END_TEST

START_TEST(test_scep_conf_sanity_check_pkcsreq)
{
	scep_conf_set(handle, SCEPCFG_PKCSREQ_CHALL_PASSWD, "");
	ck_assert(scep_conf_sanity_check_pkcsreq(handle) ==
			SCEPE_MISSING_CSR);


	scep_conf_set(handle, SCEPCFG_PKCSREQ_CSR, X509_REQ_new());
	ck_assert(scep_conf_sanity_check_pkcsreq(handle) ==
			SCEPE_MISSING_REQ_KEY);

	scep_conf_set(handle, SCEPCFG_PKCSREQ_KEY, EVP_PKEY_new());
	ck_assert(scep_conf_sanity_check_pkcsreq(handle) ==
			SCEPE_MISSING_CA_CERT);

	scep_conf_set(handle, SCEPCFG_PKCSREQ_CACERT, X509_new());
	scep_conf_set(handle, SCEPCFG_PKCSREQ_SIGKEY, EVP_PKEY_new());
	ck_assert(scep_conf_sanity_check_pkcsreq(handle) ==
			SCEPE_MISSING_SIGCERT);


	scep_conf_set(handle, SCEPCFG_PKCSREQ_SIGKEY, NULL);
	scep_conf_set(handle, SCEPCFG_PKCSREQ_SIGCERT, X509_new());
	ck_assert(scep_conf_sanity_check_pkcsreq(handle) ==
			SCEPE_MISSING_SIGKEY);

	scep_conf_set(handle, SCEPCFG_PKCSREQ_SIGKEY, EVP_PKEY_new());
	ck_assert(scep_conf_sanity_check_pkcsreq(handle) ==
			SCEPE_OK);
}
END_TEST

START_TEST(test_scep_conf_sanity_check_getcert)
{
	handle->configuration->getcert = malloc(sizeof(struct
			scep_configuration_getcert_t));
	memset(handle->configuration->getcert, 0,
			sizeof(struct scep_configuration_getcert_t));
	ck_assert(scep_conf_sanity_check_getcert(handle) ==
			SCEPE_MISSING_CERT_KEY);

	scep_conf_set(handle, SCEPCFG_GETCERT_KEY, EVP_PKEY_new());
	ck_assert(scep_conf_sanity_check_getcert(handle) ==
			SCEPE_MISSING_CA_CERT);

	scep_conf_set(handle, SCEPCFG_GETCERT_CACERT, X509_new());
	ck_assert(scep_conf_sanity_check_getcert(handle) ==
			SCEPE_OK);
}
END_TEST

START_TEST(test_scep_conf_sanity_check_getcrl)
{
	handle->configuration->getcrl = malloc(sizeof(struct
			scep_configuration_getcrl_t));
	memset(handle->configuration->getcrl, 0,
			sizeof(struct scep_configuration_getcrl_t));
	ck_assert(scep_conf_sanity_check_getcrl(handle) ==
			SCEPE_MISSING_CRL_CERT);
	scep_conf_set(handle, SCEPCFG_GETCRL_CERT, X509_new());
	ck_assert(scep_conf_sanity_check_getcrl(handle) ==
			SCEPE_OK);
}
END_TEST

START_TEST(test_scep_conf_sanity_check_getnextcacert)
{
	scep_conf_set(handle, SCEPCFG_GETNEXTCACERT_ISSUER, "");
	ck_assert(scep_conf_sanity_check_getnextcacert(handle) == SCEPE_OK);
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

	TCase *tc_sanity = tcase_create("Sanity Checks");
	tcase_add_checked_fixture(tc_sanity, setup, teardown);
	tcase_add_test(tc_sanity, test_scep_conf_sanity_check);
	tcase_add_test(tc_sanity, test_scep_conf_sanity_check_getcacert);
	tcase_add_test(tc_sanity, test_scep_conf_sanity_check_pkcsreq);
	tcase_add_test(tc_sanity, test_scep_conf_sanity_check_getcert);
	tcase_add_test(tc_sanity, test_scep_conf_sanity_check_getcrl);
	tcase_add_test(tc_sanity, test_scep_conf_sanity_check_getnextcacert);

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
