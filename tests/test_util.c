/* tests/test_scep.c */

#include <check.h>
#include <stdlib.h>
#include "../src/scep.h"

START_TEST(test_scep_urlparse)
{
	SCEP_URL *url;
	int err;

	err = scep_urlparse("http://example.com:81/cgi-bin/scep/scep", &url);
	ck_assert_str_eq(url->hostname, "example.com");
	ck_assert_str_eq(url->path, "cgi-bin/scep/scep");
	ck_assert(url->port == 81);
	ck_assert(url->scheme == HTTP);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("https://example.com", &url);
	ck_assert(err == SCEPE_OK);
	ck_assert_str_eq(url->hostname, "example.com");
	ck_assert_str_eq(url->path, "");
	ck_assert(url->port == 443);
	ck_assert(url->scheme == HTTPS);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("ftp://example.com", &url);
	ck_assert(err == SCEPE_UNKNOWN_SCHEME);
	ck_assert(url == NULL);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("example.com:443", &url);
	ck_assert(err == SCEPE_OK);
	ck_assert_str_eq(url->hostname, "example.com");
	ck_assert_str_eq(url->path, "");
	ck_assert(url->port == 443);
	ck_assert(url->scheme == HTTPS);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("example.com:99", &url);
	ck_assert(err == SCEPE_OK);
	ck_assert_str_eq(url->hostname, "example.com");
	ck_assert_str_eq(url->path, "");
	ck_assert(url->port == 99);
	ck_assert(url->scheme == HTTP);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("example.com:65536", &url);
	ck_assert(err == SCEPE_INVALID_PORT);
	ck_assert(url == NULL);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("example.com:0", &url);
	ck_assert(err == SCEPE_INVALID_PORT);
	ck_assert(url == NULL);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("example.com:1", &url);
	ck_assert(err == SCEPE_OK);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("example.com:65535", &url);
	ck_assert(err == SCEPE_OK);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("http://:80", &url);
	ck_assert(err == SCEPE_INVALID_URL);
	ck_assert(url == NULL);
	scep_cleanup_conf_url(url);

	err = scep_urlparse("eg0890429u90g 9G U G90U U09GU90U90 GU 90U09Gu0", &url);
	ck_assert(err == SCEPE_OK);
	ck_assert(url->port == 80);
	ck_assert(url->scheme == HTTP);
	scep_cleanup_conf_url(url);
}
END_TEST

START_TEST(test_scep_queryparse)
{
	StrMap *query;
	int err, value_len;
	char *value;

	err = scep_queryparse("key1=value1", &query);
	ck_assert(err == SCEPE_OK);
	ck_assert(sm_get_count(query) == 1);

	value_len = sm_get(query, "key1", NULL, 0);
	value = malloc(value_len);
	sm_get(query, "key1", value, value_len);
	ck_assert_str_eq(value, "value1");
	free(value);

	scep_cleanup_conf_query(query);


	err = scep_queryparse("", &query);
	ck_assert(err == SCEPE_OK);
	ck_assert(query == NULL);
	scep_cleanup_conf_query(query);

	err = scep_queryparse("key1=", &query);
	ck_assert(err == SCEPE_OK);
	ck_assert(sm_get_count(query) == 1);

	value_len = sm_get(query, "key1", NULL, 0);
	value = malloc(value_len);
	sm_get(query, "key1", value, value_len);
	ck_assert_str_eq(value, "");
	free(value);

	scep_cleanup_conf_query(query);


	err = scep_queryparse("key1=&key2=value2", &query);
	ck_assert(err == SCEPE_OK);
	ck_assert(sm_get_count(query) == 2);

	value_len = sm_get(query, "key1", NULL, 0);
	value = malloc(value_len);
	sm_get(query, "key1", value, value_len);
	ck_assert_str_eq("", value);
	free(value);

	value_len = sm_get(query, "key2", NULL, 0);
	value = malloc(value_len);
	sm_get(query, "key2", value, value_len);
	ck_assert_str_eq("value2", value);
	free(value);

	scep_cleanup_conf_query(query);


	err = scep_queryparse("1=1&2=2&3=3&4=4&5=5&6=6", &query);
	ck_assert(err == SCEPE_OK);
	ck_assert(sm_get_count(query) == 2);

	value = malloc(1);
	sm_get(query, "4", value, 1);
	ck_assert_str_eq("4", value);
	free(value);

	scep_cleanup_conf_query(query);
}
END_TEST

Suite * scep_conf_suite(void)
{
	Suite *s = suite_create("General");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_scep_urlparse);
	tcase_add_test(tc_core, test_scep_queryparse);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = scep_conf_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	srunner_set_fork_status(sr, CK_NOFORK);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
