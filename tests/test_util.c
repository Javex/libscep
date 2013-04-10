/* tests/test_scep.c */

#include <check.h>
#include <stdlib.h>
#include "../src/scep.h"

START_TEST(test_scep_urlparse)
{
	SCEP_URL *url;
	int ret;

	ret = scep_urlparse("http://example.com:81/cgi-bin/scep/scep", &url);
	ck_assert_str_eq(url->hostname, "example.com");
	ck_assert_str_eq(url->path, "cgi-bin/scep/scep");
	ck_assert(url->port == 81);
	ck_assert(url->scheme == HTTP);
	scep_cleanup_conf_url(url);

	ret = scep_urlparse("https://example.com", &url);
	ck_assert(ret == SCEPE_OK);
	ck_assert_str_eq(url->hostname, "example.com");
	ck_assert_str_eq(url->path, "");
	ck_assert(url->port == 443);
	ck_assert(url->scheme == HTTPS);
	scep_cleanup_conf_url(url);

	ret = scep_urlparse("ftp://example.com", &url);
	ck_assert(ret == SCEPE_UNKNOWN_SCHEME);
	ck_assert(url == NULL);
	scep_cleanup_conf_url(url);
}
END_TEST

START_TEST(test_scep_queryparse)
{
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
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
