/* tests/test_scep.c */

#include <check.h>
#include <stdlib.h>
#include "../src/scep.h"

#define TEST_ERRMSG(ival, sval) \
	ck_assert_str_eq(scep_strerror(ival), sval);

START_TEST(test_scep_strerror)
{
	int i;
	TEST_ERRMSG(SCEPE_OK, "No error");
	TEST_ERRMSG(SCEPE_MEMORY, "Not enough memory available!");
	TEST_ERRMSG(SCEPE_INVALID_URL, "The given URL is invalid.");
	TEST_ERRMSG(SCEPE_UNKNOWN_CONFIGURATION, "This configuration option is not known.");
	for(i=SCEPE_UNKNOWN_CONFIGURATION + 1; i < 100; ++i)
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
