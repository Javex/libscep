/* tests/test_scep.c */

#include <check.h>
#include <stdlib.h>
#include "../src/scep.h"

START_TEST(test_scep_init_cleanup)
{
	int error;
	SCEP *handle;
	SCEP *local_memory;
	error = scep_init(&handle);
	local_memory = malloc(sizeof(SCEP));
	memset(local_memory, 0, sizeof(SCEP));
	ck_assert(memcmp(local_memory, handle, sizeof(SCEP)));
	free(local_memory);
	scep_cleanup(handle);
}
END_TEST

Suite * scep_suite(void)
{
	Suite *s = suite_create("General");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_scep_init_cleanup);

	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = scep_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
