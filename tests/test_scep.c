/* tests/test_scep.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"

START_TEST(test_scep_init_cleanup)
{
	SCEP_ERROR error;
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

START_TEST(test_create_oids)
{
	SCEP *handle = malloc(sizeof(SCEP));
	memset(handle, 0, sizeof(SCEP));
	ck_assert(scep_create_oids(handle) == SCEPE_OK);
	ck_assert_str_eq(OBJ_nid2sn(handle->oids->messageType), "messageType");
	ck_assert_str_eq(OBJ_nid2ln(handle->oids->messageType), "messageType");

	ck_assert_str_eq(OBJ_nid2ln(handle->oids->pkiStatus), "pkiStatus");
	ck_assert_str_eq(OBJ_nid2sn(handle->oids->pkiStatus), "pkiStatus");

	ck_assert_str_eq(OBJ_nid2ln(handle->oids->failInfo), "failInfo");
	ck_assert_str_eq(OBJ_nid2sn(handle->oids->failInfo), "failInfo");

	ck_assert_str_eq(OBJ_nid2ln(handle->oids->senderNonce), "senderNonce");
	ck_assert_str_eq(OBJ_nid2sn(handle->oids->senderNonce), "senderNonce");

	ck_assert_str_eq(OBJ_nid2ln(handle->oids->recipientNonce), "recipientNonce");
	ck_assert_str_eq(OBJ_nid2sn(handle->oids->recipientNonce), "recipientNonce");

	ck_assert_str_eq(OBJ_nid2ln(handle->oids->transId), "transId");
	ck_assert_str_eq(OBJ_nid2sn(handle->oids->transId), "transId");

	ck_assert_str_eq(OBJ_nid2ln(handle->oids->extensionReq), "extensionReq");
	ck_assert_str_eq(OBJ_nid2sn(handle->oids->extensionReq), "extensionReq");
	free(handle);
}
END_TEST

START_TEST(test_multiple_handles)
{
	SCEP *handle1, *handle2;
	ck_assert(scep_init(&handle1) == SCEPE_OK);
	ck_assert(scep_init(&handle2) == SCEPE_OK);
	scep_cleanup(handle1);
	ck_assert_str_eq(OBJ_nid2sn(handle2->oids->messageType), "messageType");
	ck_assert_str_eq(OBJ_nid2ln(handle2->oids->pkiStatus), "pkiStatus");
	ck_assert_str_eq(OBJ_nid2ln(handle2->oids->failInfo), "failInfo");
	ck_assert_str_eq(OBJ_nid2ln(handle2->oids->senderNonce), "senderNonce");
	ck_assert_str_eq(OBJ_nid2ln(handle2->oids->recipientNonce), "recipientNonce");
	ck_assert_str_eq(OBJ_nid2ln(handle2->oids->transId), "transId");
	ck_assert_str_eq(OBJ_nid2ln(handle2->oids->extensionReq), "extensionReq");
	scep_cleanup(handle2);
}
END_TEST

Suite * scep_suite(void)
{
	Suite *s = suite_create("General");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_scep_init_cleanup);
	tcase_add_test(tc_core, test_create_oids);
	tcase_add_test(tc_core, test_multiple_handles);

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
