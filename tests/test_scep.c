/* tests/test_scep.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"

START_TEST(test_scep_init_cleanup)
{
	SCEP *handle;
	ck_assert(scep_init(&handle) == SCEPE_OK);
	ck_assert(handle->configuration != NULL);
	ck_assert(handle->oids != NULL);
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

START_TEST(test_senderNonce_accessor)
{
	SCEP *handle;
	ck_assert(scep_init(&handle) == SCEPE_OK);
    BIO *scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
    scep_conf_set(handle, SCEPCFG_LOG, scep_log);
    scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
	char *senderNonce = "\xc5\x76\x80\x0b\x42\xc5\x68\x55\x8c\x2e\x1d\xa1\x18\xd6\x93\x08";
	char senderNonce_ref[NONCE_LENGTH];
	ck_assert_int_eq(scep_param_set(handle, SCEP_PARAM_SENDERNONCE, (void *)senderNonce), SCEPE_OK);
	ck_assert_int_eq(scep_param_get(handle, SCEP_PARAM_SENDERNONCE, (void **) &senderNonce_ref), SCEPE_OK);
	ck_assert_int_eq(memcmp(senderNonce, senderNonce_ref, NONCE_LENGTH), 0);
}
END_TEST

START_TEST(test_senderNonce_unset)
{
	SCEP *handle;
	ck_assert(scep_init(&handle) == SCEPE_OK);
    BIO *scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
    scep_conf_set(handle, SCEPCFG_LOG, scep_log);
    scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
	ck_assert_int_eq(scep_param_get(handle, SCEP_PARAM_SENDERNONCE, NULL), SCEPE_PARAM);
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
	tcase_add_test(tc_core, test_senderNonce_accessor);
	tcase_add_test(tc_core, test_senderNonce_unset);

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
