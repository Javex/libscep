/* tests/test_scep.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"

SCEP *handle;

#define TEST_ERRMSG(ival, sval) \
	ck_assert_str_eq(scep_strerror(ival), sval)

#define TEST_SERVER "http://demo.openxpki.org/cgi-bin/scep/scep"
#define TEST_SERVER_Q "http://demo.openxpki.org/cgi-bin/scep/scep?key1=value1"
#define TEST_CSR_1 "tests/test-files/test-1-csr.pem"
#define TEST_CSR_2 "tests/test-files/test-2-csr.pem"

void setup()
{
	ck_assert(scep_init(&handle) == SCEPE_OK);
	scep_conf_set(handle, SCEPCFG_URL, TEST_SERVER_Q);
}

void teardown()
{
	scep_cleanup(handle);
}

START_TEST(test_scep_strerror)
{
	int i;
	for(i=SCEPE_OK; i < SCEPE_DUMMY_LAST_ERROR; i++)
		ck_assert(strlen(scep_strerror(i)));
	for(i=SCEPE_DUMMY_LAST_ERROR; i <= SCEPE_DUMMY_LAST_ERROR + 1; ++i)
		TEST_ERRMSG(i, "Unknown error");
}
END_TEST

START_TEST(test_scep_recieve_data)
{

}
END_TEST

START_TEST(test_scep_send_request)
{
	SCEP_ERROR error;
	SCEP_REPLY *reply;
	BIO *log;

	log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, log);
	scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);

	error = scep_send_request(handle, "GetCACert", NULL, &reply);
	ck_assert(error == SCEPE_OK);
	ck_assert(reply->status == 200);
	ck_assert_str_eq(reply->content_type, "application/x-x509-ca-ra-cert");

	BIO_free(log);
	free(reply);
}
END_TEST

START_TEST(test_scep_calculate_transaction_id)
{
	X509_REQ *req;
	FILE *fp;
	char *tid;
	SCEP_ERROR error;
	fp = fopen(TEST_CSR_1, "r");
	req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
	EVP_PKEY *pubkey = X509_REQ_get_pubkey(req);
	fclose(fp);

	error = scep_calculate_transaction_id(handle, pubkey, &tid);
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(tid, "5418898A0D8052E60EB9E9F9BEB2E402F8138122C8503213CF5FD86DBB8267CF");
	free(tid);

	fp = fopen(TEST_CSR_2, "r");
	req = PEM_read_X509_REQ(fp, NULL, NULL, NULL);
	pubkey = X509_REQ_get_pubkey(req);
	fclose(fp);

	error = scep_calculate_transaction_id(handle, pubkey, &tid);
	ck_assert(error == SCEPE_OK);
	ck_assert_str_eq(tid, "569673452595B161A6F8D272D9A214152F828133994D5B166EFFB2C140A88EA2");
	free(tid);
}
END_TEST

START_TEST(test_scep_log)
{
	BIO *bio;
	char *log_str, *check_str;
	int lineno;
	size_t log_str_len;
	scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);

	bio = BIO_new(BIO_s_mem());
	//bio = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, bio);
	// hack needed for log testing
	lineno = __LINE__; scep_log(handle, WARN, "This is a test\n");
	log_str_len = BIO_get_mem_data(bio, &log_str);
	check_str = malloc(log_str_len + 1);
	snprintf(check_str, log_str_len + 1, "test_util.c:%d: This is a test\n",
			lineno);
	ck_assert(strncmp(log_str, check_str, log_str_len) == 0);
}
END_TEST

Suite * scep_util_suite(void)
{
	Suite *s = suite_create("Util");

	/* Core test case */
	TCase *tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_scep_strerror);
	tcase_add_test(tc_core, test_scep_recieve_data);
	tcase_add_test(tc_core, test_scep_send_request);
	tcase_add_test(tc_core, test_scep_calculate_transaction_id);
	tcase_add_test(tc_core, test_scep_log);

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
