/* tests/test_configuration.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"

SCEP *handle;
BIO *scep_log;
PKCS7 *p7;
EVP_PKEY *dec_key;
X509 *dec_cert;

char *test_crt = "-----BEGIN CERTIFICATE-----\n"
"MIICLzCCAZgCCQDTeVgTQPW40zANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJE\n"
"RTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
"cyBQdHkgTHRkMRQwEgYDVQQDEwtmb28uYmFyLmNvbTAgFw0xNTAyMjYxMjAwMzla\n"
"GA8yMTE1MDIwMjEyMDAzOVowWzELMAkGA1UEBhMCREUxEzARBgNVBAgTClNvbWUt\n"
"U3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UE\n"
"AxMLZm9vLmJhci5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANFEiTNr\n"
"xDGehD636meTlC2yAmINuZn7pU9CC4BudfdDAI2YdoB9h9YqRk773EYAveAfSMYg\n"
"/ySzMlzz+yb8skZwctrocJYGpgB4N0BpmkGt7VSK9qwT4mRXqL6G2Cvvifi4BBYP\n"
"Q4c5JvYP43cDd7/Yb7Hg3Do8tG16Zo6AXaFpAgMBAAEwDQYJKoZIhvcNAQEFBQAD\n"
"gYEAbUXoPS+AhHuO7T7KRdgwJDLyr15dwUplGwtZT+MoOnnDMRWv/0VG4QUbBwvP\n"
"5Jrrk/lRHKajXLmzrqaoiadGzj6vCOh+zuf/KAOhQjvYtZyL0b727W1Sf2i7Cij+\n"
"ublOOHR0hldn/XqR7hKfZ/uIPnznQeKkVGjrEs223vtf7cI=\n"
"-----END CERTIFICATE-----\n";

char *test_key = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIICXgIBAAKBgQDRRIkza8QxnoQ+t+pnk5QtsgJiDbmZ+6VPQguAbnX3QwCNmHaA\n"
"fYfWKkZO+9xGAL3gH0jGIP8kszJc8/sm/LJGcHLa6HCWBqYAeDdAaZpBre1Uivas\n"
"E+JkV6i+htgr74n4uAQWD0OHOSb2D+N3A3e/2G+x4Nw6PLRtemaOgF2haQIDAQAB\n"
"AoGBAM9w9eRwLmLVdNhLLeSQqXGGpNAYNOTMTDk+CfK9DNkXpQO3n7iNN0r4Swve\n"
"pKML9yylNlmYufLiY8k63brvAbP/Tfg2cbzg47fv+kacqYgaH6aoII++UEAoF+pM\n"
"HgdINRIRn+wknsNxdxE+YEJW/+XfhHiwD31RKBFOYw0NL3PRAkEA+pTwf1CfXBLP\n"
"Ujap10y883PQpX+lLyFzMT2BEu5C1WfUSjHiyzZyb6utYZ9U1PlTvaUXSJ3guNcl\n"
"VVvwjll/rQJBANXK6H9xy959Y7EKfxT41BDHQoXfmEIcLSz1wgWSeKwgbFF4+n3g\n"
"JoHG1n4hQ7D6OV41oh18XXYFBE9Ienyw8C0CQEHs0WENev+kSzsb+o8UN1ntjGUe\n"
"Mf02VbIMtlqeqKKwkF98xGgmSPEsP49BdfYaKnfoaTnHn4nBwKa2a5Fn5nkCQQCr\n"
"nApwcmnRGBlzvRcxQGMJbMjrKQXQ20kv871gN6iBki0gYNnBPLHsLi1yZUUuxExU\n"
"YPzWakOjPnetJGKdwHGpAkEAnMDbIjYpg9WYtx4l5q8R8u1USf8ndybDQehite7W\n"
"nzpG25y4ERn1b0M8TJ0xK0y2b8pMWBYlavUYkCYCfWOAsw==\n"
"-----END RSA PRIVATE KEY-----";

char *test_new_key = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIICXAIBAAKBgQCnCz5qi3kW8avPCPhmKOUwSRpCcqOi0RH3tGburtCoHl56nhL3\n"
"X1Xuv+3e6HWS74IOWbwuZXADdSWswFMefJuh6D4tRACzvgbOuXaxxopj9PYnieNu\n"
"nATNl1O1fy1QG3uJiy+QuQe3/xfIIwIVtvsx5ckMfRHk4g4lsOJwLofIvwIDAQAB\n"
"AoGAGt9dMCi11zITsJ/BzjWAAU+RUOU+W+AEYvP7pyQqXxFbo6AwbulAWsM3kieV\n"
"Woj7RDG9az1YUsYSxILAHGRxaMzpMtJISEECUqlmDYU+/vinU/vYp0a2oAuqFg4G\n"
"8nSoOQ2aTG5owNNcSrK7FbEcI2XdKZNNHM+82iYv7DA4tBECQQDYJLdeudpBhgiE\n"
"u6XaRfvlOeRWK7kfgIloz23qjfbgpDkVO40gIOMxUfU7ut19PuwJ5yJJG4mYCCbP\n"
"wR9Bu1snAkEAxdi7hfgj4Lkdh3C/Qki5K5Q7KR2K6Xhfzpn+fY4SmsLHd/v6QYhF\n"
"+igQv3Y357dz67+9dxWBzaMsMBFOM7QEqQJBAJadXzofADvQjncP246yXclqAfca\n"
"GLIe+6GRieJ8cqAvT6fAC6Nrx2VC20R3/oecJRbxfS68hbDvXTxAMuu3BtkCQGdP\n"
"q2xjjOiWAZNuDpFgREE7YEEyCg2sK+tIgpmxjIl/2IUQ8TczH8dnEIfKBZtcMo4S\n"
"S69ZbbSh1jsrbjiVcjECQAlyT5MO1eWxksYaW4aFx8w+QO9vxQh0vgkI1fBArbzt\n"
"sj4kcSMpE9Tn8CeAhi1d0Qwayo8QO1TPbIgay02syMo=\n"
"-----END RSA PRIVATE KEY-----";

char *test_new_csr = "-----BEGIN CERTIFICATE REQUEST-----\n"
"MIIBhDCB7gIBADBFMQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEh\n"
"MB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEB\n"
"AQUAA4GNADCBiQKBgQCnCz5qi3kW8avPCPhmKOUwSRpCcqOi0RH3tGburtCoHl56\n"
"nhL3X1Xuv+3e6HWS74IOWbwuZXADdSWswFMefJuh6D4tRACzvgbOuXaxxopj9PYn\n"
"ieNunATNl1O1fy1QG3uJiy+QuQe3/xfIIwIVtvsx5ckMfRHk4g4lsOJwLofIvwID\n"
"AQABoAAwDQYJKoZIhvcNAQEFBQADgYEAe2JFYCaHVkpDNIWXBU9Q2WiPzVBhOPIu\n"
"OYMK8+h22AcvTxC0vXDfMItBYFo7qUSu9ITU03sVjnc4pt5KE422/ZCy4x2PrPfE\n"
"TVLyJrDSrTiXLKhG4qWYDUn1PaPkbDkZGVhSrQGfnDLIl9yMPYxWLLj1R2YDJ3x3\n"
"mSUfZ4/vOWA=\n"
"-----END CERTIFICATE REQUEST-----";

char *test_server_cert = "-----BEGIN CERTIFICATE-----\n"
"MIICLzCCAZgCCQDTeVgTQPW40zANBgkqhkiG9w0BAQUFADBbMQswCQYDVQQGEwJE\n"
"RTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0\n"
"cyBQdHkgTHRkMRQwEgYDVQQDEwtmb28uYmFyLmNvbTAgFw0xNTAyMjYxMjAwMzla\n"
"GA8yMTE1MDIwMjEyMDAzOVowWzELMAkGA1UEBhMCREUxEzARBgNVBAgTClNvbWUt\n"
"U3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEUMBIGA1UE\n"
"AxMLZm9vLmJhci5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANFEiTNr\n"
"xDGehD636meTlC2yAmINuZn7pU9CC4BudfdDAI2YdoB9h9YqRk773EYAveAfSMYg\n"
"/ySzMlzz+yb8skZwctrocJYGpgB4N0BpmkGt7VSK9qwT4mRXqL6G2Cvvifi4BBYP\n"
"Q4c5JvYP43cDd7/Yb7Hg3Do8tG16Zo6AXaFpAgMBAAEwDQYJKoZIhvcNAQEFBQAD\n"
"gYEAbUXoPS+AhHuO7T7KRdgwJDLyr15dwUplGwtZT+MoOnnDMRWv/0VG4QUbBwvP\n"
"5Jrrk/lRHKajXLmzrqaoiadGzj6vCOh+zuf/KAOhQjvYtZyL0b727W1Sf2i7Cij+\n"
"ublOOHR0hldn/XqR7hKfZ/uIPnznQeKkVGjrEs223vtf7cI=\n"
"-----END CERTIFICATE-----\n";

char *test_server_key = "-----BEGIN RSA PRIVATE KEY-----\n"
"MIICXgIBAAKBgQDRRIkza8QxnoQ+t+pnk5QtsgJiDbmZ+6VPQguAbnX3QwCNmHaA\n"
"fYfWKkZO+9xGAL3gH0jGIP8kszJc8/sm/LJGcHLa6HCWBqYAeDdAaZpBre1Uivas\n"
"E+JkV6i+htgr74n4uAQWD0OHOSb2D+N3A3e/2G+x4Nw6PLRtemaOgF2haQIDAQAB\n"
"AoGBAM9w9eRwLmLVdNhLLeSQqXGGpNAYNOTMTDk+CfK9DNkXpQO3n7iNN0r4Swve\n"
"pKML9yylNlmYufLiY8k63brvAbP/Tfg2cbzg47fv+kacqYgaH6aoII++UEAoF+pM\n"
"HgdINRIRn+wknsNxdxE+YEJW/+XfhHiwD31RKBFOYw0NL3PRAkEA+pTwf1CfXBLP\n"
"Ujap10y883PQpX+lLyFzMT2BEu5C1WfUSjHiyzZyb6utYZ9U1PlTvaUXSJ3guNcl\n"
"VVvwjll/rQJBANXK6H9xy959Y7EKfxT41BDHQoXfmEIcLSz1wgWSeKwgbFF4+n3g\n"
"JoHG1n4hQ7D6OV41oh18XXYFBE9Ienyw8C0CQEHs0WENev+kSzsb+o8UN1ntjGUe\n"
"Mf02VbIMtlqeqKKwkF98xGgmSPEsP49BdfYaKnfoaTnHn4nBwKa2a5Fn5nkCQQCr\n"
"nApwcmnRGBlzvRcxQGMJbMjrKQXQ20kv871gN6iBki0gYNnBPLHsLi1yZUUuxExU\n"
"YPzWakOjPnetJGKdwHGpAkEAnMDbIjYpg9WYtx4l5q8R8u1USf8ndybDQehite7W\n"
"nzpG25y4ERn1b0M8TJ0xK0y2b8pMWBYlavUYkCYCfWOAsw==\n"
"-----END RSA PRIVATE KEY-----";


void generic_setup()
{
	ck_assert(scep_init(&handle) == SCEPE_OK);
	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, scep_log);
	scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
}

void generic_teardown()
{
	scep_cleanup(handle);
	BIO_flush(scep_log);
	BIO_free(scep_log);
}

void make_message_data(
		X509 **sig_cert, EVP_PKEY **sig_key, EVP_PKEY **req_pubkey, 
		char **messageType, BIO **data, X509 **enc_cert, const EVP_CIPHER **enc_alg)
{
	PKCS7 *p7;
	BIO *b, *pkcs7bio;
	X509_REQ *csr;
	if(*sig_cert == NULL || *sig_key == NULL) {
		b = BIO_new(BIO_s_mem());
		BIO_puts(b, test_key);
		PEM_read_bio_PrivateKey(b, sig_key, 0, 0);
		BIO_free(b);

		b = BIO_new(BIO_s_mem());
		BIO_puts(b, test_crt);
		PEM_read_bio_X509(b, &dec_cert, 0, 0);
		BIO_free(b);
		
		b = BIO_new(BIO_s_mem());
		BIO_puts(b, test_key);
		PEM_read_bio_PrivateKey(b, &dec_key, 0, 0);
		BIO_free(b);

		b = BIO_new(BIO_s_mem());
		BIO_puts(b, test_crt);
		PEM_read_bio_X509(b, sig_cert, 0, 0);
		BIO_free(b);
	}

	if(*req_pubkey == NULL) {
		csr = X509_REQ_new();
		b = BIO_new(BIO_s_mem());
		BIO_puts(b, test_new_csr);
		PEM_read_bio_X509_REQ(b, &csr, 0, 0);
		BIO_free(b);
		*req_pubkey = X509_REQ_get_pubkey(csr);
	}

	if(*messageType == NULL) {
		*messageType = MESSAGE_TYPE_PKCSREQ;
	}

	if(*data == NULL) {
		*data = BIO_new(BIO_s_mem());
		BIO_puts(*data, "foobar\n");
	}

	if(*enc_cert == NULL) {
		b = BIO_new(BIO_s_mem());
		BIO_puts(b, test_server_cert);
		PEM_read_bio_X509(b, enc_cert, 0, 0);
		BIO_free(b);
	}

	if(*enc_alg == NULL)
		*enc_alg = EVP_des_ede3_cbc();
}

PKCS7 *make_message(
		X509 *sig_cert, EVP_PKEY *sig_key, EVP_PKEY *req_pubkey, 
		char *messageType, BIO *data, X509 *enc_cert, const EVP_CIPHER *enc_alg)
{
	make_message_data(&sig_cert, &sig_key, &req_pubkey, &messageType, &data, &enc_cert, &enc_alg);
	ck_assert(scep_pkiMessage(
		handle, sig_cert, sig_key, req_pubkey, messageType, data, 
		enc_cert, enc_alg, &p7) == SCEPE_OK);
	return p7;
}

SCEP_ERROR PKCS7_get_content(PKCS7 *p7, PKCS7 **result) {
	BIO *pkcs7bio = NULL;
	PKCS7 *content = NULL;
	SCEP_ERROR error = SCEPE_OK;
#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

	pkcs7bio = PKCS7_dataInit(p7, NULL);
	if(!pkcs7bio)
		OSSL_ERR("Could not create BIO for reading PKCS7 content.\n");

	content = d2i_PKCS7_bio(pkcs7bio, NULL);
	if(!content)
		OSSL_ERR("Could not read from content BIO.\n");

	*result = content;
finally:	
	if(error != SCEPE_OK) {
		if(pkcs7bio)
			BIO_free(pkcs7bio);
		if(content)
			PKCS7_free(content);
	}
	return error;
#undef OSSL_ERR
}

BIO *get_decrypted_data(PKCS7 *p7)
{
	// currently failing because we cannot extract data from PKCS#7 data type
	PKCS7 *p7enc = NULL, *p7_inner;
	BIO *outbio;
	ck_assert(PKCS7_get_content(p7, &p7enc) == SCEPE_OK);
	outbio = BIO_new(BIO_s_mem());

	// version == 0
	ck_assert_str_eq("0", i2s_ASN1_INTEGER(NULL, p7enc->d.enveloped->version));

	// decrypt and check content
	PKCS7_decrypt(p7enc, dec_key, dec_cert, outbio, 0);
	return outbio;
}

void null_setup()
{
	generic_setup();
	p7 = make_message(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

void null_teardown()
{
	generic_teardown();
	PKCS7_free(p7);
}

ASN1_STRING *get_attribute(PKCS7 *message, int nid) {
	STACK_OF(PKCS7_SIGNER_INFO) *sk_si = PKCS7_get_signer_info(message);
	ck_assert(sk_PKCS7_SIGNER_INFO_num(sk_si) == 1);
	PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk_si, 0);

	ASN1_TYPE *attr = PKCS7_get_signed_attribute(si, nid);
	return attr->value.printablestring;
}

char *get_attribute_data(PKCS7 *message, int nid) {
	return ASN1_STRING_data(get_attribute(message, nid));
}

START_TEST(test_scep_message_asn1_version)
{
	ck_assert_str_eq("1", i2s_ASN1_INTEGER(NULL, p7->d.sign->version));
}
END_TEST

START_TEST(test_scep_message_transaction_id)
{
	ck_assert_str_eq(
		"2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
		get_attribute_data(p7, handle->oids.transId));
}
END_TEST

START_TEST(test_scep_message_message_type)
{
	ck_assert_str_eq(
		"19",
		get_attribute_data(p7, handle->oids.messageType));
}
END_TEST

START_TEST(test_scep_message_sender_nonce)
{
	ck_assert(ASN1_STRING_length(get_attribute(p7, handle->oids.senderNonce)) == 16);
}
END_TEST

START_TEST(test_scep_message_type)
{
	ck_assert(PKCS7_type_is_signed(p7));
}
END_TEST

START_TEST(test_scep_message_content_type)
{
	PKCS7 *content;
	ck_assert(PKCS7_type_is_data(p7->d.sign->contents));
}
END_TEST


START_TEST(test_scep_message_encryption)
{
	unsigned char *reply;
	ck_assert(BIO_get_mem_data(get_decrypted_data(p7), &reply));
	ck_assert_str_eq("foobar\n", reply);
}
END_TEST


void pkcsreq_setup()
{
	BIO *b, *data = NULL;
	X509_REQ *csr;
	X509 *sig_cert = NULL, *enc_cert = NULL;
	EVP_PKEY *sig_key = NULL;
	EVP_PKEY *req_pubkey = NULL; 
	const EVP_CIPHER *enc_alg = NULL;
	char *messageType = MESSAGE_TYPE_PKCSREQ;

	b = BIO_new(BIO_s_mem());
	csr = X509_REQ_new();
	BIO_puts(b, test_new_csr);
	PEM_read_bio_X509_REQ(b, &csr, 0, 0);
	BIO_free(b);
	generic_setup();
	make_message_data(
		&sig_cert, &sig_key, &req_pubkey, &messageType,
		&data, &enc_cert, &enc_alg);
	ck_assert(scep_pkcsreq(
		handle, csr, sig_cert, sig_key,
		enc_cert, enc_alg, &p7) == SCEPE_OK);
}

void pkcsreq_teardown()
{
	generic_teardown();
	PKCS7_free(p7);

}

START_TEST(test_scep_pkcsreq)
{
	BIO *data = get_decrypted_data(p7);
	X509_REQ *csr = d2i_X509_REQ_bio(data, NULL);
	PEM_write_X509_REQ(stderr, csr);
	// how to verify this, what to test?
	ck_assert(0);

	// verify presence of following attributes:
	// tid, messageType, senderNonce
}
END_TEST

START_TEST(test_scep_pkcsreq_missing_dn)
{
	ck_assert(0);
}
END_TEST

START_TEST(test_scep_pkcsreq_missing_pubkey)
{
	ck_assert(0);
}
END_TEST

START_TEST(test_scep_pkcsreq_missing_challenge_password)
{
	ck_assert(0);
}
END_TEST


Suite * scep_message_suite(void)
{
	Suite *s = suite_create("Message");

	/* Null Message test case */
	TCase *tc_null_msg = tcase_create("Null Message");
	tcase_add_checked_fixture(tc_null_msg, null_setup, null_teardown);
	tcase_add_test(tc_null_msg, test_scep_message_asn1_version);
	tcase_add_test(tc_null_msg, test_scep_message_transaction_id);
	tcase_add_test(tc_null_msg, test_scep_message_message_type);
	tcase_add_test(tc_null_msg, test_scep_message_sender_nonce);
	tcase_add_test(tc_null_msg, test_scep_message_type);
	tcase_add_test(tc_null_msg, test_scep_message_content_type);
	tcase_add_test(tc_null_msg, test_scep_message_encryption);
	suite_add_tcase(s, tc_null_msg);

	/* PKCSReq tests */
	TCase *tc_pkcsreq_msg = tcase_create("PKCSReq Message");
	tcase_add_checked_fixture(tc_pkcsreq_msg, pkcsreq_setup, pkcsreq_teardown);
	tcase_add_test(tc_pkcsreq_msg, test_scep_pkcsreq);
	tcase_add_test(tc_pkcsreq_msg, test_scep_pkcsreq_missing_dn);
	tcase_add_test(tc_pkcsreq_msg, test_scep_pkcsreq_missing_pubkey);
	tcase_add_test(tc_pkcsreq_msg, test_scep_pkcsreq_missing_challenge_password);
	suite_add_tcase(s, tc_pkcsreq_msg);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s = scep_message_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
