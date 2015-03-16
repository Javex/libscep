/* tests/test_configuration.c */

#include <check.h>
#include <stdlib.h>
#include "scep.h"

SCEP *handle;
BIO *scep_log;
PKCS7 *p7 = NULL;
SCEP_DATA *pkiMessage;
PKCS7 *p7_nosigcert = NULL; // no signer certificate on result PKCS#7
/*TODO: Do we need them*/
EVP_PKEY *dec_key;
X509 *dec_cert;


X509 *sig_cert;
EVP_PKEY *sig_key;
X509 *enc_cert;
EVP_PKEY *enc_key;
X509 *sig_cacert;
EVP_PKEY *sig_cakey;
X509 *enc_cacert;
EVP_PKEY *enc_cakey;
X509_REQ *req;
const EVP_CIPHER *enc_alg;

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
"MIIBtTCCAR4CAQAwVzELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUtU3RhdGUx\n"
"ITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEQMA4GA1UEAxMHZm9v\n"
"LmJhcjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEApws+aot5FvGrzwj4Zijl\n"
"MEkaQnKjotER97Rm7q7QqB5eep4S919V7r/t3uh1ku+CDlm8LmVwA3UlrMBTHnyb\n"
"oeg+LUQAs74Gzrl2scaKY/T2J4njbpwEzZdTtX8tUBt7iYsvkLkHt/8XyCMCFbb7\n"
"MeXJDH0R5OIOJbDicC6HyL8CAwEAAaAeMBwGCSqGSIb3DQEJBzEPEw1GT09CQVJU\n"
"RVNUUFdEMA0GCSqGSIb3DQEBBQUAA4GBACHwu5U6KNAsgFkmgU6DNBQXriPwRvvn\n"
"uGCzClbjbwGnoi9XCtgepO6I6AbDokjpuuU8/JEGAqKwtRzOsvGJyq4tphAPf/89\n"
"/H+xoHva5tgIGv9zUQSj/6Q0B7TEUKLfVC4H0K9wde+5g13l82EzXXrsCjnyB3S7\n"
"SLYGjIEJ2RwX\n"
"-----END CERTIFICATE REQUEST-----";

char *enc_cacert_str = "-----BEGIN CERTIFICATE-----\n"
"MIIBmzCCAUWgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBHMQswCQYDVQQGEwJERTEN\n"
"MAsGA1UECAwEYXNkZjENMAsGA1UEBwwEYXNkZjENMAsGA1UECgwEYXNkZjELMAkG\n"
"A1UEAwwCY2EwHhcNMTUwMzE1MTMwMjIyWhcNMTYwMzE0MTMwMjIyWjBJMQswCQYD\n"
"VQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEYMBYGA1UECgwPZW5jcnlwdGlv\n"
"biBjZXJ0MQswCQYDVQQDDAJjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQCWdhTh\n"
"BrT7C1f6EtOKPl5nqBd/9YkTUwDt9qAUBNM6AH6tDFIy85Gk1k60ZwYBYyIZT7kN\n"
"2EqnK4zEBRyo2k4jAgMBAAGjGjAYMAkGA1UdEwQCMAAwCwYDVR0PBAQDAgXgMA0G\n"
"CSqGSIb3DQEBBQUAA0EAbce5uBBXc7BPVIcQCqIqbkSEBQ735gmV9FB1XJ4tNl+/\n"
"qjhv1MBVgGB5CAoETs8mJGHwo2c+5JgDkfMJ6gsIEA==\n"
"-----END CERTIFICATE-----\n";

char *enc_cakey_str = "-----BEGIN PRIVATE KEY-----\n"
"MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAlnYU4Qa0+wtX+hLT\n"
"ij5eZ6gXf/WJE1MA7fagFATTOgB+rQxSMvORpNZOtGcGAWMiGU+5DdhKpyuMxAUc\n"
"qNpOIwIDAQABAkBKZWabgap5OzmsECUDBSW+0VGVVr4JjRA3mau7WktrMNNYx32t\n"
"+w9fWT4G+Bvcp+E3i8Fh0hZTFQQIyHRfAikpAiEAxoU3w/HfON7oN+xwW3KgSVrZ\n"
"rC+/vbB5EMHccxrfWx8CIQDCBpys3PDhfNOKvmdIRHy6JNRqoNfnVqfv3R6k1asw\n"
"fQIgfuGgXcVWlYOqyit9OIWPurKtUycFltiW2EX/fzYasaMCIEqJsbzy8BMgGkCN\n"
"3y2zKdt09Km1+tujvcZ3QyN99lMdAiEArTBuOBncwPRJsJDo3DSR5/qwyToJk47w\n"
"K/TyUGmr7pU=\n"
"-----END PRIVATE KEY-----\n";

char *sig_cacert_str ="-----BEGIN CERTIFICATE-----\n"
"MIIB1zCCAYGgAwIBAgIJAIxnK+AvQtveMA0GCSqGSIb3DQEBBQUAMEcxCzAJBgNV\n"
"BAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARhc2RmMQ0wCwYDVQQKDARh\n"
"c2RmMQswCQYDVQQDDAJjYTAeFw0xNTAzMTUxMjIxNThaFw0xODAxMDIxMjIxNTha\n"
"MEcxCzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARhc2RmMQ0w\n"
"CwYDVQQKDARhc2RmMQswCQYDVQQDDAJjYTBcMA0GCSqGSIb3DQEBAQUAA0sAMEgC\n"
"QQC2ZbZXN6Q+k4yECXUBrv3x/zF0F16G9Yx+b9qxdhkP/+BkA5gyRFNEWL+EovU2\n"
"00F/mSpYsFW+VlIGW0x0rBvJAgMBAAGjUDBOMB0GA1UdDgQWBBTGyK1AVoV5v/Ou\n"
"4FmWrxNg3Aqv5zAfBgNVHSMEGDAWgBTGyK1AVoV5v/Ou4FmWrxNg3Aqv5zAMBgNV\n"
"HRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAFZJdlgEgGTOzRdtPsRY0ezWVow26\n"
"1OUUf1Z6x0e9z/Nzkoo2kfI4iDafebvQ1yMqSWKbUjLGAi/YCq2m3p5tHA==\n"
"-----END CERTIFICATE-----\n";

char *sig_cakey_str ="-----BEGIN RSA PRIVATE KEY-----\n"
"MIIBOwIBAAJBALZltlc3pD6TjIQJdQGu/fH/MXQXXob1jH5v2rF2GQ//4GQDmDJE\n"
"U0RYv4Si9TbTQX+ZKliwVb5WUgZbTHSsG8kCAwEAAQJAJ/wuN/qDsBAqiruEAgV5\n"
"uDZogfmpiE6GKSWePK8WGXJw4HKay/WcFRVhOmBKskPz0TWon+fykgCXUBS0f9jg\n"
"vQIhANocMJCuZm0k51AGUHzHH0+e3KNqdkYtfzFgMUzJexz7AiEA1hVMzCIo/F2s\n"
"33O/F2dw+yQC0w83d/dG06kjssoVBwsCIQCy/FEqWcP6Kz+bXyMr0mgyeaaMgDBB\n"
"FNL9HPg4EFt0gwIgH31ylnRP4w9EZnn4GdE1ZTuezrzmQ9czq96tSZdAEJECIQCQ\n"
"luNLdgk6/rH8iHtN54nKJhTNr4qZWI6b2xSpBAkerw==\n"
"-----END RSA PRIVATE KEY-----\n";

char *enc_cert_str ="-----BEGIN CERTIFICATE-----\n"
"MIIBmjCCAUSgAwIBAgIBAzANBgkqhkiG9w0BAQUFADBHMQswCQYDVQQGEwJERTEN\n"
"MAsGA1UECAwEYXNkZjENMAsGA1UEBwwEYXNkZjENMAsGA1UECgwEYXNkZjELMAkG\n"
"A1UEAwwCY2EwHhcNMTUwMzE1MTMwMzI4WhcNMTYwMzE0MTMwMzI4WjBIMQswCQYD\n"
"VQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTETMBEGA1UECgwKRW5jcnlwdGlv\n"
"bjEPMA0GA1UEAwwGY2xpZW50MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALhqBpcv\n"
"JC/0cdUGgFXzGIwwUxHUpK17LDtigQerl69FBGJJns8NZ0oKVT51/3fgLYlXDEZ9\n"
"kIbw7jcH2NLq30MCAwEAAaMaMBgwCQYDVR0TBAIwADALBgNVHQ8EBAMCBeAwDQYJ\n"
"KoZIhvcNAQEFBQADQQAdBpZ1QuDcnbbJj3yPH85y5cOYL/9d5c1utDeQEIqOFah3\n"
"n+Hm9q37a9O3404+jkNZjOwQtANC72KR5QtRtkhq\n"
"-----END CERTIFICATE-----\n";

char *enc_key_str ="-----BEGIN PRIVATE KEY-----\n"
"MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAuGoGly8kL/Rx1QaA\n"
"VfMYjDBTEdSkrXssO2KBB6uXr0UEYkmezw1nSgpVPnX/d+AtiVcMRn2QhvDuNwfY\n"
"0urfQwIDAQABAkAo1/q7s0otgNNRXg5AewXdzronQdRzQ8uJH4j6XOvMenl571Sp\n"
"Wp3y0owl+exEo+Q66QTn6orqbfOk7KYES1mRAiEA3UaGkQB5mkL9CVSK07G46+iu\n"
"1hDeOFPtzJwanbYcDpsCIQDVWqQXMgJqE55KTK8l8aSoPiH/e7QkNMK4TBoitDto\n"
"eQIger87uMY9rsBIY9udI2/sOBmcmy1CSJbuTFmwPhqel88CIQCXFishqe5/xAjS\n"
"QN+/lRGveuCElcuJ4DsMXAgeD1gKsQIhAJwkG1Q5CFsYbAsFsU0Dd7ZI6aiMDi8w\n"
"iX5k7rlRcZzQ\n"
"-----END PRIVATE KEY-----\n";

char *sig_cert_str ="-----BEGIN CERTIFICATE-----\n"
"MIIBqDCCAVKgAwIBAgIBATANBgkqhkiG9w0BAQUFADBHMQswCQYDVQQGEwJERTEN\n"
"MAsGA1UECAwEYXNkZjENMAsGA1UEBwwEYXNkZjENMAsGA1UECgwEYXNkZjELMAkG\n"
"A1UEAwwCY2EwHhcNMTUwMzE1MTI1NTA5WhcNMTYwMzE0MTI1NTA5WjBWMQswCQYD\n"
"VQQGEwJERTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQg\n"
"V2lkZ2l0cyBQdHkgTHRkMQ8wDQYDVQQDDAZjbGllbnQwXDANBgkqhkiG9w0BAQEF\n"
"AANLADBIAkEA04Eoe6STCMGPcc4znCh6KlKnK5eCtrjX3ZlO7hh7RLBPEX1NdAMp\n"
"Gg7dwOtypmsMSf9yIkoyp9Ad+zO4bXDfeQIDAQABoxowGDAJBgNVHRMEAjAAMAsG\n"
"A1UdDwQEAwIF4DANBgkqhkiG9w0BAQUFAANBAA0+zqbgx+bgtV449kHKfWObgtFO\n"
"aK0BeVoKscmmcsRw+xMVgEcJLLHjY6sMdf4AyxT1DhaCOJngIqkMi7r0QFI=\n"
"-----END CERTIFICATE-----\n";

char *sig_key_str ="-----BEGIN PRIVATE KEY-----\n"
"MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA04Eoe6STCMGPcc4z\n"
"nCh6KlKnK5eCtrjX3ZlO7hh7RLBPEX1NdAMpGg7dwOtypmsMSf9yIkoyp9Ad+zO4\n"
"bXDfeQIDAQABAkBEUINy7EVRnrNmXuPsnGZZJTk5q0ZdHnca7FnCLcYi+Pk1PdEu\n"
"KD2jmKIZ97WAxfMb7+EwtP9OuGT5VC9wHvgBAiEA7i2cIskNm3TwB7Slc6A8PICp\n"
"+wyC4x2vzCtgoR+mjukCIQDjVJrZQM618XoZWrczKp2j1te5pFAdYNFTudktT40S\n"
"EQIhAI82IYHQ/juRLpqThkBmApImkw5+0Vyahw/urSV0kIOxAiEAr/8mSyBDaNTk\n"
"xJBY2QIbPWbtaMnvRG9aYEm3+75k5yECIQDj7FLP17i8LGa2sp3qrXP+3cTb4yK/\n"
"XgTC1Ra2VYVYSQ==\n"
"-----END PRIVATE KEY-----\n";

char *issuedCert_str ="-----BEGIN CERTIFICATE-----\n"
"MIIB7TCCAZegAwIBAgIBBDANBgkqhkiG9w0BAQUFADBHMQswCQYDVQQGEwJERTEN\n"
"MAsGA1UECAwEYXNkZjENMAsGA1UEBwwEYXNkZjENMAsGA1UECgwEYXNkZjELMAkG\n"
"A1UEAwwCY2EwHhcNMTUwMzE1MTQyMzI1WhcNMTYwMzE0MTQyMzI1WjBXMQswCQYD\n"
"VQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQg\n"
"V2lkZ2l0cyBQdHkgTHRkMRAwDgYDVQQDEwdmb28uYmFyMIGfMA0GCSqGSIb3DQEB\n"
"AQUAA4GNADCBiQKBgQCnCz5qi3kW8avPCPhmKOUwSRpCcqOi0RH3tGburtCoHl56\n"
"nhL3X1Xuv+3e6HWS74IOWbwuZXADdSWswFMefJuh6D4tRACzvgbOuXaxxopj9PYn\n"
"ieNunATNl1O1fy1QG3uJiy+QuQe3/xfIIwIVtvsx5ckMfRHk4g4lsOJwLofIvwID\n"
"AQABoxowGDAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DANBgkqhkiG9w0BAQUFAANB\n"
"AGZRYophSHisfLzjA0EV766X+e7hAK1J+G3IZHHn4WvxRGEGRZmEYMwbV3/gIRW8\n"
"bIEcl2LeuPgUGWhLIowjKF0=\n"
"-----END CERTIFICATE-----\n";

char *pkiStatus_str = "PENDING";
//char *pkiStatus_str ="SUCCESS";
//char *pkiStatus_str ="FAILURE";
char *failInfo_str = NULL;
/*TODO: various failInfos when checking failure */
void make_message_data();
void generic_setup()
{
	ck_assert(scep_init(&handle) == SCEPE_OK);
	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, scep_log);
	scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
	make_message_data();
}

void generic_teardown()
{
	BIO_flush(scep_log);
	BIO_free(scep_log);
	scep_cleanup(handle);
}

void make_message_data()
{
	BIO *b;
	b = BIO_new(BIO_s_mem());
	BIO_puts(b, sig_key_str);
	sig_key = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
	ck_assert(sig_key != NULL);
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_puts(b, sig_cert_str);
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	ck_assert(sig_cert != NULL);
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_puts(b, enc_cert_str);
	enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	ck_assert(enc_cert != NULL);
	BIO_free(b);
		
	b = BIO_new(BIO_s_mem());
	BIO_puts(b, enc_key_str);
	enc_key = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
	ck_assert(enc_key != NULL);
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_puts(b, sig_cakey_str);
	sig_cakey = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
	ck_assert(sig_cakey != NULL);
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_puts(b, sig_cacert_str);
	sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	ck_assert(sig_cacert != NULL);
	BIO_free(b);
	
	b = BIO_new(BIO_s_mem());
	BIO_puts(b, enc_cacert_str);
	enc_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	ck_assert(enc_cacert != NULL);
	BIO_free(b);	
	
	b = BIO_new(BIO_s_mem());
	BIO_puts(b, enc_cakey_str);
	enc_cakey = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
	ck_assert(enc_cakey != NULL);
	BIO_free(b);
	
	b = BIO_new(BIO_s_mem());
	BIO_puts(b, test_new_csr);
	req = PEM_read_bio_X509_REQ(b, NULL, 0, 0);
	ck_assert(req != NULL);
	BIO_free(b);
	
	enc_alg = EVP_des_ede3_cbc();
	ck_assert(enc_alg != NULL);
}

void make_pkcsreq_message()
{
	//make_message_data(&sig_cert, &sig_key, NULL, NULL, NULL, NULL, &enc_cert, NULL, &req, &enc_alg);
	SCEP_ERROR s = scep_pkcsreq(
		handle, req, sig_cert, sig_key, enc_cacert, enc_alg, &p7);
	ck_assert(s == SCEPE_OK);
}

void make_pkcsreq_message_nosigcert()
{
	//make_message_data(&sig_cert, &sig_key, NULL, NULL, NULL, NULL, &enc_cert, NULL, &req, &enc_alg);
	
	SCEP_ERROR s = scep_pkcsreq(
		handle, req, sig_cert, sig_key, enc_cacert, enc_alg, &p7_nosigcert);
	ck_assert(s == SCEPE_OK);
}

PKCS7 *make_certrep_message(
		PKCS7 *scep_message, char * pkiStatus, char *failInfo, X509 *issuedCert,
		X509 *sig_cert, EVP_PKEY *sig_key, X509_REQ *req, X509 *enc_cert,
		const EVP_CIPHER *enc_alg, EVP_PKEY *enc_key)
{
	PKCS7 *certrep;
	/*build basics*/
	//make_message_data(&sig_cert, &sig_key, NULL, NULL, NULL, NULL, &enc_cert, NULL, &req, &enc_alg);
	/*build pkcsreq*/
	/*TODO: build other request types*/
	if(scep_message == NULL)
		ck_assert(scep_pkcsreq(
			handle, req, sig_cert, sig_key, enc_cert, enc_alg, &scep_message) == SCEPE_OK);
	/*read in the rest*/
	if(failInfo == NULL)
		failInfo = failInfo_str;
	if(pkiStatus == NULL)
		pkiStatus = pkiStatus_str;
	BIO *b;
	if(issuedCert == NULL) {
		b = BIO_new(BIO_s_mem());
		BIO_puts(b, issuedCert_str);
		PEM_read_bio_X509(b, &issuedCert, 0, 0);
		BIO_free(b);
	}
	/*can be replaced using make message data*/
	if(enc_key == NULL) {
		b = BIO_new(BIO_s_mem());
		BIO_puts(b, enc_cakey_str);
		PEM_read_bio_PrivateKey(b, &enc_key, 0, 0);
		BIO_free(b);
	}
	ck_assert(scep_certrep(handle, scep_message, pkiStatus, failInfo,
			issuedCert, sig_cert, sig_key, enc_cert, enc_alg,
			&certrep) == SCEPE_OK);
	return certrep;
}

SCEP_DATA *make_unwrap_message()
{
	//make_message_data(&sig_cert, &sig_key, NULL, NULL, NULL, NULL, &enc_cert, NULL, &req, &enc_alg)
	scep_pkcsreq(handle, req, sig_cert, sig_key, enc_cacert, enc_alg, &p7);
	ck_assert(p7 != NULL);
	SCEP_DATA *pkiMessage = NULL;
	ck_assert(scep_unwrap(
		handle, p7, enc_cacert, sig_cacert, enc_cakey, &pkiMessage) == SCEPE_OK);
	return pkiMessage;
}

PKCS7 *make_gci_message()
{
	PKCS7 *p7;
	ck_assert(scep_get_cert_initial(
		handle, req, sig_cert, sig_key,
		sig_cacert, enc_cacert, enc_alg, &p7) == SCEPE_OK);
	return p7;
}


PKCS7 *make_gc_message()
{
	PKCS7 *p7;
	ck_assert(scep_get_cert(
		handle, req, sig_cert, sig_key,
		sig_cert, enc_cacert, enc_alg, &p7) == SCEPE_OK);
	return p7;
}


PKCS7 *make_gcrl_message()
{
	PKCS7 *p7;
	ck_assert(scep_get_crl(
		handle, req, sig_cert, sig_key,
		sig_cert, enc_cacert, enc_alg, &p7) == SCEPE_OK);
	return p7;
}

SCEP_ERROR PKCS7_get_content(PKCS7 *p7, PKCS7 **result) {
	BIO *pkcs7bio = NULL;
	PKCS7 *content = NULL;
	SCEP_ERROR error = SCEPE_OK;

	pkcs7bio = PKCS7_dataInit(p7, NULL);
	if(!pkcs7bio)
		OSSL_ERR("Could not create BIO for reading PKCS7 content");

	content = d2i_PKCS7_bio(pkcs7bio, NULL);
	if(!content)
		OSSL_ERR("Could not read from content BIO");

	*result = content;
finally:	
	if(error != SCEPE_OK) {
		if(pkcs7bio)
			BIO_free(pkcs7bio);
		if(content)
			PKCS7_free(content);
	}
	return error;
}

BIO *get_decrypted_data(PKCS7 *p7)
{
	/*client only*/
	PKCS7 *p7enc = NULL, *p7_inner;
	BIO *outbio;
	ck_assert(PKCS7_get_content(p7, &p7enc) == SCEPE_OK);
	outbio = BIO_new(BIO_s_mem());

	// version == 0
	ck_assert_str_eq("0", i2s_ASN1_INTEGER(NULL, p7enc->d.enveloped->version));

	// decrypt and check content
	PKCS7_decrypt(p7enc, enc_cakey, enc_cacert, outbio, 0);
	ERR_print_errors_fp(stderr);
	return outbio;
}

void certrep_setup()
{
	generic_setup();
	p7 = make_certrep_message(NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

void certrep_teardown()
{
	generic_teardown();
}

void unwrap_setup()
{
	generic_setup();
	pkiMessage = make_unwrap_message();
}

void unwrap_teardown()
{
	generic_teardown();
}

void pkcsreq_setup()
{
	generic_setup();
	make_pkcsreq_message();
	scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
	make_pkcsreq_message_nosigcert();
}

void pkcsreq_teardown()
{
	PKCS7_free(p7);
	PKCS7_free(p7_nosigcert);
	generic_teardown();
}

void gci_setup()
{
	generic_setup();
	p7 = make_gci_message();
	scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
	p7_nosigcert = make_gci_message();
}

void gci_teardown()
{
	PKCS7_free(p7);
	PKCS7_free(p7_nosigcert);
	generic_teardown();
}

void gc_setup()
{
	generic_setup();
	p7 = make_gc_message();
	scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
	p7_nosigcert = make_gc_message();
}

void gc_teardown()
{
	PKCS7_free(p7);
	PKCS7_free(p7_nosigcert);
	generic_teardown();
}

void gcrl_setup()
{
	generic_setup();
	p7 = make_gcrl_message();
	scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
	p7_nosigcert = make_gcrl_message();
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

START_TEST(test_unwrap_message)
{
	ck_assert_int_ne(NULL, pkiMessage);
	ck_assert_int_eq(0, pkiMessage->initialEnrollment);
	ck_assert_str_eq(
		"2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
		pkiMessage->transactionID);
	ck_assert_str_eq("19", pkiMessage->messageType);
	ck_assert_int_eq(19, pkiMessage->messageType_int);
    ck_assert_int_ne(NULL, pkiMessage->request);
    ck_assert_int_ne(NULL, pkiMessage->senderNonce);
    ck_assert_str_eq("FOOBARTESTPWD", pkiMessage->challenge_password);
}
END_TEST


START_TEST(test_scep_message_asn1_version)
{
	ck_assert_str_eq("1", i2s_ASN1_INTEGER(NULL, p7->d.sign->version));
}
END_TEST

START_TEST(test_scep_message_transaction_id)
{
	ck_assert_str_eq(
		"2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
		get_attribute_data(p7, handle->oids->transId));
}
END_TEST

START_TEST(test_scep_message_sender_nonce)
{
	ck_assert_int_eq(ASN1_STRING_length(get_attribute(p7, handle->oids->senderNonce)), 16);
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

START_TEST(test_scep_message_certificate)
{
	BIO *b = BIO_new(BIO_s_mem());
	X509 *ref_cert = NULL;
	BIO_puts(b, sig_cert_str);
	PEM_read_bio_X509(b, &ref_cert, 0, 0);
	ck_assert(ref_cert != NULL);
	BIO_free(b);

	ck_assert(sk_X509_num(p7->d.sign->cert) == 1);
	X509 *cert = sk_X509_value(p7->d.sign->cert, 0);
	ck_assert(cert != NULL);
	ck_assert(X509_cmp(cert, ref_cert) == 0);

	ck_assert(sk_X509_num(p7_nosigcert->d.sign->cert) < 1); // -1 or 0
}
END_TEST

START_TEST(test_scep_pkcsreq)
{
	BIO *data = get_decrypted_data(p7);
	X509_REQ *csr = d2i_X509_REQ_bio(data, NULL);
	ck_assert(csr != NULL);

	data = BIO_new(BIO_s_mem());
	BIO_puts(data, test_new_csr);
	X509_REQ *ref_csr = PEM_read_bio_X509_REQ(data, NULL, 0, 0);
	BIO_free(data);

	ck_assert_int_eq(X509_REQ_cmp(csr, ref_csr), 0);
	ck_assert_str_eq(
		MESSAGE_TYPE_PKCSREQ,
		get_attribute_data(p7, handle->oids->messageType));
}
END_TEST

START_TEST(test_scep_pkcsreq_missing_dn)
{
	BIGNUM *bne = BN_new();
	ck_assert_int_eq(BN_set_word(bne, RSA_F4), 1);
	RSA *r = RSA_new();
	ck_assert_int_ne(RSA_generate_key_ex(r, 2048, bne, NULL), 0);

	X509_REQ *req = X509_REQ_new();
	ck_assert_int_ne(X509_REQ_set_version(req, 1), 0);

	EVP_PKEY *key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(key, r);
	ck_assert_int_ne(X509_REQ_set_pubkey(req, key), 0);
	ck_assert_int_ne(X509_REQ_sign(req, key, EVP_sha1()), 0);

	X509 *sig_cert = NULL, *enc_cert = NULL;
	EVP_PKEY *sig_key = NULL;
	const EVP_CIPHER *enc_alg = NULL;
	//make_message_data(&sig_cert, &sig_key, NULL, NULL, NULL, NULL, &enc_cert, NULL, &req, &enc_alg);
	ck_assert(scep_pkcsreq(handle, req, sig_cert, sig_key, enc_cert, enc_alg, &p7) == SCEPE_INVALID_CONTENT);
	ck_assert(p7 == NULL);
}
END_TEST

START_TEST(test_scep_pkcsreq_missing_pubkey)
{
	BIGNUM *bne = BN_new();
	ck_assert_int_eq(BN_set_word(bne, RSA_F4), 1);
	RSA *r = RSA_new();
	ck_assert_int_ne(RSA_generate_key_ex(r, 2048, bne, NULL), 0);

	X509_REQ *req = X509_REQ_new();
	ck_assert_int_ne(X509_REQ_set_version(req, 1), 0);

	X509_NAME *name = X509_REQ_get_subject_name(req);
	ck_assert_int_ne(X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "DE", -1, -1, 0), 0);

	EVP_PKEY *key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(key, r);
	ck_assert_int_ne(X509_REQ_sign(req, key, EVP_sha1()), 0);

	X509 *sig_cert = NULL, *enc_cert = NULL;
	EVP_PKEY *sig_key = NULL;
	const EVP_CIPHER *enc_alg = NULL;
	//make_message_data(&sig_cert, &sig_key, NULL, NULL, NULL, NULL, &enc_cert, NULL, &req, &enc_alg);
	ck_assert(scep_pkcsreq(handle, req, sig_cert, sig_key, enc_cert, enc_alg, &p7) == SCEPE_INVALID_CONTENT);
	ck_assert(p7 == NULL);
}
END_TEST

START_TEST(test_scep_pkcsreq_missing_challenge_password)
{
	BIGNUM *bne = BN_new();
	ck_assert_int_eq(BN_set_word(bne, RSA_F4), 1);
	RSA *r = RSA_new();
	ck_assert_int_ne(RSA_generate_key_ex(r, 2048, bne, NULL), 0);

	X509_REQ *req = X509_REQ_new();
	ck_assert_int_ne(X509_REQ_set_version(req, 1), 0);

	X509_NAME *name = X509_REQ_get_subject_name(req);
	ck_assert_int_ne(X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, "DE", -1, -1, 0), 0);

	EVP_PKEY *key = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(key, r);
	ck_assert_int_ne(X509_REQ_set_pubkey(req, key), 0);
	ck_assert_int_ne(X509_REQ_sign(req, key, EVP_sha1()), 0);

	X509 *sig_cert = NULL, *enc_cert = NULL;
	EVP_PKEY *sig_key = NULL;
	const EVP_CIPHER *enc_alg = NULL;
	//make_message_data(&sig_cert, &sig_key, NULL, NULL, NULL, NULL, &enc_cert, NULL, &req, &enc_alg);
	ck_assert(scep_pkcsreq(handle, req, sig_cert, sig_key, enc_cert, enc_alg, &p7) == SCEPE_INVALID_CONTENT);
	ck_assert(p7 == NULL);
}
END_TEST


START_TEST(test_scep_gci)
{
	BIO *data = get_decrypted_data(p7);

	const unsigned char *data_buf;
	int data_buf_len = BIO_get_mem_data(data, &data_buf);
	ck_assert_int_ne(data_buf_len, 0);

	ck_assert_str_eq(
		MESSAGE_TYPE_GETCERTINITIAL,
		get_attribute_data(p7, handle->oids->messageType));

	PKCS7_ISSUER_AND_SUBJECT *ias = NULL;
	d2i_PKCS7_ISSUER_AND_SUBJECT(&ias, &data_buf, data_buf_len);
	ck_assert(ias != NULL);
	ck_assert_str_eq(X509_NAME_oneline(ias->subject, NULL, 0), "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd/CN=foo.bar");
	ck_assert_str_eq(X509_NAME_oneline(ias->issuer, NULL, 0), "/C=DE/ST=asdf/L=asdf/O=asdf/CN=ca");
}
END_TEST


START_TEST(test_scep_gc)
{
	BIO *data = get_decrypted_data(p7);
	const unsigned char *data_buf;
	int data_buf_len = BIO_get_mem_data(data, &data_buf);
	ck_assert_int_ne(data_buf_len, 0);

	ck_assert_str_eq(
		MESSAGE_TYPE_GETCERT,
		get_attribute_data(p7, handle->oids->messageType));

	PKCS7_ISSUER_AND_SERIAL *ias = NULL;
	d2i_PKCS7_ISSUER_AND_SERIAL(&ias, &data_buf, data_buf_len);
	ck_assert(ias != NULL);
	ck_assert_str_eq(X509_NAME_oneline(ias->issuer, NULL, 0), "/C=DE/ST=asdf/L=asdf/O=asdf/CN=ca");
	ck_assert_str_eq("1", i2s_ASN1_INTEGER(NULL, ias->serial));

}
END_TEST


START_TEST(test_scep_gcrl)
{
	BIO *data = get_decrypted_data(p7);

	const unsigned char *data_buf;
	int data_buf_len = BIO_get_mem_data(data, &data_buf);
	ck_assert_int_ne(data_buf_len, 0);

	ck_assert_str_eq(
		MESSAGE_TYPE_GETCRL,
		get_attribute_data(p7, handle->oids->messageType));

	PKCS7_ISSUER_AND_SERIAL *ias = NULL;
	d2i_PKCS7_ISSUER_AND_SERIAL(&ias, &data_buf, data_buf_len);
	ck_assert(ias != NULL);
	ck_assert_str_eq(X509_NAME_oneline(ias->issuer, NULL, 0), "/C=DE/ST=asdf/L=asdf/O=asdf/CN=ca");
	ck_assert_str_eq("1", i2s_ASN1_INTEGER(NULL, ias->serial));

}
END_TEST


Suite * scep_message_suite(void)
{
	Suite *s = suite_create("Message");

	/*test Certrep*/
	TCase *tc_certrep_msg = tcase_create("Certrep Message");
	tcase_add_checked_fixture(tc_certrep_msg, certrep_setup, certrep_teardown);
	//tcase_add_test(tc_certrep_msg, test_certrep_message);
	suite_add_tcase(s, tc_certrep_msg);
	
	/*test unwrapping*/
	TCase *tc_unwrap_msg = tcase_create("Unwrap Message");
	tcase_add_checked_fixture(tc_unwrap_msg, unwrap_setup, unwrap_teardown);
	tcase_add_test(tc_unwrap_msg, test_unwrap_message);
	suite_add_tcase(s, tc_unwrap_msg);

	/* PKCSReq tests */
	TCase *tc_pkcsreq_msg = tcase_create("PKCSReq Message");
	tcase_add_checked_fixture(tc_pkcsreq_msg, pkcsreq_setup, pkcsreq_teardown);

	tcase_add_test(tc_pkcsreq_msg, test_scep_message_asn1_version);
	tcase_add_test(tc_pkcsreq_msg, test_scep_message_transaction_id);
	tcase_add_test(tc_pkcsreq_msg, test_scep_message_sender_nonce);
	tcase_add_test(tc_pkcsreq_msg, test_scep_message_type);
	tcase_add_test(tc_pkcsreq_msg, test_scep_message_content_type);
	tcase_add_test(tc_pkcsreq_msg, test_scep_message_certificate);
	tcase_add_test(tc_pkcsreq_msg, test_scep_pkcsreq);
	suite_add_tcase(s, tc_pkcsreq_msg);

	TCase *tc_pkcsreq_errors = tcase_create("PKCSReq Invalid");
	tcase_add_checked_fixture(tc_pkcsreq_errors, generic_setup, generic_teardown);
	tcase_add_test(tc_pkcsreq_errors, test_scep_pkcsreq_missing_dn);
	tcase_add_test(tc_pkcsreq_errors, test_scep_pkcsreq_missing_pubkey);
	tcase_add_test(tc_pkcsreq_errors, test_scep_pkcsreq_missing_challenge_password);
	suite_add_tcase(s, tc_pkcsreq_errors);

	/* GetCertInitial tests */
	TCase *tc_gci_msg = tcase_create("GetCertInitial Message");
	tcase_add_checked_fixture(tc_gci_msg, gci_setup, gci_teardown);
	tcase_add_test(tc_gci_msg, test_scep_message_transaction_id);
	tcase_add_test(tc_gci_msg, test_scep_message_sender_nonce);
	tcase_add_test(tc_gci_msg, test_scep_message_certificate);
	tcase_add_test(tc_gci_msg, test_scep_gci);
	suite_add_tcase(s, tc_gci_msg);

	/* GetCert tests */
	TCase *tc_gc_msg = tcase_create("GetCert Message");
	tcase_add_checked_fixture(tc_gc_msg, gc_setup, gc_teardown);
	tcase_add_test(tc_gc_msg, test_scep_message_transaction_id);
	tcase_add_test(tc_gc_msg, test_scep_message_sender_nonce);
	tcase_add_test(tc_gc_msg, test_scep_message_certificate);
	tcase_add_test(tc_gc_msg, test_scep_gc);
	suite_add_tcase(s, tc_gc_msg);

	/* GetCRL tests */
	TCase *tc_gcrl_msg = tcase_create("GetRL Message");
	tcase_add_checked_fixture(tc_gcrl_msg, gcrl_setup, gc_teardown);
	tcase_add_test(tc_gcrl_msg, test_scep_message_transaction_id);
	tcase_add_test(tc_gcrl_msg, test_scep_message_sender_nonce);
	tcase_add_test(tc_gcrl_msg, test_scep_message_certificate);
	tcase_add_test(tc_gcrl_msg, test_scep_gcrl);
	suite_add_tcase(s, tc_gcrl_msg);

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
