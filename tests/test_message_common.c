#include <check.h>
#include "scep.h"
#include "scep_tests.h"
#include <unistd.h>


static SCEP *handle;
static BIO *scep_log;
static PKCS7 *p7 = NULL, *p7_nosigcert = NULL;
static SCEP_DATA *pkiMessage, *pkiMessage_failure, *pkiMessage_success;
/*TODO: Do we need them*/
static EVP_PKEY *dec_key;
static X509 *dec_cert;
#ifdef WITH_ENGINE_TESTS
static int engine = 0;
#endif /* WITH_ENGINE_TESTS */


static X509 *sig_cert;
static EVP_PKEY *sig_key;
static X509 *enc_cert;
static EVP_PKEY *enc_key;
static X509 *sig_cacert;
static EVP_PKEY *sig_cakey;
static X509 *enc_cacert;
static EVP_PKEY *enc_cakey;
static X509_REQ *req;


static char *test_new_key = "-----BEGIN RSA PRIVATE KEY-----\n"
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

static char *test_new_csr = "-----BEGIN CERTIFICATE REQUEST-----\n"
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

static char *enc_cacert_str = "-----BEGIN CERTIFICATE-----\n"
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

static char *enc_cakey_str = "-----BEGIN PRIVATE KEY-----\n"
"MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAlnYU4Qa0+wtX+hLT\n"
"ij5eZ6gXf/WJE1MA7fagFATTOgB+rQxSMvORpNZOtGcGAWMiGU+5DdhKpyuMxAUc\n"
"qNpOIwIDAQABAkBKZWabgap5OzmsECUDBSW+0VGVVr4JjRA3mau7WktrMNNYx32t\n"
"+w9fWT4G+Bvcp+E3i8Fh0hZTFQQIyHRfAikpAiEAxoU3w/HfON7oN+xwW3KgSVrZ\n"
"rC+/vbB5EMHccxrfWx8CIQDCBpys3PDhfNOKvmdIRHy6JNRqoNfnVqfv3R6k1asw\n"
"fQIgfuGgXcVWlYOqyit9OIWPurKtUycFltiW2EX/fzYasaMCIEqJsbzy8BMgGkCN\n"
"3y2zKdt09Km1+tujvcZ3QyN99lMdAiEArTBuOBncwPRJsJDo3DSR5/qwyToJk47w\n"
"K/TyUGmr7pU=\n"
"-----END PRIVATE KEY-----\n";

static char *sig_cacert_str ="-----BEGIN CERTIFICATE-----\n"
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

static char *sig_cakey_str ="-----BEGIN RSA PRIVATE KEY-----\n"
"MIIBOwIBAAJBALZltlc3pD6TjIQJdQGu/fH/MXQXXob1jH5v2rF2GQ//4GQDmDJE\n"
"U0RYv4Si9TbTQX+ZKliwVb5WUgZbTHSsG8kCAwEAAQJAJ/wuN/qDsBAqiruEAgV5\n"
"uDZogfmpiE6GKSWePK8WGXJw4HKay/WcFRVhOmBKskPz0TWon+fykgCXUBS0f9jg\n"
"vQIhANocMJCuZm0k51AGUHzHH0+e3KNqdkYtfzFgMUzJexz7AiEA1hVMzCIo/F2s\n"
"33O/F2dw+yQC0w83d/dG06kjssoVBwsCIQCy/FEqWcP6Kz+bXyMr0mgyeaaMgDBB\n"
"FNL9HPg4EFt0gwIgH31ylnRP4w9EZnn4GdE1ZTuezrzmQ9czq96tSZdAEJECIQCQ\n"
"luNLdgk6/rH8iHtN54nKJhTNr4qZWI6b2xSpBAkerw==\n"
"-----END RSA PRIVATE KEY-----\n";

static char *enc_cert_str ="-----BEGIN CERTIFICATE-----\n"
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

static char *enc_key_str ="-----BEGIN PRIVATE KEY-----\n"
"MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAuGoGly8kL/Rx1QaA\n"
"VfMYjDBTEdSkrXssO2KBB6uXr0UEYkmezw1nSgpVPnX/d+AtiVcMRn2QhvDuNwfY\n"
"0urfQwIDAQABAkAo1/q7s0otgNNRXg5AewXdzronQdRzQ8uJH4j6XOvMenl571Sp\n"
"Wp3y0owl+exEo+Q66QTn6orqbfOk7KYES1mRAiEA3UaGkQB5mkL9CVSK07G46+iu\n"
"1hDeOFPtzJwanbYcDpsCIQDVWqQXMgJqE55KTK8l8aSoPiH/e7QkNMK4TBoitDto\n"
"eQIger87uMY9rsBIY9udI2/sOBmcmy1CSJbuTFmwPhqel88CIQCXFishqe5/xAjS\n"
"QN+/lRGveuCElcuJ4DsMXAgeD1gKsQIhAJwkG1Q5CFsYbAsFsU0Dd7ZI6aiMDi8w\n"
"iX5k7rlRcZzQ\n"
"-----END PRIVATE KEY-----\n";

static char *sig_cert_str ="-----BEGIN CERTIFICATE-----\n"
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

static char *sig_key_str ="-----BEGIN PRIVATE KEY-----\n"
"MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA04Eoe6STCMGPcc4z\n"
"nCh6KlKnK5eCtrjX3ZlO7hh7RLBPEX1NdAMpGg7dwOtypmsMSf9yIkoyp9Ad+zO4\n"
"bXDfeQIDAQABAkBEUINy7EVRnrNmXuPsnGZZJTk5q0ZdHnca7FnCLcYi+Pk1PdEu\n"
"KD2jmKIZ97WAxfMb7+EwtP9OuGT5VC9wHvgBAiEA7i2cIskNm3TwB7Slc6A8PICp\n"
"+wyC4x2vzCtgoR+mjukCIQDjVJrZQM618XoZWrczKp2j1te5pFAdYNFTudktT40S\n"
"EQIhAI82IYHQ/juRLpqThkBmApImkw5+0Vyahw/urSV0kIOxAiEAr/8mSyBDaNTk\n"
"xJBY2QIbPWbtaMnvRG9aYEm3+75k5yECIQDj7FLP17i8LGa2sp3qrXP+3cTb4yK/\n"
"XgTC1Ra2VYVYSQ==\n"
"-----END PRIVATE KEY-----\n";

static void make_message_data();
#ifdef WITH_ENGINE_TESTS
static void make_engine_message_data();
#endif /* WITH_ENGINE_TESTS */
static void generic_setup()
{
    scep_init(&handle);
    scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
    scep_conf_set(handle, SCEPCFG_LOG, scep_log);
    scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
    make_message_data();
}

#ifdef WITH_ENGINE_TESTS
static void generic_engine_setup()
{
    generic_setup();
    SCEP_ERROR error;
    error = scep_conf_set(handle, SCEPCFG_ENGINE_PARAM, "MODULE_PATH", MODULE_PATH);
    ck_assert_int_eq(error, SCEPE_OK);
    error = scep_conf_set(handle, SCEPCFG_ENGINE, "dynamic", "pkcs11", ENGINE_PATH);
    ck_assert_int_eq(error, SCEPE_OK);
    make_engine_message_data();

}
#endif /* WITH_ENGINE_TESTS */

static void free_message_data();
static void generic_teardown()
{
    BIO_flush(scep_log);
    BIO_free(scep_log);
    free_message_data();
    scep_cleanup(handle);
}

static void make_message_data()
{
    BIO *b;
    b = BIO_new(BIO_s_mem());
    BIO_puts(b, sig_key_str);
    sig_key = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, sig_cert_str);
    sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, enc_cert_str);
    enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, enc_key_str);
    enc_key = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, sig_cakey_str);
    sig_cakey = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, sig_cacert_str);
    sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, enc_cacert_str);
    enc_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, enc_cakey_str);
    enc_cakey = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, test_new_csr);
    req = PEM_read_bio_X509_REQ(b, NULL, 0, 0);
    BIO_free(b);
}

#ifdef WITH_ENGINE_TESTS
static void make_engine_message_data()
{
#define TMP_TEMPLATE "tmp/XXXXXX"
    char name_buffer[20], cmd_buffer[512];
    int filedes, id = 0;
    BIO *out;
    PKCS8_PRIV_KEY_INFO *p8inf;
    ENGINE *e = NULL;
    ck_assert_int_eq(scep_engine_get(handle, &e), SCEPE_OK);
    ck_assert(ENGINE_ctrl_cmd_string(e, "PIN", "1234", 0));
    int res = system(SOFTHSM_BIN " --init-token --slot 0 --label foo --pin 1234 --so-pin 123456");
    ck_assert_int_eq(res, 0);

#define import_key(key_name) \
    id++; \
    strncpy(name_buffer, TMP_TEMPLATE, 20); \
    filedes = mkstemp(name_buffer); \
    out = BIO_new_fd(filedes, BIO_NOCLOSE); \
    p8inf = EVP_PKEY2PKCS8(key_name); \
    ck_assert(p8inf != NULL); \
    PEM_write_bio_PKCS8_PRIV_KEY_INFO(out, p8inf); \
    ck_assert(snprintf(cmd_buffer, 512, SOFTHSM_BIN " --import %s --slot 0 --pin 1234 --label %s --id %02d", name_buffer, #key_name, id) >= 0); \
    res = system(cmd_buffer); \
    ck_assert_int_eq(res, 0); \
    BIO_free(out); \
    close(filedes); \
    ck_assert(snprintf(cmd_buffer, 512, "label_%s", #key_name) >= 0); \
    EVP_PKEY_free(key_name); \
    key_name = ENGINE_load_private_key(e, cmd_buffer, NULL, NULL); \
    ck_assert(key_name != NULL); \
    unlink(name_buffer)

    import_key(sig_key);
    import_key(enc_key);
    import_key(sig_cakey);
    import_key(enc_cakey);
    res = system("sqlite3 softhsm-slot0.db \"UPDATE Attributes SET value='1' WHERE type=261;\"");
    ck_assert_int_eq(res, 0);

#undef import_key
#undef TMP_TEMPLATE
}
#endif /* WITH_ENGINE_TESTS */

static void free_message_data()
{
    EVP_PKEY_free(sig_key);
    X509_free(sig_cert);
    X509_free(enc_cert);
    EVP_PKEY_free(enc_key);
    EVP_PKEY_free(sig_cakey);
    X509_free(sig_cacert);
    X509_free(enc_cacert);
    EVP_PKEY_free(enc_cakey);
    X509_REQ_free(req);
}

START_TEST(test_scep_message_asn1_version)
{
    char *val = i2s_ASN1_INTEGER(NULL, p7->d.sign->version);
    ck_assert_str_eq("1", val);
    free(val);
}
END_TEST

START_TEST(test_scep_message_transaction_id)
{
    ck_assert_str_eq(
        "2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
        get_attribute_data(p7, handle->oids->transId));
}
END_TEST

START_TEST(test_scep_message_transaction_id_getcert)
{
    ck_assert_str_eq(
        "2BF79F781878B57DC31E8BE733A3425DC09D996BA2F75A3D3F23DBEAEAA6C328",
        get_attribute_data(p7, handle->oids->transId));
}
END_TEST

START_TEST(test_scep_message_transaction_id_getcrl)
{
    ck_assert_str_eq(
        "DB49755912953898D79286AB45DCAEF07C20F7FFB2C972E67F4AE276BBE299D1",
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
    X509_free(ref_cert);
}
END_TEST

START_TEST(test_unwrap_response)
{
    ck_assert_msg(0, "Test unwrap_response sets a request type");
}
END_TEST

#ifndef HAVE_MAKE_MESSAGE
static PKCS7 *make_message();
START_TEST(test_unwrap_invalid_version)
{
    PKCS7 *msg = make_message();
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(msg), 0);
    ck_assert_int_ne(ASN1_INTEGER_set(si->version, 15), 0);
    ck_assert_int_eq(scep_unwrap(
        handle, msg, sig_cacert, enc_cacert, enc_cakey, NULL), SCEPE_INVALID_CONTENT);
    PKCS7_free(msg);
}
END_TEST
#endif /* HAVE_MAKE_MESSAGE */