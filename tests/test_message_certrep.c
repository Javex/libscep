#include <check.h>
#include "scep.h"
#define HAVE_MAKE_MESSAGE 1
#include "test_message_common.c"

static X509 *issued_cert = NULL;
static char *issued_cert_str ="-----BEGIN CERTIFICATE-----\n"
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

static PKCS7 *certrep_pending = NULL;
static char *certrep_pending_str = "-----BEGIN PKCS7-----\n"
"MIID1AYJKoZIhvcNAQcCoIIDxTCCA8ECAQExDjAMBggqhkiG9w0CBQUAMA8GCSqG\n"
"SIb3DQEHAaACBACgggHbMIIB1zCCAYGgAwIBAgIJAIxnK+AvQtveMA0GCSqGSIb3\n"
"DQEBBQUAMEcxCzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARh\n"
"c2RmMQ0wCwYDVQQKDARhc2RmMQswCQYDVQQDDAJjYTAeFw0xNTAzMTUxMjIxNTha\n"
"Fw0xODAxMDIxMjIxNThaMEcxCzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0w\n"
"CwYDVQQHDARhc2RmMQ0wCwYDVQQKDARhc2RmMQswCQYDVQQDDAJjYTBcMA0GCSqG\n"
"SIb3DQEBAQUAA0sAMEgCQQC2ZbZXN6Q+k4yECXUBrv3x/zF0F16G9Yx+b9qxdhkP\n"
"/+BkA5gyRFNEWL+EovU200F/mSpYsFW+VlIGW0x0rBvJAgMBAAGjUDBOMB0GA1Ud\n"
"DgQWBBTGyK1AVoV5v/Ou4FmWrxNg3Aqv5zAfBgNVHSMEGDAWgBTGyK1AVoV5v/Ou\n"
"4FmWrxNg3Aqv5zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAFZJdlgEg\n"
"GTOzRdtPsRY0ezWVow261OUUf1Z6x0e9z/Nzkoo2kfI4iDafebvQ1yMqSWKbUjLG\n"
"Ai/YCq2m3p5tHDGCAbowggG2AgEBMFQwRzELMAkGA1UEBhMCREUxDTALBgNVBAgM\n"
"BGFzZGYxDTALBgNVBAcMBGFzZGYxDTALBgNVBAoMBGFzZGYxCzAJBgNVBAMMAmNh\n"
"AgkAjGcr4C9C294wDAYIKoZIhvcNAgUFAKCB+zARBgpghkgBhvhFAQkCMQMTATMw\n"
"EQYKYIZIAYb4RQEJAzEDEwEzMBwGCSqGSIb3DQEJBTEPFw0xNTA0MDYxNjIyMjha\n"
"MB8GCSqGSIb3DQEJBDESBBDUHYzZjwCyBOmACZjs+EJ+MCAGCmCGSAGG+EUBCQUx\n"
"EgQQxXaAC0LFaFWMLh2hGNaTCDAgBgpghkgBhvhFAQkGMRIEEMV2gAtCxWhVjC4d\n"
"oRjWkwgwUAYKYIZIAYb4RQEJBzFCE0AyRjNDODgxMTRDMjgzRTlBNkNENTdCQjgy\n"
"NjZDRTMxM0RCMEJFRTBEQUY3NjlENzcwQzRFNUZGQjlDNEMxMDE2MA0GCSqGSIb3\n"
"DQEBAQUABEBQ9WJNzOnX3klE2GrpYfkG0MB0pLgCOhrRY0me22CXaU1LFVy2z3Vi\n"
"PTM1WRNGAryx2bzxPnjScKvpQjXv8g+6\n"
"-----END PKCS7-----\n";

static PKCS7 *certrep_success = NULL;
static char *certrep_success_str = "-----BEGIN PKCS7-----\n"
"MIIG6gYJKoZIhvcNAQcCoIIG2zCCBtcCAQExDjAMBggqhkiG9w0CBQUAMIIDIwYJ\n"
"KoZIhvcNAQcBoIIDFASCAxAwggMMBgkqhkiG9w0BBwOgggL9MIIC+QIBADGBpTCB\n"
"ogIBADBMMEcxCzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARh\n"
"c2RmMQ0wCwYDVQQKDARhc2RmMQswCQYDVQQDDAJjYQIBAzANBgkqhkiG9w0BAQEF\n"
"AARAHNxN4Lh0/dA7U1ZDWfv6Q6JlcA6N9y5CzZvESnQJdAJlOsink8cROBayi8Ej\n"
"0SweDCEXG+9GV8rWldFP722A7zCCAkoGCSqGSIb3DQEHATARBgUrDgMCBwQIzXfA\n"
"Zq6FpLuAggIo2CBOTtpTCKPYe42lGUsFI/A48V+RIx8M77kg6jkO34Qc/4FD9B/C\n"
"PMnO3MfT4m4deuiv9OP6dJVVqpKAHdKmQDHbFh97hB1tsawnbmYFbjl7d2Q2u1+B\n"
"GtAY9yQUqVfOAimFzRIf1o243A02BYm5Df4jhX/j+GQssYVLZp2tr+8rj3MJ43R9\n"
"WjavjdNlrJhNhgNDUL8AdcVT9KE1MaoMcbddN/bDxmhFa15Vz42XAkLdo8IRZqxU\n"
"+2H0FAPUh20Ahu58ySgpdDYqeqArQOTpbzIxMe38pfKk5ab9WKxFxQRR89F0SFnc\n"
"giLoEw3fep+FwHfm9Jrom8CQH0CI7ERwr7lw3RaSXoSaHXz59UaSjqChpILGgyBg\n"
"ruKohZumhDf4U5lAcIryTlv2okX62t20XN10rWeaVNR4u0johLHyZt2CGAyCT0af\n"
"0TwW1xMtnmKdKFFIzedYY2KafawuKMo6pm1dAOHavfAgeouqbNnYKCAgrSs9SheH\n"
"H1ecDe7vhp7NAJOZqTxse7XfzVuDuM4vD6YZz1nwYW277UUEJgWo4Rft/Kze4p3X\n"
"Up9oh3iwlU52ue/Djv7D9L9lXhpKeNzFE02txmD/tBT1D1h9o3adXMgAJov3ULF6\n"
"K0fPPpNrrj3rkmPSfCCqs00UBEiMGr7xUQxhA/f7/4mAGeeEDRY7Mwt5HiQC6L5c\n"
"MV1/mMYfKSWuiIiFFsruWGnljF2vdCQFWnkr4YzPlOxtoIIB2zCCAdcwggGBoAMC\n"
"AQICCQCMZyvgL0Lb3jANBgkqhkiG9w0BAQUFADBHMQswCQYDVQQGEwJERTENMAsG\n"
"A1UECAwEYXNkZjENMAsGA1UEBwwEYXNkZjENMAsGA1UECgwEYXNkZjELMAkGA1UE\n"
"AwwCY2EwHhcNMTUwMzE1MTIyMTU4WhcNMTgwMTAyMTIyMTU4WjBHMQswCQYDVQQG\n"
"EwJERTENMAsGA1UECAwEYXNkZjENMAsGA1UEBwwEYXNkZjENMAsGA1UECgwEYXNk\n"
"ZjELMAkGA1UEAwwCY2EwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAtmW2VzekPpOM\n"
"hAl1Aa798f8xdBdehvWMfm/asXYZD//gZAOYMkRTRFi/hKL1NtNBf5kqWLBVvlZS\n"
"BltMdKwbyQIDAQABo1AwTjAdBgNVHQ4EFgQUxsitQFaFeb/zruBZlq8TYNwKr+cw\n"
"HwYDVR0jBBgwFoAUxsitQFaFeb/zruBZlq8TYNwKr+cwDAYDVR0TBAUwAwEB/zAN\n"
"BgkqhkiG9w0BAQUFAANBABWSXZYBIBkzs0XbT7EWNHs1laMNutTlFH9WesdHvc/z\n"
"c5KKNpHyOIg2n3m70NcjKklim1IyxgIv2Aqtpt6ebRwxggG6MIIBtgIBATBUMEcx\n"
"CzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARhc2RmMQ0wCwYD\n"
"VQQKDARhc2RmMQswCQYDVQQDDAJjYQIJAIxnK+AvQtveMAwGCCqGSIb3DQIFBQCg\n"
"gfswEQYKYIZIAYb4RQEJAjEDEwEzMBEGCmCGSAGG+EUBCQMxAxMBMDAcBgkqhkiG\n"
"9w0BCQUxDxcNMTUwNDA3MTYyMzQwWjAfBgkqhkiG9w0BCQQxEgQQt1umyZXVxNfB\n"
"V6pLhW1HLjAgBgpghkgBhvhFAQkFMRIEEMV2gAtCxWhVjC4doRjWkwgwIAYKYIZI\n"
"AYb4RQEJBjESBBDFdoALQsVoVYwuHaEY1pMIMFAGCmCGSAGG+EUBCQcxQhNAMkYz\n"
"Qzg4MTE0QzI4M0U5QTZDRDU3QkI4MjY2Q0UzMTNEQjBCRUUwREFGNzY5RDc3MEM0\n"
"RTVGRkI5QzRDMTAxNjANBgkqhkiG9w0BAQEFAARAQxRzQdy/bjOlUroRJbbWqfOc\n"
"5Jyyzie0psLdAPMN1nBfTDTofhvBoOzF6hnz894TO+TuTbproW/q5M+S/ggLPw==\n"
"-----END PKCS7-----\n";

static PKCS7 *certrep_failure = NULL;
static char *certrep_failure_str = "-----BEGIN PKCS7-----\n"
"MIID6AYJKoZIhvcNAQcCoIID2TCCA9UCAQExDjAMBggqhkiG9w0CBQUAMA8GCSqG\n"
"SIb3DQEHAaACBACgggHbMIIB1zCCAYGgAwIBAgIJAIxnK+AvQtveMA0GCSqGSIb3\n"
"DQEBBQUAMEcxCzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARh\n"
"c2RmMQ0wCwYDVQQKDARhc2RmMQswCQYDVQQDDAJjYTAeFw0xNTAzMTUxMjIxNTha\n"
"Fw0xODAxMDIxMjIxNThaMEcxCzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0w\n"
"CwYDVQQHDARhc2RmMQ0wCwYDVQQKDARhc2RmMQswCQYDVQQDDAJjYTBcMA0GCSqG\n"
"SIb3DQEBAQUAA0sAMEgCQQC2ZbZXN6Q+k4yECXUBrv3x/zF0F16G9Yx+b9qxdhkP\n"
"/+BkA5gyRFNEWL+EovU200F/mSpYsFW+VlIGW0x0rBvJAgMBAAGjUDBOMB0GA1Ud\n"
"DgQWBBTGyK1AVoV5v/Ou4FmWrxNg3Aqv5zAfBgNVHSMEGDAWgBTGyK1AVoV5v/Ou\n"
"4FmWrxNg3Aqv5zAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA0EAFZJdlgEg\n"
"GTOzRdtPsRY0ezWVow261OUUf1Z6x0e9z/Nzkoo2kfI4iDafebvQ1yMqSWKbUjLG\n"
"Ai/YCq2m3p5tHDGCAc4wggHKAgEBMFQwRzELMAkGA1UEBhMCREUxDTALBgNVBAgM\n"
"BGFzZGYxDTALBgNVBAcMBGFzZGYxDTALBgNVBAoMBGFzZGYxCzAJBgNVBAMMAmNh\n"
"AgkAjGcr4C9C294wDAYIKoZIhvcNAgUFAKCCAQ4wEQYKYIZIAYb4RQEJAjEDEwEz\n"
"MBEGCmCGSAGG+EUBCQMxAxMBMjARBgpghkgBhvhFAQkEMQMTATAwHAYJKoZIhvcN\n"
"AQkFMQ8XDTE1MDQwNjE2Mzk0NFowHwYJKoZIhvcNAQkEMRIEENQdjNmPALIE6YAJ\n"
"mOz4Qn4wIAYKYIZIAYb4RQEJBTESBBDFdoALQsVoVYwuHaEY1pMIMCAGCmCGSAGG\n"
"+EUBCQYxEgQQxXaAC0LFaFWMLh2hGNaTCDBQBgpghkgBhvhFAQkHMUITQDJGM0M4\n"
"ODExNEMyODNFOUE2Q0Q1N0JCODI2NkNFMzEzREIwQkVFMERBRjc2OUQ3NzBDNEU1\n"
"RkZCOUM0QzEwMTYwDQYJKoZIhvcNAQEBBQAEQBDMKC1DUo39J/K0MOdPFb7XvJy2\n"
"B+oiOeChkprVCXAf3ROSda1/KXTdvYyRTzqS9z1VAFXFqdpnDNJxxZAIaoY=\n"
"-----END PKCS7-----\n";

static PKCS7 *certrep_getcacert = NULL;
static char *certrep_getcacert_str = "-----BEGIN PKCS7-----\n"
"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\n"
"AA==\n"
"-----END PKCS7-----\n";

static PKCS7* make_message(
        SCEP_PKISTATUS pkiStatus, SCEP_FAILINFO failInfo,
        X509 *issued_cert, X509 *enc_cert, STACK_OF(X509) *add_certs) {
    PKCS7 *p7 = NULL;
    char *transactionID = "2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016";
    unsigned char senderNonce[] = {0xc5, 0x76, 0x80, 0xb, 0x42, 0xc5, 0x68, 0x55, 0x8c, 0x2e, 0x1d, 0xa1, 0x18, 0xd6, 0x93, 0x8};
    SCEP_ERROR error = scep_certrep(
        handle, transactionID, senderNonce, pkiStatus,
        failInfo, issued_cert, sig_cacert, sig_cakey, enc_cert, add_certs, NULL, &p7);
    ck_assert(error == SCEPE_OK);
    return p7;
}

static void free_message(PKCS7 *p7) {
    if(p7)
        PKCS7_free(p7);
}

static void setup()
{
    generic_setup();

    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, issued_cert_str);
    issued_cert = PEM_read_bio_X509(b, NULL, 0, 0);
    ck_assert(issued_cert != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_pending_str);
    certrep_pending = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_pending != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_success_str);
    certrep_success = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_success != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_failure_str);
    certrep_failure = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_failure != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_getcacert_str);
    certrep_getcacert = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_getcacert != NULL);
    BIO_free(b);

    p7 = NULL;
    p7_nosigcert = NULL;
}

static void teardown()
{
    free_message(p7);
    p7 = NULL;
    free_message(p7_nosigcert);
    p7_nosigcert = NULL;
    X509_free(issued_cert);
    PKCS7_free(certrep_success);
    PKCS7_free(certrep_failure);
    PKCS7_free(certrep_pending);
    generic_teardown();
}

static void setup_pending()
{
    setup();
    p7 = make_message(
        SCEP_PENDING, 0,
        NULL, NULL, NULL);
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message(
        SCEP_PENDING, 0,
        NULL, NULL, NULL);
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
}

static void setup_failure()
{
    setup();
    p7 = make_message(
        SCEP_FAILURE, SCEP_BAD_MESSAGE_CHECK,
        NULL, NULL, NULL);
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message(
        SCEP_FAILURE, SCEP_BAD_MESSAGE_CHECK,
        NULL, NULL, NULL);
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
}

static void setup_pkcsreq_success()
{
    setup();

    /* Global message */
    STACK_OF(X509) *cert_stack = sk_X509_new_null();
    X509 *c = X509_dup(sig_cacert);
    sk_X509_push(cert_stack, c);
    p7 = make_message(SCEP_SUCCESS, 0, issued_cert, enc_cert, cert_stack);
    sk_X509_free(cert_stack);

    /* Global message without sig cert */
    cert_stack = sk_X509_new_null();
    sk_X509_push(cert_stack, c);
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message(SCEP_SUCCESS, 0, issued_cert, enc_cert, cert_stack);
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
    sk_X509_free(cert_stack);
}

#ifdef WITH_ENGINE_TESTS
static void setup_engine()
{
    generic_engine_setup();

    BIO *b = BIO_new(BIO_s_mem());
    BIO_puts(b, issued_cert_str);
    issued_cert = PEM_read_bio_X509(b, NULL, 0, 0);
    ck_assert(issued_cert != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_pending_str);
    certrep_pending = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_pending != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_success_str);
    certrep_success = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_success != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_failure_str);
    certrep_failure = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_failure != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_getcacert_str);
    certrep_getcacert = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_getcacert != NULL);
    BIO_free(b);

    p7 = NULL;
    p7_nosigcert = NULL;
}

static void setup_pending_engine()
{
    setup_engine();
    p7 = make_message(
        SCEP_PENDING, 0,
        NULL, NULL, NULL);
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message(
        SCEP_PENDING, 0,
        NULL, NULL, NULL);
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
}

static void setup_failure_engine()
{
    setup_engine();
    p7 = make_message(
        SCEP_FAILURE, SCEP_BAD_MESSAGE_CHECK,
        NULL, NULL, NULL);
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message(
        SCEP_FAILURE, SCEP_BAD_MESSAGE_CHECK,
        NULL, NULL, NULL);
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
}

static void setup_pkcsreq_success_engine()
{
    setup_engine();

    /* Global message */
    STACK_OF(X509) *cert_stack = sk_X509_new_null();
    X509 *c = X509_dup(sig_cacert);
    sk_X509_push(cert_stack, c);
    p7 = make_message(SCEP_SUCCESS, 0, issued_cert, enc_cert, cert_stack);
    sk_X509_free(cert_stack);

    /* Global message without sig cert */
    cert_stack = sk_X509_new_null();
    sk_X509_push(cert_stack, c);
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_SKIP_SIGNER_CERT);
    p7_nosigcert = make_message(SCEP_SUCCESS, 0, issued_cert, enc_cert, cert_stack);
    scep_conf_set(handle, SCEPCFG_FLAG_CLEAR, SCEP_SKIP_SIGNER_CERT);
    sk_X509_free(cert_stack);
}
#endif /* WITH_ENGINE_TESTS */

START_TEST(test_pkcsreq_pending)
{
    ck_assert(p7 != NULL);
    ck_assert_str_eq(
        SCEP_MSG_CERTREP_STR,
        get_attribute_data(p7, handle->oids->messageType));
    ck_assert_str_eq(get_attribute_data(p7, handle->oids->pkiStatus), SCEP_PKISTATUS_PENDING);

    /* Make sure pkcsPKIEnvelope is omitted */
    PKCS7 *datap7 = p7->d.sign->contents;
    ck_assert(PKCS7_type_is_data(datap7));
    ASN1_OCTET_STRING *data = datap7->d.data;
    ck_assert_int_eq(data->length, 0);
    ck_assert_int_eq(data->data, 0);
    ck_assert_int_eq(data->type, V_ASN1_OCTET_STRING);
}
END_TEST

START_TEST(test_pkcsreq_failure)
{
    ck_assert(p7 != NULL);
    ck_assert_str_eq(
        SCEP_MSG_CERTREP_STR,
        get_attribute_data(p7, handle->oids->messageType));
    ck_assert_str_eq(get_attribute_data(p7, handle->oids->pkiStatus), SCEP_PKISTATUS_FAILURE);
    ck_assert_str_eq(get_attribute_data(p7, handle->oids->failInfo), SCEP_BAD_MESSAGE_CHECK_NR);

    /* Make sure pkcsPKIEnvelope is omitted */
    PKCS7 *datap7 = p7->d.sign->contents;
    ck_assert(PKCS7_type_is_data(datap7));
    ASN1_OCTET_STRING *data = datap7->d.data;
    ck_assert_int_eq(data->length, 0);
    ck_assert_int_eq(data->data, 0);
    ck_assert_int_eq(data->type, V_ASN1_OCTET_STRING);
}
END_TEST

START_TEST(test_pkcsreq_success)
{
    ck_assert(p7 != NULL);
    ck_assert_str_eq(
        SCEP_MSG_CERTREP_STR,
        get_attribute_data(p7, handle->oids->messageType));
    ck_assert_str_eq(get_attribute_data(p7, handle->oids->pkiStatus), SCEP_PKISTATUS_SUCCESS);

    PKCS7 *datap7 = p7->d.sign->contents;
    ck_assert(PKCS7_type_is_data(datap7));
    ASN1_OCTET_STRING *encdata = datap7->d.data;
    ck_assert_int_ne(encdata->length, 0);
    ck_assert_int_ne(encdata->data, 0);
    ck_assert_int_eq(encdata->type, V_ASN1_OCTET_STRING);
    BIO *data = get_decrypted_data(p7, enc_cert, enc_key);
    PKCS7 *reply_data = d2i_PKCS7_bio(data, NULL);
    ck_assert_int_ne(reply_data, NULL);
    ck_assert(PKCS7_type_is_signed(reply_data));
    PKCS7_SIGNED *degen = reply_data->d.sign;
    ck_assert(sk_X509_num(degen->cert) >= 1);
    ck_assert(sk_X509_CRL_num(degen->crl) <= 0);
    ck_assert_int_ne(degen->contents, NULL);
    ck_assert(PKCS7_type_is_data(degen->contents));
    ASN1_OCTET_STRING *inner_data = degen->contents->d.data;
    ck_assert_int_eq(inner_data, 0);
}
END_TEST

START_TEST(test_recipient_nonce)
{
    ASN1_STRING *recipientNonce = get_attribute(p7, handle->oids->recipientNonce);
    ASN1_STRING *senderNonce = get_attribute(p7, handle->oids->senderNonce);
    ck_assert_int_eq(ASN1_STRING_length(recipientNonce), 16);
    ck_assert_int_eq(ASN1_STRING_cmp(recipientNonce, senderNonce), 0);
}
END_TEST

START_TEST(test_sig_certificate)
{
    BIO *b = BIO_new(BIO_s_mem());
    X509 *ref_cert = NULL;
    BIO_puts(b, sig_cacert_str);
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

START_TEST(test_unwrap_pkcsreq_pending)
{
    SCEP_DATA *data;
    char senderNonce[NONCE_LENGTH];

    STACK_OF(PKCS7_SIGNER_INFO) *sk_si = PKCS7_get_signer_info(certrep_pending);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk_si, 0);
    ASN1_TYPE *asn1_senderNonce = PKCS7_get_signed_attribute(si, handle->oids->senderNonce);
    ASN1_TYPE_get_octetstring(asn1_senderNonce, senderNonce, NONCE_LENGTH);
    scep_param_set(handle, SCEP_PARAM_SENDERNONCE, (void *)senderNonce);
    ck_assert(scep_unwrap_response(
        handle, certrep_pending, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, &data) == SCEPE_OK);
    ck_assert_int_ne(NULL, data);
    ck_assert_str_eq(
        "2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
        data->transactionID);
    ck_assert_str_eq(SCEP_MSG_CERTREP_STR, data->messageType_str);
    ck_assert_int_eq(SCEP_MSG_CERTREP, data->messageType);
    ck_assert_int_ne(NULL, (char*)data->senderNonce);
    ck_assert_int_ne(NULL, (char*)data->recipientNonce);
    ck_assert_int_eq(SCEP_PENDING, data->pkiStatus);
    ck_assert_int_eq(data->certs, NULL);
    SCEP_DATA_free(data);
}
END_TEST

START_TEST(test_unwrap_pkcsreq_success)
{
    SCEP_DATA *data;
    char senderNonce[NONCE_LENGTH];

    STACK_OF(PKCS7_SIGNER_INFO) *sk_si = PKCS7_get_signer_info(certrep_success);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk_si, 0);
    ASN1_TYPE *asn1_senderNonce = PKCS7_get_signed_attribute(si, handle->oids->senderNonce);
    ASN1_TYPE_get_octetstring(asn1_senderNonce, senderNonce, NONCE_LENGTH);
    scep_param_set(handle, SCEP_PARAM_SENDERNONCE, (void *)senderNonce);
    ck_assert(scep_unwrap_response(
        handle, certrep_success, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, &data) == SCEPE_OK);
    ck_assert_int_ne(NULL, data);
    ck_assert_str_eq(
        "2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
        data->transactionID);
    ck_assert_str_eq(SCEP_MSG_CERTREP_STR, data->messageType_str);
    ck_assert_int_eq(SCEP_MSG_CERTREP, data->messageType);
    ck_assert_int_ne(NULL, (char*)data->senderNonce);
    ck_assert_int_ne(NULL, (char*)data->recipientNonce);
    ck_assert_int_eq(SCEP_SUCCESS, data->pkiStatus);
    ck_assert_int_eq(sk_X509_num(data->certs), 1);
    SCEP_DATA_free(data);
}
END_TEST

START_TEST(test_unwrap_pkcsreq_failure)
{
    SCEP_DATA *data;
    char senderNonce[NONCE_LENGTH];

    STACK_OF(PKCS7_SIGNER_INFO) *sk_si = PKCS7_get_signer_info(certrep_failure);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(sk_si, 0);
    ASN1_TYPE *asn1_senderNonce = PKCS7_get_signed_attribute(si, handle->oids->senderNonce);
    ASN1_TYPE_get_octetstring(asn1_senderNonce, senderNonce, NONCE_LENGTH);
    scep_param_set(handle, SCEP_PARAM_SENDERNONCE, (void *)senderNonce);
    ck_assert(scep_unwrap_response(
        handle, certrep_failure, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, &data) == SCEPE_OK);
    ck_assert_int_ne(NULL, data);
    ck_assert_str_eq(
        "2F3C88114C283E9A6CD57BB8266CE313DB0BEE0DAF769D770C4E5FFB9C4C1016",
        data->transactionID);
    ck_assert_str_eq(SCEP_MSG_CERTREP_STR, data->messageType_str);
    ck_assert_int_eq(SCEP_MSG_CERTREP, data->messageType);
    ck_assert_int_ne(NULL, (char*)data->senderNonce);
    ck_assert_int_ne(NULL, (char*)data->recipientNonce);
    ck_assert_int_eq(SCEP_FAILURE, data->pkiStatus);
    ck_assert_int_eq(0, data->failInfo);
    ck_assert_int_eq(data->certs, NULL);
    SCEP_DATA_free(data);
}
END_TEST

START_TEST(test_unwrap_getcacert)
{
    SCEP_DATA *data;
    ck_assert(scep_unwrap_response(
        handle, certrep_getcacert, NULL, NULL, NULL,
        SCEPOP_GETCACERT, &data) == SCEPE_OK);
    ck_assert_int_ne(NULL, data);
    ck_assert_int_eq(NULL, data->transactionID);
    int i;
    for(i=0; i < NONCE_LENGTH; i++) {
        ck_assert_int_eq(0, data->senderNonce[i]);
        ck_assert_int_eq(0, data->recipientNonce[i]);
    }
    ck_assert_int_eq(SCEP_SUCCESS, data->pkiStatus);
    ck_assert_int_eq(0, data->failInfo);

    /* Check stack */
    ck_assert_int_eq(sk_X509_num(data->certs), 3);

    SCEP_DATA_free(data);
}
END_TEST

START_TEST(test_invalid_sig)
{
    PKCS7 *certrep_dup = PKCS7_dup(certrep_pending);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(certrep_dup), 0);
    ASN1_TYPE *t = PKCS7_get_signed_attribute(si, handle->oids->pkiStatus);
    ck_assert_int_ne(ASN1_STRING_set(t->value.printablestring, SCEP_PKISTATUS_SUCCESS, -1), 0);
    ck_assert_int_eq(scep_unwrap_response(
        handle, certrep_dup, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, NULL), SCEPE_OPENSSL);
    PKCS7_free(certrep_dup);
}
END_TEST

START_TEST(test_unwrap_invalid_pkiStatus)
{
    PKCS7 *certrep_dup = PKCS7_dup(certrep_pending);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(certrep_dup), 0);
    ASN1_TYPE *t = PKCS7_get_signed_attribute(si, handle->oids->pkiStatus);
    ck_assert(t != NULL);
    ck_assert_int_ne(ASN1_STRING_set(t->value.printablestring, "foobar", -1), 0);
    ck_assert_int_ne(PKCS7_SIGNER_INFO_set(si, sig_cert, sig_key, handle->configuration->sigalg), 0);
    ck_assert_int_ne(PKCS7_add_certificate(certrep_dup, sig_cert), 0);
    int res = PKCS7_SIGNER_INFO_sign(si);
    ck_assert_int_ne(res, 0);
    ck_assert_int_eq(scep_unwrap_response(
        handle, certrep_dup, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, NULL), SCEPE_PROTOCOL);
    PKCS7_free(certrep_dup);
}
END_TEST

START_TEST(test_unwrap_invalid_version_certrep)
{
    PKCS7 *certrep_dup = PKCS7_dup(certrep_pending);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(certrep_dup), 0);
    ck_assert_int_ne(ASN1_INTEGER_set(si->version, 15), 0);
    ck_assert_int_eq(scep_unwrap_response(
        handle, certrep_dup, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, NULL), SCEPE_INVALID_CONTENT);
    PKCS7_free(certrep_dup);
}
END_TEST

START_TEST(test_unwrap_wrong_senderNonce)
{
    SCEP_DATA *data;
    char senderNonce[NONCE_LENGTH];
    memset(senderNonce, 0, NONCE_LENGTH);
    scep_param_set(handle, SCEP_PARAM_SENDERNONCE, senderNonce);
    ck_assert(scep_unwrap_response(
        handle, certrep_failure, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, &data) == SCEPE_INVALID_PARAMETER);
}
END_TEST

START_TEST(test_unwrap_unmatching_nonces_warning)
{
    SCEP_DATA *data;
    char log_str[4096];
    char recipientNonce[NONCE_LENGTH];
    PKCS7 *certrep = make_message(SCEP_PENDING, 0, NULL, NULL, NULL);
    memset(recipientNonce, 0, NONCE_LENGTH);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(certrep), 0);
    ASN1_OCTET_STRING *asn1_recipient_nonce = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(asn1_recipient_nonce, recipientNonce, NONCE_LENGTH);
    PKCS7_add_signed_attribute(
        si, handle->oids->recipientNonce, V_ASN1_OCTET_STRING,
        asn1_recipient_nonce);
    PKCS7_SIGNER_INFO_set(si, sig_cacert, sig_cakey, handle->configuration->sigalg);
    PKCS7_SIGNER_INFO_sign(si);

    scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
    BIO *bio = BIO_new(BIO_s_mem());
    handle->configuration->log = bio;
    BIO_gets(bio, log_str, 4096);
    ck_assert_str_eq(log_str, "");
    ck_assert(scep_unwrap_response(
        handle, certrep, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, &data) == SCEPE_OK);
    BIO_gets(bio, log_str, 4096);
    ck_assert(strstr(log_str, "recipientNonce and senderNonce don't") != NULL);
    PKCS7_free(certrep);
}
END_TEST

START_TEST(test_unwrap_unmatching_nonces_strict)
{
    SCEP_DATA *data;
    char recipientNonce[NONCE_LENGTH];
    PKCS7 *certrep = make_message(SCEP_PENDING, 0, NULL, NULL, NULL);
    memset(recipientNonce, 0, NONCE_LENGTH);
    PKCS7_SIGNER_INFO *si = sk_PKCS7_SIGNER_INFO_value(PKCS7_get_signer_info(certrep), 0);
    scep_conf_set(handle, SCEPCFG_FLAG_SET, SCEP_STRICT_SENDER_NONCE);
    ASN1_OCTET_STRING *asn1_recipient_nonce = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(asn1_recipient_nonce, recipientNonce, NONCE_LENGTH);
    PKCS7_add_signed_attribute(
        si, handle->oids->recipientNonce, V_ASN1_OCTET_STRING,
        asn1_recipient_nonce);
    PKCS7_SIGNER_INFO_set(si, sig_cacert, sig_cakey, handle->configuration->sigalg);
    PKCS7_SIGNER_INFO_sign(si);
    ck_assert(scep_unwrap_response(
        handle, certrep, sig_cacert, enc_cert, enc_key,
        SCEPOP_PKCSREQ, &data) == SCEPE_INVALID_PARAMETER);
    PKCS7_free(certrep);
}
END_TEST

void add_certrep(Suite *s)
{
    TCase *tc;
#define add_tcase(name, setup, teardown) \
    tc = tcase_create("Certrep " name " Message"); \
    tcase_add_unchecked_fixture(tc, setup, teardown); \
    tcase_add_test(tc, test_scep_message_asn1_version); \
    tcase_add_test(tc, test_scep_message_transaction_id); \
    tcase_add_test(tc, test_scep_message_sender_nonce); \
    tcase_add_test(tc, test_scep_message_type); \
    tcase_add_test(tc, test_scep_message_content_type); \
    tcase_add_test(tc, test_recipient_nonce); \
    tcase_add_test(tc, test_sig_certificate)

    add_tcase("PKCSReq PENDING", setup_pending, teardown);
    tcase_add_test(tc, test_pkcsreq_pending);
    suite_add_tcase(s, tc);

    add_tcase("PKCSReq FAILURE", setup_failure, teardown);
    tcase_add_test(tc, test_pkcsreq_failure);
    suite_add_tcase(s, tc);

    add_tcase("PKCSReq SUCCESS", setup_pkcsreq_success, teardown);
    tcase_add_test(tc, test_pkcsreq_success);
    suite_add_tcase(s, tc);

    TCase *tc_unwrap = tcase_create("Certrep Unwrapping");
    tcase_add_unchecked_fixture(tc_unwrap, setup, teardown);
    tcase_add_test(tc_unwrap, test_invalid_sig);
    tcase_add_test(tc_unwrap, test_unwrap_invalid_pkiStatus);
    tcase_add_test(tc_unwrap, test_unwrap_pkcsreq_pending);
    tcase_add_test(tc_unwrap, test_unwrap_pkcsreq_success);
    tcase_add_test(tc_unwrap, test_unwrap_pkcsreq_failure);
    tcase_add_test(tc_unwrap, test_unwrap_getcacert);
    tcase_add_test(tc_unwrap, test_unwrap_invalid_version_certrep);
    tcase_add_test(tc_unwrap, test_unwrap_wrong_senderNonce);
    tcase_add_test(tc_unwrap, test_unwrap_unmatching_nonces_warning);
    tcase_add_test(tc_unwrap, test_unwrap_unmatching_nonces_strict);
    suite_add_tcase(s, tc_unwrap);

#ifdef WITH_ENGINE_TESTS
    TCase *tc_engine;
    /* We need a checked fixture on all engine tests, possibly because
     * the engine process cannot deal with the forking of check
     */
#define add_tcase_engine(name, setup, teardown) \
    tc_engine = tcase_create("Certrep " name " Message with Engine"); \
    tcase_add_checked_fixture(tc_engine, setup, teardown); \
    tcase_add_test(tc_engine, test_scep_message_asn1_version); \
    tcase_add_test(tc_engine, test_scep_message_transaction_id); \
    tcase_add_test(tc_engine, test_scep_message_sender_nonce); \
    tcase_add_test(tc_engine, test_scep_message_type); \
    tcase_add_test(tc_engine, test_scep_message_content_type); \
    tcase_add_test(tc_engine, test_recipient_nonce); \
    tcase_add_test(tc_engine, test_sig_certificate)

    add_tcase_engine("PKCSReq PENDING", setup_pending_engine, teardown);
    tcase_add_test(tc_engine, test_pkcsreq_pending);
    suite_add_tcase(s, tc_engine);

    add_tcase_engine("PKCSReq FAILURE", setup_failure_engine, teardown);
    tcase_add_test(tc_engine, test_pkcsreq_failure);
    suite_add_tcase(s, tc_engine);

    add_tcase_engine("PKCSReq SUCCESS", setup_pkcsreq_success_engine, teardown);
    tcase_add_test(tc_engine, test_pkcsreq_success);
    suite_add_tcase(s, tc_engine);

    TCase *tc_unwrap_engine = tcase_create("Certrep Unwrapping with Engine");
    tcase_add_checked_fixture(tc_unwrap_engine, setup_engine, teardown);
    tcase_add_test(tc_unwrap_engine, test_invalid_sig);
    tcase_add_test(tc_unwrap_engine, test_unwrap_invalid_pkiStatus);
    tcase_add_test(tc_unwrap_engine, test_unwrap_pkcsreq_pending);
    tcase_add_test(tc_unwrap_engine, test_unwrap_pkcsreq_success);
    tcase_add_test(tc_unwrap_engine, test_unwrap_pkcsreq_failure);
    tcase_add_test(tc_unwrap_engine, test_unwrap_getcacert);
    tcase_add_test(tc_unwrap_engine, test_unwrap_invalid_version_certrep);
    tcase_add_test(tc_unwrap_engine, test_unwrap_wrong_senderNonce);
    tcase_add_test(tc_unwrap_engine, test_unwrap_unmatching_nonces_warning);
    tcase_add_test(tc_unwrap_engine, test_unwrap_unmatching_nonces_strict);
    suite_add_tcase(s, tc_unwrap_engine);
#undef add_tcase_engine
#endif /* WITH_ENGINE_TESTS */
#undef add_tcase
}