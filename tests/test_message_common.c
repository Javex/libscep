#include <check.h>
#include "scep.h"
#include "scep_tests.h"

static SCEP *handle;
static BIO *scep_log;
static PKCS7 *p7 = NULL;
static SCEP_DATA *pkiMessage, *pkiMessage_certrep, *pkiMessage_failure, *pkiMessage_success, *unwrap_own_certrep_pending, *unwrap_own_certrep_failure, *unwrap_own_certrep_success;
static PKCS7 *p7_nosigcert = NULL; // no signer certificate on result PKCS#7
/*TODO: Do we need them*/
static EVP_PKEY *dec_key;
static X509 *dec_cert;


static X509 *sig_cert;
static EVP_PKEY *sig_key;
static X509 *enc_cert;
static EVP_PKEY *enc_key;
static X509 *sig_cacert;
static EVP_PKEY *sig_cakey;
static X509 *enc_cacert;
static EVP_PKEY *enc_cakey;
static X509_REQ *req;
static PKCS7 *certrep_pending;
static PKCS7 *certrep_failure;
static PKCS7 *certrep_success;
static PKCS7 *own_certrep_pending;
static PKCS7 *own_certrep_failure;
static PKCS7 *own_certrep_success;


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

static char *issuedCert_str ="-----BEGIN CERTIFICATE-----\n"
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

/*TODO: This is generated via a different tool and should be
replaced as soon as we have developed our own implementation of certrep*/
static char *certrep_pending_str ="-----BEGIN PKCS7-----\n"
"MIID7wYJKoZIhvcNAQcCoIID4DCCA9wCAQExDjAMBggqhkiG9w0CBQUAMA8GCSqG\n"
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
"Ai/YCq2m3p5tHDGCAdUwggHRAgEBMFQwRzELMAkGA1UEBhMCREUxDTALBgNVBAgM\n"
"BGFzZGYxDTALBgNVBAcMBGFzZGYxDTALBgNVBAoMBGFzZGYxCzAJBgNVBAMMAmNh\n"
"AgkAjGcr4C9C294wDAYIKoZIhvcNAgUFAKCCARUwEQYKYIZIAYb4RQEJAjEDEwEz\n"
"MBEGCmCGSAGG+EUBCQMxAxMBMzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwG\n"
"CSqGSIb3DQEJBTEPFw0xNTAzMTYxNzQ0MjBaMB8GCSqGSIb3DQEJBDESBBDUHYzZ\n"
"jwCyBOmACZjs+EJ+MCAGCmCGSAGG+EUBCQUxEgQQbUAUiO8G88l4Jy1QkgTJUjAg\n"
"BgpghkgBhvhFAQkGMRIEEAJICl05ayrpLhotWdJb79IwUAYKYIZIAYb4RQEJBzFC\n"
"E0AyRjNDODgxMTRDMjgzRTlBNkNENTdCQjgyNjZDRTMxM0RCMEJFRTBEQUY3NjlE\n"
"NzcwQzRFNUZGQjlDNEMxMDE2MA0GCSqGSIb3DQEBAQUABEBJawZlCBpsc/WRjihL\n"
"deuFoobZNtIFxAdMRT7Y1Pa9fw/sQQy0rrMcn6eF/O3F6FIhD3KgR74SpmbbMVzc\n"
"RePK\n"
"-----END PKCS7-----\n";

static char *certrep_failure_str ="-----BEGIN PKCS7-----\n"
"MIIEAgYJKoZIhvcNAQcCoIID8zCCA+8CAQExDjAMBggqhkiG9w0CBQUAMA8GCSqG\n"
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
"Ai/YCq2m3p5tHDGCAegwggHkAgEBMFQwRzELMAkGA1UEBhMCREUxDTALBgNVBAgM\n"
"BGFzZGYxDTALBgNVBAcMBGFzZGYxDTALBgNVBAoMBGFzZGYxCzAJBgNVBAMMAmNh\n"
"AgkAjGcr4C9C294wDAYIKoZIhvcNAgUFAKCCASgwEQYKYIZIAYb4RQEJAjEDEwEz\n"
"MBEGCmCGSAGG+EUBCQMxAxMBMjARBgpghkgBhvhFAQkEMQMTATAwGAYJKoZIhvcN\n"
"AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTUwMzE3MTU0OTEwWjAf\n"
"BgkqhkiG9w0BCQQxEgQQ1B2M2Y8AsgTpgAmY7PhCfjAgBgpghkgBhvhFAQkFMRIE\n"
"EBxUO6OtE+FF886d/ugbeI0wIAYKYIZIAYb4RQEJBjESBBACSApdOWsq6S4aLVnS\n"
"W+/SMFAGCmCGSAGG+EUBCQcxQhNAMkYzQzg4MTE0QzI4M0U5QTZDRDU3QkI4MjY2\n"
"Q0UzMTNEQjBCRUUwREFGNzY5RDc3MEM0RTVGRkI5QzRDMTAxNjANBgkqhkiG9w0B\n"
"AQEFAARAAvvsi2JqARL+fIr9wahfAyTLt7/zjFgltfNA6rLUVyssy3F2l7sA5hhO\n"
"YijXlooLa3ApoZqAtMeFhPL9LN61kg==\n"
"-----END PKCS7-----\n";

static char *certrep_success_str ="-----BEGIN PKCS7-----\n"
"MIIHCAYJKoZIhvcNAQcCoIIG+TCCBvUCAQExDjAMBggqhkiG9w0CBQUAMIIDJgYJ\n"
"KoZIhvcNAQcBoIIDFwSCAxMwggMPBgkqhkiG9w0BBwOgggMAMIIC/AIBADGBpTCB\n"
"ogIBADBMMEcxCzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARh\n"
"c2RmMQ0wCwYDVQQKDARhc2RmMQswCQYDVQQDDAJjYQIBAzANBgkqhkiG9w0BAQEF\n"
"AARAsWdL/PascMiDqeUM7aJi3uv2m/CLJhj/VE+TuecVbUaGXO5Ecrgrtyw/dzV/\n"
"8aV1uw3j5gI0QXLZ2R+FVpiMGjCCAk0GCSqGSIb3DQEHATAUBggqhkiG9w0DBwQI\n"
"VBjKAfNvcN6AggIoIGNDJ9eyCuE07rLk21qQKg52bab1GFULFu+e+Lx7wjiFy/OZ\n"
"lwenlqbTBs15hC5MZUDsPL3DNouLS++nl+EUh4+Mcwavwh1iWsm6ZQyjZkrZrg6W\n"
"cnO9Hx0BwkNjuovl5yJAiii4FnUOnZpES00sgykte3JX4i/64YEwiAouR2833n+s\n"
"DHdIJkLLiaDN7ExgTTEt+qgaDg66zd6C3NaWaA54OtIVJw3HbV/hDFzI9enOc1ZK\n"
"LnJR65gt8lhtPXMr1yQtsIkfGH8PIsFhugb9HjggWoYRHcqaseXJ90Z2DWcv8A0n\n"
"vhj2w3g1K9oez7eBs+B9HuCX8q8hgucdu5VeL6OS5GmDWCbJCP+CrweIEZt/rt7i\n"
"ewmMeyuv9j2LPRrbUWoZI+cGhdHkphzZKW4SLwFXqc4/4M+85CONx3kt04WCsQ1r\n"
"AoN1VuHmeaNR8Px6hvHShLUULX/JFgWfbUhSLDyLJNgZ0vZ4doA5ElSvnUUnojek\n"
"Nn9LG9CScgHJmx2JO8PlnDN2lcCX6YSXzDk0xCe+KzSHRjlGldZKURWlPvhY7fyV\n"
"WAoZMPGAWDkTJsYr6hXWDqBkRpfIbU4Ltb4RqUFQHh5ePdKHNp0hUCATa2ISVkdt\n"
"WeVkwxWyfy1mutodZIDcC7KOTphpgRJf4KFcGKiXj6zWsaHl9swtCqCK1bAqs6nM\n"
"fPTDR9J4X74mbY8gbeX7VdM5iruzCoe5lJVEkr7MKaPu0PCLoIIB2zCCAdcwggGB\n"
"oAMCAQICCQCMZyvgL0Lb3jANBgkqhkiG9w0BAQUFADBHMQswCQYDVQQGEwJERTEN\n"
"MAsGA1UECAwEYXNkZjENMAsGA1UEBwwEYXNkZjENMAsGA1UECgwEYXNkZjELMAkG\n"
"A1UEAwwCY2EwHhcNMTUwMzE1MTIyMTU4WhcNMTgwMTAyMTIyMTU4WjBHMQswCQYD\n"
"VQQGEwJERTENMAsGA1UECAwEYXNkZjENMAsGA1UEBwwEYXNkZjENMAsGA1UECgwE\n"
"YXNkZjELMAkGA1UEAwwCY2EwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAtmW2Vzek\n"
"PpOMhAl1Aa798f8xdBdehvWMfm/asXYZD//gZAOYMkRTRFi/hKL1NtNBf5kqWLBV\n"
"vlZSBltMdKwbyQIDAQABo1AwTjAdBgNVHQ4EFgQUxsitQFaFeb/zruBZlq8TYNwK\n"
"r+cwHwYDVR0jBBgwFoAUxsitQFaFeb/zruBZlq8TYNwKr+cwDAYDVR0TBAUwAwEB\n"
"/zANBgkqhkiG9w0BAQUFAANBABWSXZYBIBkzs0XbT7EWNHs1laMNutTlFH9WesdH\n"
"vc/zc5KKNpHyOIg2n3m70NcjKklim1IyxgIv2Aqtpt6ebRwxggHVMIIB0QIBATBU\n"
"MEcxCzAJBgNVBAYTAkRFMQ0wCwYDVQQIDARhc2RmMQ0wCwYDVQQHDARhc2RmMQ0w\n"
"CwYDVQQKDARhc2RmMQswCQYDVQQDDAJjYQIJAIxnK+AvQtveMAwGCCqGSIb3DQIF\n"
"BQCgggEVMBEGCmCGSAGG+EUBCQIxAxMBMzARBgpghkgBhvhFAQkDMQMTATAwGAYJ\n"
"KoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTUwMzE4MTIz\n"
"NTM1WjAfBgkqhkiG9w0BCQQxEgQQz5TUdLzI+bltWl+EP0dg4zAgBgpghkgBhvhF\n"
"AQkFMRIEEPohP2TBgldJgN7x5By5sc4wIAYKYIZIAYb4RQEJBjESBBACSApdOWsq\n"
"6S4aLVnSW+/SMFAGCmCGSAGG+EUBCQcxQhNAMkYzQzg4MTE0QzI4M0U5QTZDRDU3\n"
"QkI4MjY2Q0UzMTNEQjBCRUUwREFGNzY5RDc3MEM0RTVGRkI5QzRDMTAxNjANBgkq\n"
"hkiG9w0BAQEFAARAmDbpLIwcMGts6V91KHw0KXY11Mr4VQehoU0c4QJ5wEZobL3a\n"
"phbTlq5K3BlTmUFrdo+SqhmJB8TuN2WZUmeCZQ==\n"
"-----END PKCS7-----\n";

static void make_message_data();
static void generic_setup()
{
    ck_assert(scep_init(&handle) == SCEPE_OK);
    scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
    scep_conf_set(handle, SCEPCFG_LOG, scep_log);
    scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
    make_message_data();
}

static void free_message_data();
static void generic_teardown()
{
    BIO_flush(scep_log);
    BIO_free(scep_log);
    scep_cleanup(handle);
    free_message_data();
}

static void make_message_data()
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

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_pending_str);
    certrep_pending = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_pending != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_failure_str);
    certrep_failure = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_failure != NULL);
    BIO_free(b);

    b = BIO_new(BIO_s_mem());
    BIO_puts(b, certrep_success_str);
    certrep_success = PEM_read_bio_PKCS7(b, NULL, 0, 0);
    ck_assert(certrep_success != NULL);
    BIO_free(b);
}

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
    PKCS7_free(certrep_pending);
    PKCS7_free(certrep_failure);
    PKCS7_free(certrep_success);
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