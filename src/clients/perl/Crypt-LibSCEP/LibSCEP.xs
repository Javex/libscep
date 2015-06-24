#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "scep.h"
#include <stdlib.h>

#include "helperfunctions.h"
#include "config.h"



IV
init_config(SV *rv_config) {
	Conf *config = malloc(sizeof(Conf));
	if (SvROK(rv_config) && (SvTYPE(SvRV(rv_config)) == SVt_PVHV)) {

		HV *hv_config = (HV*)SvRV(rv_config);

		config->passin = "plain";
		SV **svv = hv_fetch(hv_config, "passin", strlen("passin"),FALSE);
		if(svv) {
			SvPV_nolen(*svv);
			config->passin = SvPV_nolen(*svv);
		}

		config->passwd = "";
		svv = hv_fetch(hv_config, "passwd", strlen("passwd"),FALSE);
		if(svv) {
			SvPV_nolen(*svv);
			config->passwd = SvPV_nolen(*svv);
		}

	}
	else {
		printf("Config is not a perl hash structure");
	}
	return PTR2IV(config);
}


EVP_PKEY *load_key(char *key_str, Conf *config) {
	BIO *b = BIO_new(BIO_s_mem());
	BIO_write(b, key_str, strlen(key_str));
	EVP_PKEY *key;
	char *pwd = NULL;
	if(!strcmp(config->passin, "env")) {
		pwd = getenv("pwd");
		if (pwd == NULL) {
			printf("environment variable not set");
			exit (1);
		}
	}
	else if(!strcmp(config->passin, "pass")) {
		pwd = config->passwd;
		if(pwd == NULL) {
			printf("passin = pass set but no password provided");
			exit (1);
		}
	}
	else if (!strcmp(config->passin, "plain")) {
		pwd = "";
	}
	else {
		printf("unsupperted pass format");
		exit (1);
	}
	if(!(key = PEM_read_bio_PrivateKey(b, NULL, 0, pwd))) {
		ERR_print_errors_fp(stderr);
		exit (1);
	}
	return key;
}

MODULE = Crypt::LibSCEP		PACKAGE = Crypt::LibSCEP	

char *
certrep_success(rv_config, cakey_str, cacert_str, pkcsreq_str, issuedCert_str, enc_cert_str)
SV * rv_config
char * cakey_str
char * cacert_str
char * pkcsreq_str
char * issuedCert_str
char * enc_cert_str
PREINIT:
	Conf *config;
CODE: 
	SCEP *handle;
	//const EVP_CIPHER *enc_alg;
	//enc_alg = EVP_des_ede3_cbc();
	setup(&handle);
	
	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;

	config = INT2PTR(Conf *, init_config(rv_config));

	EVP_PKEY *sig_cakey;

	sig_cakey = load_key(cakey_str, config);

	if(sig_cakey == NULL)
		printf("failure2");
	BIO_free(b);


	b = BIO_new(BIO_s_mem());
	BIO_write(b, cacert_str, strlen(cacert_str));
	X509 *sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cacert == NULL)
		printf("failure3");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, pkcsreq_str, strlen(pkcsreq_str));
	PKCS7 *pkcsreq = PEM_read_bio_PKCS7(b, NULL, 0, 0);
	if(pkcsreq == NULL)
		printf("failure4");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, issuedCert_str, strlen(issuedCert_str));
	X509 *issuedCert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(issuedCert == NULL)
		printf("failure7");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, enc_cert_str, strlen(enc_cert_str));
	X509 *enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL)
		printf("failure7");
	BIO_free(b);


	SCEP_ERROR s;
	SCEP_DATA *unwrapped = NULL;
	s = scep_unwrap(handle, pkcsreq, NULL, NULL, NULL, &unwrapped);
	
	if(s != SCEPE_OK)
		printf("failure5");

	SCEP_PKISTATUS pkiStatus = SCEP_SUCCESS;
	s = scep_certrep(handle, unwrapped->transactionID, unwrapped->senderNonce, pkiStatus, 0, issuedCert, sig_cacert, sig_cakey, enc_cert, NULL, NULL, &p7);

	if(s != SCEPE_OK)
		printf("failure6");

	b = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b, p7);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
OUTPUT:
	RETVAL


char *
certrep_failure(cakey_str, cacert_str, pkcsreq_str, failInfo_str)
char * cakey_str
char * cacert_str
char * pkcsreq_str
char * failInfo_str
CODE: 
	SCEP *handle;
	setup(&handle);
	
	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	b = BIO_new(BIO_s_mem());;
	BIO_write(b, cakey_str, strlen(cakey_str));
	EVP_PKEY *sig_cakey;
	char *pwd = getenv("pwd");
	if (pwd == NULL)
		sig_cakey = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
	else
		sig_cakey = PEM_read_bio_PrivateKey(b, NULL, 0, pwd);
	if(sig_cakey == NULL)
		printf("failure2");
	BIO_free(b);


	b = BIO_new(BIO_s_mem());
	BIO_write(b, cacert_str, strlen(cacert_str));
	X509 *sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cacert == NULL)
		printf("failure3");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, pkcsreq_str, strlen(pkcsreq_str));
	PKCS7 *pkcsreq = PEM_read_bio_PKCS7(b, NULL, 0, 0);
	if(pkcsreq == NULL)
		printf("failure4");
	BIO_free(b);

	SCEP_ERROR s;
	SCEP_DATA *unwrapped = NULL;
	s = scep_unwrap(handle, pkcsreq, NULL, NULL, NULL, &unwrapped);
	
	if(s != SCEPE_OK)
		printf("failure5");

	SCEP_PKISTATUS pkiStatus = SCEP_FAILURE;
	SCEP_FAILINFO failInfo = 0;
	if(strcmp("badAlg", failInfo_str) == 0)
		failInfo = SCEP_BAD_ALG;
	else if(strcmp("badMessageCheck", failInfo_str) == 0)
		failInfo = SCEP_BAD_MESSAGE_CHECK;
	else if(strcmp("badRequest", failInfo_str) == 0)
		failInfo = SCEP_BAD_REQUEST;
	else if(strcmp("badTime", failInfo_str) == 0)
		failInfo = SCEP_BAD_TIME;
	else if(strcmp("badCertId", failInfo_str) == 0)
		failInfo = SCEP_BAD_CERT_ID;
	else 
		printf("unsupported failInfo");

	s = scep_certrep(handle, unwrapped->transactionID, unwrapped->senderNonce, pkiStatus, failInfo, NULL, sig_cacert, sig_cakey, NULL, NULL, NULL, &p7);

	if(s != SCEPE_OK)
		printf("failure6");

	b = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b, p7);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
OUTPUT:
	RETVAL

char *
certrep_pending(cakey_str, cacert_str, pkcsreq_str)
char * cakey_str
char * cacert_str
char * pkcsreq_str
CODE: 
	SCEP *handle;
	setup(&handle);
	
	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	b = BIO_new(BIO_s_mem());;
	BIO_write(b, cakey_str, strlen(cakey_str));
	EVP_PKEY *sig_cakey;
	char *pwd = getenv("pwd");
	if (pwd == NULL)
		sig_cakey = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
	else
		sig_cakey = PEM_read_bio_PrivateKey(b, NULL, 0, pwd);
	if(sig_cakey == NULL)
		printf("failure2");
	BIO_free(b);


	b = BIO_new(BIO_s_mem());
	BIO_write(b, cacert_str, strlen(cacert_str));
	X509 *sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cacert == NULL)
		printf("failure3");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, pkcsreq_str, strlen(pkcsreq_str));
	PKCS7 *pkcsreq = PEM_read_bio_PKCS7(b, NULL, 0, 0);
	if(pkcsreq == NULL)
		printf("failure4");
	BIO_free(b);

	SCEP_ERROR s;
	SCEP_DATA *unwrapped = NULL;
	s = scep_unwrap(handle, pkcsreq, NULL, NULL, NULL, &unwrapped);
	
	if(s != SCEPE_OK)
		printf("failure5");

	SCEP_PKISTATUS pkiStatus = SCEP_PENDING;
	s = scep_certrep(handle, unwrapped->transactionID, unwrapped->senderNonce, pkiStatus, 0, NULL, sig_cacert, sig_cakey, NULL, NULL, NULL, &p7);

	if(s != SCEPE_OK)
		printf("failure6");

	b = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b, p7);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
OUTPUT:
	RETVAL

char *
pkcsreq(key_str, ca_str, enc_str, req_str)
char * key_str
char * ca_str
char * enc_str
char * req_str
CODE:
	SCEP *handle;
	setup(&handle);

	BIO *b;
	//const EVP_CIPHER *enc_alg;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	b = BIO_new(BIO_s_mem());;
	BIO_write(b, key_str, strlen(key_str));
	EVP_PKEY *sig_key;
	char *pwd = getenv("pwd");
	if (pwd == NULL)
		sig_key = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
	else
		sig_key = PEM_read_bio_PrivateKey(b, NULL, 0, pwd);
	if(sig_key == NULL)
		printf("failure");
	BIO_free(b);

	
	b = BIO_new(BIO_s_mem());
	BIO_write(b, ca_str, strlen(ca_str));
	X509 *sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL)
		printf("failure");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, req_str, strlen(req_str));
	X509_REQ *req = PEM_read_bio_X509_REQ(b, NULL, 0, 0);
	if(req == NULL)
		printf("failure");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, enc_str, strlen(enc_str));
	X509 *enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL)
		printf("failure");
	BIO_free(b);

	//enc_alg = EVP_des_ede3_cbc();

	SCEP_ERROR s = scep_pkcsreq(
		handle, req, sig_cert, sig_key, enc_cert, &p7);

	if(s != SCEPE_OK)
		printf("failure");

	b = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b, p7);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
OUTPUT:
	RETVAL

	

char *
print_transid(rv_config, pkiMessage_str)
SV * rv_config
char * pkiMessage_str
PREINIT:
	Conf *config;
CODE:
	BIO *b;
	SCEP *handle;
	SCEP_DATA *unwrapped;
	setup(&handle);
	config = INT2PTR(Conf *, init_config(rv_config));
	b = BIO_new(BIO_s_mem());
	BIO_write(b, pkiMessage_str, strlen(pkiMessage_str));
	PKCS7 *pkiMessage = PEM_read_bio_PKCS7(b, NULL, 0, 0);
	if(pkiMessage == NULL)
		printf("failure4");
	BIO_free(b);
	unwrapped = get_pkiData(handle, pkiMessage);
	RETVAL = unwrapped->transactionID;
OUTPUT:
	RETVAL

char *
print_msgtype(pkiMessage_str)
char * pkiMessage_str
CODE:
	BIO *b;
	SCEP *handle;
	SCEP_DATA *unwrapped;
	setup(&handle);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, pkiMessage_str, strlen(pkiMessage_str));
	PKCS7 *pkiMessage = PEM_read_bio_PKCS7(b, NULL, 0, 0);
	if(pkiMessage == NULL)
		printf("failure4");
	BIO_free(b);
	unwrapped = get_pkiData(handle, pkiMessage);

	RETVAL = "";
	if(SCEP_MSG_PKCSREQ == unwrapped->messageType)
		RETVAL = "PKCSReq";
	if(SCEP_MSG_CERTREP == unwrapped->messageType)
		RETVAL = "CertRep";
	if(SCEP_MSG_GETCERTINITIAL == unwrapped->messageType)
		RETVAL = "GetCertInitial";
	if(SCEP_MSG_GETCERT == unwrapped->messageType)
		RETVAL = "GetCert";
	if(SCEP_MSG_GETCRL == unwrapped->messageType)
		RETVAL = "GetCRL";
OUTPUT:
	RETVAL