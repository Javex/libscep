#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "scep.h"
#include <stdlib.h>

#include "helperfunctions.h"
#include "config.h"

IV
init_config(SV *rv_config, SCEP **handle) {
	SCEP *local_handle;
	BIO *scep_log;
	SCEP_ERROR s;
	s = scep_init(&local_handle);
	if (s != SCEPE_OK) {
		exit(EXIT_FAILURE);
	}
	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);

	s = scep_conf_set(local_handle, SCEPCFG_LOG, scep_log);
	if (s != SCEPE_OK) {
		exit(EXIT_FAILURE);
	}


	s = scep_conf_set(local_handle, SCEPCFG_VERBOSITY, DEBUG);
	if (s != SCEPE_OK) {
		exit(EXIT_FAILURE);
	}

	Conf *config = malloc(sizeof(Conf));
	if(config == NULL) {
		BIO_printf(scep_log, "Could not malloc for config\n");
		exit(EXIT_FAILURE);
	}

	config->log = BIO_new_fp(stdout, BIO_NOCLOSE);

	if (SvROK(rv_config) && (SvTYPE(SvRV(rv_config)) == SVt_PVHV)) {
		HV *hv_config = (HV*)SvRV(rv_config);
		SV **svv;
		
		config->passin = "plain";
		svv = hv_fetch(hv_config, "passin", strlen("passin"),FALSE);
		if(svv) {
			config->passin = SvPV_nolen(*svv);
		}

		svv = hv_fetch(hv_config, "sigalg", strlen("sigalg"),FALSE);
		if(svv) {
			char *md = SvPV_nolen(*svv);
			if(!(local_handle->configuration->sigalg = EVP_get_digestbyname(md))) {
				ERR_print_errors(scep_log);
				exit(EXIT_FAILURE);
			}
		}

		svv = hv_fetch(hv_config, "encalg", strlen("encalg"),FALSE);
		if(svv) {
			char *encalg = SvPV_nolen(*svv);
			if(!(local_handle->configuration->encalg = EVP_get_cipherbyname(encalg))) {
				ERR_print_errors(scep_log);
				exit(EXIT_FAILURE);
			}		
		}

		config->passwd = "";
		svv = hv_fetch(hv_config, "passwd", strlen("passwd"),FALSE);
		if(svv) {
			config->passwd = SvPV_nolen(*svv);
		}
		config->engine = NULL;
		svv = hv_fetch(hv_config, "engine", strlen("engine"),FALSE);
		if(svv) {
			 SV* sv = SvROK(*svv) ? SvRV(*svv) : *svv;
			 size_t s = SvIV(sv);
			 config->engine = INT2PTR(ENGINE*, s);
		}
	}
	else {
		BIO_printf(scep_log, "Config is not a perl hash structure\n");
		exit(EXIT_FAILURE);
	}

	*handle = local_handle;
	return PTR2IV(config);
}

IV
load_engine(SV *rv_config, SCEP *handle) {
	Engine_conf *config = malloc(sizeof(Engine_conf));
	if(config == NULL) {
		BIO_printf(handle->configuration->log, "Could not malloc for config\n");
		exit(EXIT_FAILURE);
	}
	if (SvROK(rv_config) && (SvTYPE(SvRV(rv_config)) == SVt_PVHV)) {
		SCEP_ERROR s;
		HV *hv_config = (HV*)SvRV(rv_config);
		config->label = "";
		config->so = "";
		config->pin = "";
		config->engine = NULL;
		config->module = "";
		SV **svv = hv_fetch(hv_config, "label", strlen("label"),FALSE);
		if(svv) {
			config->label = SvPV_nolen(*svv);
			svv = hv_fetch(hv_config, "so", strlen("so"),FALSE);
			if(svv) {
				config->so = SvPV_nolen(*svv);
				//engine-specific configuration
				if(!strcmp(config->label, "pkcs11")) {
					svv = hv_fetch(hv_config, "module", strlen("module"),FALSE);
					if(svv) {
						config->module = SvPV_nolen(*svv);
					}
					else {
						BIO_printf(handle->configuration->log, "Engine pkcs11 requires module path\n");
						exit(EXIT_FAILURE);
					}
					s = scep_conf_set(handle, SCEPCFG_ENGINE_PARAM, "MODULE_PATH", config->module);
					if (s != SCEPE_OK) {
						exit(EXIT_FAILURE);
					}
				}	
				s = scep_conf_set(handle, SCEPCFG_ENGINE, "dynamic", config->label, config->so);	
				if (s != SCEPE_OK) {
					exit(EXIT_FAILURE);
				}		
				s = scep_engine_get(handle, &config->engine);
				if (s != SCEPE_OK) {
					exit(EXIT_FAILURE);
				}
				if(!strcmp(config->label, "pkcs11")) {
					svv = hv_fetch(hv_config, "pin", strlen("pin"),FALSE);
					if(svv) {
						config->pin = SvPV_nolen(*svv);
						ENGINE_ctrl_cmd_string(config->engine, "PIN", config->pin, 0);
					}
					else {
						BIO_printf(handle->configuration->log, "Engine pkcs11 requires PIN\n");
						exit(EXIT_FAILURE);
					}
				}
			}
			else {
				BIO_printf(handle->configuration->log, "Engine requires path to shared object\n");
				exit(EXIT_FAILURE);
			}		
		}	
	}
	else {
		BIO_printf(handle->configuration->log, "Engine config is not a perl hash structure\n");
		exit(EXIT_FAILURE);
	}
	return PTR2IV(config);
	
}

EVP_PKEY *load_key(char *key_str, Conf *config) {
	EVP_PKEY *key = NULL;
	if(config->engine == NULL) {
		BIO *b = BIO_new(BIO_s_mem());
		BIO_write(b, key_str, strlen(key_str));
		char *pwd = NULL;
		if(!strcmp(config->passin, "env")) {
			pwd = getenv("pwd");
			if (pwd == NULL) {
				BIO_printf(config->log, "env:pwd not set\n");
				exit(EXIT_FAILURE);
			}
		}
		else if(!strcmp(config->passin, "pass")) {
			pwd = config->passwd;
			if(pwd == NULL) {
				BIO_printf(config->log, "pass set but no password provided\n");
				exit(EXIT_FAILURE);
			}
		}
		else if (!strcmp(config->passin, "plain")) {
			pwd = "";
		}
		else {
			BIO_printf(config->log, "unsupported pass format\n");
			exit (EXIT_FAILURE);
		}
		if(!(key = PEM_read_bio_PrivateKey(b, NULL, 0, pwd))) {
			ERR_print_errors(config->log);
			exit (EXIT_FAILURE);
		}
	}
	else {
		//we got an engine
		if(!(key = ENGINE_load_private_key(config->engine, key_str, NULL, NULL))) {
			ERR_print_errors(config->log);
			exit (EXIT_FAILURE);
		}
	}
	return key;
}

typedef SCEP_DATA *Crypt__LibSCEP;

MODULE = Crypt::LibSCEP		PACKAGE = Crypt::LibSCEP	

#include <openssl/engine.h>

=pod
sig_key: key for creating signature
sig_cert: cert for creating signature
enc_cert: recipients encryption cert cert for encryption
=cut
char *
create_certificate_reply_wop7(rv_config, sig_key_str, sig_cert_str, transID, senderNonce, enc_cert_str, issuedCert_str)
SV * rv_config
char * sig_key_str
char * sig_cert_str
char * issuedCert_str
char * enc_cert_str
char * transID
unsigned char * senderNonce
PREINIT:
	Conf *config;
CODE: 
	SCEP *handle;	
	BIO *b;
	EVP_PKEY *sig_key = NULL;
	X509 *sig_cert  = NULL;
	PKCS7 *p7 = NULL;
	X509 *issuedCert = NULL;
	X509 *enc_cert = NULL;
	char *reply = NULL;
	SCEP_ERROR s;
	SCEP_PKISTATUS pkiStatus;

	if(!rv_config) {
		exit (EXIT_FAILURE);
	}

	config = INT2PTR(Conf *, init_config(rv_config, &handle));

	sig_key = load_key(sig_key_str, config);
	if(sig_key == NULL) {
		BIO_printf(config->log, "No key provided\n");
		exit (EXIT_FAILURE);
	}


	b = BIO_new(BIO_s_mem());
	BIO_write(b, sig_cert_str, strlen(sig_cert_str));
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL) {
		BIO_printf(config->log, "No encryption cert provided\n");
		exit (EXIT_FAILURE);
	}
	BIO_free(b);


	b = BIO_new(BIO_s_mem());
	BIO_write(b, issuedCert_str, strlen(issuedCert_str));
	issuedCert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(issuedCert == NULL) {
		BIO_printf(config->log, "No issued cert provided\n");
		exit (EXIT_FAILURE);
	}
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, enc_cert_str, strlen(enc_cert_str));
	enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL) {
		BIO_printf(config->log, "No signer cert provided\n");
		exit (EXIT_FAILURE);
	}
	BIO_free(b);

	pkiStatus = SCEP_SUCCESS;
	s = scep_certrep(handle, transID, senderNonce, pkiStatus, 0, issuedCert, sig_cert, sig_key, enc_cert, NULL, NULL, &p7);

	if(s != SCEPE_OK) {
		exit (EXIT_FAILURE);
	}

	b = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b, p7);
	reply = (char *) malloc(b->num_write + 1);
	if(reply == NULL) {
		BIO_printf(config->log, "Could not malloc for reply\n");
		exit(EXIT_FAILURE);
	}
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
	scep_cleanup(handle);
OUTPUT:
	RETVAL

char *
create_certificate_reply(rv_config, cakey_str, cacert_str, pkcsreq_str, issuedCert_str, enc_cert_str)
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
	
	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;

	config = INT2PTR(Conf *, init_config(rv_config, &handle));
	EVP_PKEY *sig_cakey;

	sig_cakey = load_key(cakey_str, config);
	if(sig_cakey == NULL)
		printf("failure2");


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


	//b = BIO_new(BIO_s_mem());
	//BIO_write(b, enc_cert_str, strlen(enc_cert_str));
	//X509 *enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	//if(enc_cert == NULL)
//		printf("failure7");
//	BIO_free(b);


	SCEP_ERROR s;
	SCEP_DATA *unwrapped = NULL;
	s = scep_unwrap(handle, pkcsreq, NULL, NULL, NULL, &unwrapped);
	
	if(s != SCEPE_OK)
		printf("failure5");

	X509 *enc_cert = unwrapped->signer_certificate;
	if(enc_cert == NULL) {
		printf("failure, no encryption cert within pkcsreq");
	}
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
	scep_cleanup(handle);
OUTPUT:
	RETVAL


char *
create_error_reply(rv_config, cakey_str, cacert_str, pkcsreq_str, failInfo_str)
SV   * rv_config
char * cakey_str
char * cacert_str
char * pkcsreq_str
char * failInfo_str
PREINIT:
	Conf *config;
CODE: 
	SCEP *handle;
	config = INT2PTR(Conf *, init_config(rv_config, &handle));
	
	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	EVP_PKEY *sig_cakey;
	sig_cakey = load_key(cakey_str, config);
	if(sig_cakey == NULL)
		printf("failure2");


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
	scep_cleanup(handle);
OUTPUT:
	RETVAL

char *
create_error_reply_wop7(rv_config, cakey_str, cacert_str, transID, senderNonce, failInfo_str)
SV   * rv_config
char * cakey_str
char * cacert_str
char * transID
unsigned char *senderNonce
char * failInfo_str
PREINIT:
	Conf *config;
CODE: 
	SCEP *handle;
	config = INT2PTR(Conf *, init_config(rv_config, &handle));
	
	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	EVP_PKEY *sig_cakey;
	sig_cakey = load_key(cakey_str, config);
	if(sig_cakey == NULL)
		printf("failure2");


	b = BIO_new(BIO_s_mem());
	BIO_write(b, cacert_str, strlen(cacert_str));
	X509 *sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cacert == NULL)
		printf("failure3");
	BIO_free(b);

	SCEP_ERROR s;

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

	s = scep_certrep(handle, transID, senderNonce, pkiStatus, failInfo, NULL, sig_cacert, sig_cakey, NULL, NULL, NULL, &p7);

	if(s != SCEPE_OK)
		printf("failure6");

	b = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b, p7);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
	scep_cleanup(handle);
OUTPUT:
	RETVAL

char *
create_pending_reply_wop7(rv_config, cakey_str, cacert_str, transID, senderNonce)
SV   * rv_config
char * cakey_str
char * cacert_str
char * transID
unsigned char * senderNonce
PREINIT:
	Conf *config;
CODE: 
	SCEP *handle;
	config = INT2PTR(Conf *, init_config(rv_config, &handle));
	
	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	EVP_PKEY *sig_cakey;
	sig_cakey = load_key(cakey_str, config);
	if(sig_cakey == NULL)
		printf("failure2");

	b = BIO_new(BIO_s_mem());
	BIO_write(b, cacert_str, strlen(cacert_str));
	X509 *sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cacert == NULL)
		printf("failure3");
	BIO_free(b);

	SCEP_ERROR s;
	SCEP_PKISTATUS pkiStatus = SCEP_PENDING;
	s = scep_certrep(handle, transID, senderNonce, pkiStatus, 0, NULL, sig_cacert, sig_cakey, NULL, NULL, NULL, &p7);

	if(s != SCEPE_OK)
		printf("failure6");

	b = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b, p7);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
	scep_cleanup(handle);
OUTPUT:
	RETVAL


char *
create_pending_reply(rv_config, cakey_str, cacert_str, pkcsreq_str)
SV   * rv_config
char * cakey_str
char * cacert_str
char * pkcsreq_str
PREINIT:
	Conf *config;
CODE: 
	SCEP *handle;
	config = INT2PTR(Conf *, init_config(rv_config, &handle));
	
	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	EVP_PKEY *sig_cakey;
	sig_cakey = load_key(cakey_str, config);
	if(sig_cakey == NULL)
		printf("failure2");

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
	scep_cleanup(handle);
OUTPUT:
	RETVAL

char *
pkcsreq(rv_config, key_str, ca_str, enc_str, req_str)
SV   * rv_config
char * key_str
char * ca_str
char * enc_str
char * req_str
PREINIT:
	Conf *config;
CODE:
	SCEP *handle;
	config = INT2PTR(Conf *, init_config(rv_config, &handle));

	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	b = BIO_new(BIO_s_mem());
	EVP_PKEY *sig_key;
	sig_key = load_key(key_str, config);
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
	scep_cleanup(handle);
	free(config);
OUTPUT:
	RETVAL

char *
getcert(rv_config, key_str, ca_str, enc_str)
SV 	 * rv_config
char * key_str
char * ca_str
char * enc_str
PREINIT:
	Conf *config;
CODE:
	SCEP *handle;
	config = INT2PTR(Conf *, init_config(rv_config, &handle));

	BIO *b;
	PKCS7 *p7 = NULL;
	char *reply = NULL;

	EVP_PKEY *sig_key;
	sig_key = load_key(key_str, config);
	if(sig_key == NULL)
		printf("failure");

	
	b = BIO_new(BIO_s_mem());
	BIO_write(b, ca_str, strlen(ca_str));
	X509 *sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL)
		printf("failure");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, enc_str, strlen(enc_str));
	X509 *enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL)
		printf("failure");
	BIO_free(b);

	ASN1_INTEGER *serial = X509_get_serialNumber(sig_cert);
    X509_NAME *issuer = X509_get_issuer_name(sig_cert);

    SCEP_ERROR s = scep_get_cert(
        handle, sig_cert, sig_key,
        issuer, serial, enc_cert, &p7);

	if(s != SCEPE_OK)
		printf("failure");

	b = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b, p7);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
	scep_cleanup(handle);
OUTPUT:
	RETVAL

char *
get_message_type(pkiMessage)
Crypt::LibSCEP pkiMessage
CODE:
	RETVAL = "";
	if(SCEP_MSG_PKCSREQ == pkiMessage->messageType)
		RETVAL = "PKCSReq";
	if(SCEP_MSG_CERTREP == pkiMessage->messageType)
		RETVAL = "CertRep";
	if(SCEP_MSG_GETCERTINITIAL == pkiMessage->messageType)
		RETVAL = "GetCertInitial";
	if(SCEP_MSG_GETCERT == pkiMessage->messageType)
		RETVAL = "GetCert";
	if(SCEP_MSG_GETCRL == pkiMessage->messageType)
		RETVAL = "GetCRL";
OUTPUT:
	RETVAL

Crypt::LibSCEP
parse(pkiMessage_str)
char * pkiMessage_str
CODE:
	Newx(RETVAL, 1, SCEP_DATA);
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
	if(unwrapped == NULL)
		printf("failure4");
	RETVAL = unwrapped;
	scep_cleanup(handle);
OUTPUT:
	RETVAL

Crypt::LibSCEP
unwrap(rv_config, pkiMessage_str, sig_cacert_str, enc_cert_str, enc_key_str)
SV 			* rv_config
char 		* pkiMessage_str
char 		* sig_cacert_str
char 		* enc_cert_str
char 		* enc_key_str
PREINIT:
	Conf *config;
CODE:
	SCEP *handle;
	config = INT2PTR(Conf *, init_config(rv_config, &handle));

	BIO *b = BIO_new(BIO_s_mem());

	EVP_PKEY *enc_key;
	enc_key = load_key(enc_key_str, config);
	if(enc_key == NULL)
		printf("failure");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, sig_cacert_str, strlen(sig_cacert_str));
	X509 *sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cacert == NULL)
		printf("failure");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, enc_cert_str, strlen(enc_cert_str));
	X509 *enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL)
		printf("failure");
	BIO_free(b);

	Newx(RETVAL, 1, SCEP_DATA);
	
	SCEP_DATA *unwrapped = NULL;

	b = BIO_new(BIO_s_mem());
	BIO_write(b, pkiMessage_str, strlen(pkiMessage_str));
	PKCS7 *pkiMessage = PEM_read_bio_PKCS7(b, NULL, 0, 0);

	if(pkiMessage == NULL)
		printf("failure4");
	BIO_free(b);
	SCEP_ERROR s = scep_unwrap(handle, pkiMessage, sig_cacert, enc_cert, enc_key, &unwrapped);
	if(s != SCEPE_OK)
		printf("failure4");
	RETVAL = unwrapped;
	scep_cleanup(handle);
OUTPUT:
	RETVAL

Crypt::LibSCEP
create_engine(rv_config)
SV 			* rv_config
PREINIT:
	Engine_conf *config;
CODE:
	
	SCEP *handle;
	scep_init(&handle);
	if (scep_init(&handle) != SCEPE_OK)
		printf("failure");
	BIO *scep_log;
	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, scep_log);
	scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
	config = INT2PTR(Engine_conf *, load_engine(rv_config, handle));
	if(config->engine == NULL)
		printf("failure");
	RETVAL = config->engine;
	free(config);
	scep_cleanup(handle);
OUTPUT:
	RETVAL

const char *
get_transaction_id(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
    RETVAL = pkiMessage->transactionID;
OUTPUT:
    RETVAL

unsigned char *
get_senderNonce(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
    RETVAL = pkiMessage->senderNonce;
OUTPUT:
    RETVAL

unsigned char *
get_recipientNonce(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
    RETVAL = pkiMessage->recipientNonce;
OUTPUT:
    RETVAL

const char *
create_nextca_reply(rv_config, chain_str, cert_str, key_str)
SV 		* rv_config
char 	* chain_str
char 	* cert_str
char 	* key_str
PREINIT:
	Conf *config;
CODE:	
    SCEP *handle;
	config = INT2PTR(Conf *, init_config(rv_config, &handle));

	char *reply = NULL;
	BIO *b = BIO_new(BIO_s_mem());

	EVP_PKEY *sig_key;
	sig_key = load_key(key_str, config);
	if(sig_key == NULL)
		printf("failure");
	BIO_free(b);

	b = BIO_new(BIO_s_mem());
	BIO_write(b, cert_str, strlen(cert_str));
	X509 *sig_cacert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cacert == NULL)
		printf("failure");
	BIO_free(b);


	int i;
	STACK_OF(X509) *certs = sk_X509_new_null();
	STACK_OF(X509_INFO) *X509Infos = NULL;
	X509_INFO *X509Info;
	PKCS7 *p7 = NULL;
	BIO *b1 = BIO_new(BIO_s_mem());
	BIO *b2 = BIO_new(BIO_s_mem());
	BIO_write(b1, chain_str, strlen(chain_str));

	X509Infos = PEM_X509_INFO_read_bio(b1, NULL, NULL, NULL);
	for (i = 0; i < sk_X509_INFO_num(X509Infos); i++) {
        X509Info = sk_X509_INFO_value(X509Infos, i);
        if (X509Info->x509 && certs) {
            if (!sk_X509_push(certs, X509Info->x509))
                printf("failure");
            X509Info->x509 = NULL;
        }
    }

    if (certs && sk_X509_num(certs) > 0) {
    	if (!(scep_getcacert_reply(handle, certs, sig_cacert, sig_key, &p7) == SCEPE_OK)) {
    		printf("failure");
    	}
    }
    else {
    	printf("failure2");
    }

    sk_X509_INFO_pop_free(X509Infos, X509_INFO_free);

	b2 = BIO_new(BIO_s_mem());
	PEM_write_bio_PKCS7(b2, p7);
	reply = (char *) malloc(b2->num_write + 1);
	memset(reply, 0, b2->num_write + 1);
	BIO_read(b2, reply, b2->num_write);
	BIO_free(b2);

	RETVAL = reply;
	scep_cleanup(handle);
OUTPUT:
    RETVAL

const char *
get_getcert_serial(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
	RETVAL = i2s_ASN1_INTEGER(NULL, pkiMessage->issuer_and_serial->serial);
OUTPUT:
    RETVAL


const char *
get_signer_cert(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
	X509 *cert = pkiMessage->signer_certificate;
	char *reply = NULL;
	BIO *b = BIO_new(BIO_s_mem());
	PEM_write_bio_X509(b, cert);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
OUTPUT:
    RETVAL

const char *
get_pkcs10(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
	X509_REQ * req = pkiMessage->request;
	char *reply = NULL;
	BIO *b = BIO_new(BIO_s_mem());
	PEM_write_bio_X509_REQ(b, req);
	reply = (char *) malloc(b->num_write + 1);
	memset(reply, 0, b->num_write + 1);
	BIO_read(b, reply, b->num_write);
	BIO_free(b);

	RETVAL = reply;
OUTPUT:
    RETVAL