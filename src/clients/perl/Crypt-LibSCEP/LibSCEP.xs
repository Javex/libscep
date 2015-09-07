#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "scep.h"
#include <stdlib.h>
#include "config.h"

/*
Puts the error log to a string and frees config.
IMPORTANT: This is only for cleanup purposes at the end!
*/
void
create_err_msg(Conf *config) {
	char *error = NULL;
	if(config) {
		ERR_print_errors(config->handle->configuration->log);
		(void)BIO_flush(config->handle->configuration->log);
		BIO_get_mem_data(config->handle->configuration->log, &error);
		(void)BIO_set_close(config->handle->configuration->log, BIO_NOCLOSE);
		if(config->cleanup) {
			BIO_free(config->handle->configuration->log);
			scep_cleanup(config->handle);
		}
		free(config);
	}
	Perl_croak(aTHX_ error);
}

/*
Creates a new configuration accoring to specified parameter.
In case a handle is already present, it will be used instead
of creating a new one.
*/
IV
init_config(SV *rv_config) {
	SCEP_ERROR s;
	BIO *scep_log = NULL;
	Conf *config = malloc(sizeof(Conf));
	if(config == NULL) {
		goto err;
	}

	config->cleanup = FALSE;
	config->passin = "plain";
	config->passwd = "";

	if (SvROK(rv_config) && (SvTYPE(SvRV(rv_config)) == SVt_PVHV)) {
		HV *hv_config = (HV*)SvRV(rv_config);
		SV **svv;
		svv = hv_fetch(hv_config, "handle", strlen("handle"),FALSE);
		if(svv) {
			SV *sv;
			if(SvROK(*svv)) {
				sv = SvRV(*svv);
			} 
			else {
				goto err;
			}
			size_t s = SvIV(sv);
			config->handle = INT2PTR(SCEP*, s);
		}
		else {
			s = scep_init(&config->handle);
			if (s != SCEPE_OK) {
				goto err;
			}
			config->cleanup = TRUE;
			//TODO accept a log file as external configuration parameter
			scep_log = BIO_new(BIO_s_mem());
			if(scep_log == NULL) {
				goto err;
			}
			//cannot fail but we want to tolerate changes of scep_conf_set
			s = scep_conf_set(config->handle, SCEPCFG_LOG, scep_log);
			if (s != SCEPE_OK) {
				goto err;
			}
			s = scep_conf_set(config->handle, SCEPCFG_VERBOSITY, DEBUG);
			if (s != SCEPE_OK) {
				goto err;
			}		
		}		
		svv = hv_fetch(hv_config, "passin", strlen("passin"),FALSE);
		if(svv) {
			config->passin = SvPV_nolen(*svv);
		}
		svv = hv_fetch(hv_config, "sigalg", strlen("sigalg"),FALSE);
		if(svv) {
			char *md = SvPV_nolen(*svv);
			if(!(config->handle->configuration->sigalg = EVP_get_digestbyname(md))) {
				scep_log(config->handle, ERROR, "Could not set digest");
				goto err;
			}
		}
		svv = hv_fetch(hv_config, "encalg", strlen("encalg"),FALSE);
		if(svv) {
			char *encalg = SvPV_nolen(*svv);
			if(!(config->handle->configuration->encalg = EVP_get_cipherbyname(encalg))) {
				scep_log(config->handle, ERROR, "Could not set cipher");
				goto err;
			}		
		}
		svv = hv_fetch(hv_config, "passwd", strlen("passwd"),FALSE);
		if(svv) {
			config->passwd = SvPV_nolen(*svv);
		}
	}
	else {
		free(config);
		Perl_croak(aTHX_ "Configuration parameter is not a perl hash structure");
	}
	return PTR2IV(config);
err:
	if(scep_log) {	
		ERR_print_errors(scep_log);
		create_err_msg(config);
	}
	if(config) {
		if(config->cleanup) {
			scep_cleanup(config->handle);
		}
		free(config);
		Perl_croak(aTHX_ "Could not create error log or scep handle. Configuration parameter damaged?");
	}
	Perl_croak(aTHX_ "Memory allocation failure for config");	
}

/*adds an engine to the handle according to config */
void
load_engine(SV *rv_engine_conf, Conf *config) {
	Engine_conf *engine_config = malloc(sizeof(Engine_conf));
	if(engine_config == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error for engine_conf");
		create_err_msg(config);
	}
	if (SvROK(rv_engine_conf) && (SvTYPE(SvRV(rv_engine_conf)) == SVt_PVHV)) {
		SCEP_ERROR s;
		HV *hv_config = (HV*)SvRV(rv_engine_conf);
		engine_config->label = "";
		engine_config->so = "";
		engine_config->pin = "";
		engine_config->module = "";
		SV **svv = hv_fetch(hv_config, "label", strlen("label"),FALSE);
		if(svv) {
			engine_config->label = SvPV_nolen(*svv);
			svv = hv_fetch(hv_config, "so", strlen("so"),FALSE);
			if(svv) {
				engine_config->so = SvPV_nolen(*svv);
				//engine-specific configuration
				//pkcs11
				if(!strcmp(engine_config->label, "pkcs11")) {
					svv = hv_fetch(hv_config, "module", strlen("module"),FALSE);
					if(svv) {
						engine_config->module = SvPV_nolen(*svv);
					}
					else {
						scep_log(config->handle, ERROR, "Engine pkcs11 requires module path");
						goto err;
					}
					s = scep_conf_set(config->handle, SCEPCFG_ENGINE_PARAM, "MODULE_PATH", engine_config->module);
					if (s != SCEPE_OK) {
						scep_log(config->handle, ERROR, "Could not set module path in handle");
						goto err;
					}
				}	
				else {
					scep_log(config->handle, ERROR, "Sorry, unknown or unsupported engine");
					goto err;
				}
				s = scep_conf_set(config->handle, SCEPCFG_ENGINE, "dynamic", engine_config->label, engine_config->so);	
				if (s != SCEPE_OK) {
					scep_log(config->handle, ERROR, "Could not set dynamic engine in handle");
					goto err2;
				}	
				//add engine-specific configuration to loaded engine
				//pkcs11	
				if(!strcmp(engine_config->label, "pkcs11")) {
					svv = hv_fetch(hv_config, "pin", strlen("pin"),FALSE);
					if(svv) {
						engine_config->pin = SvPV_nolen(*svv);
						if(!ENGINE_ctrl_cmd_string(config->handle->configuration->engine, "PIN", engine_config->pin, 0)) {
							scep_log(config->handle, ERROR, "Setting PIN for engine failed");
							goto err2;
						}
					}
					else {
						scep_log(config->handle, ERROR, "Engine pkcs11 requires PIN");
						goto err2;
					}
				}
			}
			else {
				scep_log(config->handle, ERROR, "Engine requires path to shared object");
				goto err;
			}		
		}	
	}
	else {
		scep_log(config->handle, ERROR, "Engine config is not a perl hash structure");
		goto err;
	}
	free(engine_config);
	return;

	//Only call err2 if yout want do destroy the engine. You dont want this in case it comes from the outside
	err2:return;
	if (config->handle->configuration->engine)
	{
		ENGINE_finish(config->handle->configuration->engine);
		ENGINE_free(config->handle->configuration->engine);
	}
	if(config->handle->configuration->params) {
		config->handle->configuration->params = NULL;
	}	
	err:return;
		free(engine_config);
		create_err_msg(config);
}

EVP_PKEY *load_key(char *key_str, Conf *config) {
	EVP_PKEY *key = NULL;
	BIO *b;
	if(config->handle->configuration->engine == NULL) {
		b = BIO_new(BIO_s_mem());
		if(b == NULL) {
			scep_log(config->handle, ERROR, "Memory allocation failure for BIO");
			create_err_msg(config);
		}
		if(!BIO_write(b, key_str, strlen(key_str))) {
			scep_log(config->handle, ERROR, "Could not write to BIO");
			goto err;
		}
		char *pwd = NULL;
		if(!strcmp(config->passin, "env")) {
			pwd = getenv("pwd");
			if (pwd == NULL) {
				scep_log(config->handle, ERROR, "env:pwd not set");
				goto err;
			}
		}
		else if(!strcmp(config->passin, "pass")) {
			pwd = config->passwd;
			if(pwd == NULL) {
				scep_log(config->handle, ERROR, "pass set but no password provided");
				goto err;
			}
		}
		else if (!strcmp(config->passin, "plain")) {
			pwd = "";
		}
		else {
			scep_log(config->handle, ERROR, "unsupported pass format");
			goto err;
		}
		if(!(key = PEM_read_bio_PrivateKey(b, NULL, 0, pwd))) {
			scep_log(config->handle, ERROR, "Reading private key failed");
			goto err;
		}
		BIO_free(b);
	}
	else {
		//we got an engine
		if(!(key = ENGINE_load_private_key(config->handle->configuration->engine, key_str, NULL, NULL))) {
			scep_log(config->handle, ERROR, "Loading private key from engine failed");
			create_err_msg(config);
		}
	}
	return key;
	err:
		BIO_free(b);
		create_err_msg(config);
	return NULL;
}

typedef SCEP_DATA *Crypt__LibSCEP;
typedef SCEP 	  *Handle;
MODULE = Crypt::LibSCEP		PACKAGE = Crypt::LibSCEP	

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
	BIO *b;
	EVP_PKEY *sig_key;
	X509 *sig_cert;
	PKCS7 *p7;
	X509 *issuedCert;
	X509 *enc_cert;
	char *reply;
	SCEP_ERROR s;
	bool success;
CODE: 
	sig_key = NULL;
	sig_cert  = NULL;
	p7 = NULL;
	issuedCert = NULL;
	enc_cert = NULL;
	reply = NULL;
	success = FALSE;

	config = INT2PTR(Conf *, init_config(rv_config));

	sig_key = load_key(sig_key_str, config);

	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}
	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL) {
		scep_log(config->handle, ERROR, "Could not read signing cert");
		goto err;
	}
	(void)BIO_reset(b);

	if(BIO_write(b, issuedCert_str, strlen(issuedCert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write issued cert to BIO");
		goto err;
	}
	issuedCert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(issuedCert == NULL) {
		scep_log(config->handle, ERROR, "Could not read issued cert");
		goto err;
	}
	//TODO do I really need to check those???
	(void)BIO_reset(b);

	if(BIO_write(b, enc_cert_str, strlen(enc_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write encryption cert to BIO");
		goto err;
	}
	enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL) {
		scep_log(config->handle, ERROR, "Could not read encryption cert");
		goto err;
	}
	(void)BIO_reset(b);

	s = scep_certrep(config->handle, transID, senderNonce, SCEP_SUCCESS, 0, issuedCert, sig_cert, sig_key, enc_cert, NULL, NULL, &p7);
	if(s != SCEPE_OK || p7 == NULL) {
		scep_log(config->handle, ERROR, "scep_certrep failed");
		goto err;
	}

	if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}

	BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	
	success = TRUE;
	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}

	RETVAL = reply;
OUTPUT:
	RETVAL

char *
create_certificate_reply(rv_config, sig_key_str, sig_cert_str, pkcsreq_str, issuedCert_str)
SV * rv_config
char * sig_key_str
char * sig_cert_str
char * pkcsreq_str
char * issuedCert_str
PREINIT:
	Conf *config;
	BIO *b;
	PKCS7 *p7;
	char *reply;
	bool success;
	EVP_PKEY *sig_key;
	X509 *sig_cert;
	PKCS7 *pkcsreq;
	X509 *issuedCert;
	X509 *enc_cert;
	SCEP_ERROR s;
	SCEP_DATA *unwrapped;
CODE: 	
	success = FALSE;
	p7 = NULL;
	reply = NULL;
	config = INT2PTR(Conf *, init_config(rv_config));	
	sig_key = load_key(sig_key_str, config);
	unwrapped = NULL;

	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}

	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL) {
		scep_log(config->handle, ERROR, "Could not read signature cert");
		goto err;
	}
	(void)BIO_reset(b);

	if(BIO_write(b, pkcsreq_str, strlen(pkcsreq_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write PKCS request to BIO");
		goto err;
	}
	pkcsreq = PEM_read_bio_PKCS7(b, NULL, 0, 0);
	if(pkcsreq == NULL){
		scep_log(config->handle, ERROR, "Could not read pkcsreq");
		goto err;
	}
	(void)BIO_reset(b);

	if(BIO_write(b, issuedCert_str, strlen(issuedCert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write issued cert to BIO");
		goto err;
	}

	issuedCert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(issuedCert == NULL){
		scep_log(config->handle, ERROR, "Could not read issued cert");
		goto err;
	}
	(void)BIO_reset(b);

	s = scep_unwrap(config->handle, pkcsreq, NULL, NULL, NULL, &unwrapped);
	if(s != SCEPE_OK || unwrapped == NULL){
		scep_log(config->handle, ERROR, "scep_unwrap failed");
		goto err;
	}

	//TODO check for unwrapped->certs, then verify which one can be used for encryption
	//NOTE that this uses the fist certificate from pkcsreq for encryption. If this is not
	//the right one, the programm will fail.
	//if you want to use an external encryption cert, use create_certificate_reply_wop7
	enc_cert = unwrapped->signer_certificate;
	if(enc_cert == NULL) {
		//cannot happen as LibSCEP would have failed on unwrap
		scep_log(config->handle, ERROR, "No encryption certificate in pkcsreq");
		goto err;
	}

	s = scep_certrep(config->handle, unwrapped->transactionID, unwrapped->senderNonce, SCEP_SUCCESS, 0, issuedCert, sig_cert, sig_key, enc_cert, NULL, NULL, &p7);
	if(s != SCEPE_OK  || p7 == NULL){
		scep_log(config->handle, ERROR, "scep_certrep failed");
		goto err;
	}

	if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}

    BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	
	success = TRUE;
	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = reply;
OUTPUT:
	RETVAL

char *
create_error_reply(rv_config, sig_key_str, sig_cert_str, pkcsreq_str, failInfo_str)
SV   * rv_config
char * sig_key_str
char * sig_cert_str
char * pkcsreq_str
char * failInfo_str
PREINIT:
	Conf *config;
	BIO *b;
	PKCS7 *p7;
	char *reply;
	EVP_PKEY *sig_key;
	bool success;
	X509 *sig_cert;
	PKCS7 *pkcsreq;
	SCEP_ERROR s;
	SCEP_DATA *unwrapped;
	SCEP_FAILINFO failInfo;
CODE: 
	success = FALSE;
	config = INT2PTR(Conf *, init_config(rv_config));
	p7 = NULL;
	reply = NULL;	
	sig_key = load_key(sig_key_str, config);
	unwrapped = NULL;
	failInfo = 0;

	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}
	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	(void)BIO_reset(b);

	if(BIO_write(b, pkcsreq_str, strlen(pkcsreq_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write pkcsreq to BIO");
		goto err;
	}
	pkcsreq = PEM_read_bio_PKCS7(b, NULL, 0, 0);

	if(pkcsreq == NULL) {
		scep_log(config->handle, ERROR, "Could not write pcksreq to BIO");
		goto err;
	}
	(void)BIO_reset(b);
	s = scep_unwrap(config->handle, pkcsreq, NULL, NULL, NULL, &unwrapped);
	if(s != SCEPE_OK || unwrapped == NULL) {
		scep_log(config->handle, ERROR, "scep_unwrap failed");
		goto err;
	}		
	
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
	else  {
		scep_log(config->handle, ERROR, "Invalid fail info");
		goto err;
	}

	s = scep_certrep(config->handle, unwrapped->transactionID, unwrapped->senderNonce, SCEP_FAILURE, failInfo, NULL, sig_cert, sig_key, NULL, NULL, NULL, &p7);
	if(s != SCEPE_OK || p7 == NULL) {
		scep_log(config->handle, ERROR, "scep_certrep failed");
		goto err;
	}	

	if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}
    BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	success = TRUE;

	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = reply;
OUTPUT:
	RETVAL

char *
create_error_reply_wop7(rv_config, sig_key_str, sig_cert_str, transID, senderNonce, failInfo_str)
SV   * rv_config
char * sig_key_str
char * sig_cert_str
char * transID
unsigned char *senderNonce
char * failInfo_str
PREINIT:
	Conf *config;
	BIO *b;
	PKCS7 *p7;
	EVP_PKEY *sig_key;
	char *reply;
	SCEP_ERROR s;
	bool success;
	X509 *sig_cert;
	SCEP_FAILINFO failInfo;
CODE: 
	config = INT2PTR(Conf *, init_config(rv_config));	
	p7 = NULL;
	reply = NULL;
	failInfo = 0;
	sig_key = load_key(sig_key_str, config);
	success = FALSE;
	
	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}

	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL){
		scep_log(config->handle, ERROR, "Could not read signature cert");
		goto err;
	}	
	(void)BIO_reset(b);
	
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
	else  {
		scep_log(config->handle, ERROR, "Invalid fail info");
		goto err;
	}

	s = scep_certrep(config->handle, transID, senderNonce, SCEP_FAILURE, failInfo, NULL, sig_cert, sig_key, NULL, NULL, NULL, &p7);
	if(s != SCEPE_OK || p7 == NULL) {
		scep_log(config->handle, ERROR, "scep_certrep failed");
		goto err;
	}

	if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}
    BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	
	success = TRUE;
	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = reply;
OUTPUT:
	RETVAL

char *
create_pending_reply_wop7(rv_config, sig_key_str, sig_cert_str, transID, senderNonce)
SV   * rv_config
char * sig_key_str
char * sig_cert_str
char * transID
unsigned char * senderNonce
PREINIT:
	Conf *config;
	BIO *b;
	PKCS7 *p7;
	EVP_PKEY *sig_key;
	char *reply;
	SCEP_ERROR s;
	bool success;
	X509 *sig_cert;
CODE: 
	config = INT2PTR(Conf *, init_config(rv_config));
	p7 = NULL;
	reply = NULL;
	sig_key = load_key(sig_key_str, config);
	success = FALSE;

	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}

	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signer cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL){
		scep_log(config->handle, ERROR, "Could not read signature cert");
		goto err;
	}	
	(void)BIO_reset(b);

	s = scep_certrep(config->handle, transID, senderNonce, SCEP_PENDING, 0, NULL, sig_cert, sig_key, NULL, NULL, NULL, &p7);
	if(s != SCEPE_OK || p7 == NULL) {
		scep_log(config->handle, ERROR, "scep_certrep failed");
		goto err;
	}

	if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}
    BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	
	success = TRUE;

	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = reply;
OUTPUT:
	RETVAL


char *
create_pending_reply(rv_config, sig_key_str, sig_cert_str, pkcsreq_str)
SV   * rv_config
char * sig_key_str
char * sig_cert_str
char * pkcsreq_str
PREINIT:
	Conf *config;
	BIO *b;
	PKCS7 *p7;
	EVP_PKEY *sig_key;
	char *reply;
	SCEP_ERROR s;
	bool success;
	X509 *sig_cert;
	PKCS7 *pkcsreq;
	SCEP_DATA *unwrapped;
CODE: 
	success = FALSE;
	config = INT2PTR(Conf *, init_config(rv_config));
	p7 = NULL;
	reply = NULL;
	unwrapped = NULL;
	sig_key = load_key(sig_key_str, config);
	
	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}

	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL){
		scep_log(config->handle, ERROR, "Could not read signature cert");
		goto err;
	}	
	(void)BIO_reset(b);

	if(BIO_write(b, pkcsreq_str, strlen(pkcsreq_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write pkcsreq to BIO");
		goto err;
	}
	pkcsreq = PEM_read_bio_PKCS7(b, NULL, 0, 0);

	if(pkcsreq == NULL) {
		scep_log(config->handle, ERROR, "Could not write pcksreq to BIO");
		goto err;
	}
	(void)BIO_reset(b);

	s = scep_unwrap(config->handle, pkcsreq, NULL, NULL, NULL, &unwrapped);
	if(s != SCEPE_OK || unwrapped == NULL) {
		scep_log(config->handle, ERROR, "scep_unwrap failed");
		goto err;
	}

	s = scep_certrep(config->handle, unwrapped->transactionID, unwrapped->senderNonce, SCEP_PENDING, 0, NULL, sig_cert, sig_key, NULL, NULL, NULL, &p7);
	if(s != SCEPE_OK || p7 == NULL) {
		scep_log(config->handle, ERROR, "scep_certrep failed");
		goto err;
	}

	if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}
    BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	
	success = TRUE;

	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = reply;
OUTPUT:
	RETVAL

char *
pkcsreq(rv_config, sig_key_str, sig_cert_str, enc_cert_str, req_str)
SV   * rv_config
char * sig_cert_str
char * enc_cert_str
char * sig_key_str
char * req_str
PREINIT:
	Conf *config;
	BIO *b;
	PKCS7 *p7;
	EVP_PKEY *sig_key;
	char *reply;
	SCEP_ERROR s;
	bool success;
	X509 *sig_cert;
	X509_REQ *req;
	X509 *enc_cert;
CODE:
	success = FALSE;
	reply = NULL;
	config = INT2PTR(Conf *, init_config(rv_config));
	p7 = NULL;
	sig_key = load_key(sig_key_str, config);

	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}

	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL){
		scep_log(config->handle, ERROR, "Could not read signature cert");
		goto err;
	}	
	(void)BIO_reset(b);

	if(BIO_write(b, req_str, strlen(req_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write X509 req to BIO");
		goto err;
	}
	req = PEM_read_bio_X509_REQ(b, NULL, 0, 0);
	if(req == NULL){
		scep_log(config->handle, ERROR, "Could not read X509 req");
		goto err;
	}
	(void)BIO_reset(b);

	if(BIO_write(b, enc_cert_str, strlen(enc_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write encryption cert to BIO");
		goto err;
	}

	enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL) {
		scep_log(config->handle, ERROR, "Could not read encryption cert");
		goto err;
	}		
	(void)BIO_reset(b);

	s = scep_pkcsreq(
		config->handle, req, sig_cert, sig_key, enc_cert, &p7);
	if(s != SCEPE_OK || p7 == NULL) {
		scep_log(config->handle, ERROR, "scep_pkcsreq failed");
		goto err;
	}
	if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}
    BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	
    success = TRUE;

	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = reply;
OUTPUT:
	RETVAL

char *
getcert(rv_config, sig_key_str, sig_cert_str, enc_cert_str)
SV 	 * rv_config
char * sig_key_str
char * sig_cert_str
char * enc_cert_str
PREINIT:
	Conf *config;
	BIO *b;
	PKCS7 *p7;
	char *reply;
	EVP_PKEY *sig_key;
	bool success;
	X509 *sig_cert;
	X509 *enc_cert;
	ASN1_INTEGER *serial;
	X509_NAME *issuer;
	SCEP_ERROR s;
CODE:
	success = FALSE;
	config = INT2PTR(Conf *, init_config(rv_config));
	p7 = NULL;
	reply = NULL;
	sig_key = load_key(sig_key_str, config);

	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}

	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL){
		scep_log(config->handle, ERROR, "Could not read signature cert");
		goto err;
	}	
	(void)BIO_reset(b);

	if(BIO_write(b, enc_cert_str, strlen(enc_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write encryption cert to BIO");
		goto err;
	}
	enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL) {
		scep_log(config->handle, ERROR, "Could not read encryption cert");
		goto err;
	}		
	(void)BIO_reset(b);

	//TODO are other methods than issuer and serial such as key identifier allowed?
	serial = X509_get_serialNumber(sig_cert);
	if(serial == NULL) {
		scep_log(config->handle, ERROR, "Serial number must be present in signer cert");
		goto err;
	}	
    issuer = X509_get_issuer_name(sig_cert);
    if(issuer == NULL) {
		scep_log(config->handle, ERROR, "Issuer must be present in signer cert");
		goto err;
	}	

    s = scep_get_cert(
        config->handle, sig_cert, sig_key,
        issuer, serial, enc_cert, &p7);
	if(s != SCEPE_OK || p7 == NULL) {
		scep_log(config->handle, ERROR, "scep_get_cert failed");
		goto err;
	}

	if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}
    BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	
	success = TRUE;

	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = reply;
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
parse(rv_config, pkiMessage_str)
SV 	*rv_config
char * pkiMessage_str
PREINIT:
	BIO *b;
	SCEP_ERROR s;
	Conf *config;
	PKCS7 *pkiMessage;
	SCEP_DATA *unwrapped;
	bool success;
CODE:
	success = FALSE;
	config = INT2PTR(Conf *, init_config(rv_config));
	unwrapped = NULL;
	Newx(RETVAL, 1, SCEP_DATA);

	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}

	if(BIO_write(b, pkiMessage_str, strlen(pkiMessage_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write pkiMessage to BIO");
		goto err;
	}
	pkiMessage = PEM_read_bio_PKCS7(b, NULL, 0, 0);
	if(pkiMessage == NULL) {
		scep_log(config->handle, ERROR, "Could not read PKI Message");
		goto err;
	}

	s = scep_unwrap(config->handle, pkiMessage, NULL, NULL, NULL, &unwrapped);
	if(s != SCEPE_OK || unwrapped == NULL) {
		scep_log(config->handle, ERROR, "scep_unwrap failed");
		goto err;
	}
	success = TRUE;

	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = unwrapped;
OUTPUT:
	RETVAL

Crypt::LibSCEP
unwrap(rv_config, pkiMessage_str, sig_cert_str, enc_cert_str, enc_key_str)
SV 			* rv_config
char 		* pkiMessage_str
char 		* sig_cert_str
char 		* enc_cert_str
char 		* enc_key_str
PREINIT:
	Conf *config;
	BIO *b;
	SCEP_ERROR s;
	PKCS7 *pkiMessage;
	SCEP_DATA *unwrapped;
	bool success;
	EVP_PKEY *enc_key;
	X509 *sig_cert;
	X509 *enc_cert;
CODE:
	success = FALSE;
	config = INT2PTR(Conf *, init_config(rv_config));
	enc_key = load_key(enc_key_str, config);
	unwrapped = NULL;

	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}
	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signature cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL){
		scep_log(config->handle, ERROR, "Could not read signature cert");
		goto err;
	}	
	(void)BIO_reset(b);

	if(BIO_write(b, enc_cert_str, strlen(enc_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write decryption cert to BIO");
		goto err;
	}
	enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL){
		scep_log(config->handle, ERROR, "Could not read decryption cert");
		goto err;
	}
	(void)BIO_reset(b);

	Newx(RETVAL, 1, SCEP_DATA);
	
	if(BIO_write(b, pkiMessage_str, strlen(pkiMessage_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write PKI message to BIO");
		goto err;
	}
	pkiMessage = PEM_read_bio_PKCS7(b, NULL, 0, 0);
	if(enc_cert == NULL){
		scep_log(config->handle, ERROR, "Could not read PKI message");
		goto err;
	}
	
	s = scep_unwrap(config->handle, pkiMessage, sig_cert, enc_cert, enc_key, &unwrapped);
	
	if(s != SCEPE_OK || unwrapped == NULL) {
		scep_log(config->handle, ERROR, "scep_unwrap failed");
		goto err;
	}
	success = TRUE;
	err:
		BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}
	RETVAL = unwrapped;
OUTPUT:
	RETVAL

void
create_engine(rv_config, rv_engine_conf)
SV 			* rv_config
SV 			* rv_engine_conf
PREINIT:
	Conf *config;
CODE:
	config = INT2PTR(Conf *, init_config(rv_config));
	load_engine(rv_engine_conf, config);

const char *
get_transaction_id(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
    RETVAL = pkiMessage->transactionID;
OUTPUT:
    RETVAL

SV*
get_senderNonce(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
    RETVAL = newSVpvn((char*)pkiMessage->senderNonce, 16);
OUTPUT:
    RETVAL

SV *
get_recipientNonce(pkiMessage)
    Crypt::LibSCEP pkiMessage
PREINIT:
CODE:
	RETVAL = NULL;	
	if(strlen((char*)pkiMessage->recipientNonce) > 0) {
		RETVAL = newSVpvn((char*)pkiMessage->recipientNonce, 16);
	}
	else
		RETVAL = newSVpv("", 0);
OUTPUT:
    RETVAL

const char *
create_nextca_reply(rv_config, chain_str, sig_cert_str, sig_key_str)
SV 		* rv_config
char 	* chain_str
char 	* sig_cert_str
char 	* sig_key_str
PREINIT:
	Conf *config;
	char *reply;
	BIO *b;
	EVP_PKEY *sig_key;
	X509 *sig_cert;
	int i;
	STACK_OF(X509) *certs;
	STACK_OF(X509_INFO) *X509Infos;
	X509_INFO *X509Info;
	PKCS7 *p7;
	bool success;
CODE:	
	success = FALSE;
	config = INT2PTR(Conf *, init_config(rv_config));
	reply = NULL;
	certs = sk_X509_new_null();
	X509Infos = NULL;
	p7 = NULL;
	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		scep_log(config->handle, ERROR, "Memory allocation error");
		create_err_msg(config);
	}
	sig_key = load_key(sig_key_str, config);

	if(BIO_write(b, sig_cert_str, strlen(sig_cert_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write signer cert to BIO");
		goto err;
	}
	sig_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(sig_cert == NULL) {
		scep_log(config->handle, ERROR, "Could not read signer cert");
		goto err;
	}
	(void)BIO_reset(b);
		
	if(BIO_write(b, chain_str, strlen(chain_str)) <= 0) {
		scep_log(config->handle, ERROR, "Could not write cert chain to BIO");
		goto err;
	}
	X509Infos = PEM_X509_INFO_read_bio(b, NULL, NULL, NULL);
	if(X509Infos == NULL) {
		scep_log(config->handle, ERROR, "Could not read signer infos from cert chain");
		goto err;
	}
	(void)BIO_reset(b);

	for (i = 0; i < sk_X509_INFO_num(X509Infos); i++) {
        X509Info = sk_X509_INFO_value(X509Infos, i);
        if (X509Info->x509) {
            if (!sk_X509_push(certs, X509Info->x509)) {
                scep_log(config->handle, WARN, "Could not read a signer info from stack of signer infos");
            }
            X509Info->x509 = NULL;
        }
    }
    sk_X509_INFO_pop_free(X509Infos, X509_INFO_free);

    if (sk_X509_num(certs) > 0) {
    	if (!(scep_getcacert_reply(config->handle, certs, sig_cert, sig_key, &p7) == SCEPE_OK) || p7 == NULL) {
    		scep_log(config->handle, ERROR, "scep_getcacert_reply failed");
			goto err;
    	}
    }
    else {
    	scep_log(config->handle, ERROR, "No signer infos found");
		goto err;
    }  
   
    if(!PEM_write_bio_PKCS7(b, p7)) {
		scep_log(config->handle, ERROR, "Could not write SCEP result to BIO");
		goto err;
	}

    BIO_get_mem_data(b, &reply);
	(void)BIO_set_close(b, BIO_NOCLOSE);
	
	success = TRUE;
    
    err:
    	BIO_free(b);
		if(!success) {
			create_err_msg(config);
		}

	RETVAL = reply;
OUTPUT:
    RETVAL

const char *
get_getcert_serial(pkiMessage)
    Crypt::LibSCEP pkiMessage
CODE:
	RETVAL = "";
	if(pkiMessage->issuer_and_serial != NULL) {
		RETVAL = i2s_ASN1_INTEGER(NULL, pkiMessage->issuer_and_serial->serial);
	}
OUTPUT:
    RETVAL

const char *
get_signer_cert(pkiMessage)
    Crypt::LibSCEP pkiMessage
  PREINIT:
	X509 *cert;
	char *reply;
	BIO *b;
CODE:
	cert = pkiMessage->signer_certificate;
	reply = NULL;
	RETVAL = "";
	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		Perl_croak(aTHX_ "Memory allocation error");
	}
	if(PEM_write_bio_X509(b, cert)) {
		BIO_get_mem_data(b, &reply);
		RETVAL = reply;
	} 
	(void)BIO_set_close(b, BIO_NOCLOSE);
	BIO_free(b);
OUTPUT:
    RETVAL

const char *
get_pkcs10(pkiMessage)
    Crypt::LibSCEP pkiMessage
PREINIT:
	X509_REQ * req;
	char *reply;
	BIO *b;
CODE:
	RETVAL = "";
	req = pkiMessage->request;
	reply = NULL;
	b = BIO_new(BIO_s_mem());
	if(b == NULL) {
		Perl_croak(aTHX_ "Memory allocation error");
	}
	if(PEM_write_bio_X509_REQ(b, req)) {
		BIO_get_mem_data(b, &reply);
		RETVAL = reply;
	}
	(void)BIO_set_close(b, BIO_NOCLOSE);
	BIO_free(b); 
OUTPUT:
    RETVAL

Handle
create_handle(rv_config)
SV 			* rv_config
PREINIT:
	Conf *config;
CODE:
	config = INT2PTR(Conf *, init_config(rv_config));
	Newx(RETVAL, 1, SCEP);
	RETVAL = config->handle;
OUTPUT:
    RETVAL

void
cleanup(rv_handle)
SV 			* rv_handle
PREINIT:
	SCEP *handle;
	size_t s;
	SV *sv;
CODE:
	handle = NULL;
	if(SvROK(rv_handle)) {
		sv = SvRV(rv_handle);
		s = SvIV(sv);
		handle = INT2PTR(SCEP *, s);
	}
	else {
		Perl_croak(aTHX_ "Handle is not a Perl hash");
	}
	if(handle) {
		scep_cleanup(handle);
	}

void
DESTROY(result)
    Crypt::LibSCEP result
CODE:
    Safefree(result);