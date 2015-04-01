#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "ppport.h"

#include "../../../../build/scep.h"
#include <stdlib.h>


#include <unistd.h>


MODULE = Crypt::LibSCEP		PACKAGE = Crypt::LibSCEP		

char *
pkcsreq(key_str, ca_str, enc_str, req_str)
char * key_str
char * ca_str
char * enc_str
char * req_str
CODE:
	SCEP *handle;
	BIO *scep_log;
	scep_init(&handle);
	if (scep_init(&handle) != SCEPE_OK)
		printf("failure");

	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, scep_log);
	scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
	
	BIO *b;
	const EVP_CIPHER *enc_alg;
	PKCS7 *p7 = NULL;
	char *reply = NULL;
	
	b = BIO_new(BIO_s_mem());;
	BIO_write(b, key_str, strlen(key_str));
	EVP_PKEY *sig_key = PEM_read_bio_PrivateKey(b, NULL, 0, 0);
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
	BIO_write(b, enc_str, strlen(ca_str));
	X509 *enc_cert = PEM_read_bio_X509(b, NULL, 0, 0);
	if(enc_cert == NULL)
		printf("failure");
	BIO_free(b);

	enc_alg = EVP_des_ede3_cbc();

	SCEP_ERROR s = scep_pkcsreq(
		handle, req, sig_cert, sig_key, enc_cert, enc_alg, &p7);

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
