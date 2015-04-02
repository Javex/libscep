#include "scep.h"

#include <stdlib.h>


void setup(SCEP **handle) {
	SCEP *local_handle;
	BIO *scep_log;
	scep_init(&local_handle);
	if (scep_init(&local_handle) != SCEPE_OK)
		printf("failure");
	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(local_handle, SCEPCFG_LOG, scep_log);
	scep_conf_set(local_handle, SCEPCFG_VERBOSITY, DEBUG);
	*handle = local_handle;
}

SCEP_DATA *get_pkiData(SCEP *handle, PKCS7 *pkiMessage) {
	SCEP_ERROR s;
	SCEP_DATA *unwrapped = NULL;
	s = scep_unwrap(handle, pkiMessage, NULL, NULL, NULL, &unwrapped);
	if(s != SCEPE_OK)
		printf("failure6");
	return unwrapped;
}