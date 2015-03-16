/* src/scep.c */

#include "scep.h"

/* Global variables to track global state */
static SCEP_OIDS *_scep_oids = NULL;
static int _scep_handle_count = 0;

SCEP_ERROR scep_init(SCEP **handle)
{
	SCEP *local_handle;
	SCEP_ERROR error;

	// globally run once
	if(_scep_handle_count == 0) {
		OpenSSL_add_all_algorithms();
		ERR_load_crypto_strings();	
	}
	if(!(local_handle = malloc(sizeof(SCEP))))
		return SCEPE_MEMORY;
	memset(local_handle, 0, sizeof(SCEP));
	if((error = scep_conf_init(local_handle)) != SCEPE_OK)
	{
		scep_cleanup(local_handle);
		return error;
	}

	if((error = scep_create_oids(local_handle))) {
		scep_cleanup(local_handle);
		return error;
	}
	
	_scep_handle_count += 1;
	*handle = local_handle;
	return SCEPE_OK;
}

void scep_cleanup(SCEP *handle)
{
	scep_conf_free(handle->configuration);
	_scep_handle_count -= 1;
	// globally run once
	if(_scep_handle_count == 0) {
		free(_scep_oids);
		_scep_oids = NULL;
		EVP_cleanup();
		ERR_free_strings();
		OBJ_cleanup();
	}
	free(handle);
}

SCEP_ERROR scep_create_oids(SCEP *handle)
{
#define OID_ERR(oid)									\
	do {												\
		ERR_print_errors(handle->configuration->log);   \
		scep_log(handle, FATAL, "Could not create new OID \"" oid "\"");	\
		return SCEPE_OPENSSL;								 \
	} while(0)

	if(_scep_oids == NULL) {
		_scep_oids = malloc(sizeof(SCEP_OIDS));
		if(!_scep_oids)
			return SCEPE_MEMORY;
		memset(_scep_oids, 0, sizeof(SCEP_OIDS));

		_scep_oids->messageType = OBJ_create(
			"2.16.840.1.113733.1.9.2", "messageType", "messageType");
		if(_scep_oids->messageType == 0)
			OID_ERR("messageType");

		_scep_oids->pkiStatus = OBJ_create(
			"2.16.840.1.113733.1.9.3", "pkiStatus", "pkiStatus");
		if(_scep_oids->pkiStatus == 0)
			OID_ERR("pkiStatus");

		_scep_oids->failInfo = OBJ_create(
			"2.16.840.1.113733.1.9.4", "failInfo", "failInfo");
		if(_scep_oids->failInfo == 0)
			OID_ERR("failInfo");

		_scep_oids->senderNonce = OBJ_create(
			"2.16.840.1.113733.1.9.5", "senderNonce", "senderNonce");
		if(_scep_oids->senderNonce == 0)
			OID_ERR("senderNonce");

		_scep_oids->recipientNonce = OBJ_create(
			"2.16.840.1.113733.1.9.6", "recipientNonce", "recipientNonce");
		if(_scep_oids->recipientNonce == 0)
			OID_ERR("recipientNonce");

		_scep_oids->transId = OBJ_create(
			"2.16.840.1.113733.1.9.7", "transId", "transId");
		if(_scep_oids->transId == 0)
			OID_ERR("transId");

		_scep_oids->extensionReq = OBJ_create(
			"2.16.840.1.113733.1.9.8", "extensionReq", "extensionReq");
		if(_scep_oids->extensionReq == 0)
			OID_ERR("extensionReq");
	}
	handle->oids = _scep_oids;
	return SCEPE_OK;
}