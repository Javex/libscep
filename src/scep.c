/* src/scep.c */

#include "scep.h"

SCEP_ERROR scep_init(SCEP **handle)
{
	SCEP *local_handle;
	SCEP_ERROR error;
	curl_global_init(CURL_GLOBAL_ALL);
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
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
	
	*handle = local_handle;
	return SCEPE_OK;
}

void scep_cleanup(SCEP *handle)
{
	EVP_cleanup();
	scep_conf_free(handle->configuration);
	free(handle);
	curl_global_cleanup();
}

SCEP_ERROR scep_create_oids(SCEP *handle)
{
#define OID_ERR(oid)                                    \
    do {                                                \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, "Could not create new OID \"" oid "\".\n");	\
        return SCEPE_OPENSSL;                                 \
    } while(0)


	handle->oids.messageType = OBJ_create(
		"2.16.840.1.113733.1.9.2", "messageType", "messageType");
	if(handle->oids.messageType == 0)
		OID_ERR("messageType");

	handle->oids.pkiStatus = OBJ_create(
		"2.16.840.1.113733.1.9.3", "pkiStatus", "pkiStatus");
	if(handle->oids.pkiStatus == 0)
		OID_ERR("pkiStatus");

	handle->oids.failInfo = OBJ_create(
		"2.16.840.1.113733.1.9.4", "failInfo", "failInfo");
	if(handle->oids.failInfo == 0)
		OID_ERR("failInfo");

	handle->oids.senderNonce = OBJ_create(
		"2.16.840.1.113733.1.9.5", "senderNonce", "senderNonce");
	if(handle->oids.senderNonce == 0)
		OID_ERR("senderNonce");

	handle->oids.recipientNonce = OBJ_create(
		"2.16.840.1.113733.1.9.6", "recipientNonce", "recipientNonce");
	if(handle->oids.recipientNonce == 0)
		OID_ERR("recipientNonce");

	handle->oids.transId = OBJ_create(
		"2.16.840.1.113733.1.9.7", "transId", "transId");
	if(handle->oids.transId == 0)
		OID_ERR("transId");

	handle->oids.extensionReq = OBJ_create(
		"2.16.840.1.113733.1.9.8", "extensionReq", "extensionReq");
	if(handle->oids.extensionReq == 0)
		OID_ERR("extensionReq");

	return SCEPE_OK;
}