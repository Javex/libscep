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
