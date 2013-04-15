/* src/scep.c */

#include "scep.h"

SCEP_ERROR scep_init(SCEP **handle)
{
	SCEP *local_handle;
	int error;
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
	scep_conf_free(handle->configuration);
	free(handle);
}
