#include "scep.h"

SCEP *scep_init()
{
	SCEP *handle;
	handle = malloc(sizeof(SCEP));
	memset(handle, 0, sizeof(SCEP));
	handle->configuration = malloc(sizeof(SCEP_CONFIGURATION));
	memset(handle->configuration, 0, sizeof(SCEP_CONFIGURATION));
	return handle;
}

void scep_cleanup(SCEP *handle)
{
	scep_cleanup_conf(handle->configuration);
}
