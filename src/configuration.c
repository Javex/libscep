#include "scep.h"
#include <string.h>


void scep_set_conf(SCEP *handle, SCEPCFG_TYPE type, void *cfg_value)
{
	switch(type)
	{
		case SCEPCFG_URL:
		case SCEPCFG_PROXY:
			scep_set_conf_url(handle, type, (SCEP_URL *) cfg_value);
			break;
	}
}

void scep_set_conf_url(SCEP *handle, SCEPCFG_TYPE type, SCEP_URL *url)
{
	SCEP_URL *local_url;

	local_url = malloc(sizeof(SCEP_URL));
	memcpy(local_url, url, sizeof(SCEP_URL));
	local_url->hostname = strdup(url->hostname);
	local_url->path = strdup(url->path);
	switch(type)
	{
		case SCEPCFG_URL:
			// first free possible, already allocated memory, then set new.
			scep_cleanup_conf_url(handle->configuration->url);
			handle->configuration->url = local_url;
			break;
		case SCEPCFG_PROXY:
			// first free possible, already allocated memory, then set new.
			scep_cleanup_conf_url(handle->configuration->proxy);
			handle->configuration->proxy = local_url;
			break;
		default:
			//TODO: throw error
			break;
	}

}

void scep_cleanup_conf(SCEP_CONFIGURATION *conf)
{
	scep_cleanup_conf_url(conf->url);
	scep_cleanup_conf_url(conf->proxy);
}


void scep_cleanup_conf_url(SCEP_URL *url)
{
	if(url)
	{
		if(url->hostname)
			free(url->hostname);
		if(url->path)
			free(url->path);
		free(url);
	}
}
