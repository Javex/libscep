/* src/configuration.c */

#include "scep.h"
#include <string.h>
#include <stdarg.h>


void scep_set_conf(SCEP *handle, SCEPCFG_TYPE type, ...)
{
	va_list arg;

	va_start(arg, type);
	switch(type)
	{
		case SCEPCFG_URL:
		case SCEPCFG_PROXY:
			scep_set_conf_url(handle, type, va_arg(arg, SCEP_URL *));
			break;
		case SCEPCFG_ENCALG:
			scep_set_conf_encalg(handle, va_arg(arg, SCEP_ENCRYPTION_ALG));
			break;
		case SCEPCFG_SIGALG:
			scep_set_conf_sigalg(handle, va_arg(arg, SCEP_SIGNATURE_ALG));
			break;
		case SCEPCFG_VERBOSITY:
			scep_set_conf_verbosity(handle, va_arg(arg, SCEP_VERBOSITY));
			break;
		default:
			//TODO: throw error
			break;
	}
	va_end(arg);
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
			if(handle->configuration->url)
				scep_cleanup_conf_url(handle->configuration->url);
			handle->configuration->url = local_url;
			break;
		case SCEPCFG_PROXY:
			// first free possible, already allocated memory, then set new.
			scep_cleanup_conf_url(handle->configuration->proxy);
			handle->configuration->proxy = local_url;
			break;
		default:
			scep_cleanup_conf_url(local_url);
			//TODO: throw error
			break;
	}

}

void scep_set_conf_encalg(SCEP *handle, SCEP_ENCRYPTION_ALG encalg)
{
	handle->configuration->encalg = encalg;
}

void scep_set_conf_sigalg(SCEP *handle, SCEP_SIGNATURE_ALG sigalg)
{
	handle->configuration->sigalg = sigalg;
}

void scep_set_conf_verbosity(SCEP *handle, SCEP_VERBOSITY verbosity)
{
	handle->configuration->verbosity = verbosity;
}


void scep_cleanup_conf(SCEP_CONFIGURATION *conf)
{
	scep_cleanup_conf_url(conf->url);
	scep_cleanup_conf_url(conf->proxy);
	free(conf);
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

void scep_cleanup_conf_query(StrMap *query)
{
	if(query)
	{
		sm_delete(query);
	}
}
