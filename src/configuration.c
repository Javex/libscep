/* src/configuration.c */

#include "scep.h"

SCEP_ERROR scep_conf_init(SCEP *handle)
{
	SCEP_ERROR error;

	if(!(handle->configuration = malloc(sizeof(SCEP_CONFIGURATION))))
		return SCEPE_MEMORY;
	memset(handle->configuration, 0, sizeof(SCEP_CONFIGURATION));

	if((error = scep_conf_set(handle, SCEPCFG_VERBOSITY, DEFAULT_VERBOSITY)) !=
			SCEPE_OK)
		return error;

	if((error = scep_conf_set(handle, SCEPCFG_SIGALG, DEFAULT_SIGALG)) !=
			SCEPE_OK)
		return error;

	if((error = scep_conf_set(handle, SCEPCFG_ENCALG, DEFAULT_ENCALG)) !=
			SCEPE_OK)
		return error;
	return error;
}

SCEP_ERROR scep_conf_set(SCEP *handle, SCEPCFG_TYPE type, ...)
{
	va_list arg;
	SCEP_ERROR error = SCEPE_OK;

	va_start(arg, type);
	switch(type)
	{
		// globals
		case SCEPCFG_URL:
		case SCEPCFG_PROXY:
			error = scep_conf_set_url(handle, type, va_arg(arg, char *));
			break;
		case SCEPCFG_VERBOSITY:
			handle->configuration->verbosity = va_arg(arg, SCEP_VERBOSITY);
			break;
		case SCEPCFG_SIGALG:
			handle->configuration->sigalg = va_arg(arg, EVP_MD *);
			break;
		case SCEPCFG_ENCALG:
			handle->configuration->encalg = va_arg(arg, EVP_CIPHER *);
			break;
		case SCEPCFG_LOG:
			if(handle->configuration->log)
			{
				scep_log(handle,
						ERROR,
						"Overwriting the BIO log is not allowed and also not "
						"recommended. BIOs can be modified in-place and "
						"should never need to be swapped.\n");
				error = SCEPE_DUPLICATE_BIO;
				break;
			}
			handle->configuration->log = va_arg(arg, BIO *);
			break;
		default:
			error = SCEPE_UNKNOWN_CONFIGURATION;
			break;
	}
	va_end(arg);
	return error;
}

SCEP_ERROR scep_conf_set_url(SCEP *handle, SCEPCFG_TYPE type, char *url_str)
{
	UriParserStateA state;
	UriUriA *url;
	SCEP_ERROR error = SCEPE_OK;

	scep_log(handle, DEBUG, "Setting URL to %s\n", url_str);
	url = malloc(sizeof(UriUriA));
	state.uri = url;
	if(uriParseUriA(&state, url_str) != URI_SUCCESS)
	{
		error = SCEPE_INVALID_URL;
		goto finally;
	}
	switch(type)
	{
		case SCEPCFG_URL:
			// first free possible, already allocated memory, then set new.
			if(handle->configuration->url)
			{
				uriFreeUriMembersA(handle->configuration->url);
				free(handle->configuration->url);
			}
			handle->configuration->url = url;
			break;
		case SCEPCFG_PROXY:
			// first free possible, already allocated memory, then set new.
			if(handle->configuration->proxy)
			{
				uriFreeUriMembersA(handle->configuration->proxy);
				free(handle->configuration->proxy);
			}
			handle->configuration->proxy = url;
			break;
		default:
			error = SCEPE_UNKNOWN_CONFIGURATION;
			uriFreeUriMembersA(url);
			goto finally;
	}

finally:
	if(error != SCEPE_OK)
		free(url);
	return error;
}

void scep_conf_free(SCEP_CONFIGURATION *conf)
{
	if(conf->url)
	{
		uriFreeUriMembersA(conf->url);
		free(conf->url);
	}
	if(conf->proxy)
	{
		uriFreeUriMembersA(conf->proxy);
		free(conf->proxy);
	}
	free(conf);
}

SCEP_ERROR scep_conf_sanity_check(SCEP *handle)
{
	if(!handle->configuration->url)
		return SCEPE_MISSING_URL;
	return SCEPE_OK;
}
