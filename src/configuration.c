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
						"should never need to be swapped");
				error = SCEPE_DUPLICATE_BIO;
				break;
			}
			handle->configuration->log = va_arg(arg, BIO *);
			break;
		case SCEPCFG_FLAG_CLEAR:
			handle->configuration->flags = 0;
			break;
		case SCEPCFG_FLAG_SKIP_SIGNER_CERT:
			handle->configuration->flags |= SCEP_SKIP_SIGNER_CERT;
			break;
		default:
			error = SCEPE_UNKNOWN_CONFIGURATION;
			break;
	}
	va_end(arg);
	return error;
}

void scep_conf_free(SCEP_CONFIGURATION *conf)
{
	free(conf);
}

SCEP_ERROR scep_conf_sanity_check(SCEP *handle)
{
	return SCEPE_OK;
}
