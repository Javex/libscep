/* src/configuration.c */

#include "scep.h"

SCEP_ERROR scep_conf_init(SCEP *handle)
{
	int error;

	if(!(handle->configuration = malloc(sizeof(SCEP_CONFIGURATION))))
		return SCEPE_MEMORY;
	memset(handle->configuration, 0, sizeof(SCEP_CONFIGURATION));

	if((error = scep_conf_set(handle, SCEPCFG_VERBOSITY, DEFAULT_VERBOSITY)) != SCEPE_OK)
		return error;

	if((error = scep_conf_set(handle, SCEPCFG_SIGALG, DEFAULT_SIGALG)) != SCEPE_OK)
		return error;

	if((error = scep_conf_set(handle, SCEPCFG_ENCALG, DEFAULT_ENCALG)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_conf_set(SCEP *handle, SCEPCFG_TYPE type, ...)
{
	va_list arg;
	int error = SCEPE_OK;

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

			/* GetCACert options */
		case SCEPCFG_GETCACERT_ISSUER:
			error = scep_conf_set_getcacert(handle, type, arg);
			break;

		/* PKCSReq options */
		case SCEPCFG_PKCSREQ_CSR:
		case SCEPCFG_PKCSREQ_KEY:
		case SCEPCFG_PKCSREQ_CACERT:
		case SCEPCFG_PKCSREQ_CHALL_PASSWD:
		case SCEPCFG_PKCSREQ_SIGKEY:
		case SCEPCFG_PKCSREQ_SIGCERT:
		case SCEPCFG_PKCSREQ_POLL_INTERVAL:
		case SCEPCFG_PKCSREQ_POLL_TIME:
		case SCEPCFG_PKCSREQ_POLL_COUNT:
			error = scep_conf_set_pkcsreq(handle, type, arg);
			break;

		/* GetCert options */
		case SCEPCFG_GETCERT_KEY:
		case SCEPCFG_GETCERT_CACERT:
			error = scep_conf_set_getcert(handle, type, arg);
			break;

		/* GetCRL */
		case SCEPCFG_GETCRL_CERT:
			error = scep_conf_set_getcrl(handle, type, arg);
			break;

		/* GetNextCACert */
		case SCEPCFG_GETNEXTCACERT_ISSUER:
			error = scep_conf_set_getnextcacert(handle, type, arg);
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
	int error = SCEPE_OK;

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

SCEP_ERROR scep_conf_set_getcacert(SCEP *handle, SCEPCFG_TYPE type, va_list arg)
{

	// if struct does not already exist, create it.
	if(handle->configuration->getcacert == NULL)
	{
		if(!(handle->configuration->getcacert =
				malloc(sizeof(struct scep_configuration_getcacert_t))))
			return SCEPE_MEMORY;
		memset(handle->configuration->getcacert, 0,
				sizeof(struct scep_configuration_getcacert_t));
	}

	switch(type)
	{
		case SCEPCFG_GETCACERT_ISSUER:
			if(handle->configuration->getcacert->issuer)
				free(handle->configuration->getcacert->issuer);
			if(!(handle->configuration->getcacert->issuer =
					strdup(va_arg(arg, char *))))
				return SCEPE_MEMORY;
			break;
		default:
			return SCEPE_UNKNOWN_CONFIGURATION;
	}

	return SCEPE_OK;
}

SCEP_ERROR scep_conf_set_pkcsreq(SCEP *handle, SCEPCFG_TYPE type, va_list arg)
{
	// if struct does not already exist, create it.
	if(handle->configuration->pkcsreq == NULL)
	{
		if(!(handle->configuration->pkcsreq =
				malloc(sizeof(struct scep_configuration_pkcsreq_t))))
			return SCEPE_MEMORY;
		memset(handle->configuration->pkcsreq, 0,
				sizeof(struct scep_configuration_pkcsreq_t));
		handle->configuration->pkcsreq->polling_interval = DEFAULT_POLL_INTERVAL;
		handle->configuration->pkcsreq->maximum_poll_time = DEFAULT_MAX_POLL_TIME;
		handle->configuration->pkcsreq->maximum_poll_count = DEFAULT_MAX_POLL_COUNT;
	}

	switch(type)
	{
		case SCEPCFG_PKCSREQ_CSR:
			OSSL_CONDITIONAL_FREE(handle->configuration->pkcsreq->request, X509_REQ);
			break;
		case SCEPCFG_PKCSREQ_KEY:
			OSSL_CONDITIONAL_FREE(handle->configuration->pkcsreq->request_key, EVP_PKEY);
			break;
		case SCEPCFG_PKCSREQ_CACERT:
			OSSL_CONDITIONAL_FREE(handle->configuration->pkcsreq->ca_cert, X509);
			break;
		case SCEPCFG_PKCSREQ_CHALL_PASSWD:
			if(handle->configuration->pkcsreq->challenge_password)
				free(handle->configuration->pkcsreq->challenge_password);
			if(!(handle->configuration->pkcsreq->challenge_password =
					strdup(va_arg(arg, char *))))
				return SCEPE_MEMORY;
			break;
		case SCEPCFG_PKCSREQ_SIGKEY:
			OSSL_CONDITIONAL_FREE(handle->configuration->pkcsreq->signature_key, EVP_PKEY);
			break;
		case SCEPCFG_PKCSREQ_SIGCERT:
			OSSL_CONDITIONAL_FREE(handle->configuration->pkcsreq->signature_cert, X509);
			break;
		case SCEPCFG_PKCSREQ_POLL_INTERVAL:
			handle->configuration->pkcsreq->polling_interval = va_arg(arg, int);
			break;
		case SCEPCFG_PKCSREQ_POLL_TIME:
			handle->configuration->pkcsreq->maximum_poll_time = va_arg(arg, int);
			break;
		case SCEPCFG_PKCSREQ_POLL_COUNT:
			handle->configuration->pkcsreq->maximum_poll_count = va_arg(arg, int);
			break;
		default:
			return SCEPE_UNKNOWN_CONFIGURATION;
	}
	return SCEPE_OK;
}

SCEP_ERROR scep_conf_set_getcert(SCEP *handle, SCEPCFG_TYPE type, va_list arg)
{

	// if struct does not already exist, create it.
	if(handle->configuration->getcert == NULL)
	{
		if(!(handle->configuration->getcert =
				malloc(sizeof(struct scep_configuration_getcert_t))))
			return SCEPE_MEMORY;
		memset(handle->configuration->getcert, 0,
				sizeof(struct scep_configuration_getcert_t));
	}

	switch(type)
	{
		case SCEPCFG_GETCERT_KEY:
			OSSL_CONDITIONAL_FREE(handle->configuration->getcert->request_key, EVP_PKEY);
			break;
		case SCEPCFG_GETCERT_CACERT:
			OSSL_CONDITIONAL_FREE(handle->configuration->getcert->ca_cert, X509);
			break;
		default:
			return SCEPE_UNKNOWN_CONFIGURATION;

	}
	return SCEPE_OK;
}

SCEP_ERROR scep_conf_set_getcrl(SCEP *handle, SCEPCFG_TYPE type, va_list arg)
{

	// if struct does not already exist, create it.
	if(handle->configuration->getcrl == NULL)
	{
		if(!(handle->configuration->getcrl =
				malloc(sizeof(struct scep_configuration_getcrl_t))))
			return SCEPE_MEMORY;
		memset(handle->configuration->getcrl, 0,
				sizeof(struct scep_configuration_getcrl_t));
	}

	switch(type)
	{
		case SCEPCFG_GETCRL_CERT:
			OSSL_CONDITIONAL_FREE(handle->configuration->getcrl->cert, X509);
			break;
		default:
			return SCEPE_UNKNOWN_CONFIGURATION;

	}
	return SCEPE_OK;
}

SCEP_ERROR scep_conf_set_getnextcacert(SCEP *handle, SCEPCFG_TYPE type, va_list arg)
{

	// if struct does not already exist, create it.
	if(handle->configuration->getnextcacert == NULL)
	{
		if(!(handle->configuration->getnextcacert =
				malloc(sizeof(struct scep_configuration_getcacert_t))))
			return SCEPE_MEMORY;
		memset(handle->configuration->getnextcacert, 0,
				sizeof(struct scep_configuration_getcacert_t));
	}

	switch(type)
	{
		case SCEPCFG_GETNEXTCACERT_ISSUER:
			if(handle->configuration->getnextcacert->issuer)
				free(handle->configuration->getnextcacert->issuer);
			if(!(handle->configuration->getnextcacert->issuer =
					strdup(va_arg(arg, char *))))
				return SCEPE_MEMORY;
			break;
		default:
			return SCEPE_UNKNOWN_CONFIGURATION;

	}
	return SCEPE_OK;
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

	scep_conf_getcacert_free(conf->getcacert);
	scep_conf_pkcsreq_free(conf->pkcsreq);
	scep_conf_getcert_free(conf->getcert);
	scep_conf_getcrl_free(conf->getcrl);
	scep_conf_getcacert_free(conf->getnextcacert);

	free(conf);
}

void scep_conf_getcacert_free(struct scep_configuration_getcacert_t *getcacert)
{
	if(getcacert)
	{
		if(getcacert->issuer)
			free(getcacert->issuer);
		free(getcacert);
	}
}

void scep_conf_pkcsreq_free(struct scep_configuration_pkcsreq_t *pkcsreq)
{
	if(pkcsreq)
	{
		if(pkcsreq->request)
			X509_REQ_free(pkcsreq->request);
		if(pkcsreq->request_key)
			EVP_PKEY_free(pkcsreq->request_key);
		if(pkcsreq->challenge_password)
			free(pkcsreq->challenge_password);
		if(pkcsreq->signature_key)
			EVP_PKEY_free(pkcsreq->signature_key);
		if(pkcsreq->signature_cert)
			X509_free(pkcsreq->signature_cert);
		if(pkcsreq->ca_cert)
			X509_free(pkcsreq->ca_cert);
		free(pkcsreq);
	}
}

void scep_conf_getcert_free(struct scep_configuration_getcert_t *getcert)
{
	if(getcert)
	{
		if(getcert->request_key)
			EVP_PKEY_free(getcert->request_key);
		if(getcert->ca_cert)
			X509_free(getcert->ca_cert);
		free(getcert);
	}
}

void scep_conf_getcrl_free(struct scep_configuration_getcrl_t *getcrl)
{
	if(getcrl)
	{
		if(getcrl->cert)
			X509_free(getcrl->cert);
		free(getcrl);
	}
}

SCEP_ERROR scep_conf_sanity_check(SCEP *handle, SCEP_OPERATION op)
{
	int error = SCEPE_OK;
	if(!handle->configuration->url)
		return SCEPE_MISSING_URL;

	switch(op)
	{
		case SCEPOP_GETCACERT:
			error = scep_conf_sanity_check_getcacert(handle);
			break;
		case SCEPOP_PKCSREQ:
			error = scep_conf_sanity_check_pkcsreq(handle);
			break;
		case SCEPOP_GETCERT:
			error = scep_conf_sanity_check_getcert(handle);
			break;
		case SCEPOP_GETCRL:
			error = scep_conf_sanity_check_getcrl(handle);
			break;
		case SCEPOP_GETNEXTCACERT:
			error = scep_conf_sanity_check_getnextcacert(handle);
			break;
		default:
			error = SCEPE_UNKOWN_OPERATION;
	}

	return error;
}

SCEP_ERROR scep_conf_sanity_check_getcacert(SCEP *handle)
{
	if(!handle->configuration->getcacert)
		return SCEPE_MISSING_CONFIG;

	return SCEPE_OK;
}

SCEP_ERROR scep_conf_sanity_check_pkcsreq(SCEP *handle)
{
	if(!handle->configuration->pkcsreq)
		return SCEPE_MISSING_CONFIG;

	if(!handle->configuration->pkcsreq->request)
		return SCEPE_MISSING_CSR;

	if(!handle->configuration->pkcsreq->request_key)
		return SCEPE_MISSING_REQ_KEY;

	if(!handle->configuration->pkcsreq->ca_cert)
		return SCEPE_MISSING_CA_CERT;

	if(handle->configuration->pkcsreq->signature_key &&
			!handle->configuration->pkcsreq->signature_cert)
		return SCEPE_MISSING_SIGCERT;

	if(handle->configuration->pkcsreq->signature_cert &&
			!handle->configuration->pkcsreq->signature_key)
		return SCEPE_MISSING_SIGKEY;

	return SCEPE_OK;
}

SCEP_ERROR scep_conf_sanity_check_getcert(SCEP *handle)
{
	if(!handle->configuration->getcert)
		return SCEPE_MISSING_CONFIG;

	if(!handle->configuration->getcert->request_key)
		return SCEPE_MISSING_CERT_KEY;

	if(!handle->configuration->getcert->ca_cert)
		return SCEPE_MISSING_CA_CERT;

	return SCEPE_OK;
}

SCEP_ERROR scep_conf_sanity_check_getcrl(SCEP *handle)
{
	if(!handle->configuration->getcrl)
		return SCEPE_MISSING_CONFIG;

	if(!handle->configuration->getcrl->cert)
		return SCEPE_MISSING_CRL_CERT;
	return SCEPE_OK;
}

SCEP_ERROR scep_conf_sanity_check_getnextcacert(SCEP *handle)
{
	if(!handle->configuration->getnextcacert)
		return SCEPE_MISSING_CONFIG;

	return SCEPE_OK;
}
