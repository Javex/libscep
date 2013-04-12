/* src/configuration.c */

#include "scep.h"


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
		case SCEPCFG_GETCACERT_CACERT_TARGET:
			error = scep_conf_set_getcacert(handle, type, arg);
			break;

		/* PKCSReq options */
		case SCEPCFG_PKCSREQ_CSR:
		case SCEPCFG_PKCSREQ_KEY:
		case SCEPCFG_PKCSREQ_CACERT:
		case SCEPCFG_PKCSREQ_CHALL_PASSWD:
		case SCEPCFG_PKCSREQ_SIGKEY:
		case SCEPCFG_PKCSREQ_SIGCERT:
		case SCEPCFG_PKCSREQ_CERT_TARGET:
		case SCEPCFG_PKCSREQ_POLL_INTERVAL:
		case SCEPCFG_PKCSREQ_POLL_TIME:
		case SCEPCFG_PKCSREQ_POLL_COUNT:
			error = scep_conf_set_pkcsreq(handle, type, arg);
			break;

		/* GetCert options */
		case SCEPCFG_GETCERT_KEY:
		case SCEPCFG_GETCERT_CACERT:
		case SCEPCFG_GETCERT_CERT_TARGET:
			error = scep_conf_set_getcert(handle, type, arg);
			break;

		/* GetCRL */
		case SCEPCFG_GETCRL_CERT:
		case SCEPCFG_GETCRL_CRL_TARGET:
			error = scep_conf_set_getcrl(handle, type, arg);
			break;

		/* GetNextCACert */
		case SCEPCFG_GETNEXTCACERT_ISSUER:
		case SCEPCFG_GETNEXTCACERT_CACERT_TARGET:
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
		case SCEPCFG_GETCACERT_CACERT_TARGET:
			OSSL_CONDITIONAL_FREE(handle->configuration->getcacert->ca_cert_target, X509);
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
		case SCEPCFG_PKCSREQ_CERT_TARGET:
			OSSL_CONDITIONAL_FREE(handle->configuration->pkcsreq->cert_target, X509);
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
		case SCEPCFG_GETCERT_CERT_TARGET:
			OSSL_CONDITIONAL_FREE(handle->configuration->getcert->cert_target, X509);
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
		case SCEPCFG_GETCRL_CRL_TARGET:
			OSSL_CONDITIONAL_FREE(handle->configuration->getcrl->crl_target, X509_CRL);
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
		case SCEPCFG_GETNEXTCACERT_CACERT_TARGET:
			OSSL_CONDITIONAL_FREE(handle->configuration->getnextcacert->ca_cert_target, X509);
			break;
		default:
			return SCEPE_UNKNOWN_CONFIGURATION;

	}
	return SCEPE_OK;
}

void scep_cleanup_conf(SCEP_CONFIGURATION *conf)
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

	scep_cleanup_conf_getcacert(conf->getcacert);
	scep_cleanup_conf_pkcsreq(conf->pkcsreq);
	scep_cleanup_conf_getcert(conf->getcert);
	scep_cleanup_conf_getcrl(conf->getcrl);
	scep_cleanup_conf_getcacert(conf->getnextcacert);

	free(conf);
}

void scep_cleanup_conf_getcacert(struct scep_configuration_getcacert_t *getcacert)
{
	if(getcacert)
	{
		if(getcacert->issuer)
			free(getcacert->issuer);
		if(getcacert->ca_cert_target)
			X509_free(getcacert->ca_cert_target);
		free(getcacert);
	}
}

void scep_cleanup_conf_pkcsreq(struct scep_configuration_pkcsreq_t *pkcsreq)
{
	if(pkcsreq)
	{
		if(pkcsreq->request)
			X509_REQ_free(pkcsreq->request);
		if(pkcsreq->request_key)
			EVP_PKEY_free(pkcsreq->request_key);
		if(pkcsreq->cert_target)
			X509_free(pkcsreq->cert_target);
		if(pkcsreq->challenge_password)
			free(pkcsreq->challenge_password);
		if(pkcsreq->signature_key)
			EVP_PKEY_free(pkcsreq->signature_key);
		if(pkcsreq->signature_cert)
			X509_free(pkcsreq->signature_cert);
		free(pkcsreq);
	}
}

void scep_cleanup_conf_getcert(struct scep_configuration_getcert_t *getcert)
{
	if(getcert)
	{
		if(getcert->request_key)
			EVP_PKEY_free(getcert->request_key);
		if(getcert->cert_target)
			X509_free(getcert->cert_target);
		if(getcert->ca_cert)
			X509_free(getcert->ca_cert);
		free(getcert);
	}
}

void scep_cleanup_conf_getcrl(struct scep_configuration_getcrl_t *getcrl)
{
	if(getcrl)
	{
		if(getcrl->cert)
			X509_free(getcrl->cert);
		if(getcrl->crl_target)
			X509_CRL_free(getcrl->crl_target);
		free(getcrl);
	}
}
