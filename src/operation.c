#include "scep.h"

SCEP_ERROR scep_operation_getcacert(SCEP *handle, STACK_OF(X509) **certs)
{
	SCEP_ERROR error;
	SCEP_REPLY *reply;
	X509 *cert = NULL;
	BIO *bio = NULL;
	PKCS7 *p7 = NULL;
	if((error = scep_conf_sanity_check(handle, SCEPOP_GETCACERT)) != SCEPE_OK)
		return error;

	// send the message
	error = scep_send_request(handle, "GetCACert", handle->configuration->getcacert->issuer, &reply);
	if(error != SCEPE_OK)
	{
		scep_log(handle, FATAL, "Operation \"GetCACert\" failed with error "
				"\"%s\". See error log for possible details\n",
				scep_strerror(error));
		return error;
	}

	// work with the content
	if(strncmp(reply->content_type, SCEP_MIME_GETCA_RA,
			strlen(SCEP_MIME_GETCA_RA)) == 0)
	{
		if(!(bio = BIO_new_mem_buf(reply->payload, reply->length)))
		{
			error = SCEPE_OPENSSL;
			ERR_print_errors(handle->configuration->log);
			scep_log(handle, FATAL, "Could not create BIO for PKCS#7 data.\n");
			goto finally;
		}

		if(!(p7 = d2i_PKCS7_bio(bio, NULL)))
		{
			error = SCEPE_OPENSSL;
			ERR_print_errors(handle->configuration->log);
			scep_log(handle, FATAL, "Could not covert data to PKCS#7.\n");
			goto finally;
		}

		switch(OBJ_obj2nid(p7->type))
		{
			case NID_pkcs7_signed:
				*certs = sk_X509_new_null();
				while((cert = sk_X509_pop(p7->d.sign->cert)))
				{
					sk_X509_push(*certs, cert);
				}
				break;
			default:
				error = SCEPE_OPENSSL;
				ERR_print_errors(handle->configuration->log);
				scep_log(handle, FATAL, "Wrong NID provided.\n");
				goto finally;
		}

		if(*certs == NULL)
		{
			error = SCEPE_OPENSSL;
			ERR_print_errors(handle->configuration->log);
			scep_log(handle, FATAL, "Server did not send back "
					"certificates.\n");
		}
	} else if(strncmp(reply->content_type, SCEP_MIME_GETCA,
			strlen(SCEP_MIME_GETCA)) == 0)
	{
		scep_log(handle, FATAL, "CA Certificate Only Response not yet "
				"implemented\n");
		error = SCEPE_NYI;
		goto finally;
	} else {
		scep_log(handle, FATAL, "Wrong Content-Type: %s\n",
				reply->content_type);
		error = SCEPE_INVALID_RESPONSE;
		goto finally;
	}
finally:
	scep_reply_free(reply);
	if(bio)
		BIO_free(bio);
	if(p7)
		PKCS7_free(p7);
	return error;
}

SCEP_ERROR scep_operation_pkcsreq(SCEP *handle, X509 **cert)
{
	SCEP_ERROR error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_PKCSREQ)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_operation_getcert(SCEP *handle, X509 **cert)
{
	SCEP_ERROR error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_GETCERT)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_operation_getcrl(SCEP *handle, X509_CRL **crl)
{
	SCEP_ERROR error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_GETCRL)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_operation_getnextcacert(SCEP *handle, X509 **cert)
{
	SCEP_ERROR error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_GETNEXTCACERT)) !=
			SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_operation_init(SCEP *handle, scep_pkiMessage_t **pkiMessage)
{
	SCEP_ERROR error = SCEPE_OK;
	scep_pkiMessage_t *local_pkiMessage;

	local_pkiMessage = malloc(sizeof(scep_pkiMessage_t));
	local_pkiMessage->senderNonce = malloc(NONCE_LENGTH);
	RAND_bytes(local_pkiMessage->senderNonce, NONCE_LENGTH);

	return error;
}

void scep_operation_free(scep_pkiMessage_t *pkiMessage)
{
	if(pkiMessage)
	{
		if(pkiMessage->messageType)
			free(pkiMessage->messageType);
		if(pkiMessage->recipientNonce)
			free(pkiMessage->recipientNonce);
		if(pkiMessage->senderNonce)
			free(pkiMessage->senderNonce);
		if(pkiMessage->transactionID)
			free(pkiMessage->transactionID);
		free(pkiMessage);
	}
}
