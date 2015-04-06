#include "scep.h"
#include "message_static_functions.c"

SCEP_ERROR scep_p7_client_init(SCEP *handle, X509 *sig_cert, EVP_PKEY *sig_key, struct p7_data_t *p7data)
{
	SCEP_ERROR error = SCEPE_OK;

	p7data->p7 = PKCS7_new();
	if(p7data->p7 == NULL)
		OSSL_ERR("Could not create PKCS#7 data structure");

	if(!PKCS7_set_type(p7data->p7, NID_pkcs7_signed))
		OSSL_ERR("Could not set PKCS#7 type");

	p7data->signer_info = PKCS7_add_signature(
		p7data->p7, sig_cert, sig_key, handle->configuration->sigalg);
	if(p7data->signer_info == NULL)
		OSSL_ERR("Could not create new PKCS#7 signature");

	/* Certificate to verify signature
	 * See the discussion at https://github.com/Javex/libscep/issues/3
	 * on this issue about when, how and why we need this. It is not required
	 * by either PKCS#7 or SCEP
	 */
	if(!(handle->configuration->flags & SCEP_SKIP_SIGNER_CERT))
		if(!PKCS7_add_certificate(p7data->p7, sig_cert))
			OSSL_ERR("Could not add signer certificate");

	/* sender nonce */
	if(RAND_bytes(p7data->sender_nonce, NONCE_LENGTH) == 0)
		OSSL_ERR("Could not generate random sender nonce");

	/* Initialize content */
	if(!PKCS7_content_new(p7data->p7, NID_pkcs7_data))
		OSSL_ERR("Could not create inner PKCS#7 data structure");
	p7data->bio = PKCS7_dataInit(p7data->p7, NULL);
	if(!p7data->bio)
		OSSL_ERR("Could not initialize PKCS#7 data");

finally:
	if(error != SCEPE_OK) {
		if(p7data->p7)
			PKCS7_free(p7data->p7);
		if(p7data->signer_info)
			PKCS7_SIGNER_INFO_free(p7data->signer_info);
		if(p7data->bio)
			BIO_free(p7data->bio);
		if(p7data->transaction_id)
			free(p7data->transaction_id);
	}
	return error;
}

SCEP_ERROR scep_p7_final(SCEP *handle, struct p7_data_t *p7data, PKCS7 **p7)
{
	SCEP_ERROR error = SCEPE_OK;

	if(!PKCS7_dataFinal(p7data->p7, p7data->bio))
		OSSL_ERR("Could not finalize PKCS#7 data");

	*p7 = p7data->p7;
finally:
	if(p7data->bio)
		BIO_free_all(p7data->bio);
	if(p7data->transaction_id)
		free(p7data->transaction_id);
	if(error && p7data->p7)
		PKCS7_free(p7data->p7);
	return error;
}

SCEP_ERROR scep_pkcsreq(
	SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *enc_cert, PKCS7 **pkiMessage)
{
	BIO *databio = NULL;
	EVP_PKEY *req_pubkey = NULL;
	SCEP_ERROR error = SCEPE_OK;
	struct p7_data_t p7data;
	X509_NAME *subject;
	char *subject_str = NULL;
	int passwd_index;

	subject = X509_REQ_get_subject_name(req);
	if(!subject)
		OSSL_ERR("Error extracting subject from request");
	subject_str = X509_NAME_oneline(subject, NULL, 0);
	if(!subject_str || !strlen(subject_str))
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Need a subject on CSR as required by SCEP protocol specification");
	else
		scep_log(handle, INFO, "Certificate subject: %s", subject_str);

	req_pubkey = X509_REQ_get_pubkey(req);
	if(!req_pubkey)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Need public key on CSR");

	passwd_index = X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword, -1);
	if(passwd_index == -1)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Need challenge password field on CSR");

	databio = BIO_new(BIO_s_mem());
	if(!databio)
		OSSL_ERR("Could not create data BIO");

	if(i2d_X509_REQ_bio(databio, req) <= 0)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Error reading request into data BIO. Malformed CSR?");

	if((error = scep_p7_client_init(handle, sig_cert, sig_key, &p7data)) != SCEPE_OK)
		goto finally;

	/* transaction ID */
	if((error = scep_calculate_transaction_id_pubkey(handle, req_pubkey, &p7data.transaction_id)) != SCEPE_OK)
		goto finally;

	if((error = scep_pkiMessage(
			handle, SCEP_MSG_PKCSREQ_STR,
			databio, enc_cert, &p7data)) != SCEPE_OK)
		goto finally;
	if((error = scep_p7_final(handle, &p7data, pkiMessage)) != SCEPE_OK)
		goto finally;

finally:
	if(databio)
		BIO_free(databio);
	if(req_pubkey)  // needed?
		EVP_PKEY_free(req_pubkey);
	if(subject_str)
		free(subject_str);
	return error;
}

SCEP_ERROR scep_certrep(
		SCEP *handle,
		char *transactionID,
		unsigned char *senderNonce,
		SCEP_PKISTATUS pkiStatus, /*required*/
		SCEP_FAILINFO failInfo, /*required, if pkiStatus = failure*/
		X509 *requestedCert, /*iff success, issuedCert (PKCSReq, GetCertInitial, or other one if GetCert*/
		X509 *sig_cert, EVP_PKEY *sig_key, /*required*/
		X509 *enc_cert, /*required iff success, alternative:read out from request, alternative 2: put into SCEP_DATA when unwrapping*/
		STACK_OF(X509) *additionalCerts, /*optional (in success case): additional certs to be included*/
		X509_CRL *crl, /*mutually exclusive to requestedCert*/
		PKCS7 **pkiMessage) /*return pkcs7*/
		/*Note: additionalCerts does not include requestedCert in order to ensure that requestedCert is first in list*/
{	ASN1_PRINTABLESTRING *asn1_recipient_nonce, *asn1_pkiStatus, *asn1_failInfo;
	SCEP_ERROR error = SCEPE_OK;
	char *failInfo_nr;
	PKCS7 *degenP7 = NULL;
	BIO *databio = NULL;
	struct p7_data_t *p7data = NULL;

	if(sig_cert == NULL)
		SCEP_ERR(SCEPE_INVALID_PARAMETER, "signer Cert is required");

	if(sig_key == NULL)
		SCEP_ERR(SCEPE_INVALID_PARAMETER, "signer Key is required");

	/*TODO: add string attributes to header*/

	if(pkiStatus == SCEP_SUCCESS) {
		if(enc_cert == NULL)
			SCEP_ERR(SCEPE_INVALID_PARAMETER, "SUCCESS requires an encryption cert");
		if(!(requestedCert == NULL) ^ (crl == NULL))
			SCEP_ERR(SCEPE_INVALID_PARAMETER, "requested cert and crl are mutually exclusive");
		if((additionalCerts != NULL) && (requestedCert == NULL))
			SCEP_ERR(SCEPE_INVALID_PARAMETER, "additional certs can only be added if a requested cert is included");
	}

	/*TODO: way more checks e.g. whether SCEP_DATA contains transID etc*/

	//PKCS7 *local_pkiMessage;
	p7data = malloc(sizeof(*p7data));
	if(!p7data)
		SCEP_ERR(SCEPE_MEMORY, NULL);
	memset(p7data, 0, sizeof(*p7data));

	/*generic for all certrep types*/
	p7data->p7 = PKCS7_new();
	if(p7data->p7 == NULL)
		OSSL_ERR("Could not create PKCS#7 data structure");

	if(!PKCS7_set_type(p7data->p7, NID_pkcs7_signed))
		OSSL_ERR("Could not set PKCS#7 type");

	p7data->signer_info = PKCS7_add_signature(
		p7data->p7, sig_cert, sig_key, handle->configuration->sigalg);
	if(p7data->signer_info == NULL)
		OSSL_ERR("Could not create new PKCS#7 signature");

	if(!(handle->configuration->flags & SCEP_SKIP_SIGNER_CERT))
		if(!PKCS7_add_certificate(p7data->p7, sig_cert))
			OSSL_ERR("Could not add signer certificate");

	/*TODO: Investigate, wether this is really needed*/
	if(!PKCS7_content_new(p7data->p7, NID_pkcs7_data))
		OSSL_ERR("Could not create inner PKCS#7 data structure");


	p7data->transaction_id = strdup(transactionID);
	if(!p7data->transaction_id)
		SCEP_ERR(SCEPE_MEMORY, NULL);

	memcpy(p7data->sender_nonce, senderNonce, NONCE_LENGTH);
	if(!p7data->sender_nonce)
		SCEP_ERR(SCEPE_MEMORY, NULL);

	p7data->bio = PKCS7_dataInit(p7data->p7, NULL);
	if(!p7data->bio)
		OSSL_ERR("Could not initialize PKCS#7 data");

	if(pkiStatus == SCEP_PENDING) {
		/*encryption content MUST be ommited*/
		if((error = scep_pkiMessage(
				handle, SCEP_MSG_CERTREP_STR,
				NULL, NULL, p7data)) != SCEPE_OK)
			goto finally;

		/* pkiStatus */
		asn1_pkiStatus = ASN1_PRINTABLESTRING_new();
		if(asn1_pkiStatus == NULL)
			OSSL_ERR("Could not create ASN1 pkiStatus object");
		if(!ASN1_STRING_set(asn1_pkiStatus, SCEP_PKISTATUS_PENDING, -1))
			OSSL_ERR("Could not set ASN1 pkiStatus object");
		if(!PKCS7_add_signed_attribute(
				p7data->signer_info, handle->oids->pkiStatus, V_ASN1_PRINTABLESTRING,
				asn1_pkiStatus))
			OSSL_ERR("Could not add attribute for pkiStatus");
	}
	else if(pkiStatus == SCEP_FAILURE) {
		/*encryption content MUST be ommited*/
		if((error = scep_pkiMessage(
				handle, SCEP_MSG_CERTREP_STR,
				NULL, NULL, p7data)) != SCEPE_OK)
			goto finally;

		/* pkiStatus */
		asn1_pkiStatus = ASN1_PRINTABLESTRING_new();
		if(asn1_pkiStatus == NULL)
			OSSL_ERR("Could not create ASN1 pkiStatus object");
		if(!ASN1_STRING_set(asn1_pkiStatus, SCEP_PKISTATUS_FAILURE, -1))
			OSSL_ERR("Could not set ASN1 pkiStatus object");
		if(!PKCS7_add_signed_attribute(
				p7data->signer_info, handle->oids->pkiStatus, V_ASN1_PRINTABLESTRING,
				asn1_pkiStatus))
			OSSL_ERR("Could not add attribute for pkiStatus");

		switch(failInfo) {
			case SCEP_BAD_ALG:
				failInfo_nr = SCEP_BAD_ALG_NR;
				break;
			case SCEP_BAD_MESSAGE_CHECK:
				failInfo_nr = SCEP_BAD_MESSAGE_CHECK_NR;
				break;
			case SCEP_BAD_REQUEST:
				failInfo_nr = SCEP_BAD_REQUEST_NR;
				break;
			case SCEP_BAD_TIME:
				failInfo_nr = SCEP_BAD_TIME_NR;
				break;
			case SCEP_BAD_CERT_ID:
				failInfo_nr = SCEP_BAD_CERT_ID_NR;
				break;
			default:
				SCEP_ERR(SCEPE_UNHANDLED, "Invalid failInfo %d", failInfo);
		}

		asn1_failInfo = ASN1_PRINTABLESTRING_new();
		if(asn1_failInfo == NULL)
			OSSL_ERR("Could not create ASN1 failInfo object");
		if(!ASN1_STRING_set(asn1_failInfo, failInfo_nr, -1))
			OSSL_ERR("Could not set ASN1 failInfo object");
		if(!PKCS7_add_signed_attribute(
				p7data->signer_info, handle->oids->failInfo, V_ASN1_PRINTABLESTRING,
				asn1_failInfo))
			OSSL_ERR("Could not add attribute for failInfo");
	}
	else if(pkiStatus == SCEP_SUCCESS) {
		/*create degen p7*/
		if((error = make_degenP7(
				handle, requestedCert, additionalCerts, crl, &degenP7)) != SCEPE_OK)
			goto finally;

		/*make it to BIO for encryption*/
		databio = BIO_new(BIO_s_mem());
		if(!databio)
			OSSL_ERR("Could not create data BIO");
		if(i2d_PKCS7_bio(databio, degenP7) <= 0)
			OSSL_ERR("Could not read degenP7 into data BIO");

		if((error = scep_pkiMessage(
				handle, SCEP_MSG_CERTREP_STR,
				databio, enc_cert, p7data)) != SCEPE_OK)
			goto finally;

		/* pkiStatus */
		asn1_pkiStatus = ASN1_PRINTABLESTRING_new();
		if(asn1_pkiStatus == NULL)
			OSSL_ERR("Could not create ASN1 pkiStatus object");
		if(!ASN1_STRING_set(asn1_pkiStatus, SCEP_PKISTATUS_SUCCESS, -1))
			OSSL_ERR("Could not set ASN1 pkiStatus object");
		if(!PKCS7_add_signed_attribute(
				p7data->signer_info, handle->oids->pkiStatus, V_ASN1_PRINTABLESTRING,
				asn1_pkiStatus))
			OSSL_ERR("Could not add attribute for pkiStatus");

	}
	else {
		SCEP_ERR(SCEPE_UNHANDLED, "unknown pkiStatus %d", pkiStatus);
	}


	/* set recipient nonce to sender nonce*/
	/*TODO: User should be able to chose different senderNonce*/
	asn1_recipient_nonce = ASN1_OCTET_STRING_new();
	if(asn1_recipient_nonce == NULL)
		OSSL_ERR("Could not create ASN1 recipient nonce object");
	if(!ASN1_OCTET_STRING_set(asn1_recipient_nonce, p7data->sender_nonce, NONCE_LENGTH))
		OSSL_ERR("Could not set ASN1 recipient nonce object");
	if(!PKCS7_add_signed_attribute(
			p7data->signer_info, handle->oids->recipientNonce, V_ASN1_OCTET_STRING,
			asn1_recipient_nonce))
		OSSL_ERR("Could not add attribute for recipient nonce");


	/*searching in openssl source is like a box of chocklate...*/
	/*yes, set content and than detach it again. That way, OID is present but not its content. Must be to be conform with PKCS7 spec*/
	//PKCS7_set_detached(p7data->p7, 1);

finally:
	/* always finalize if we have initialized to avoid memory leak */
	if(p7data->bio) {
		SCEP_ERROR tmp_err = scep_p7_final(handle, p7data, pkiMessage);
		if(error == SCEPE_OK)
			error = tmp_err;
	}
	if(degenP7)
		PKCS7_free(degenP7);
	if(databio)
		BIO_free(databio);
	if(p7data)
		free(p7data);
	return error;
}

SCEP_ERROR scep_get_cert_initial(
		SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *cacert, X509 *enc_cert,
		PKCS7 **pkiMessage)
{

	SCEP_ERROR error = SCEPE_OK;
	struct p7_data_t p7data;
	EVP_PKEY *req_pubkey = NULL;
	PKCS7_ISSUER_AND_SUBJECT *ias = NULL;
	unsigned char *ias_data = NULL;
	int ias_data_size;
	BIO *databio;
	char *subject_str = NULL, *issuer_str = NULL;

	req_pubkey = X509_REQ_get_pubkey(req);
	if(!req_pubkey)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Need public key on CSR");

	ias = malloc(sizeof(PKCS7_ISSUER_AND_SUBJECT));
	if(!ias)
		OSSL_ERR("Could not create new issuer and subject structure");

	ias->subject = X509_REQ_get_subject_name(req);
	if(!ias->subject)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Need a subject on CSR to produce issuer and serial");
	subject_str = X509_NAME_oneline(ias->subject, NULL, 0);
	if(!(subject_str || strlen(subject_str))) {
		ERR_print_errors(handle->configuration->log);
		scep_log(handle, ERROR, "Error converting subject to string");
	} else {
		scep_log(handle, INFO, "Certificate subject: %s", subject_str);
		free(subject_str);
	}

	ias->issuer = X509_get_issuer_name(cacert);
	if(!ias->issuer)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Need a issuer on CA cert to produce issuer and serial");
	issuer_str = X509_NAME_oneline(ias->issuer, NULL, 0);
	if(!(issuer_str || strlen(issuer_str))) {
		ERR_print_errors(handle->configuration->log);
		scep_log(handle, ERROR, "Error converting issuer to string");
	} else {
		scep_log(handle, INFO, "Issuer name is: %s", issuer_str);
		free(issuer_str);
	}

	ias_data_size = i2d_PKCS7_ISSUER_AND_SUBJECT(ias, &ias_data);
	if(!ias_data_size)
		OSSL_ERR("Could not extract issuer and subject data");

	databio = BIO_new(BIO_s_mem());
	if(!databio)
		OSSL_ERR("Could not create data BIO");

	if(!BIO_write(databio, ias_data, ias_data_size))
		OSSL_ERR("Could not write issuer and subject data into BIO");

	if((error = scep_p7_client_init(handle, sig_cert, sig_key, &p7data)))
		goto finally;

	/* transaction ID */
	if((error = scep_calculate_transaction_id_pubkey(handle, req_pubkey, &p7data.transaction_id)) != SCEPE_OK)
		goto finally;

	if((error = scep_pkiMessage(
			handle, SCEP_MSG_GETCERTINITIAL_STR, databio, enc_cert, &p7data)) != SCEPE_OK)
		goto finally;

finally:
	/* always finalize if we have initialized to avoid memory leak */
	if(p7data.bio) {
		SCEP_ERROR tmp_err = scep_p7_final(handle, &p7data, pkiMessage);
		if(error == SCEPE_OK)
			error = tmp_err;
	}
	if(databio)
		BIO_free(databio);
	if(req_pubkey)
		EVP_PKEY_free(req_pubkey);
	if(ias)
		free(ias);
	if(ias_data)
		free(ias_data);

	return error;
}

static SCEP_ERROR _scep_get_cert_or_crl(
		SCEP *handle, X509 *sig_cert, EVP_PKEY *sig_key,
		X509_NAME *issuer, ASN1_INTEGER *serial, X509 *enc_cert,
		char *messageType, PKCS7 **pkiMessage)
{

	SCEP_ERROR error = SCEPE_OK;
	struct p7_data_t p7data;
	PKCS7_ISSUER_AND_SERIAL *ias = NULL;
	unsigned char *ias_data = NULL;
	int ias_data_size;
	BIO *databio;
	char *issuer_str = NULL;

	ias = malloc(sizeof(PKCS7_ISSUER_AND_SERIAL));
	if(!ias)
		OSSL_ERR("Could not create new issuer and serial structure");

	ias->serial = serial;
	ias->issuer = issuer;
	issuer_str = X509_NAME_oneline(ias->issuer, NULL, 0);
	if(!(issuer_str || strlen(issuer_str))) {
		ERR_print_errors(handle->configuration->log);
		scep_log(handle, ERROR, "Error converting issuer to string");
	} else {
		scep_log(handle, INFO, "Issuer name is: %s", issuer_str);
		free(issuer_str);
	}

	ias_data_size = i2d_PKCS7_ISSUER_AND_SERIAL(ias, &ias_data);
	if(!ias_data_size)
		OSSL_ERR("Could not extract issuer and subject data");

	databio = BIO_new(BIO_s_mem());
	if(!databio)
		OSSL_ERR("Could not create data BIO");

	if(!BIO_write(databio, ias_data, ias_data_size))
		OSSL_ERR("Could not write issuer and subject data into BIO");

	if((error = scep_p7_client_init(handle, sig_cert, sig_key, &p7data)))
		goto finally;

	/* transaction ID */
	if((error = scep_calculate_transaction_id_ias_type(handle, ias, messageType, &p7data.transaction_id)) != SCEPE_OK)
		goto finally;

	if((error = scep_pkiMessage(
			handle, messageType, databio, enc_cert, &p7data)) != SCEPE_OK)
		goto finally;
	if((error = scep_p7_final(handle, &p7data, pkiMessage)) != SCEPE_OK)
		goto finally;

finally:
	if(databio)
		BIO_free(databio);
	if(ias)
		free(ias);
	if(ias_data)
		free(ias_data);
	return error;
}

SCEP_ERROR scep_get_cert(
		SCEP *handle, X509 *sig_cert, EVP_PKEY *sig_key,
		X509_NAME *issuer, ASN1_INTEGER *serial, X509 *enc_cert,
		PKCS7 **pkiMessage)
{
	return _scep_get_cert_or_crl(
		handle, sig_cert, sig_key,
		issuer, serial, enc_cert,
		SCEP_MSG_GETCERT_STR, pkiMessage);
}

SCEP_ERROR scep_get_crl(
		SCEP *handle, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *req_cert, X509 *enc_cert,
		PKCS7 **pkiMessage)
{
	SCEP_ERROR error = SCEPE_OK;
	ASN1_INTEGER *serial = X509_get_serialNumber(req_cert);
	if(!serial)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Could not get serial from CA cert");

	X509_NAME *issuer = X509_get_issuer_name(req_cert);
	if(!issuer)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Could not get issuer name for CA cert");

	return _scep_get_cert_or_crl(
		handle, sig_cert, sig_key,
		issuer, serial, enc_cert,
		SCEP_MSG_GETCRL_STR, pkiMessage);
finally:
	return error;
}

SCEP_ERROR scep_pkiMessage(
		SCEP *handle,
		char *messageType, BIO *data,
		X509 *enc_cert,
		struct p7_data_t *p7data) {
	PKCS7 *encdata = NULL;
	SCEP_ERROR error = SCEPE_OK;
	STACK_OF(X509) *enc_certs = NULL;
	ASN1_PRINTABLESTRING *asn1_transaction_id, *asn1_message_type, *asn1_sender_nonce;

	/* transaction ID */
	asn1_transaction_id = ASN1_PRINTABLESTRING_new();
	if(asn1_transaction_id == NULL)
		OSSL_ERR("Could not create ASN1 TID object");
	if(!ASN1_STRING_set(asn1_transaction_id, p7data->transaction_id, -1))
		OSSL_ERR("Could not set ASN1 TID object");
	if(!PKCS7_add_signed_attribute(
			p7data->signer_info, handle->oids->transId, V_ASN1_PRINTABLESTRING,
			asn1_transaction_id))
		OSSL_ERR("Could not add attribute for transaction ID");

	/* message type */
	asn1_message_type = ASN1_PRINTABLESTRING_new();
	if(asn1_message_type == NULL)
		OSSL_ERR("Could not create ASN1 message type object");
	if(!ASN1_STRING_set(asn1_message_type, messageType, -1))
		OSSL_ERR("Could not set ASN1 message type object");
	if(!PKCS7_add_signed_attribute(
			p7data->signer_info, handle->oids->messageType, V_ASN1_PRINTABLESTRING,
			asn1_message_type))
		OSSL_ERR("Could not add attribute for message type");

	/* sender nonce */
	asn1_sender_nonce = ASN1_OCTET_STRING_new();
	if(asn1_sender_nonce == NULL)
		OSSL_ERR("Could not create ASN1 sender nonce object");
	if(!ASN1_OCTET_STRING_set(asn1_sender_nonce, p7data->sender_nonce, NONCE_LENGTH))
		OSSL_ERR("Could not set ASN1 sender nonce object");
	if(!PKCS7_add_signed_attribute(
			p7data->signer_info, handle->oids->senderNonce, V_ASN1_OCTET_STRING,
			asn1_sender_nonce))
		OSSL_ERR("Could not add attribute for sender nonce");

	/* encrypt data, skip if no data is given */
	if(data) {
		enc_certs = sk_X509_new_null();
		if(!enc_certs)
			OSSL_ERR("Could not create enc cert stack");
		if(!sk_X509_push(enc_certs, enc_cert))
			OSSL_ERR("Could not push enc cert onto stack");
		encdata = PKCS7_encrypt(enc_certs, data, handle->configuration->encalg, PKCS7_BINARY);
		if(!encdata)
			OSSL_ERR("Could not encrypt data");
		/* put encrypted data into p7 */
		if(!i2d_PKCS7_bio(p7data->bio, encdata))
			OSSL_ERR("Could not write encdata to PKCS#7 BIO");
	}

finally:
	if(encdata)
		PKCS7_free(encdata);
	if(enc_certs)
		sk_X509_free(enc_certs);
	return error;
}

SCEP_ERROR scep_unwrap_response(
		SCEP *handle, PKCS7 *pkiMessage, X509 *ca_cert,
		X509 *request_cert, EVP_PKEY *request_key,
		SCEP_OPERATION request_type, SCEP_DATA **output)
{
	SCEP_ERROR error = SCEPE_OK;
	SCEP_DATA *local_out = NULL;
	PKCS7 *messageData = NULL;

	error = scep_unwrap(
		handle, pkiMessage, ca_cert, request_cert, request_key,
		&local_out);
	if(error != SCEPE_OK)
		goto finally;

	if(local_out->pkiStatus == SCEP_SUCCESS) {
		messageData = local_out->messageData;
		/* ensure type is correct */
		if(!PKCS7_type_is_signed(local_out->messageData))
			SCEP_ERR(SCEPE_INVALID_CONTENT, "Type of inner PKCS#7 must be signed (degenerate)");

		switch(request_type) {
			case SCEPOP_GETCACERT:
			case SCEPOP_PKCSREQ:
			case SCEPOP_GETCERT:
			case SCEPOP_GETNEXTCACERT:
			case SCEPOP_GETCERTINITIAL: ; // Small necessary hack
				/* ensure there are certs (at least 1) */
				STACK_OF(X509) *certs = sk_X509_dup(local_out->messageData->d.sign->cert);
				if(sk_X509_num(certs) < 1)
					SCEP_ERR(SCEPE_INVALID_CONTENT, "Invalid number of certificates");

				/* set the output param */
				local_out->certs = certs;
				break;

			case SCEPOP_GETCRL: ; // hack again...
				/* ensure only one CRL */
				STACK_OF(X509_CRL) *crls = sk_X509_CRL_dup(local_out->messageData->d.sign->crl);
				if(sk_X509_CRL_num(crls) != 1)
					SCEP_ERR(SCEPE_INVALID_CONTENT, "Invalid number of CRLs");

				/* set output param */
				local_out->crl = sk_X509_CRL_pop(crls);
				sk_X509_CRL_free(crls);
				if(local_out->crl == NULL)
					SCEP_ERR(SCEPE_INVALID_CONTENT, "Unable to retrieve CRL from stack");
				break;

			default:
				SCEP_ERR(SCEPE_UNKOWN_OPERATION, "Invalid operation, cannot parse content");
		}
	}

	*output = local_out;
finally:
	if(messageData)
		PKCS7_free(messageData);
	if(error != SCEPE_OK)
		free(local_out);
	return error;
}

SCEP_ERROR scep_unwrap(
		SCEP *handle, PKCS7 *pkiMessage, X509 *ca_cert, X509 *dec_cert,
		EVP_PKEY *dec_key, SCEP_DATA **output)
{
	SCEP_DATA 					*local_out = NULL;
	SCEP_ERROR 					error = SCEPE_OK;
	STACK_OF(PKCS7_SIGNER_INFO)	*sk_si;
	PKCS7_SIGNER_INFO			*si;
	ASN1_TYPE					*messageType, *senderNonce, *transId;
	X509						*signerCert;
	STACK_OF(X509)				*certs = NULL;
	BIO							*encData = NULL;
	PKCS7 						*p7env = NULL;

	local_out = malloc(sizeof(SCEP_DATA));
	if(!local_out) {
		error = SCEPE_MEMORY;
		goto finally;
	}
	memset(local_out, 0, sizeof(SCEP_DATA));

	if(!PKCS7_type_is_signed(pkiMessage))
		SCEP_ERR(SCEPE_INVALID_CONTENT, "pkiMessage MUST be content type signed-data");

	/* Extract signer certificate from pkiMessage */
	certs = PKCS7_get0_signers(pkiMessage, NULL, 0);
	if(sk_X509_num(certs) < 1)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Signer certificate missing");
	if(sk_X509_num(certs) > 1) {
		if(handle->configuration->flags & SCEP_ALLOW_MULTIPLE_SIGNER_CERT) {
			scep_log(handle, WARN, "Multiple signer certs present. Ignoring as per configuration");
		} else {
			SCEP_ERR(SCEPE_UNHANDLED, "More than one signer certificate. Don't know how to handle this");
		}
	}
	signerCert = sk_X509_value(certs, 0);

	/* Verification only happens when a trusted CA cert is present */
	if(ca_cert) {
		error = verify(handle, pkiMessage, ca_cert, &encData);
		if(error != SCEPE_OK)
			goto finally;
	}

	/* pkiMessage attributes
	 * First check for attributes common for all types, then specific fields.
	 */

	/* Retrieve signer info that contains attributes */
	if(!(sk_si = PKCS7_get_signer_info(pkiMessage)))
		 SCEP_ERR(SCEPE_INVALID_CONTENT, "Failed to get signer info");
	if(sk_PKCS7_SIGNER_INFO_num(sk_si) != 1)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Unexpected number of signer infos");
	if(!(si = sk_PKCS7_SIGNER_INFO_value(sk_si, 0)))
		 OSSL_ERR("Failed to get signer info value");

	if (!ASN1_INTEGER_get(si->version) == 1)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "version MUST be 1");

	if(!(messageType = PKCS7_get_signed_attribute(si, handle->oids->messageType)))
		SCEP_ERR(SCEPE_INVALID_CONTENT, "messageType is missing. Not a pkiMessage?");

	/* luckily, standard defines single types */
	local_out->messageType_str = (char *) ASN1_STRING_data(messageType->value.printablestring);
	if(!local_out->messageType_str)
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Failed to extract message type");

	/* Fill in integer-based type as well (redundant convenience field)
	 * Note: We check for each field specifically here as the number is limited.
	 * This avoids issues if someone sets weird values on this field that might
	 * confuse parsing functions like atoi or strtol. Also we can directly check
	 * for invalid message types.
	 */
	if(strncmp(local_out->messageType_str, SCEP_MSG_PKCSREQ_STR, sizeof(SCEP_MSG_PKCSREQ_STR)) == 0)
		local_out->messageType = SCEP_MSG_PKCSREQ;
	else if(strncmp(local_out->messageType_str, SCEP_MSG_CERTREP_STR, sizeof(SCEP_MSG_CERTREP_STR)) == 0)
		local_out->messageType = SCEP_MSG_CERTREP;
	else if(strncmp(local_out->messageType_str, SCEP_MSG_GETCERTINITIAL_STR, sizeof(SCEP_MSG_GETCERTINITIAL_STR)) == 0)
		local_out->messageType = SCEP_MSG_GETCERTINITIAL;
	else if(strncmp(local_out->messageType_str, SCEP_MSG_GETCERT_STR, sizeof(SCEP_MSG_GETCERT_STR)) == 0)
		local_out->messageType = SCEP_MSG_GETCERT;
	else if(strncmp(local_out->messageType_str, SCEP_MSG_GETCRL_STR, sizeof(SCEP_MSG_GETCRL_STR)) == 0)
		local_out->messageType = SCEP_MSG_GETCRL;
	else
		SCEP_ERR(SCEPE_INVALID_CONTENT, "Invalid messageType");

	/* transaction ID */
	if(!(transId = PKCS7_get_signed_attribute(si, handle->oids->transId)))
		SCEP_ERR(SCEPE_INVALID_CONTENT, "transaction ID is missing");
	local_out->transactionID = (char *) ASN1_STRING_data(transId->value.printablestring);
	if(!local_out->transactionID)
		OSSL_ERR("Failed to extract transaction ID as string");

	/* senderNonce */
	if(!(senderNonce = PKCS7_get_signed_attribute(si, handle->oids->senderNonce)))
		SCEP_ERR(SCEPE_INVALID_CONTENT, "sender Nonce is missing");
	ASN1_TYPE_get_octetstring(senderNonce, local_out->senderNonce, NONCE_LENGTH);

	/* type-specific attributes */
	if(local_out->messageType == SCEP_MSG_CERTREP)
		error = handle_certrep_attributes(handle, local_out, si);
	else if(local_out->messageType == SCEP_MSG_PKCSREQ)
		error = check_initial_enrollment(handle, local_out, signerCert);

	/* for unhandled types this is SCEPE_OK anyway */
	if(error != SCEPE_OK)
		goto finally;

	/* If CA certificate & key are provided, decrypt enveloped message */
	if(dec_cert && dec_key) {
		if((p7env = d2i_PKCS7_bio(encData, NULL))){
			error = handle_encrypted_content(handle, local_out, p7env, dec_cert, dec_key);
			if(error != SCEPE_OK)
				goto finally;
		} else {
			/* Sort out any types which MUST contain encrypted data */
			if(local_out->messageType != SCEP_MSG_CERTREP || local_out->pkiStatus == SCEP_SUCCESS)
				SCEP_ERR(SCEPE_INVALID_CONTENT, "Message type requires an encrypted content");
		}
	}

	*output = local_out;

finally:
	if(error != SCEPE_OK)
		if(local_out)
			free(local_out);
	if(encData)
		BIO_free(encData);
	if(p7env)
		PKCS7_free(p7env);
	if(certs)
		sk_X509_free(certs);
	return error;

}