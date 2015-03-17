#include "scep.h"
#include<unistd.h>
SCEP_ERROR scep_p7_client_init(SCEP *handle, EVP_PKEY *req_pubkey, X509 *sig_cert, EVP_PKEY *sig_key, struct p7_data_t *p7data)
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

	/* transaction ID */
	if((error = scep_calculate_transaction_id(handle, req_pubkey, &p7data->transaction_id)) != SCEPE_OK) {
		scep_log(handle, FATAL, "Could create transaction ID");
		goto finally;
	}

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
	return error;
}

SCEP_ERROR scep_pkcsreq(
	SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *enc_cert, const EVP_CIPHER *enc_alg,
		PKCS7 **pkiMessage)
{
	BIO *databio = NULL;
	EVP_PKEY *req_pubkey = NULL;
	SCEP_ERROR error = SCEPE_OK;
	struct p7_data_t p7data;
	X509_NAME *subject;
	char *subject_str = NULL;
	int passwd_index;

	subject = X509_REQ_get_subject_name(req);
	subject_str = X509_NAME_oneline(subject, NULL, 0);
	if(!strlen(subject_str)) {
		scep_log(handle, ERROR, "Need a subject on CSR as required by SCEP protocol specification");
		return SCEPE_INVALID_CONTENT;
	}
	scep_log(handle, INFO, "Certificate subject: %s", subject_str);
	free(subject_str);

	req_pubkey = X509_REQ_get_pubkey(req);
	if(!req_pubkey) {
		scep_log(handle, ERROR, "Need public key on CSR");
		return SCEPE_INVALID_CONTENT;
	}
	passwd_index = X509_REQ_get_attr_by_NID(req, NID_pkcs9_challengePassword, -1);
	if(passwd_index == -1) {
		scep_log(handle, ERROR, "Need challenge password field on CSR");
		return SCEPE_INVALID_CONTENT;
	}

	databio = BIO_new(BIO_s_mem());
	if(!databio)
		OSSL_ERR("Could not create data BIO");

	if(i2d_X509_REQ_bio(databio, req) <= 0)
		OSSL_ERR("Could not read request into data BIO");

	if((error = scep_p7_client_init(handle, req_pubkey, sig_cert, sig_key, &p7data)) != SCEPE_OK)
		goto finally;
	if((error = scep_pkiMessage(
			handle, MESSAGE_TYPE_PKCSREQ,
			databio, enc_cert, enc_alg, &p7data)) != SCEPE_OK)
		goto finally;
	if((error = scep_p7_final(handle, &p7data, pkiMessage)) != SCEPE_OK)
		goto finally;

finally:
	if(databio)
		BIO_free(databio);
	if(req_pubkey)  // needed?
		EVP_PKEY_free(req_pubkey);
	return error;
}

SCEP_ERROR scep_certrep(
	SCEP *handle, PKCS7 *pkcsreq, char * pkiStatus, char *failInfo, X509 *issuedCert, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *enc_cert, const EVP_CIPHER *enc_alg, PKCS7 **pkiMessage)
{
	SCEP_ERROR error = SCEPE_OK;
	return error;
}

SCEP_ERROR scep_get_cert_initial(
		SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *cacert, X509 *enc_cert, const EVP_CIPHER *enc_alg,
		PKCS7 **pkiMessage)
{

	SCEP_ERROR error = SCEPE_OK;
	struct p7_data_t p7data;
	EVP_PKEY *req_pubkey = NULL;
	PKCS7_ISSUER_AND_SUBJECT *ias;
	unsigned char *ias_data = NULL;
	int ias_data_size;
	BIO *databio;
	char *subject_str = NULL, *issuer_str = NULL;

	req_pubkey = X509_REQ_get_pubkey(req);
	if(!req_pubkey) {
		scep_log(handle, ERROR, "Need public key on CSR");
		return SCEPE_INVALID_CONTENT;
	}

	ias = PKCS7_ISSUER_AND_SUBJECT_new();
	if(!ias)
		OSSL_ERR("Could not create new issuer and subject structure");

	ias->subject = X509_REQ_get_subject_name(req);
	if(!ias->subject)
		OSSL_ERR("Could not get subject from request");
	subject_str = X509_NAME_oneline(ias->subject, NULL, 0);
	scep_log(handle, INFO, "Request subject is %s", subject_str);

	ias->issuer = X509_get_issuer_name(cacert);
	if(!ias->issuer)
		OSSL_ERR("Could not get issuer name for CA cert");
	issuer_str = X509_NAME_oneline(ias->issuer, NULL, 0);
	scep_log(handle, INFO, "Issuer Name is %s", issuer_str);

	ias_data_size = i2d_PKCS7_ISSUER_AND_SUBJECT(ias, &ias_data);
	if(!ias_data_size)
		OSSL_ERR("Could not extract issuer and subject data");

	databio = BIO_new(BIO_s_mem());
	if(!databio)
		OSSL_ERR("Could not create data BIO");

	if(!BIO_write(databio, ias_data, ias_data_size))
		OSSL_ERR("Could not write issuer and subject data into BIO");

	if((error = scep_p7_client_init(handle, req_pubkey, sig_cert, sig_key, &p7data)))
		goto finally;
	if((error = scep_pkiMessage(
			handle, MESSAGE_TYPE_GETCERTINITIAL, databio, enc_cert, enc_alg, &p7data)) != SCEPE_OK)
		goto finally;
	if((error = scep_p7_final(handle, &p7data, pkiMessage)) != SCEPE_OK)
		goto finally;

finally:
	if(databio)
		BIO_free(databio);
	return error;
}

static SCEP_ERROR _scep_get_cert_or_crl(
		SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *req_cert, X509 *enc_cert, const EVP_CIPHER *enc_alg,
		char *messageType, PKCS7 **pkiMessage)
{

	SCEP_ERROR error = SCEPE_OK;
	struct p7_data_t p7data;
	EVP_PKEY *req_pubkey = NULL;
	PKCS7_ISSUER_AND_SERIAL *ias;
	unsigned char *ias_data = NULL;
	int ias_data_size;
	BIO *databio;
	char *issuer_str = NULL;

	req_pubkey = X509_REQ_get_pubkey(req);
	if(!req_pubkey) {
		scep_log(handle, ERROR, "Need public key on CSR");
		return SCEPE_INVALID_CONTENT;
	}

	ias = PKCS7_ISSUER_AND_SERIAL_new();
	if(!ias)
		OSSL_ERR("Could not create new issuer and subject structure");

	ias->serial = X509_get_serialNumber(req_cert);
	if(!ias->serial)
		OSSL_ERR("Could not get serial from CA cert");

	ias->issuer = X509_get_issuer_name(req_cert);
	if(!ias->issuer)
		OSSL_ERR("Could not get issuer name for CA cert");
	issuer_str = X509_NAME_oneline(ias->issuer, NULL, 0);
	scep_log(handle, INFO, "Issuer Name is %s", issuer_str);

	ias_data_size = i2d_PKCS7_ISSUER_AND_SERIAL(ias, &ias_data);
	if(!ias_data_size)
		OSSL_ERR("Could not extract issuer and subject data");

	databio = BIO_new(BIO_s_mem());
	if(!databio)
		OSSL_ERR("Could not create data BIO");

	if(!BIO_write(databio, ias_data, ias_data_size))
		OSSL_ERR("Could not write issuer and subject data into BIO");

	if((error = scep_p7_client_init(handle, req_pubkey, sig_cert, sig_key, &p7data)))
		goto finally;
	if((error = scep_pkiMessage(
			handle, messageType, databio, enc_cert, enc_alg, &p7data)) != SCEPE_OK)
		goto finally;
	if((error = scep_p7_final(handle, &p7data, pkiMessage)) != SCEPE_OK)
		goto finally;

finally:
	if(databio)
		BIO_free(databio);
	return error;
}

SCEP_ERROR scep_get_cert(
		SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *req_cert, X509 *enc_cert, const EVP_CIPHER *enc_alg,
		PKCS7 **pkiMessage)
{
	return _scep_get_cert_or_crl(
		handle, req, sig_cert, sig_key,
		req_cert, enc_cert, enc_alg,
		MESSAGE_TYPE_GETCERT, pkiMessage);
}

SCEP_ERROR scep_get_crl(
		SCEP *handle, X509_REQ *req, X509 *sig_cert, EVP_PKEY *sig_key,
		X509 *req_cert, X509 *enc_cert, const EVP_CIPHER *enc_alg,
		PKCS7 **pkiMessage)
{
	return _scep_get_cert_or_crl(
		handle, req, sig_cert, sig_key,
		req_cert, enc_cert, enc_alg,
		MESSAGE_TYPE_GETCRL, pkiMessage);
}

SCEP_ERROR scep_pkiMessage(
		SCEP *handle,
		char *messageType, BIO *data,
		X509 *enc_cert, const EVP_CIPHER *enc_alg,
		struct p7_data_t *p7data) {
	PKCS7 *encdata = NULL;
	SCEP_ERROR error = SCEPE_OK;
	STACK_OF(X509) *enc_certs;
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

	/* encrypt data */
	// since we currently are a client, we always have data
	// however, if we want to support server in the future as well
	// we sould make data optional.
	// certificate to encrypt data with
	enc_certs = sk_X509_new_null();
	if(!enc_certs)
		OSSL_ERR("Could not create enc cert stack");
	if(!sk_X509_push(enc_certs, enc_cert))
		OSSL_ERR("Could not push enc cert onto stack");
	encdata = PKCS7_encrypt(enc_certs, data, enc_alg, PKCS7_BINARY);
	if(!encdata)
		OSSL_ERR("Could not encrypt data");
	// put encrypted data into p7
	if(!i2d_PKCS7_bio(p7data->bio, encdata))
		OSSL_ERR("Could not write encdata to PKCS#7 BIO");
finally:
	return error;
}

SCEP_ERROR scep_unwrap(
	SCEP *handle, PKCS7 *pkiMessage, X509 *cacert, X509 *sig_cacert, EVP_PKEY *cakey,
	SCEP_DATA **output)
{
	SCEP_DATA *local_out = malloc(sizeof(SCEP_DATA));
	SCEP_ERROR error = SCEPE_OK;
	STACK_OF(PKCS7_SIGNER_INFO)	*sk;
	PKCS7_SIGNER_INFO			*si;
	unsigned char				*buf;
	ASN1_TYPE					*messageType, *senderNonce, *recipientNonce, *transId, *pkiStatus;
	X509_NAME					*issuer, *subject;
	X509						*signerCert;
	STACK_OF(X509)				*certs;
	BIO							*encData, *decData;
	X509_STORE					*store;
	PKCS7 						*p7env;
	/*prepare trusted store*/
	store = X509_STORE_new();
	encData = BIO_new(BIO_s_mem());
	decData = BIO_new(BIO_s_mem());
	/*add trusted cert*/
	X509_STORE_add_cert(store, sig_cacert);
	local_out->initialEnrollment = 0;
	if(!PKCS7_type_is_signed(pkiMessage))
		OSSL_ERR("pkiMessage MUST be content type signed-data");

	/* TODO: additional checks for generic attributes */

	/* Extract signer certificate from pkiMessage */
	certs = PKCS7_get0_signers(pkiMessage, NULL, 0);
	if(sk_X509_num(certs) < 1)
		OSSL_ERR("Signer certificate missing");
	if(sk_X509_num(certs) > 1) {
		if(handle->configuration->flags & SCEP_ALLOW_MULTIPLE_SIGNER_CERT) {
			scep_log(handle, WARN, "Multiple signer certs present. Ignoring as per configuration");
		} else {
			error = SCEPE_UNHANDLED;
			scep_log(handle, FATAL, "More than one signer certificate. Don't know how to handle this");
			goto finally;
		}
	}
	signerCert = sk_X509_value(certs, 0);
	/* Message type*/
	if(!(sk = PKCS7_get_signer_info(pkiMessage)))
		 OSSL_ERR("Failed to get signer info");
	 if(sk_PKCS7_SIGNER_INFO_num(sk) != 1)
		OSSL_ERR("Unexpected number of signer infos");
	if(!(si = sk_PKCS7_SIGNER_INFO_value(sk, 0)))
		 OSSL_ERR("Failed to get signer info value");
	if(!(messageType = PKCS7_get_signed_attribute(si, handle->oids->messageType)))
		OSSL_ERR("messageType is missing. Not a pkiMessage?");

	if (!ASN1_INTEGER_get(si->version) == 1)
		OSSL_ERR("version MUST be 1");

	/*luckily, standard defines unique types*/
	ASN1_STRING_to_UTF8(&buf,messageType->value.printablestring);
	local_out->messageType = (char*)buf;
	/*struct is redundant, however*/
	local_out->messageType_int = atoi(local_out->messageType);
	/*initial PKCSreq message could be selfsigned*/

	if(strncmp(local_out->messageType, MESSAGE_TYPE_PKCSREQ, 2) == 0) {
		/*check for self-signed*/
		issuer = X509_get_issuer_name(signerCert);
		if(!issuer)
			OSSL_ERR("Failed to extract issuer from certificate");
		subject = X509_get_subject_name(signerCert);
		if(!subject)
			OSSL_ERR("Failed to extract subject from certificate");

		if(X509_NAME_cmp(subject, issuer) == 0)
			local_out->initialEnrollment = 1;

			//TODO: only necessary if signerCert does not equal encryptioncert
			//X509_STORE_add_cert(store, signerCert);
	}

	if(verify(handle, pkiMessage, store, encData) != SCEPE_OK)
		goto finally;


	/*pkiMessage attributes*/

	/*transaction id*/
	if(!(transId = PKCS7_get_signed_attribute(si, handle->oids->transId)))
		OSSL_ERR("transaction ID is missing");

	ASN1_STRING_to_UTF8(&buf,transId->value.printablestring);
	local_out->transactionID = (char*)buf;

	/*senderNonce*/
	/*needed in every pkiMessage*/
	if(!(senderNonce = PKCS7_get_signed_attribute(si, handle->oids->senderNonce)))
		OSSL_ERR("sender Nonce is missing.\n");
	ASN1_TYPE_get_octetstring(senderNonce, local_out->senderNonce, 16);


	/*type-specific attributes*/
	if(strcmp(local_out->messageType, MESSAGE_TYPE_CERTREP) == 0) {
		/*recipientNonce*/
		if(!(recipientNonce = PKCS7_get_signed_attribute(si, handle->oids->recipientNonce)))
			OSSL_ERR("recipient Nonce is missing.\n");
		ASN1_TYPE_get_octetstring(recipientNonce, local_out->recipientNonce, 16);

		/*pkiStatus*/
		if(!(pkiStatus = PKCS7_get_signed_attribute(si, handle->oids->pkiStatus)))
			OSSL_ERR("PKI Status is missing.\n");
		local_out->pkiStatus = ASN1_STRING_data(pkiStatus->value.printablestring);
	}

		/*TODO: certrep failure*/
	
	/*Message is a pkiMessage and consists of a valid signature.*/
	/*decrypt it*/
	if((p7env = d2i_PKCS7_bio(encData, NULL))){
		/*Sort out invalid Certrep PENDING requests*/
		if(strcmp(local_out->messageType, MESSAGE_TYPE_CERTREP) == 0)
			if(local_out->pkiStatus == 3)
				OSSL_ERR("PENDING Certreps MUST NOT have encrypted content.\n");
		if(ASN1_INTEGER_get(p7env->d.enveloped->version) != 0) {
			OSSL_ERR("Version of the enveloped parst MUST be 0.\n");
		}
		
		/*Is there a pretty way?*/
		char buf[11];
		if(!i2t_ASN1_OBJECT(buf, 11, p7env->d.enveloped->enc_data->content_type)) {
			/*probably never be reached because of segfaults if it does not exists*/
			OSSL_ERR("missing content-type.\n");
		}
		if(!strcmp(buf, "pkcs7-data") == 0) {
			OSSL_ERR("content-type of pkcs7envelope MUST be pkcs7-data.\n");
		}
			
		/*decrypt will only handle enveloped data which is a requirement in SCEP*/ 
		if(!PKCS7_decrypt(p7env, cakey, cacert, decData, 0)) {
			OSSL_ERR("decryption failed");
		}
		if(strcmp(local_out->messageType, MESSAGE_TYPE_PKCSREQ) == 0) {
			local_out->request = NULL;
			
			/*message type PKCSreq means there MUST be a CSR in it*/
			d2i_X509_REQ_bio(decData, &(local_out->request));
			
			/*subject distinguished name*/
			if(!(X509_REQ_get_subject_name(local_out->request))) {
				OSSL_ERR("The CSR MUST contain a Subject Distinguished Name.\n");
			}
			
			/*public key*/
			if(!(X509_REQ_get_pubkey(local_out->request))) {
				OSSL_ERR("The CSR MUST contain a public key.\n");
			}
			
			/*challenge pasword*/
			int passwd_index = X509_REQ_get_attr_by_NID(local_out->request, NID_pkcs9_challengePassword, -1);
			if(passwd_index == -1) {
				OSSL_ERR("The CSR MUST contain a challenge password.\n");
			}
			
			X509_ATTRIBUTE *attr = X509_REQ_get_attr(local_out->request, passwd_index);
			if(attr->single == 0) { // set
				if(sk_ASN1_TYPE_num(attr->value.set) != 1)
					OSSL_ERR("Unexpected number of elements in challenge password");
				local_out->challenge_password = sk_ASN1_TYPE_value(attr->value.set, 0);
			} else { // single
				local_out->challenge_password = attr->value.single;
			}
		}
		/*TODO: other types besides PKCSreq dealing with encrypted content*/
	}
	else{
		/*sort out any types which MUST contain encrypted data*/
		if(strcmp(local_out->messageType, MESSAGE_TYPE_PKCSREQ) == 0) {
			if(!encData) {
				OSSL_ERR("Message type PKCSreq requires an encrypted content.\n");
			}
		}
	}

	*output = local_out;

finally:
	ERR_print_errors_fp(stderr);
	return error;

}

SCEP_ERROR verify(
	SCEP *handle, PKCS7 *pkiMessage, X509_STORE * store, BIO *encData)
{
	SCEP_ERROR error = SCEPE_OK;
	/*assuming cert is within pkiMessage*/
	/*TODO replace NULL with a seperately provided verification
	 * cert if it is not in pkiMessage*/
	if (!PKCS7_verify(pkiMessage, NULL, store, NULL, encData, 0)) {
		OSSL_ERR("verification failed");
	}
finally:
	return error;
}
