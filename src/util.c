/* src/util.c */

#include "scep.h"
#include <stdio.h>
#include <openssl/asn1t.h>

char *scep_strerror(SCEP_ERROR err)
{
	switch(err)
	{
		case SCEPE_OK:
			return "No error";
		case SCEPE_MEMORY:
			return "Not enough memory available";
		case SCEPE_UNKNOWN_CONFIGURATION:
			return "This configuration option is not known";
		case SCEPE_UNKOWN_OPERATION:
			return "Operation is unknown or no operation specified";
		case SCEPE_DUPLICATE_BIO:
			return "Overwriting BIO not allowed. Check error log for details";
		case SCEPE_PROTOCOL:
			return "Invalid protocol operation";
		case SCEPE_MISSING_CSR:
			return "You have to provide a CSR for the PKCSReq operation";
		case SCEPE_MISSING_REQ_KEY:
			return "You have to provide the private key for which you want a "
					"certificate";
		case SCEPE_MISSING_CA_CERT:
			return "The CA certificate is missing but is needed to encrypt the "
					"message for the server and/or extract certain values";
		case SCEPE_MISSING_SIGKEY:
			return "If you provide a signature certificate, you also need to "
					"provide a signature key";
		case SCEPE_MISSING_SIGCERT:
			return "If you provide a signature key, you also need to provide "
					"a signature certificate";
		case SCEPE_MISSING_CERT_KEY:
			return "To request an existing certificate you need to provide "
					"the key for which it was created";
		case SCEPE_MISSING_CRL_CERT:
			return "To request a CRL you need to provide the certificate "
					"which you want to validate";
		case SCEPE_INVALID_CONTENT:
			return "The content did not match protocol specifications. "
					"Consult log for additional information.";
		case SCEPE_UNHANDLED:
			return "The library could not handle this specific case and "
				   "does not know how to proceed. Please contact the developers "
				   "of the project.";
		case SCEPE_NYI:
			return "Action is defined by protocol but client does not yet "
					"support it. See log for details on which action is "
					"responsible for this.";
		case SCEPE_OPENSSL:
			return "Error in OpenSSL. See error log for details.";
		case SCEPE_DUMMY_LAST_ERROR:
			return "Unknown error";
	}

	/**
	 * Nifty little trick stolen from libcurl: If an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}

SCEP_ERROR scep_calculate_transaction_id(SCEP *handle, EVP_PKEY *pubkey, char **transaction_id)
{
	SCEP_ERROR error = SCEPE_OK;
	BIO *bio;
	unsigned char *data, digest[SHA256_DIGEST_LENGTH];
	int len, i;
	EVP_MD_CTX *ctx;

	if(!(*transaction_id = malloc(2 * SHA256_DIGEST_LENGTH + 1)))
		return SCEPE_MEMORY;
	memset(*transaction_id, 0, 2 * SHA256_DIGEST_LENGTH + 1);

	if(!(bio = BIO_new(BIO_s_mem())))
	{
		error = SCEPE_MEMORY;
		goto finally;
	}
	
	if(!i2d_PUBKEY_bio(bio, pubkey))
		OSSL_ERR("Could not convert pubkey to DER");

	len = BIO_get_mem_data(bio, &data);
	if(len == 0)
		OSSL_ERR("Could not get data from bio");
	
	SHA256(data, len, digest);
	ctx = EVP_MD_CTX_create();
	if(ctx == NULL)
		OSSL_ERR("Could not create hash context");

	if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 0)
		OSSL_ERR("Could not initialize hash context");

	if(EVP_DigestUpdate(ctx, data, len) == 0)
		OSSL_ERR("Could not read data into context");

	if(EVP_DigestFinal_ex(ctx, digest, NULL) == 0)
		OSSL_ERR("Could not finalize context");

	for(i=0; i < SHA256_DIGEST_LENGTH; ++i)
		sprintf((*transaction_id) + i * 2, "%02X", digest[i]);
	scep_log(handle, INFO, "Generated transaction id %s", *transaction_id);
finally:
	if(error != SCEPE_OK)
		if(*transaction_id)
			free(*transaction_id);
	if(bio)
		BIO_free(bio);
	return error;
}

SCEP_ERROR scep_PKCS7_base64_encode(SCEP *handle, PKCS7 *p7, char **encoded)
{
	BIO *outbio = NULL, *input_b64bio = NULL;
	SCEP_ERROR error = SCEPE_OK;

	outbio = BIO_new(BIO_s_mem());
	BIO_set_close(outbio, BIO_NOCLOSE);
	input_b64bio = BIO_push(BIO_new(BIO_f_base64()), outbio);
	if(!input_b64bio || !outbio)
		OSSL_ERR("Could not create B64 encoding BIO chain");

	if(!i2d_PKCS7_bio(input_b64bio, p7))
		OSSL_ERR("Could read data into BIO");
	BIO_flush(input_b64bio);

	if(!BIO_get_mem_data(outbio, encoded))
		OSSL_ERR("Could not copy data from BIO to output char *");

finally:
	BIO_free_all(input_b64bio);
	return error;
}

void _scep_log(SCEP *handle, SCEP_VERBOSITY verbosity, const char *file,
		int line, char *format, ...)
{
	char *full_message;
	char *message;
	int message_len, full_message_len;
	va_list args;
	char *filecopy, *filename;
	/* we don't handle any errors here (besides checking for them).
	 * If there's not enough memory, there are bigger issues at stake
	 * than logging.
	 */
	if(handle->configuration->log &&
			handle->configuration->verbosity >= verbosity)
	{
		filecopy = strdup(file);
		filename = basename(filecopy);
		// create the message from format string and var args.
		va_start(args, format);
		message_len = vsnprintf(NULL, 0, format, args) + 1;
		va_end(args);
		message = malloc(message_len);
		if(!message)
			return;
		va_start(args, format);
		vsnprintf(message, message_len, format, args);
		va_end(args);

		full_message_len = snprintf(NULL, 0, "%s:%d: %s\n", filename, line, message) + 1;
		full_message = malloc(full_message_len);
		if(!full_message)
			return;
		memset(full_message, 0, full_message_len);
		snprintf(full_message, full_message_len, "%s:%d: %s\n", filename, line, message);
		BIO_puts(handle->configuration->log, full_message);
		free(filecopy);
		free(full_message);
		free(message);
	}
}

SCEP_ERROR scep_new_selfsigned_X509(
		SCEP *handle, X509_REQ *req, EVP_PKEY *req_key, X509 **cert)
{
	SCEP_ERROR error = SCEPE_OK;
	X509 *new_cert = NULL;
	EVP_PKEY *pub_key;
	X509_NAME *subject;
	ASN1_INTEGER *serial;

	pub_key = X509_REQ_get_pubkey(req);
	if(!pub_key)
		OSSL_ERR("Could not get public key from CSR");

	subject = X509_REQ_get_subject_name(req);
	if(!subject)
		OSSL_ERR("Could not get subject from CSR");

	new_cert = X509_new();
	if(!new_cert)
		OSSL_ERR("Could not create new certificate");

	if(!X509_set_version(new_cert, 2))
		OSSL_ERR("Could not set certificate to V3");

	serial = s2i_ASN1_INTEGER(NULL, "1");
	if(!serial)
		OSSL_ERR("Could not create serial");

	if(!X509_set_serialNumber(new_cert, serial))
		OSSL_ERR("Could not set serial number on cert");

	if(!X509_set_subject_name(new_cert, subject))
		OSSL_ERR("Could not set subject name");

	if(!X509_set_issuer_name(new_cert, subject))
		OSSL_ERR("Could not set issuer name");

	if(!X509_set_pubkey(new_cert, pub_key))
		OSSL_ERR("Could not set public key");

	if(!X509_gmtime_adj(X509_get_notBefore(new_cert), 0))
		OSSL_ERR("Could not set notBefore field");
	if(!X509_gmtime_adj(X509_get_notAfter(new_cert),
			SCEP_SELFSIGNED_EXPIRE_DAYS * 24 * 60 * 60))
		OSSL_ERR("Could not set notAfter field");

	if(!X509_sign(new_cert, req_key, handle->configuration->sigalg))
		OSSL_ERR("Could not sign certificate with private key");
	*cert = new_cert;
finally:
	if(error != SCEPE_OK)
		if(new_cert)
			X509_free(new_cert);
	return error;
}

int X509_REQ_cmp(X509_REQ *req1, X509_REQ *req2)
{
	int rv = 0;
	rv |= ASN1_STRING_cmp(req1->signature, req2->signature);
	return rv;
}

ASN1_SEQUENCE(PKCS7_ISSUER_AND_SUBJECT) = {
	ASN1_SIMPLE(PKCS7_ISSUER_AND_SUBJECT, issuer, X509_NAME),
	ASN1_SIMPLE(PKCS7_ISSUER_AND_SUBJECT, subject, X509_NAME)
} ASN1_SEQUENCE_END(PKCS7_ISSUER_AND_SUBJECT)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ISSUER_AND_SUBJECT)
