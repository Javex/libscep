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

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

	if(!(*transaction_id = malloc(2 * SHA256_DIGEST_LENGTH + 1)))
		return SCEPE_MEMORY;
	memset(*transaction_id, 0, 2 * SHA256_DIGEST_LENGTH + 1);

	if(!(bio = BIO_new(BIO_s_mem())))
	{
		error = SCEPE_MEMORY;
		goto finally;
	}
	
	if(!i2d_PUBKEY_bio(bio, pubkey))
		OSSL_ERR("Could not convert pubkey to DER.\n");

	len = BIO_get_mem_data(bio, &data);
	if(len == 0)
		OSSL_ERR("Could not get data from bio.\n");
	
	SHA256(data, len, digest);
	ctx = EVP_MD_CTX_create();
	if(ctx == NULL)
		OSSL_ERR("Could not create hash context.\n");

	if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 0)
		OSSL_ERR("Could not initialize hash context.\n");

	if(EVP_DigestUpdate(ctx, data, len) == 0)
		OSSL_ERR("Could not read data into context.\n");

	if(EVP_DigestFinal_ex(ctx, digest, NULL) == 0)
		OSSL_ERR("Could not finalize context.\n");

	for(i=0; i < SHA256_DIGEST_LENGTH; ++i)
		sprintf((*transaction_id) + i * 2, "%02X", digest[i]);
	scep_log(handle, INFO, "Generated transaction id %s\n", *transaction_id);
finally:
	if(error != SCEPE_OK)
		if(*transaction_id)
			free(*transaction_id);
	if(bio)
		BIO_free(bio);
	return error;
#undef OSSL_ERR
}

SCEP_ERROR scep_PKCS7_base64_encode(SCEP *handle, PKCS7 *p7, char **encoded)
{
	BIO *outbio = NULL, *input_b64bio = NULL;
	SCEP_ERROR error = SCEPE_OK;

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

	outbio = BIO_new(BIO_s_mem());
	BIO_set_close(outbio, BIO_NOCLOSE);
	input_b64bio = BIO_push(BIO_new(BIO_f_base64()), outbio);
	if(!input_b64bio || !outbio)
		OSSL_ERR("Could not create B64 encoding BIO chain.\n");

	if(!i2d_PKCS7_bio(input_b64bio, p7))
		OSSL_ERR("Could read data into BIO.\n");
	BIO_flush(input_b64bio);

	if(!BIO_get_mem_data(outbio, encoded))
		OSSL_ERR("Could not copy data from BIO to output char *.\n");

finally:
	BIO_free_all(input_b64bio);
	return error;
#undef OSSL_ERR
}

inline void _scep_log(SCEP *handle, SCEP_VERBOSITY verbosity, const char *file,
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

		full_message_len = snprintf(NULL, 0, "%s:%d: %s\n", filename, line, message);
		full_message = malloc(full_message_len);
		if(!full_message)
			return;
		snprintf(full_message, full_message_len, "%s:%d: %s\n", filename, line, message);
		BIO_puts(handle->configuration->log, full_message);
		free(filecopy);
		free(full_message);
		free(message);
	}
}

ASN1_SEQUENCE(PKCS7_ISSUER_AND_SUBJECT) = {
	ASN1_SIMPLE(PKCS7_ISSUER_AND_SUBJECT, issuer, X509_NAME),
	ASN1_SIMPLE(PKCS7_ISSUER_AND_SUBJECT, subject, X509_NAME)
} ASN1_SEQUENCE_END(PKCS7_ISSUER_AND_SUBJECT)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ISSUER_AND_SUBJECT)
