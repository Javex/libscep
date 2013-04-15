/* src/util.c */

#include "scep.h"
#include <stdio.h>

char *scep_strerror(SCEP_ERROR err)
{
	switch(err)
	{
		case SCEPE_OK:
			return "No error";
		case SCEPE_MEMORY:
			return "Not enough memory available";
		case SCEPE_INVALID_URL:
			return "The given URL is invalid";
		case SCEPE_UNKNOWN_CONFIGURATION:
			return "This configuration option is not known";
		case SCEPE_UNKOWN_OPERATION:
			return "Operation is unknown or no operation specified";
		case SCEPE_MISSING_URL:
			return "Missing URL configuration";
		case SCEPE_MISSING_CONFIG:
			return "This operation was not configured";
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
		case SCEPE_DUMMY_LAST_ERROR:
			return "Unknown error";
	}

	/**
	 * Nifty little trick stolen from libcurl: If an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}


