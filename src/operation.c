#include "scep.h"

SCEP_ERROR scep_operation_getcacert(SCEP *handle, STACK_OF(X509) **certs)
{
	int error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_GETCACERT)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_operation_pkcsreq(SCEP *handle, X509 **cert)
{
	int error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_PKCSREQ)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_operation_getcert(SCEP *handle, X509 **cert)
{
	int error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_GETCERT)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_operation_getcrl(SCEP *handle, X509_CRL **crl)
{
	int error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_GETCRL)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}

SCEP_ERROR scep_operation_getnextcacert(SCEP *handle, X509 **cert)
{
	int error;
	if((error = scep_conf_sanity_check(handle, SCEPOP_GETNEXTCACERT)) != SCEPE_OK)
		return error;

	return SCEPE_OK;
}
