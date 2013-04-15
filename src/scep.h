/* src/scep.h */

#ifndef SCEP_H_
#define SCEP_H_

#include <stdarg.h>
#include <string.h>
#include <uriparser/Uri.h>

#include <openssl/x509.h>
#include <openssl/evp.h>

#define DEFAULT_POLL_INTERVAL 300
#define DEFAULT_MAX_POLL_TIME 28800
#define DEFAULT_MAX_POLL_COUNT 256
#define DEFAULT_SIGALG EVP_md5()
#define DEFAULT_ENCALG EVP_des_cbc()
#define DEFAULT_VERBOSITY ERROR

/* macro to free any openssl structure if it exists and dynamically load
 * a new value from a var arg. Massively used in configuration.c
 */
#define OSSL_CONDITIONAL_FREE(item, type) \
	if(item) \
		type ## _free(item); \
	item = va_arg(arg, type *)

typedef enum {
	FATAL,
	ERROR,
	WARN,
	INFO,
	DEBUG,
} SCEP_VERBOSITY;

typedef enum {
	/* Global options */
	SCEPCFG_URL,
	SCEPCFG_PROXY,
	SCEPCFG_VERBOSITY,
	SCEPCFG_SIGALG,
	SCEPCFG_ENCALG,

	/* GetCACert options */
	SCEPCFG_GETCACERT_ISSUER,

	/* PKCSReq options */
	SCEPCFG_PKCSREQ_CSR,
	SCEPCFG_PKCSREQ_KEY,
	SCEPCFG_PKCSREQ_CACERT,
	SCEPCFG_PKCSREQ_CHALL_PASSWD,
	SCEPCFG_PKCSREQ_SIGKEY,
	SCEPCFG_PKCSREQ_SIGCERT,
	SCEPCFG_PKCSREQ_POLL_INTERVAL,
	SCEPCFG_PKCSREQ_POLL_TIME,
	SCEPCFG_PKCSREQ_POLL_COUNT,

	/* GetCert options */
	SCEPCFG_GETCERT_KEY,
	SCEPCFG_GETCERT_CACERT,

	/* GetCRL */
	SCEPCFG_GETCRL_CERT,

	/* GetNextCACert */
	SCEPCFG_GETNEXTCACERT_ISSUER,
} SCEPCFG_TYPE;

typedef enum {
	SCEPE_OK,
	SCEPE_MEMORY,
	SCEPE_INVALID_URL,
	SCEPE_UNKNOWN_CONFIGURATION,
	SCEPE_UNKOWN_OPERATION,

	SCEPE_MISSING_URL,
	SCEPE_MISSING_CONFIG,
	SCEPE_MISSING_CSR,
	SCEPE_MISSING_REQ_KEY,
	SCEPE_MISSING_CA_CERT,
	SCEPE_MISSING_SIGKEY,
	SCEPE_MISSING_SIGCERT,
	SCEPE_MISSING_CERT_KEY,
	SCEPE_MISSING_CRL_CERT,

	// this always needs to be the last error for unit tests. It is used to
	// make sure we test all error messages.
	SCEPE_DUMMY_LAST_ERROR,
} SCEP_ERROR;

typedef enum {
	SCEPOP_GETCACERT,
	SCEPOP_PKCSREQ,
	SCEPOP_GETCERT,
	SCEPOP_GETCRL,
	SCEPOP_GETNEXTCACERT,
} SCEP_OPERATION;

struct scep_configuration_getcacert_t {
	char *issuer;
};

struct scep_configuration_pkcsreq_t {
	X509_REQ *request;
	EVP_PKEY *request_key;
	X509 *ca_cert;
	char *challenge_password;
	EVP_PKEY *signature_key;
	X509 *signature_cert;
	int polling_interval;
	int maximum_poll_time;
	int maximum_poll_count;
};

struct scep_configuration_getcert_t {
	EVP_PKEY *request_key;
	X509 *ca_cert;
};

struct scep_configuration_getcrl_t {
	X509 *cert;
};

typedef struct {
	UriUriA *url;
	UriUriA *proxy;
	SCEP_VERBOSITY verbosity;
	EVP_MD *sigalg;
	EVP_CIPHER *encalg;
	struct scep_configuration_getcacert_t *getcacert;
	struct scep_configuration_pkcsreq_t *pkcsreq;
	struct scep_configuration_getcert_t *getcert;
	struct scep_configuration_getcrl_t *getcrl;
	struct scep_configuration_getcacert_t *getnextcacert;
} SCEP_CONFIGURATION;

typedef struct {
	SCEP_CONFIGURATION *configuration;
} SCEP;

/* External functions */
SCEP_ERROR scep_init(SCEP **handle);
void scep_cleanup(SCEP *handle);
SCEP_ERROR scep_conf_set(SCEP *handle, SCEPCFG_TYPE type, ...);
char *scep_strerror(SCEP_ERROR err);

SCEP_ERROR scep_operation_getcacert(SCEP *handle, STACK_OF(X509) **certs);
SCEP_ERROR scep_operation_pkcsreq(SCEP *handle, X509 **cert);
SCEP_ERROR scep_operation_getcert(SCEP *handle, X509 **cert);
SCEP_ERROR scep_operation_getcrl(SCEP *handle, X509_CRL **crl);
SCEP_ERROR scep_operation_getnextcacert(SCEP *handle, X509 **cert);

/* Internal functions */
SCEP_ERROR scep_conf_init(SCEP *handle);
SCEP_ERROR scep_conf_set_url(SCEP *handle, SCEPCFG_TYPE type, char *url_str);
SCEP_ERROR scep_conf_set_getcacert(SCEP *handle, SCEPCFG_TYPE type, va_list arg);
SCEP_ERROR scep_conf_set_pkcsreq(SCEP *handle, SCEPCFG_TYPE type, va_list arg);
SCEP_ERROR scep_conf_set_getcert(SCEP *handle, SCEPCFG_TYPE type, va_list arg);
SCEP_ERROR scep_conf_set_getcrl(SCEP *handle, SCEPCFG_TYPE type, va_list arg);
SCEP_ERROR scep_conf_set_getnextcacert(SCEP *handle, SCEPCFG_TYPE type, va_list arg);

void scep_conf_free(SCEP_CONFIGURATION *conf);
void scep_conf_getcacert_free(struct scep_configuration_getcacert_t *getcacert);
void scep_conf_pkcsreq_free(struct scep_configuration_pkcsreq_t *pkcsreq);
void scep_conf_getcert_free(struct scep_configuration_getcert_t *getcert);
void scep_conf_getcrl_free(struct scep_configuration_getcrl_t *getcrl);

SCEP_ERROR scep_conf_sanity_check(SCEP *handle, SCEP_OPERATION op);
SCEP_ERROR scep_conf_sanity_check_getcacert(SCEP *handle);
SCEP_ERROR scep_conf_sanity_check_pkcsreq(SCEP *handle);
SCEP_ERROR scep_conf_sanity_check_getcert(SCEP *handle);
SCEP_ERROR scep_conf_sanity_check_getcrl(SCEP *handle);
SCEP_ERROR scep_conf_sanity_check_getnextcacert(SCEP *handle);

#endif /* SCEP_H_ */
