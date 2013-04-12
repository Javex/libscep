/* src/scep.h */

#ifndef SCEP_H_
#define SCEP_H_

#include <stdarg.h>
#include <string.h>
#include <uriparser/Uri.h>

#include <openssl/x509.h>
#include <openssl/evp.h>

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
	DEBUG
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
	SCEPCFG_GETCACERT_CACERT_TARGET,

	/* PKCSReq options */
	SCEPCFG_PKCSREQ_CSR,
	SCEPCFG_PKCSREQ_KEY,
	SCEPCFG_PKCSREQ_CACERT,
	SCEPCFG_PKCSREQ_CHALL_PASSWD,
	SCEPCFG_PKCSREQ_SIGKEY,
	SCEPCFG_PKCSREQ_SIGCERT,
	SCEPCFG_PKCSREQ_CERT_TARGET,
	SCEPCFG_PKCSREQ_POLL_INTERVAL,
	SCEPCFG_PKCSREQ_POLL_TIME,
	SCEPCFG_PKCSREQ_POLL_COUNT,

	/* GetCert options */
	SCEPCFG_GETCERT_KEY,
	SCEPCFG_GETCERT_CACERT,
	SCEPCFG_GETCERT_CERT_TARGET,

	/* GetCRL */
	SCEPCFG_GETCRL_CERT,
	SCEPCFG_GETCRL_CRL_TARGET,

	/* GetNextCACert */
	SCEPCFG_GETNEXTCACERT_ISSUER,
	SCEPCFG_GETNEXTCACERT_CACERT_TARGET,
} SCEPCFG_TYPE;

typedef enum {
	SCEPE_OK,
	SCEPE_MEMORY,
	SCEPE_INVALID_URL,
	SCEPE_UNKNOWN_CONFIGURATION,
	SCEPE_UNKNOWN_SIGALG,
	SCEPE_UNKNOWN_ENCALG,
} SCEP_ERROR;

struct scep_configuration_getcacert_t {
	char *issuer;
	X509 *ca_cert_target;
};

struct scep_configuration_pkcsreq_t {
	X509_REQ *request;
	EVP_PKEY *request_key;
	X509 *cert_target;
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
	X509 *cert_target;
	X509 *ca_cert;
};

struct scep_configuration_getcrl_t {
	X509 *cert;
	X509_CRL *crl_target;
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
SCEP *scep_init();
void scep_cleanup(SCEP *handle);
SCEP_ERROR scep_conf_set(SCEP *handle, SCEPCFG_TYPE type, ...);
char *scep_strerror(SCEP_ERROR err);

/* Internal functions */
SCEP_ERROR scep_conf_set_url(SCEP *handle, SCEPCFG_TYPE type, char *url_str);
SCEP_ERROR scep_conf_set_getcacert(SCEP *handle, SCEPCFG_TYPE type, va_list arg);
SCEP_ERROR scep_conf_set_pkcsreq(SCEP *handle, SCEPCFG_TYPE type, va_list arg);
SCEP_ERROR scep_conf_set_getcert(SCEP *handle, SCEPCFG_TYPE type, va_list arg);
SCEP_ERROR scep_conf_set_getcrl(SCEP *handle, SCEPCFG_TYPE type, va_list arg);
SCEP_ERROR scep_conf_set_getnextcacert(SCEP *handle, SCEPCFG_TYPE type, va_list arg);

void scep_cleanup_conf(SCEP_CONFIGURATION *conf);
void scep_cleanup_conf_getcacert(struct scep_configuration_getcacert_t *getcacert);
void scep_cleanup_conf_pkcsreq(struct scep_configuration_pkcsreq_t *pkcsreq);
void scep_cleanup_conf_getcert(struct scep_configuration_getcert_t *getcert);
void scep_cleanup_conf_getcrl(struct scep_configuration_getcrl_t *getcrl);

#endif /* SCEP_H_ */
