/* src/scep.h */

#ifndef SCEP_H_
#define SCEP_H_

#include "strmap.h"

typedef enum { HTTP = 1, HTTPS } SCEP_SCHEME;

typedef enum {
	DES,
	TRIPLE_DES,
	BLOWFISH
} SCEP_ENCRYPTION_ALG;

typedef enum { MD5, SHA1 } SCEP_SIGNATURE_ALG;

typedef enum {
	FATAL,
	ERROR,
	WARN,
	INFO,
	DEBUG
} SCEP_VERBOSITY;

typedef enum {
	SCEPCFG_URL,
	SCEPCFG_PROXY,
	SCEPCFG_ENCALG,
	SCEPCFG_SIGALG,
	SCEPCFG_VERBOSITY,
	SCEPCFG_ADDQUERY
} SCEPCFG_TYPE;

typedef enum {
	SCEPE_OK,
	SCEPE_MEMORY,
	SCEPE_UNKNOWN_SCHEME,
	SCEPE_INVALID_PORT,
	SCEPE_INVALID_URL,
	SCEPE_QUERY_PARSE
} SCEP_ERROR;


typedef struct {
	SCEP_SCHEME scheme;
	char *hostname;
	int port;
	char *path;
} SCEP_URL;

typedef struct {
	SCEP_URL *url;
	SCEP_URL *proxy;
	SCEP_ENCRYPTION_ALG encalg;
	SCEP_SIGNATURE_ALG sigalg;
	SCEP_VERBOSITY verbosity;
	StrMap *additional_query;
} SCEP_CONFIGURATION;

typedef struct {
	SCEP_CONFIGURATION *configuration;
} SCEP;

/* External functions */
SCEP *scep_init();
void scep_cleanup(SCEP *handle);
void scep_set_conf(SCEP *handle, SCEPCFG_TYPE type, ...);

/* Internal functions */
void scep_set_conf_url(SCEP *handle, SCEPCFG_TYPE type, SCEP_URL *url);

void scep_cleanup_conf(SCEP_CONFIGURATION *conf);
void scep_cleanup_conf_url(SCEP_URL *url);
void scep_cleanup_conf_query(StrMap *query);
void scep_set_conf_encalg(SCEP *handle, SCEP_ENCRYPTION_ALG encalg);
void scep_set_conf_sigalg(SCEP *handle, SCEP_SIGNATURE_ALG sigalg);
void scep_set_conf_verbosity(SCEP *handle, SCEP_VERBOSITY verbosity);

SCEP_ERROR scep_urlparse(const char *url_str, SCEP_URL **url);
SCEP_ERROR scep_queryparse(const char *query_str, StrMap** query);
char *scep_strerror(SCEP_ERROR err);
#endif /* SCEP_H_ */
