#ifndef SCEP_H_
#define SCEP_H_

#include "strmap.h"

typedef enum { HTTP, HTTPS } SCEP_SCHEME;

typedef enum {
	DES,
	TRIPLE_DES,
	BLOWFISH
} SCEP_ENCRYPTION_ALG;

typedef enum { MD5, SHA1 } SCEP_SIGNATURE_ALG;

typedef enum { false, true } bool;

typedef enum {
	SCEPCFG_URL,
	SCEPCFG_PROXY,
	SCEPCFG_ENCALG,
	SCEPCFG_SIGALG,
	SCEPCFG_VERBOSE,
	SCEPCFG_DEBUG,
	SCEPCFG_ADDQUERY
} SCEPCFG_TYPE;

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
	bool verbose;
	bool debug;
	StrMap *additional_query;
} SCEP_CONFIGURATION;

typedef struct {
	SCEP_CONFIGURATION *configuration;
} SCEP;

/* External functions */
SCEP *scep_init();
void scep_cleanup(SCEP *handle);
void scep_set_conf(SCEP *handle, SCEPCFG_TYPE type, void *cfg_value);

/* Internal functions */
void scep_set_conf_url(SCEP *handle, SCEPCFG_TYPE type, SCEP_URL *url);

void scep_cleanup_conf(SCEP_CONFIGURATION *conf);
void scep_cleanup_conf_url(SCEP_URL *url);
#endif /* SCEP_H_ */
