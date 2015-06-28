
#ifndef CONFIGURATION_H_
#define CONFIGURATION_H_

#include "scep-client.h"
#include <openssl/conf.h>

/* On a legacy setup, we use the old configuration file names,
 * otherwise use the new names.
 */

#ifdef SSCEP_LEGACY

#define SECTION_BASE                 "sscep"
#define SECTION_ENGINE_TEMPLATE      "sscep_engine_%s"
#define SECTION_GETCA                "sscep_getca"
#define SECTION_GETNEXTCA            "sscep_getnextca"
#define SECTION_PKCSREQ              "sscep_pkcsreq"
#define SECTION_GETCERT              "sscep_getcert"
#define SECTION_GETCRL               "sscep_getcrl"

#else

#define SECTION_BASE                 "scep"
#define SECTION_ENGINE_TEMPLATE      "scep_engine_%s"
#define SECTION_GETCA                "scep_getca"
#define SECTION_GETNEXTCA            "scep_getnextca"
#define SECTION_PKCSREQ              "scep_enroll"
#define SECTION_GETCERT              "scep_getcert"
#define SECTION_GETCRL               "scep_getcrl"

#endif /* SSCEP_LEGACY */

SCEP_CLIENT_ERROR configuration_set_args(struct cmd_handle_t *cmd_handle);
SCEP_CLIENT_ERROR configuration_load(struct cmd_handle_t *cmd_handle, char *filepath);

#endif /* CONFIGURATION_H_ */