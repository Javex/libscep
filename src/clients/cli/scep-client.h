
#ifndef SCEP_CLIENT_H_
#define SCEP_CLIENT_H_

#include <scep.h>
#include <uriparser/Uri.h>
#include <curl/curl.h>

/* Command-Line Client Structures */

typedef enum {
    SCEPE_CLIENT_OK,
    SCEPE_CLIENT_MEMORY,
    SCEPE_CLIENT_OPENSSL,
    SCEPE_CLIENT_INVALID_URL,
    SCEPE_CLIENT_QUERY_OP,
    SCEPE_CLIENT_QUERY_PARSE,
    SCEPE_CLIENT_CURL,
    SCEPE_CLIENT_INVALID_RESPONSE,
    SCEPE_CLIENT_FILE_DOES_NOT_EXIST,
    SCEPE_CLIENT_FILE,
    SCEPE_CLIENT_CFG_FILE,
    SCEPE_CLIENT_NYI,

    SCEPE_CLIENT_DUMMY_LAST_ERROR,

} SCEP_CLIENT_ERROR;

/* Flags to describe parameters that were set by the command line.
 * These flags are only required for those values where we have a
 * default value in the library and need to check whether our
 * configuration file should overwrite this or if it was already
 * overwritten by the command line (which is preferred over the
 * configuration file).
 */
typedef enum {
    SCEP_CLIENT_ENCALG    = 0x0001,
    SCEP_CLIENT_SIGALG    = 0x0002,
    SCEP_CLIENT_VERBOSITY = 0x0004,
    SCEP_CLIENT_RESUME    = 0x0008,
} SCEP_CLIENT_PARAM_FLAGS;


struct cmd_args_t
{
    SCEP_OPERATION operation;
    UriUriA *url;
    UriUriA *proxy;
    CONF *configuration;
    union {
        X509 *cacert;
        char *cacert_target;
    };
    union {
        struct {
            /* GetCA */
            char *identifier;
            const EVP_MD *fp_algorithm;
        } getca;

        struct {
            /* GetNextCA */
            X509_STORE *ca_chain;
            const EVP_MD *fp_algorithm;
            char *taget_signer_cert_filename;
        } getnextca;

        struct {
            /* PKCSReq */
            EVP_PKEY *request_key;
            X509_REQ *request;
            EVP_PKEY *sig_key;
            X509 *sig_cert;
            X509 *enc_cert;
            char *cert_target_filename;
            char *self_signed_target;
            unsigned int poll_interval;
            unsigned int max_poll_time;
            unsigned int max_poll_count;
        } pkcsreq;

        struct {
            /* GetCert */
            EVP_PKEY *private_key;
            X509 *local_cert;
            ASN1_INTEGER *serial;
            char *target_cert_filename;
        } getcert;

        struct {
            /* GetCRL */
            EVP_PKEY *private_key;
            X509 *local_cert;
            char *target_crl_filename;
        } getcrl;
    };
};

struct cmd_handle_t
{
    SCEP *handle;
    struct cmd_args_t cmd_args;
    SCEP_CLIENT_PARAM_FLAGS param_flags;
};

typedef struct {
    char *payload;
    int length;
    long status;
    char *content_type;
} SCEP_REPLY;

size_t scep_recieve_data(void *buffer, size_t size, size_t nmemb, void *userp);
SCEP_CLIENT_ERROR scep_send_request(struct cmd_handle_t *cmd_handle, char *operation, char *message,
        SCEP_REPLY **reply);
char *scep_client_strerror(SCEP_CLIENT_ERROR err);
SCEP_CLIENT_ERROR scep_conf_set_url(struct cmd_handle_t *cmd_handle, char *url_str, UriUriA **target);
SCEP_CLIENT_ERROR scep_read_key(SCEP *handle, EVP_PKEY** key, char* filename);
SCEP_CLIENT_ERROR scep_read_cert(SCEP *handle, X509 **cert, char *filename);
SCEP_CLIENT_ERROR scep_read_request(SCEP *handle, X509_REQ **req, char *filename);
SCEP_CLIENT_ERROR scep_bio_PEM_fp(SCEP *handle, BIO *data, FILE *out);
void scep_write_certinfo(struct cmd_handle_t cmd_handle, X509 *cert);
const EVP_MD *load_md_algorithm(SCEP *handle, char *md_name);
const EVP_CIPHER *load_enc_algorithm(SCEP *handle, char *cipher_name);
#endif /* SCEP_CLIENT_H_ */