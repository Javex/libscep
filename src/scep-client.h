
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

    SCEPE_CLIENT_DUMMY_LAST_ERROR,

} SCEP_CLIENT_ERROR;


struct cmd_args_t
{
    SCEP_OPERATION operation;
    UriUriA *url;
    UriUriA *proxy;
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
            /* PKCSReq */
            EVP_PKEY *request_key;
            X509_REQ *request;
            EVP_PKEY *sig_key;
            X509 *sig_cert;
            X509 *enc_cert;
            char *self_signed_target;
            unsigned int poll_interval;
            unsigned int max_poll_time;
            unsigned int max_poll_count;
            int resume;
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
#endif /* SCEP_CLIENT_H_ */