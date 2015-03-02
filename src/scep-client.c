#include <scep.h>
#include <argp.h>

#define STR(x) #x
#define libscep_VERSION_STR(major, minor) "scep-client v" STR(major) "." STR(minor)
const char *argp_program_version = libscep_VERSION_STR(libscep_VERSION_MAJOR, libscep_VERSION_MINOR);


/* Command-Line Client Structures */

struct cmd_args_t
{
    SCEP_OPERATION operation;

    /* GetCA */
    char *identifier;
    char *target_filename;

    /* PKCSReq */
    EVP_PKEY *request_key;
    X509_REQ *request;
    EVP_PKEY *sig_key;
    X509 *sig_cert;
    X509 *ca_cert;
    char *self_signed_target;
    int poll_interval;
    int max_poll_time;
    int max_poll_count;
    int resume;

    /* GetCert */
    int serial; // TODO: Is int enough!?
    char *target_cert_filename;

    /* GetCRL */
    char *target_crl_filename;

    /* GetCRL & GetCert */
    EVP_PKEY *private_key;
    X509 *local_cert;
};


struct cmd_handle_t
{
    SCEP *handle;
    struct cmd_args_t cmd_args;
};


static char doc[] = "SCEP client -- Command line interface to the client side of the SCEP protocol";

static char args_doc[] = "OPERATION";

static struct argp_option options[] = {
    /* General Options */
    {"url", 'u', "url", 0, "SCEP server URL"},
    {"proxy", 'p', "host:port", 0, "Use proxy server at host:port"},
    {"configuration", 'f', "file", 0, "Use configuration file"},
    {"encryption-algorithm", 'E', "algorithm", 0, "PKCS#7 encryption algorithm (des|3des|blowfish)"},
    {"signature-algorithm", 'S', "algorithm", 0, "PKCS#7 signature algorithm (md5|sha1)"},
    {"verbose", 'v', 0, 0, "Verbose output"},
    {"debug", 'd', 0, 0, "Debug (even more verbose output)"},
    
    /* GetCA Options */
    {"\nOPTIONS for OPERATION getca are:", 0, 0, OPTION_DOC, 0, 1},
    {"identifier", 'i', "string", 0, "CA identifier string", 2},
    {"fingerprint-algorithm", 'F', "name", 0, "Fingerprint algorithm", 2},

    /* PKCSReq Options */
    {"\nOPTIONS for OPERATION enroll are:", 0, 0, OPTION_DOC, 0, 2},
    {"private-key", 'k', "file", 0, "Private key file", 3},
    {"certificate-request", 'r', "file", 0, "Certificate request file", 3},
    {"signature-key", 'K', "file", 0, "Signature private key file, use with -O", 3},
    {"signature-cert", 'O', "file", 0, "Signature certificate (used instead of self-signed)", 3},
    {"ca-cert", 'e', "file", 0, "Use different CA cert for encryption", 3},
    {"self-signed-target", 'L', "file", 0, "Write selfsigned certificate in file", 3},
    {"--poll-interval", 't', "secs", 0, "Polling interval in seconds", 3},
    {"--max-poll-time", 'T', "secs", 0, "Max polling time in seconds", 3},
    {"--max-poll-count", 'n', "count", 0, "Max number of GetCertInitial requests", 3},
    {"--resume", 'R', 0, 0, "Resume interrupted enrollment"},

    /* GetCert Options */
    {"\nOPTIONS for OPERATION getcert are:", 0, 0, OPTION_DOC, 0, 3},
    {"private-key", 'k', "file", 0, "Private key file", 4},
    {"local-cert", 'l', "file", 0, "Local certificate file", 4},
    {"serial", 's', "number", 0, "Certificate serial number", 4},
    {"certificate-out", 'w', "file", 0, "Write certificate in file", 4},

    /* GetCRL Options */
    {"\nOPTIONS for OPERATION getcrl are:", 0, 0, OPTION_DOC, 0, 4},
    {"private-key", 'k', "file", 0, "Private key file", 5},
    {"local-cert", 'l', "file", 0, "Local certificate file", 5},
    {"crl-out", 'w', "file", 0, "Write CRL in file", 5},

    {"\n\n", 0, 0, OPTION_DOC, 0, 5},
    { 0 },
};

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
    struct cmd_handle_t *cmd_handle = state->input;
    SCEP *handle = cmd_handle->handle;
    const EVP_CIPHER *enc_alg = NULL;
    const EVP_MD *sig_alg = NULL;
    SCEP_OPERATION op;
    if(key == ARGP_KEY_ARG) {
        if(state->arg_num > 1)
            argp_failure(state, 1, 0, "only one operation per execution");
        if(strncmp(arg, "getca", 5) == 0)
            op = SCEPOP_GETCACERT;
        else if(strncmp(arg, "enroll", 6) == 0)
            op = SCEPOP_PKCSREQ;
        else if(strncmp(arg, "getcert", 7) == 0)
            op = SCEPOP_GETCERT;
        else if(strncmp(arg, "getcrl", 6) == 0)
            op = SCEPOP_GETCRL;
        else if(strncmp(arg, "getnextca", 9) == 0)
            op = SCEPOP_GETNEXTCACERT;
        else
            return ARGP_ERR_UNKNOWN;
        cmd_handle->cmd_args.operation = op;
        state->next = 1;
    } else if(key == ARGP_KEY_END)
        if(state->arg_num < 1)
            argp_failure(state, 1, 0, "Missing operation");


    if(cmd_handle->cmd_args.operation == SCEPOP_NONE)
        return 0;

    /* Common Options */
    switch(key)
    {
        case 'u':
            scep_conf_set(handle, SCEPCFG_URL, arg);
            break;
        case 'p':
            scep_conf_set(handle, SCEPCFG_PROXY, arg);
            break;
        case 'f':
            return ARGP_ERR_UNKNOWN; // NYI
            break;
        case 'E':
            if(strncmp(arg, "blowfish", 8) == 0)
                enc_alg = EVP_bf_cbc();
            else if(strncmp(arg, "des", 3) == 0)
                enc_alg = EVP_des_cbc();
            else if(strncmp(arg, "3des", 4) == 0)
                enc_alg = EVP_des_ede3_cbc();
            else
                return ARGP_ERR_UNKNOWN;
            scep_conf_set(handle, SCEPCFG_ENCALG, enc_alg);
            break;
        case 'S':
            if(strncmp(arg, "md5", 3) == 0)
                sig_alg = EVP_md5();
            else if(strncmp(arg, "sha1", 4) == 0)
                sig_alg = EVP_sha1();
            else if(strncmp(arg, "sha256", 6) == 0)
                sig_alg = EVP_sha256();
            else if(strncmp(arg, "sha512", 6) == 0)
                sig_alg = EVP_sha512();
            else
                return ARGP_ERR_UNKNOWN;
            scep_conf_set(handle, SCEPCFG_SIGALG, sig_alg);
            break;
        case 'v':
            scep_conf_set(handle, SCEPCFG_VERBOSITY, INFO);
            break;
        case 'd':
            scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
            break;
    }

    /* GetCA Options */
    switch(key)
    {
        case 'i':
            break;
        case 'F':
            break;
    }
    return 0;
}


static struct argp argp = { options, parse_opt, args_doc, doc };


int main(int argc, char *argv[])
{
    struct cmd_handle_t cmd_handle;
    SCEP_ERROR error;
    if((error = scep_init(&cmd_handle.handle)) != SCEPE_OK) {
        fprintf(stderr, "Failed to initialize basic SCEP structure: %s\n", scep_strerror(error));
        exit(1);
    }
    cmd_handle.cmd_args.operation = SCEPOP_NONE;
    argp_parse(&argp, argc, argv, 0, 0, &cmd_handle);
    exit(0);
}