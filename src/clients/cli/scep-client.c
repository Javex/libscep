#include "scep-client.h"
#include <argp.h>

const char *argp_program_version = libscep_VERSION_STR(libscep_VERSION_MAJOR, libscep_VERSION_MINOR);

static char doc[] = "SCEP client -- Command line interface to the client side of the SCEP protocol";

static char args_doc[] = "OPERATION";

static struct argp_option options[] = {
	/* General Options */
	{"url", 'u', "url", 0, "SCEP server URL"},
	{"proxy", 'p', "host:port", 0, "Use proxy server at host:port"},
	{"configuration", 'f', "file", 0, "Use configuration file"},
	{"ca-cert", 'c', "file", 0, "CA certificate file (write if OPERATION is getca or getnextca)"},
	{"encryption-algorithm", 'E', "algorithm", 0, "PKCS#7 encryption algorithm (des|3des|blowfish)"},
	{"signature-algorithm", 'S', "algorithm", 0, "PKCS#7 signature algorithm (md5|sha1|sha256|sha512)"},
	{"verbose", 'v', 0, 0, "Verbose output"},
	{"debug", 'd', 0, 0, "Debug (even more verbose output)"},
	
	/* GetCACert Options */
	{"\nOPTIONS for OPERATION getca are:", 0, 0, OPTION_DOC, 0, 1},
	{"identifier", 'i', "string", 0, "CA identifier string", 2},
	{"fingerprint-algorithm", 'F', "name", 0, "Fingerprint algorithm (md5|sha1|sha256|sha512", 2},

	/* GetNextCACert */
	{"\nOPTIONS for OPERATION getnextca are:", 0, 0, OPTION_DOC, 0, 2},
	{"cert-chain", 'C', "file", 0, "Local certificate chain file for signature verification in PEM format", 3},
	{"fingerprint-algorithm", 'F', "name", 0, "Fingerprint algorithm (md5|sha1|sha256|sha512", 3},
	{"signer-cert", 'w', "file", 0, "Write signer certificate in file (optional)", 3},

	/* PKCSReq Options */
	{"\nOPTIONS for OPERATION enroll are:", 0, 0, OPTION_DOC, 0, 3},
	{"private-key", 'k', "file", 0, "Private key file", 4},
	{"certificate-request", 'r', "file", 0, "Certificate request file", 4},
	{"signature-key", 'K', "file", 0, "Signature private key file, use with -O", 4},
	{"signature-cert", 'O', "file", 0, "Signature certificate (used instead of self-signed)", 4},
	{"cert-target", 'l', "file", 0, "Write enrolled certificate in file", 4},
	{"encryption-cert", 'e', "file", 0, "Use different CA cert for encryption", 4},
	{"self-signed-target", 'L', "file", 0, "Write selfsigned certificate in file", 4},
	{"poll-interval", 't', "secs", 0, "Polling interval in seconds", 4},
	{"max-poll-time", 'T', "secs", 0, "Max polling time in seconds", 4},
	{"max-poll-count", 'n', "count", 0, "Max number of GetCertInitial requests", 4},
	{"resume", 'R', 0, 0, "Resume interrupted enrollment"},

	/* GetCert Options */
	{"\nOPTIONS for OPERATION getcert are:", 0, 0, OPTION_DOC, 0, 4},
	{"private-key", 'k', "file", 0, "Private key file", 5},
	{"local-cert", 'l', "file", 0, "Local certificate file", 5},
	{"serial", 's', "number", 0, "Certificate serial number", 5},
	{"certificate-out", 'w', "file", 0, "Write certificate in file", 5},

	/* GetCRL Options */
	{"\nOPTIONS for OPERATION getcrl are:", 0, 0, OPTION_DOC, 0, 5},
	{"private-key", 'k', "file", 0, "Private key file", 6},
	{"local-cert", 'l', "file", 0, "Local certificate file", 6},
	{"crl-out", 'w', "file", 0, "Write CRL in file", 6},

	{"\n\n", 0, 0, OPTION_DOC, 0, 7},
	{ 0 },
};

static void verify_arguments(struct argp_state *state)
{
	struct cmd_handle_t *cmd_handle = state->input;
	struct cmd_args_t *cmd_args = &cmd_handle->cmd_args;

#define FAIL(msg, ...) argp_failure(state, 1, 0, msg, ##__VA_ARGS__)

	// general argument check
	if(!cmd_args->url)
		FAIL("SCEP server URL required");
	if(cmd_args->operation == SCEPOP_GETCACERT) {
			if(!cmd_args->cacert_target)
				FAIL("Target filename for CA cert missing");
	} else {
		if(!cmd_args->cacert)
			FAIL("Missing CA certificate");
	}

	// operation specific checks
	switch(cmd_args->operation)
	{
		case SCEPOP_GETCACERT:
			break;  // no required arguments
		case SCEPOP_GETCERTINITIAL:
		case SCEPOP_PKCSREQ:
			if(!cmd_args->pkcsreq.request_key)
				FAIL("Key of CSR missing");
			if(!cmd_args->pkcsreq.request)
				FAIL("CSR missing");
			if(!cmd_args->pkcsreq.cert_target_filename)
				FAIL("Certificate output filename missing");
			if((!cmd_args->pkcsreq.sig_key && cmd_args->pkcsreq.sig_cert) ||
					(!cmd_args->pkcsreq.sig_key && cmd_args->pkcsreq.sig_cert))
				FAIL("Signature key and certificate always required together");
			break;
		case SCEPOP_GETCERT:
			if(!cmd_args->getcert.private_key)
				FAIL("Missing private key");
			if(!cmd_args->getcert.local_cert)
				FAIL("Missing issuer CA cert");
			if(!cmd_args->getcert.serial)
				FAIL("Missing serial for certificate");
			if(!cmd_args->getcert.target_cert_filename)
				FAIL("Missing target filepath for requested certificate");
			break;
		case SCEPOP_GETCRL:
			if(!cmd_args->getcrl.private_key)
				FAIL("Missing private key");
			if(!cmd_args->getcrl.local_cert)
				FAIL("Missing CA cert");
			if(!cmd_args->getcrl.target_crl_filename)
				FAIL("Missing target filepath for requested CRL");
			break;
		case SCEPOP_GETNEXTCACERT:
			if(!cmd_args->getnextca.ca_chain)
				FAIL("Missing CA chain");
			break;
		case SCEPOP_NONE:
		default:
			exit(1);
	}
#undef FAIL
}

static error_t
parse_opt(int key, char *arg, struct argp_state *state)
{
	struct cmd_handle_t *cmd_handle = state->input;
	SCEP *handle = cmd_handle->handle;
	struct cmd_args_t *cmd_args = &cmd_handle->cmd_args;
	const EVP_CIPHER *enc_alg = NULL;
	const EVP_MD *sig_alg = NULL;
	SCEP_OPERATION op;
	SCEP_CLIENT_ERROR error;
	SCEP_ERROR lib_error;
	if(key == ARGP_KEY_ARG) {
		if(cmd_args->operation != SCEPOP_NONE)
			return 0;
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
		cmd_args->operation = op;
		state->next = 1;
		return 0;
	} else if(key == ARGP_KEY_END) {
		if(state->arg_num < 1)
			argp_failure(state, 1, 0, "Missing operation");
		verify_arguments(state);
		if(cmd_args->operation == SCEPOP_PKCSREQ || cmd_args->operation == SCEPOP_GETCERTINITIAL) {
			if(!cmd_args->pkcsreq.enc_cert)
				cmd_args->pkcsreq.enc_cert = cmd_args->cacert;
			if(!cmd_args->pkcsreq.sig_key)
				cmd_args->pkcsreq.sig_key = cmd_args->pkcsreq.request_key;
			if(!cmd_args->pkcsreq.sig_cert)
				if((lib_error = scep_new_selfsigned_X509(
						handle,
						cmd_args->pkcsreq.request,
						cmd_args->pkcsreq.request_key,
						&cmd_args->pkcsreq.sig_cert)) != SCEPE_OK) {
					fprintf(stderr, "Error generating selfsinged certificate: %s\n", scep_strerror(lib_error));
					exit(1);
				}
		}
	}

	if(cmd_args->operation == SCEPOP_NONE)
		return 0;

	/* Common Options */
	switch(key)
	{
		case 'u':
			if((error = scep_conf_set_url(cmd_handle, arg, &cmd_args->url)) != SCEPE_CLIENT_OK)
				argp_failure(state, 1, 0, "Setting URL failed: %s", scep_client_strerror(error));
			break;
		case 'p':
			if((error = scep_conf_set_url(cmd_handle, arg, &cmd_args->proxy)) != SCEPE_CLIENT_OK)
				argp_failure(state, 1, 0, "Setting Proxy failed: %s", scep_client_strerror(error));
			break;
		case 'f':
			argp_failure(state, 1, 0, "Configuration File not supported, yet");
			break;
		case 'c':
			if(cmd_args->operation == SCEPOP_GETCACERT) {
				cmd_args->cacert_target = malloc(strlen(arg) + 1);
				strncpy(cmd_args->cacert_target, arg, strlen(arg) + 1);
			} else {
				if((error = scep_read_cert(handle, &cmd_args->cacert, arg)) != SCEPE_CLIENT_OK)
					argp_failure(state, 1, 0, "Failed to load CA certificate: %s", scep_client_strerror(error));
			}
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
		default:
			switch(cmd_args->operation)
			{
				case SCEPOP_GETCACERT:
					/* GetCA Options */
					switch(key)
					{
						case 'i':
							cmd_args->getca.identifier = malloc(strlen(arg) + 1);
							strncpy(cmd_args->getca.identifier, arg, strlen(arg) + 1);
							break;
						case 'F':
							if(strncmp(arg, "md5", 3) == 0)
								sig_alg = EVP_md5();
							else if(strncmp(arg, "sha1", 4) == 0)
								sig_alg = EVP_sha1();
							else if(strncmp(arg, "sha256", 6) == 0)
								sig_alg = EVP_sha256();
							else if(strncmp(arg, "sha512", 6) == 0)
								sig_alg = EVP_sha512();
							else
								argp_failure(state, 1, 0, "Invalid fingerprint signature algorithm: %s\n", arg);
							cmd_args->getca.fp_algorithm = sig_alg;
							break;
					}
					break;
				case SCEPOP_GETNEXTCACERT:
					break;
				case SCEPOP_PKCSREQ:
				case SCEPOP_GETCERTINITIAL:
					/* PKCSReq Options */
					switch(key)
					{
						case 'k':
							if((error = scep_read_key(handle, &cmd_args->pkcsreq.request_key, arg)) != SCEPE_CLIENT_OK)
								argp_failure(state, 1, 0, "Failed to load request key: %s", scep_client_strerror(error));
							break;
						case 'r':
							if((error = scep_read_request(handle, &cmd_args->pkcsreq.request, arg)) != SCEPE_CLIENT_OK)
								argp_failure(state, 1, 0, "Failed to load request: %s", scep_client_strerror(error));
							break;
						case 'K':
							if((error = scep_read_key(handle, &cmd_args->pkcsreq.sig_key, arg)) != SCEPE_CLIENT_OK)
								argp_failure(state, 1, 0, "Failed to load signature key: %s", scep_client_strerror(error));
							break;
						case 'O':
							if((error = scep_read_cert(handle, &cmd_args->pkcsreq.sig_cert, arg)) != SCEPE_CLIENT_OK)
								argp_failure(state, 1, 0, "Failed to load signature certificate: %s", scep_client_strerror(error));
							break;
						case 'l':
							cmd_args->pkcsreq.cert_target_filename = malloc(strlen(arg) + 1);
							strncpy(cmd_args->pkcsreq.cert_target_filename, arg, strlen(arg) + 1);
							break;
						case 'e':
							if((error = scep_read_cert(handle, &cmd_args->pkcsreq.enc_cert, arg)) != SCEPE_CLIENT_OK)
								argp_failure(state, 1, 0, "Failed to load encryption certificate: %s", scep_client_strerror(error));
							break;
						case 'L':
							cmd_args->pkcsreq.self_signed_target = malloc(strlen(arg) + 1);
							strncpy(cmd_args->pkcsreq.self_signed_target, arg, strlen(arg) + 1);
							break;
						case 't':
							cmd_args->pkcsreq.poll_interval = strtoul(arg, NULL, 10);
							break;
						case 'T':
							cmd_args->pkcsreq.max_poll_time = strtoul(arg, NULL, 10);
							break;
						case 'n':
							cmd_args->pkcsreq.max_poll_count = strtoul(arg, NULL, 10);
							break;
						case 'R':
							cmd_args->operation = SCEPOP_GETCERTINITIAL;
							break;
					}
					break;
				case SCEPOP_GETCERT:
					break;
				case SCEPOP_GETCRL:
					break;
				default:
					return ARGP_ERR_UNKNOWN;
			}
			break;
	}
	return 0;
}


static struct argp argp = { options, parse_opt, args_doc, doc };


int main(int argc, char *argv[])
{
	struct cmd_handle_t cmd_handle;
	struct cmd_args_t *cmd_args = &cmd_handle.cmd_args;
	SCEP_ERROR error;
	PKCS7 *request = NULL, *response = NULL;
	char *message = NULL;
	SCEP_REPLY *reply = NULL;
	SCEP_DATA *output = NULL;
	FILE *cert_target = NULL;
	memset(&cmd_handle, 0, sizeof(cmd_handle));
	if((error = scep_init(&cmd_handle.handle)) != SCEPE_OK) {
		fprintf(stderr, "Failed to initialize basic SCEP structure: %s\n", scep_strerror(error));
		exit(1);
	}

	if((error = scep_conf_set(cmd_handle.handle, SCEPCFG_LOG, BIO_new_fp(stdout, 0))) != SCEPE_OK) {
		fprintf(stderr, "Failed to set log BIO: %s\n", scep_strerror(error));
		exit(1);
	}

	cmd_args->operation = SCEPOP_NONE;
	argp_parse(&argp, argc, argv, 0, 0, &cmd_handle);

	switch(cmd_args->operation)
	{
		case SCEPOP_GETCACERT:
			break;
		case SCEPOP_PKCSREQ:
			if((error = scep_pkcsreq(
					cmd_handle.handle,
					cmd_args->pkcsreq.request,
					cmd_args->pkcsreq.sig_cert,
					cmd_args->pkcsreq.sig_key,
					cmd_args->pkcsreq.enc_cert,
					cmd_handle.handle->configuration->encalg,
					&request
					)) != SCEPE_OK)
				exit(1);
			if((error = scep_PKCS7_base64_encode(
					cmd_handle.handle,
					request, &message)) != SCEPE_OK)
				exit(1);

			// send request
			if((error = scep_send_request(&cmd_handle, "PKIOperation", message, &reply)) != SCEPE_OK)
				exit(1);
			fprintf(stderr, "Payload Response: %s\n", reply->payload);

			// parse response
			BIO *reply_bio = BIO_new(BIO_s_mem());
			if(!reply_bio)
				exit(1);
			BIO_write(reply_bio, reply->payload, reply->length);
			if(!(response = d2i_PKCS7_bio(reply_bio, NULL))) {
				ERR_print_errors(cmd_handle.handle->configuration->log);
				scep_log(cmd_handle.handle, FATAL, "Unable to convert response to PKCS#7");
				exit(1);
			}
			if(!(output = malloc(sizeof(SCEP_DATA))))
				exit(1);
			memset(output, 0, sizeof(SCEP_DATA));

			if((error = scep_unwrap_response(
					cmd_handle.handle,
					response,
					cmd_args->cacert,
					cmd_args->pkcsreq.sig_cert,
					cmd_args->pkcsreq.sig_key,
					SCEPOP_PKCSREQ,
					&output)) != SCEPE_OK)
				exit(1);

			cert_target = fopen(cmd_args->pkcsreq.cert_target_filename, "w");
			if(!cert_target) {
				scep_log(cmd_handle.handle, FATAL, "Unable to open certificate target file for writing: %s", strerror(errno));
				exit(1);
			}

			if(sk_X509_num(output->certs) < 1) {
				scep_log(cmd_handle.handle, FATAL, "No certificates in response...");
				exit(1);
			}

			X509 *new_cert = sk_X509_value(output->certs, 0);
			if(!new_cert)
				exit(1);

			BIO *cert_bio = BIO_new(BIO_s_mem());
			if(!cert_bio)
				exit(1);

			if(!i2d_X509_bio(cert_bio, new_cert)) {
				ERR_print_errors(cmd_handle.handle->configuration->log);
				scep_log(cmd_handle.handle, FATAL, "Unable to read in certificate to BIO");
				exit(1);
			}

			if((error = scep_bio_PEM_fp(cmd_handle.handle, cert_bio, cert_target)) != SCEPE_OK) {
				fclose(cert_target);
				exit(1);
			}
			scep_log(cmd_handle.handle, INFO, "New certificate written to %s", cmd_args->pkcsreq.cert_target_filename);
			break;
		case SCEPOP_GETCERT:
			break;
		case SCEPOP_GETCRL:
			break;
		case SCEPOP_GETNEXTCACERT:
			break;
		case SCEPOP_GETCERTINITIAL:
			break;
		case SCEPOP_NONE:
			scep_log(cmd_handle.handle, FATAL, "Missing Operation");
			exit(1);
	}

	scep_cleanup(cmd_handle.handle);
	exit(0);
}