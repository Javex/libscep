#include "configuration.h"

#define handle_unpack(cmd_handle) \
	SCEP *handle = cmd_handle->handle; \
	struct cmd_args_t *cmd_args = &cmd_handle->cmd_args; \
	CONF *conf = cmd_args->configuration; \
	SCEP_CLIENT_ERROR error = SCEPE_CLIENT_OK

static SCEP_CLIENT_ERROR set_getca(struct cmd_handle_t *cmd_handle)
{
	handle_unpack(cmd_handle);
	char *var;

	var = NCONF_get_string(conf, SECTION_GETCA, "CAIdentifier");
	if(var && !cmd_args->getca.identifier)
		cmd_args->getca.identifier = var;

	var = NCONF_get_string(conf, SECTION_GETCA, "FingerPrint");
	if(var && !cmd_args->getca.fp_algorithm) {
		cmd_args->getca.fp_algorithm = load_md_algorithm(handle, var);
		if(!cmd_args->getca.fp_algorithm)
			return SCEPE_CLIENT_CFG_FILE;
	}

	var = NCONF_get_string(conf, SECTION_GETCA, "WriteCACertFile");
	if(var && !cmd_args->cacert_target)
		cmd_args->cacert_target = var;

	return error;
}

static SCEP_CLIENT_ERROR set_pkcsreq(struct cmd_handle_t *cmd_handle)
{
	handle_unpack(cmd_handle);
	char *var;
	long ivar;

	var = NCONF_get_string(conf, SECTION_PKCSREQ, "PrivateKeyFile");
	if(var && !cmd_args->pkcsreq.request_key) {
		error = scep_read_key(handle, &cmd_args->pkcsreq.request_key, var);
		if(error != SCEPE_CLIENT_OK)
			return error;
	}

	var = NCONF_get_string(conf, SECTION_PKCSREQ, "CertReqFile");
	if(var && !cmd_args->pkcsreq.request) {
		error = scep_read_request(handle, &cmd_args->pkcsreq.request, var);
		if(error != SCEPE_CLIENT_OK)
			return error;
	}

	var = NCONF_get_string(conf, SECTION_PKCSREQ, "SignKeyFile");
	if(var && !cmd_args->pkcsreq.sig_key) {
		error = scep_read_key(handle, &cmd_args->pkcsreq.sig_key, var);
		if(error != SCEPE_CLIENT_OK)
			return error;
	}

	var = NCONF_get_string(conf, SECTION_PKCSREQ, "SignerCertificateFile");
	if(var && !cmd_args->pkcsreq.sig_cert) {
		error = scep_read_cert(handle, &cmd_args->pkcsreq.sig_cert, var);
		if(error != SCEPE_CLIENT_OK)
			return error;
	}

	var = NCONF_get_string(conf, SECTION_PKCSREQ, "LocalCertFile");
	if(var && !cmd_args->pkcsreq.cert_target_filename)
		cmd_args->pkcsreq.cert_target_filename = var;

	var = NCONF_get_string(conf, SECTION_PKCSREQ, "EncCertFile");
	if(var && !cmd_args->pkcsreq.enc_cert) {
		error = scep_read_cert(handle, &cmd_args->pkcsreq.enc_cert, var);
		if(error != SCEPE_CLIENT_OK)
			return error;
	}

	var = NCONF_get_string(conf, SECTION_PKCSREQ, "SelfSignedFile");
	if(var && !cmd_args->pkcsreq.self_signed_target)
		cmd_args->pkcsreq.self_signed_target = var;

	if(NCONF_get_number_e(conf, SECTION_PKCSREQ, "PollInterval", &ivar) && !cmd_args->pkcsreq.poll_interval)
		cmd_args->pkcsreq.poll_interval = ivar;

	if(NCONF_get_number_e(conf, SECTION_PKCSREQ, "MaxPollTime", &ivar) && !cmd_args->pkcsreq.max_poll_time)
		cmd_args->pkcsreq.max_poll_time = ivar;

	if(NCONF_get_number_e(conf, SECTION_PKCSREQ, "MaxPollCount", &ivar) && !cmd_args->pkcsreq.max_poll_count)
		cmd_args->pkcsreq.max_poll_count = ivar;

	var = NCONF_get_string(conf, SECTION_PKCSREQ, "Resume");
	if(var && !(cmd_handle->param_flags & SCEP_CLIENT_RESUME))
		if(strncmp(var, "true", 3) == 0)
			cmd_args->operation = SCEPOP_GETCERTINITIAL;
	return error;
}

#ifndef OPENSSL_NO_ENGINE
static SCEP_CLIENT_ERROR set_engine(struct cmd_handle_t *cmd_handle, char *section_name)
{
	return SCEPE_CLIENT_NYI;
}
#endif /* OPENSSL_NO_ENGINE */

SCEP_CLIENT_ERROR configuration_set_args(struct cmd_handle_t *cmd_handle)
{
	handle_unpack(cmd_handle);
	char *var, *var2;
	const EVP_CIPHER *enc_alg;
	const EVP_MD *sig_alg;

	/* Load [scep] section */

	var = NCONF_get_string(conf, SECTION_BASE, "URL");
	if(var && !cmd_args->url) {
		error = scep_conf_set_url(cmd_handle, var, &cmd_args->url);
		if(error != SCEPE_CLIENT_OK)
			return error;
	}

	var = NCONF_get_string(conf, SECTION_BASE, "Proxy");
	if(var && !cmd_args->proxy) {
		error = scep_conf_set_url(cmd_handle, var, &cmd_args->proxy);
		if(error != SCEPE_CLIENT_OK)
			return error;
	}

	if(cmd_args->operation != SCEPOP_GETCACERT)
	{
		var = NCONF_get_string(conf, SECTION_BASE, "CACertFile");
		if(var && !cmd_args->cacert) {
			error = scep_read_cert(handle, &cmd_args->cacert, var);
			if(error != SCEPE_CLIENT_OK)
				return error;
		}
	}

	var = NCONF_get_string(conf, SECTION_BASE, "EncAlgorithm");
	if(var && !(cmd_handle->param_flags & SCEP_CLIENT_ENCALG)) {
		enc_alg = load_enc_algorithm(handle, var);
		if(!enc_alg)
			return SCEPE_CLIENT_CFG_FILE;
		scep_conf_set(handle, SCEPCFG_ENCALG, enc_alg);
	}

	var = NCONF_get_string(conf, SECTION_BASE, "SigAlgorithm");
	if(var && !(cmd_handle->param_flags & SCEP_CLIENT_SIGALG)) {
		sig_alg = load_md_algorithm(handle, var);
		if(!sig_alg)
			return SCEPE_CLIENT_CFG_FILE;
		scep_conf_set(handle, SCEPCFG_SIGALG, enc_alg);
	}

	var = NCONF_get_string(conf, SECTION_BASE, "Verbose");
	var2 = NCONF_get_string(conf, SECTION_BASE, "Debug");
	if((var || var2) && !(cmd_handle->param_flags & SCEP_CLIENT_VERBOSITY)) {
		if(var2)
			scep_conf_set(handle, SCEPCFG_VERBOSITY, DEBUG);
		else
			scep_conf_set(handle, SCEPCFG_VERBOSITY, INFO);
	}


#ifndef OPENSSL_NO_ENGINE
	/* Load engine part */
	var = NCONF_get_string(conf, SECTION_BASE, "engine");
	if(var)
		if((error = set_engine(cmd_handle, var)) != SCEPE_CLIENT_OK)
			return error;
#endif /* OPENSSL_NO_ENGINE */

	/* Load the operation specific part from [scep_getca] and friends */
	switch(cmd_args->operation) {
				case SCEPOP_GETCACERT:
					return set_getca(cmd_handle);
				case SCEPOP_GETNEXTCACERT:
					return SCEPE_CLIENT_NYI;
					break;
				case SCEPOP_PKCSREQ:
				case SCEPOP_GETCERTINITIAL:
					return set_pkcsreq(cmd_handle);
				case SCEPOP_GETCERT:
					return SCEPE_CLIENT_NYI;
					break;
				case SCEPOP_GETCRL:
					return SCEPE_CLIENT_NYI;
					break;
				default:
					return SCEPE_CLIENT_OK;
	}
#undef load_param
}

SCEP_CLIENT_ERROR configuration_load(struct cmd_handle_t *cmd_handle, char *filepath)
{
	SCEP *handle = cmd_handle->handle;
	struct cmd_args_t *cmd_args = &cmd_handle->cmd_args;
	long conf_err = 0;
	CONF *conf;

	conf = NCONF_new(NCONF_default());
	if(!NCONF_load(conf, filepath, &conf_err)) {
		ERR_print_errors(handle->configuration->log);
		scep_log(handle, FATAL, "Error in %s on line %li", filepath, conf_err);
		return SCEPE_CLIENT_CFG_FILE;
	}
	cmd_args->configuration = conf;
	return SCEPE_CLIENT_OK;
}