/* src/configuration.c */

#include "scep.h"

static int _engine_count = 0;

SCEP_ERROR scep_conf_init(SCEP *handle)
{
	SCEP_ERROR error;

	if(!(handle->configuration = malloc(sizeof(SCEP_CONFIGURATION))))
		return SCEPE_MEMORY;
	memset(handle->configuration, 0, sizeof(SCEP_CONFIGURATION));

	if((error = scep_conf_set(handle, SCEPCFG_VERBOSITY, DEFAULT_VERBOSITY)) !=
			SCEPE_OK)
		return error;

	if((error = scep_conf_set(handle, SCEPCFG_SIGALG, DEFAULT_SIGALG)) !=
			SCEPE_OK)
		return error;

	if((error = scep_conf_set(handle, SCEPCFG_ENCALG, DEFAULT_ENCALG)) !=
			SCEPE_OK)
		return error;
	return error;
}

static SCEP_ERROR scep_engine_init(SCEP *handle, char *engine_id, char *dyn_engine_id, char *so_path)
{
	ENGINE *e = NULL;
	SCEP_ERROR error = SCEPE_OK;

	ENGINE_load_builtin_engines();
	ENGINE_load_dynamic();

	e = ENGINE_by_id(engine_id);
	if(!e)
		OSSL_ERR("Error loading engine %s", engine_id);

	/* dynamic means we need to add the module */
	if(strncmp(engine_id, "dynamic", 7) == 0) {
		if(!so_path)
			SCEP_ERR(SCEPE_INVALID_PARAMETER, "Need an SO path to load a dynamic engine");
		if(ENGINE_ctrl_cmd_string(e, "SO_PATH", so_path, 0) == 0)
			OSSL_ERR("Error setting SO_PATH for dynamic engine to %s", so_path);
		if(ENGINE_ctrl_cmd_string(e, "ID", dyn_engine_id, 0) == 0)
			OSSL_ERR("Error setting engine ID for dynamic engine to %s", dyn_engine_id);
		if(ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0) == 0)
			OSSL_ERR("Error setting LIST_ADD");
		if(ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0) == 0)
			OSSL_ERR("Error loading engine from SO_PATH %s", so_path);
		scep_log(handle, DEBUG, "Dynamic loading of %s done", dyn_engine_id);
	}

	/* Enumerate all parameters and set the values on the engine */
	struct engine_params_t *param;
	for(param = handle->configuration->params; param != NULL; param = param->next) {
		if(ENGINE_ctrl_cmd_string(e, param->name, param->value, 0) == 0)
			OSSL_ERR("Error setting engine parameter %s to %s", param->name, param->value);
	}

	if(ENGINE_set_default(e, ENGINE_METHOD_ALL) == 0)
		OSSL_ERR("Error making engine default for all operations");

	if(ENGINE_init(e) == 0)
		OSSL_ERR("Error initializing engine");

	scep_log(handle, DEBUG, "Engine %s successfully loaded", engine_id);
	handle->configuration->engine = e;
	handle->configuration->internal_engine = 1;
	_engine_count += 1;
finally:
	if(error != SCEPE_OK && e){
		ENGINE_finish(e);
		ENGINE_free(e);
	}
	return error;
}

static SCEP_ERROR engine_param_set(SCEP *handle, char *name, char *value)
{
	SCEP_ERROR error = SCEPE_OK;
	struct engine_params_t *param = NULL;

	if(handle->configuration->engine)
		SCEP_ERR(SCEPE_UNKNOWN_CONFIGURATION, "An engine has already been configured");

	param = calloc(1, sizeof(struct engine_params_t));
	if(!param)
		SCEP_ERR(SCEPE_MEMORY, "Error creating param structure");

	param->name = strdup(name);
	if(!param->name)
		SCEP_ERR(SCEPE_MEMORY, "Error setting param name");

	param->value = strdup(value);
	if(!param->name)
		SCEP_ERR(SCEPE_MEMORY, "Error setting param value");

	param->next = handle->configuration->params;
	handle->configuration->params = param;
finally:
	if(error != SCEPE_OK) {
		if(param)
			free(param);
	}
	return error;
}

SCEP_ERROR scep_conf_set(SCEP *handle, SCEPCFG_TYPE type, ...)
{
	va_list arg;
	SCEP_ERROR error = SCEPE_OK;

	va_start(arg, type);
	switch(type)
	{
		case SCEPCFG_VERBOSITY:
			handle->configuration->verbosity = va_arg(arg, SCEP_VERBOSITY);
			break;
		case SCEPCFG_SIGALG:
			handle->configuration->sigalg = va_arg(arg, EVP_MD *);
			break;
		case SCEPCFG_ENCALG:
			handle->configuration->encalg = va_arg(arg, EVP_CIPHER *);
			break;
		case SCEPCFG_LOG:
			if(handle->configuration->log)
			{
				scep_log(handle,
						ERROR,
						"Overwriting the BIO log is not allowed and also not "
						"recommended. BIOs can be modified in-place and "
						"should never need to be swapped");
				error = SCEPE_DUPLICATE_BIO;
				break;
			}
			handle->configuration->log = va_arg(arg, BIO *);
			break;
		case SCEPCFG_ENGINE: ;
			char *engine_id = va_arg(arg, char *);
			char *so_path = NULL;
			char *dyn_engine_id = NULL;
			if(strncmp(engine_id, "dynamic", 7) == 0) {
				dyn_engine_id = va_arg(arg, char *);
				so_path = va_arg(arg, char *);
			}
			error = scep_engine_init(handle, engine_id, dyn_engine_id, so_path);
			break;
		case SCEPCFG_ENGINE_PARAM: ;
			char *param_name = va_arg(arg, char *);
			char *param_value = va_arg(arg, char *);
			error = engine_param_set(handle, param_name, param_value);
			break;
		case SCEPCFG_ENGINE_OBJ:
			handle->configuration->engine = va_arg(arg, ENGINE *);
			handle->configuration->internal_engine = 0;
			_engine_count += 1;
			break;
		case SCEPCFG_FLAG_CLEAR:
			handle->configuration->flags = 0;
			break;
		case SCEPCFG_FLAG_SET:
			handle->configuration->flags |= va_arg(arg, SCEP_FLAGS);
			break;
		default:
			error = SCEPE_UNKNOWN_CONFIGURATION;
			break;
	}
	va_end(arg);
	return error;
}

void scep_conf_free(SCEP_CONFIGURATION *conf)
{
	if(conf->engine) {
		if(conf->internal_engine) {
			struct engine_params_t *param = conf->params;
			for(param = conf->params; param != NULL; param = param->next) {
				free(param->name);
				free(param->value);
				free(param);
			}
			ENGINE_finish(conf->engine);
			ENGINE_free(conf->engine);
			if(_engine_count == 1)
				ENGINE_cleanup();
		}
		/* Decrement count for any engine, we also count the externals */
		_engine_count -= 1;
	}
	free(conf);
}

SCEP_ERROR scep_conf_sanity_check(SCEP *handle)
{
	return SCEPE_OK;
}

SCEP_ERROR scep_engine_get(SCEP *handle, ENGINE **e)
{
	if(!handle || !handle->configuration) {
		scep_log(handle, ERROR, "libscep not yet initialized and/or configured");
		return SCEPE_UNKNOWN_CONFIGURATION;
	}

	if(!handle->configuration->engine) {
		scep_log(handle, ERROR, "No engine has been configured, yet");
		return SCEPE_UNKNOWN_CONFIGURATION;
	}
	*e = handle->configuration->engine;
	return SCEPE_OK;
}
