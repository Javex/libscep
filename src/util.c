/* src/util.c */

#include "scep.h"
#include <stdio.h>


SCEP_ERROR scep_urlparse(const char *url_str, SCEP_URL **url)
{
	SCEP_URL *local_url;
	SCEP_ERROR error = SCEPE_OK;
	char *tmp, *url_cpy, *url_cpy2;
	url_cpy = strdup(url_str);
	// keep the original pointer around to call free on it at the end
	url_cpy2 = url_cpy;
	local_url = malloc(sizeof(SCEP_URL));
	memset(local_url, 0, sizeof(SCEP_URL));

	// find the scheme
	tmp = strstr(url_cpy, "://");
	if(tmp)
	{
		*tmp = '\0';
		url_cpy = tmp + 3;
		if(strcmp(url_cpy2, "http") == 0)
			local_url->scheme = HTTP;
		else if(strcmp(url_cpy2, "https") == 0)
			local_url->scheme = HTTPS;
		else {
			error = SCEPE_UNKNOWN_SCHEME;
			goto finally;
		}

	}

	// find everything until the path
	tmp = strchr(url_cpy, '/');
	if(tmp) {
		*tmp = '\0';
		local_url->path = strdup(tmp + 1);
	} else {
		local_url->path = strdup("");
	}
	if(!local_url->path) {
		error = SCEPE_MEMORY;
		goto finally;
	}

	tmp = strchr(url_cpy, ':');
	if(tmp) {
		*tmp = '\0';
		local_url->port = atoi(tmp + 1);
		if(local_url->port < 1 || local_url->port > 65535) {
			error = SCEPE_INVALID_PORT;
			goto finally;
		}
		if(local_url->port == 443)
			local_url->scheme = HTTPS;
		else
			local_url->scheme = HTTP;

	} else {
		if(local_url->scheme == HTTP)
			local_url->port = 80;
		else if(local_url->scheme == HTTPS)
			local_url->port = 443;
		else {
			local_url->port = 80;
			local_url->scheme = HTTP;
		}
	}

	if(!(local_url->hostname = strdup(url_cpy)))
	{
		error = SCEPE_MEMORY;
		goto finally;
	}

	if(strlen(local_url->hostname) == 0)
	{
		error = SCEPE_INVALID_URL;
		goto finally;
	}

	*url = local_url;
finally:
	free(url_cpy2);
	if(error != SCEPE_OK) {
		scep_cleanup_conf_url(local_url);
		*url = NULL;
	}
	return error;
}

SCEP_ERROR scep_queryparse(const char *query_str, StrMap** query)
{
	SCEP_ERROR error = SCEPE_OK;
	char *tmp, *value, *key, *cpy;
	int no_of_params, value_str_len;

	if(strlen(query_str) == 0) {
		*query = NULL;
		return SCEPE_OK;
	}

	cpy = strdup(query_str);
	tmp = cpy;
	for (no_of_params = 1;
			tmp[no_of_params];
			tmp[no_of_params] == '&' ? no_of_params++ : tmp++);
	key = cpy;

	*query = sm_new(no_of_params);
	for(; no_of_params > 0; no_of_params--)
	{
		tmp = strchr(key, '=');
		printf("Currently at: %s/%s\n", key, tmp); fflush(stdout);
		*tmp = '\0';
		tmp = tmp + 1;
		printf("Currently at: %s/%s\n", key, tmp); fflush(stdout);
		value_str_len = tmp - strchr(tmp, '&') + 1;
		value = malloc(value_str_len);
		strncpy(value, tmp, value_str_len - 1);
		value[value_str_len - 1] = '\0';
		printf("Adding...\n"); fflush(stdout);
		printf("Adding Key '%s' and Value '%s'\n", key, value); fflush(stdout);
		sm_put(*query, key, value);
		free(value);

		key = strchr(tmp, '&') + 1;
	}

finally:
	free(cpy);
	if(error != SCEPE_OK)
	{
		scep_cleanup_conf_query(*query);
		*query = NULL;
	}
	return error;
}

char *scep_strerror(SCEP_ERROR err)
{
	switch(err)
	{
		case SCEPE_OK:
			return "No error";
		case SCEPE_MEMORY:
			return "Not enough memory available!";
		case SCEPE_UNKNOWN_SCHEME:
			return "The provided scheme is unknown. Please specify HTTP or "
					"HTTPS";
		case SCEPE_INVALID_PORT:
			return "The specified port is invalid. The allowed port range is "
					"between 1 and 65535";
		case SCEPE_INVALID_URL:
			return "The given URL is invalid.";
		case SCEPE_QUERY_PARSE:
			return "The query can not be parsed.";
	}
	/**
	 * Nifty little trick stolen from libcurl: If an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}


