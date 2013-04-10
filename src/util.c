/* src/util.c */

#include "scep.h"
#include <stdio.h>


SCEP_ERROR scep_urlparse(char *url_str, SCEP_URL **url)
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
	} else {
		if(local_url->scheme == HTTP)
			local_url->port = 80;
		else if(local_url->scheme == HTTPS)
			local_url->port = 443;
	}
	if(!(local_url->hostname = strdup(url_cpy)))
	{
		error = SCEPE_MEMORY;
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

StrMap *scep_queryparse(char *query_str)
{

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
			return "The provided scheme was unknown. Please specify HTTP or HTTPS";
	}
	/**
	 * Nifty little trick stolen from libcurl: If an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}


