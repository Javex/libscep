/* src/util.c */

#include "scep.h"
#include <stdio.h>


int scep_urlparse(char *url_str, SCEP_URL **url)
{
	SCEP_URL *local_url;
	char *tmp, *url_cpy, *url_cpy2;
	url_cpy = strdup(url_str);
	url_cpy2 = url_cpy;
	local_url = *url;
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
		else {/* TODO: throw error */}

	}

	// find everything until the path
	tmp = strchr(url_cpy, '/');
	if(tmp) {
		printf("Found a path in URL.\n"); fflush(stdout);
		*tmp = '\0';
		local_url->path = strdup(tmp + 1);
	} else {
		local_url->path = strdup("");
	}
	if(!local_url->path)
		return SCEPE_MEMORY;

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
	local_url->hostname = strdup(url_cpy);
	free(url_cpy2);
	return SCEPE_OK;
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
	}
	/**
	 * Nifty little trick stolen from libcurl: If there an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}


