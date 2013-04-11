/* src/util.c */

#include "scep.h"
#include <stdio.h>
/*
SCEP_ERROR scep_urlparse(const char *url_str, SCEP_URL **url)
{
	UriParserStateA state;
	UriUriA uri;
	SCEP_ERROR error = SCEPE_OK;
	char *tmp, *tmp2;
	int tmp_length, port;
	SCEP_URL *local_url;
	local_url = malloc(sizeof(SCEP_URL));
	memset(local_url, 0, sizeof(SCEP_URL));

	// first parse the URI
	state.uri = &uri;
	if(uriParseUriA(&state, url_str) != URI_SUCCESS)
	{
		error = SCEPE_INVALID_URL;
		goto finally;
	}

	// handle the scheme
	if(uri.scheme.afterLast != NULL && uri.scheme.first != NULL)
	{

		tmp_length = uri.scheme.afterLast - uri.scheme.first + 1;
		if(!(tmp = malloc(tmp_length)))
		{
			error = SCEPE_MEMORY;
			goto finally;
		}
		strncpy(tmp, uri.scheme.first, tmp_length - 1);
		tmp[tmp_length - 1] = '\0';

		if(strcmp(tmp, "http") != 0 && strcmp(tmp, "https") != 0) {
			error = SCEPE_UNKNOWN_SCHEME;
			free(tmp);
			goto finally;
		}
		local_url->scheme = tmp;
		printf("URI scheme: %s\n", local_url->scheme); fflush(stdout);
	}

	// handle the port
	if(uri.portText.afterLast != NULL && uri.portText.first != NULL)
	{
		tmp_length = uri.portText.afterLast - uri.portText.first + 1;
		if(!(tmp = malloc(tmp_length)))
		{
			error = SCEPE_MEMORY;
			goto finally;
		}

		strncpy(tmp, uri.portText.first, tmp_length - 1);
		tmp[tmp_length - 1] = '\0';

		port = atoi(tmp);
		if(port < 1 || port > 65535)
		{
			error = SCEPE_INVALID_PORT;
			free(tmp);
			goto finally;
		}

		local_url->port = tmp;
		printf("URI port: %s\n", local_url->port); fflush(stdout);
	}

	// handle un-set port or scheme:
	if(local_url->port == NULL || local_url->scheme == NULL)
	{
		if(local_url->port != NULL)
		{
			if(strcmp("80", local_url->port) == 0) {
				local_url->scheme = malloc(5);
				strncpy(local_url->scheme, "http", 5);
			} else if(strcmp("443", local_url->port) == 0) {
				local_url->scheme = malloc(6);
				strncpy(local_url->scheme, "https", 6);
			}
		} else if(local_url->scheme != NULL) {
			if(strcmp("http", local_url->scheme) == 0) {
				local_url->port = malloc(3);
				strncpy(local_url->port, "80", 3);
			} else if(strcmp("https", local_url->scheme) == 0) {
				local_url->port = malloc(4);
				strncpy(local_url->port, "443", 4);
			}
		}

		printf("Port & Scheme: %s, %s\n", local_url->port, local_url->scheme);
	}
	// if it is STILL not set, we have a problem
	if(local_url->port == NULL || local_url->scheme == NULL)
	{
		error = SCEPE_QUERY_PARSE;
		goto finally;
	}

	// handle the hostname
	// TODO: handle IPv4/IPv6 addresses
	if(uri.hostText.afterLast == NULL || uri.hostText.first == NULL)
	{
		error = SCEPE_QUERY_PARSE;
		goto finally;
	}

	tmp_length = uri.hostText.afterLast - uri.hostText.first + 1;
	if(!(tmp = malloc(tmp_length)))
	{
		error = SCEPE_MEMORY;
		goto finally;
	}
	strncpy(tmp, uri.hostText.first, tmp_length - 1);
	tmp[tmp_length - 1] = '\0';
	if(strlen(tmp) < 1)
	{
		error = SCEPE_INVALID_URL;
		goto finally;
	}

	local_url->hostname = tmp;
	printf("URI hostname: %s\n", local_url->hostname); fflush(stdout);


	// handle the path
	if(uri.pathHead != NULL &&
		uri.pathHead->text.first != NULL &&
		uri.pathTail->text.afterLast != NULL)
	{
		tmp_length = uri.pathTail->text.afterLast - uri.pathHead->text.first + 1;
		if(!(tmp = malloc(tmp_length)))
		{
			error = SCEPE_MEMORY;
			goto finally;
		}
		strncpy(tmp, uri.pathHead->text.first, tmp_length - 1);
		tmp[tmp_length - 1] = '\0';
		local_url->path = tmp;
	} else {
		local_url->path = malloc(1);
		strncpy(local_url->path, "", 1);
	}
	printf("URI path: %s\n", local_url->path); fflush(stdout);


	*url = local_url;
finally:
	uriFreeUriMembersA(&uri);
	if(error != SCEPE_OK)
	{
		scep_cleanup_conf_url(local_url);
		*url = NULL;
	}
	return error;
}*/

/*SCEP_ERROR scep_urlparse(const char *url_str, SCEP_URL **url)
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
}*/

/*
SCEP_ERROR scep_queryparse(const char *query_str, StrMap** query)
{
	SCEP_ERROR error = SCEPE_OK;
	char *tmp, *value, *key, *cpy, *ampersand_pos;
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
		if(*key == '=')
		{
			error = SCEPE_QUERY_PARSE;
			goto finally;
		}
		tmp = strchr(key, '=');
		if(tmp == NULL)
		{
			error = SCEPE_QUERY_PARSE;
			goto finally;
		}

		printf("Currently at: %s/%s\n", key, tmp); fflush(stdout);
		*tmp = '\0';
		tmp++;
		printf("Currently at: %s/%s\n", key, tmp); fflush(stdout);
		ampersand_pos = strchr(tmp, '&');
		if(ampersand_pos)
			value_str_len = ampersand_pos - tmp + 1;
		else
			value_str_len = strlen(tmp) + 1;

		printf("Length of value_str: %d\n", value_str_len); fflush(stdout);
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
}*/

char *scep_strerror(SCEP_ERROR err)
{
	switch(err)
	{
		case SCEPE_OK:
			return "No error";
		case SCEPE_MEMORY:
			return "Not enough memory available!";
		case SCEPE_INVALID_URL:
			return "The given URL is invalid.";
		case SCEPE_UNKNOWN_CONFIGURATION:
			return "This configuration option is not known.";
		case SCEPE_UNKNOWN_SIGALG:
			return "No signature algorithm found.";
		case SCEPE_UNKNOWN_ENCALG:
			return "No encryption algorithm found.";
	}
	/**
	 * Nifty little trick stolen from libcurl: If an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}


