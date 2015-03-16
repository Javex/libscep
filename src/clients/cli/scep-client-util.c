#include "scep-client.h"

size_t scep_recieve_data(void *buffer, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	SCEP_REPLY *reply = (SCEP_REPLY *)userp;

	reply->payload= realloc(reply->payload, reply->length + realsize + 1);
	if(reply->payload == NULL) {
		printf("Not enough memory for HTTP data. Aborting\n");
		return 0;
	}

	memcpy(&(reply->payload[reply->length]), buffer, realsize);
	reply->length += realsize;
	reply->payload[reply->length] = 0;
	return realsize;
}

SCEP_CLIENT_ERROR scep_send_request(
		struct cmd_handle_t *cmd_handle, char *operation, char *message,
		SCEP_REPLY **reply)
{
	SCEP *handle = cmd_handle->handle;
	struct cmd_args_t cmd_args = cmd_handle->cmd_args;
	SCEP_CLIENT_ERROR error = SCEPE_CLIENT_OK;
	char *full_url = NULL, *tmp_str = NULL;
	int url_length, query_items_count, tmp_str_len, chars_required = 0,
		chars_written;
	UriQueryListA *query_list = NULL, *query_list_start = NULL;
	CURL *curl_handle = NULL;
	SCEP_REPLY *local_reply = NULL;
	CURLcode curl_error;

	// first get everything UNTIL the query
	url_length = cmd_args.url->pathTail->text.afterLast -
			cmd_args.url->scheme.first + 1; // + 1 for '?'
	full_url = malloc(url_length); // already includes space for '\0'!
	if(!full_url)
		return SCEPE_CLIENT_MEMORY;
	strncpy(full_url, cmd_args.url->scheme.first, url_length);

	// replace '\0' from strncpy with '?' for query
	full_url[url_length - 1] = '?';

	if(cmd_args.url->query.first)
	{

		// now build the query list, i.e. all items that were part of the query
		if(uriDissectQueryMallocA(&query_list, &query_items_count,
				cmd_args.url->query.first,
				cmd_args.url->query.afterLast) != URI_SUCCESS)
		{
			error = SCEPE_CLIENT_MEMORY;
			goto finally;
		}
		query_list_start = query_list;

		// find the last element of the linked list
		do
		{
			if(strncmp(query_list->key, "operation", 9) == 0)
			{
				error = SCEPE_CLIENT_QUERY_OP;
				goto finally;
			}
			if(query_list->next == NULL)
				break;
			query_list = query_list->next;
		} while(1);

		// allocate memory for another element (our operation)
		if(!(query_list->next = malloc(sizeof(UriQueryListA))))
		{
			error = SCEPE_CLIENT_MEMORY;
			goto finally;
		}
		memset(query_list->next, 0, sizeof(UriQueryListA));
		// set this new object as the current working object
		query_list = query_list->next;
	} else {
		if(!(query_list = malloc(sizeof(UriQueryListA))))
		{
			error = SCEPE_CLIENT_MEMORY;
			goto finally;
		}
		memset(query_list, 0, sizeof(UriQueryListA));
		query_list_start = query_list;
	}

	// set key & value for operation
	if(!(tmp_str = malloc(10))) // strlen("operation") + 1
	{
		error = SCEPE_CLIENT_MEMORY;
		goto finally;
	}
	strncpy(tmp_str, "operation", 10);
	query_list->key = tmp_str;

	tmp_str_len = strlen(operation) + 1;
	if(!(tmp_str = malloc(tmp_str_len)))
	{
		error = SCEPE_CLIENT_MEMORY;
		goto finally;
	}
	strncpy(tmp_str, operation, tmp_str_len);
	query_list->value = tmp_str;
	scep_log(handle, INFO, "Set operation to %s", operation);

	if(message)
	{
		// allocate memory for another element (the message)
		if(!(query_list->next = malloc(sizeof(UriQueryListA))))
		{
			error = SCEPE_CLIENT_MEMORY;
			goto finally;
		}
		memset(query_list->next, 0, sizeof(UriQueryListA));
		// set this new object as the current working object
		query_list = query_list->next;

		// set key & value for message
		if(!(tmp_str = malloc(8))) // strlen("message") + 1
		{
			error = SCEPE_CLIENT_MEMORY;
			goto finally;
		}
		strncpy(tmp_str, "message", 8);
		query_list->key = tmp_str;

		tmp_str_len = strlen(message) + 1;
		if(!(tmp_str = malloc(tmp_str_len)))
		{
			error = SCEPE_CLIENT_MEMORY;
			goto finally;
		}
		strncpy(tmp_str, message, tmp_str_len);
		query_list->value = tmp_str;
		scep_log(handle, DEBUG, "Set message to %s", message);
	}

	// get length of query string
	if(uriComposeQueryCharsRequiredA(query_list_start, &chars_required) !=
			URI_SUCCESS)
	{
		error = SCEPE_CLIENT_QUERY_PARSE;
		goto finally;
	}

	// reserve more memory on the string so the query fits as well
	if(!(full_url = realloc(full_url, url_length + chars_required)))
	{
		error = SCEPE_CLIENT_MEMORY;
		goto finally;
	}

	// append the query to our URL. Our target string is offset to the end.
	if(uriComposeQueryA(full_url + url_length, query_list_start, chars_required + 1,
			&chars_written) != URI_SUCCESS)
	{
		error = SCEPE_CLIENT_QUERY_PARSE;
		goto finally;
	}
	scep_log(handle, INFO, "Full request URL including query: \"%s\"",
			full_url);

	curl_handle = curl_easy_init();
	if(!curl_handle)
	{
		error = SCEPE_CLIENT_CURL;
		goto finally;
	}

	local_reply = malloc(sizeof(SCEP_REPLY));
	memset(local_reply, 0, sizeof(SCEP_REPLY));

	curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, scep_recieve_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, local_reply);

	scep_log(handle, INFO, "Sending request...");
	if((curl_error = curl_easy_perform(curl_handle)) != CURLE_OK)
	{
		error = SCEPE_CLIENT_CURL;
		scep_log(handle, FATAL, "cURL error: %s",
				curl_easy_strerror(curl_error));
		goto finally;
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE,
			&(local_reply->status));
	scep_log(handle, INFO, "Got reply status code %d", local_reply->status);
	if((curl_error = curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_TYPE,
			&(tmp_str))) != CURLE_OK)
	{
		error = SCEPE_CLIENT_CURL;
		scep_log(handle, FATAL, "cURL error: %s",
				curl_easy_strerror(curl_error));
		goto finally;
	}

	tmp_str_len = strlen(tmp_str) + 1;
	local_reply->content_type = malloc(tmp_str_len);
	strncpy(local_reply->content_type, tmp_str, tmp_str_len);
	if(!local_reply->content_type)
	{
		error = SCEPE_CLIENT_INVALID_RESPONSE;
		scep_log(handle, FATAL, "Server did not send a content type.");
		goto finally;
	}

	scep_log(handle, INFO, "MIME content type: %s",
			local_reply->content_type);
	*reply = local_reply;
finally:
	if(error != SCEPE_CLIENT_OK)
		if(local_reply)
			free(local_reply);
	if(query_list_start)
		uriFreeQueryListA(query_list_start);
	if(full_url)
		free(full_url);
	if(curl_handle)
		curl_easy_cleanup(curl_handle);
	return error;
}

char *scep_client_strerror(SCEP_CLIENT_ERROR err)
{
	switch(err)
	{
		case SCEPE_CLIENT_OK:
			return scep_strerror(SCEPE_OK);
		case SCEPE_CLIENT_MEMORY:
			return scep_strerror(SCEPE_MEMORY);
		case SCEPE_CLIENT_OPENSSL:
			return scep_strerror(SCEPE_OPENSSL);
		case SCEPE_CLIENT_INVALID_URL:
			return "The given URL is invalid";
		case SCEPE_CLIENT_QUERY_OP:
			return "The query key \"operation\" is a reserved string and may "
					"not be used in query by the user";
		case SCEPE_CLIENT_QUERY_PARSE:
			return "There was an error while preparing the query of the URL";
		case SCEPE_CLIENT_CURL:
			return "cURL error. See error log for more details";
		case SCEPE_CLIENT_INVALID_RESPONSE:
			return "Server response was invalid. Log contains more details";
		case SCEPE_CLIENT_FILE_DOES_NOT_EXIST:
			return "Given file does not exist";

		case SCEPE_CLIENT_DUMMY_LAST_ERROR:
			return "Unknown error";
	}

	/**
	 * Nifty little trick stolen from libcurl: If an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}

SCEP_CLIENT_ERROR scep_conf_set_url(struct cmd_handle_t *cmd_handle, char *url_str, UriUriA **target)
{
	SCEP *handle = cmd_handle->handle;
	UriParserStateA state;
	UriUriA *url;
	SCEP_CLIENT_ERROR error = SCEPE_CLIENT_OK;

	scep_log(handle, DEBUG, "Setting URL to %s", url_str);
	url = malloc(sizeof(UriUriA));
	if(!url) {
		error = SCEPE_CLIENT_MEMORY;
		goto finally;
	}
	state.uri = url;
	if(uriParseUriA(&state, url_str) != URI_SUCCESS)
	{
		error = SCEPE_CLIENT_INVALID_URL;
		goto finally;
	}

	if(!url->scheme.first || !url->scheme.afterLast)
	{
		error = SCEPE_CLIENT_INVALID_URL;
		scep_log(handle, ERROR, "Need scheme (e.g. http://) in URL.");
		goto finally;
	}

	*target = url;

finally:
	if(error != SCEPE_CLIENT_OK)
		free(url);
	return error;
}

/* Read private key */

SCEP_CLIENT_ERROR scep_read_key(SCEP *handle, EVP_PKEY** key, char* filename) {
	FILE *file;
	if(!(file = fopen(filename, "r"))) {
		scep_log(handle, FATAL, "cannot open private key file %s", filename);
		return SCEPE_CLIENT_FILE_DOES_NOT_EXIST;
	}
	if(!PEM_read_PrivateKey(file, key, NULL, NULL)) {
		ERR_print_errors(handle->configuration->log);
		scep_log(handle, FATAL, "error while reading private key %s", filename);
		return SCEPE_CLIENT_OPENSSL;
	}
	fclose(file);
	return SCEPE_CLIENT_OK;
}

SCEP_CLIENT_ERROR scep_read_cert(SCEP *handle, X509 **cert, char *filename) {
	FILE *file;
	if(!(file = fopen(filename, "r"))) {
		scep_log(handle, FATAL, "cannot open certificate file %s", filename);
		return SCEPE_CLIENT_FILE_DOES_NOT_EXIST;
	}
	if(!PEM_read_X509(file, cert, NULL, NULL)) {
		ERR_print_errors(handle->configuration->log);
		scep_log(handle, FATAL, "error while reading certificate %s", filename);
		return SCEPE_CLIENT_OPENSSL;
	}
	fclose(file);
	return SCEPE_CLIENT_OK;
}

SCEP_CLIENT_ERROR scep_read_request(SCEP *handle, X509_REQ **req, char *filename) {
	FILE *file;
	if(!(file = fopen(filename, "r"))) {
		scep_log(handle, FATAL, "cannot open CSR file %s", filename);
		return SCEPE_CLIENT_FILE_DOES_NOT_EXIST;
	}
	if(!PEM_read_X509_REQ(file, req, NULL, NULL)) {
		ERR_print_errors(handle->configuration->log);
		scep_log(handle, FATAL, "error while reading CSR %s", filename);
		return SCEPE_CLIENT_OPENSSL;
	}
	fclose(file);
	return SCEPE_CLIENT_OK;
}