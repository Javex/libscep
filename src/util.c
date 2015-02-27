/* src/util.c */

#include "scep.h"
#include <stdio.h>

char *scep_strerror(SCEP_ERROR err)
{
	switch(err)
	{
		case SCEPE_OK:
			return "No error";
		case SCEPE_MEMORY:
			return "Not enough memory available";
		case SCEPE_INVALID_URL:
			return "The given URL is invalid";
		case SCEPE_UNKNOWN_CONFIGURATION:
			return "This configuration option is not known";
		case SCEPE_UNKOWN_OPERATION:
			return "Operation is unknown or no operation specified";
		case SCEPE_QUERY_OP:
			return "The query key \"operation\" is a reserved string and may "
					"not be used in query by the user";
		case SCEPE_QUERY_PARSE:
			return "There was an error while preparing the query of the URL";
		case SCEPE_DUPLICATE_BIO:
			return "Overwriting BIO not allowed. Check error log for details";
		case SCEPE_MISSING_URL:
			return "Missing URL configuration";
		case SCEPE_MISSING_CSR:
			return "You have to provide a CSR for the PKCSReq operation";
		case SCEPE_MISSING_REQ_KEY:
			return "You have to provide the private key for which you want a "
					"certificate";
		case SCEPE_MISSING_CA_CERT:
			return "The CA certificate is missing but is needed to encrypt the "
					"message for the server and/or extract certain values";
		case SCEPE_MISSING_SIGKEY:
			return "If you provide a signature certificate, you also need to "
					"provide a signature key";
		case SCEPE_MISSING_SIGCERT:
			return "If you provide a signature key, you also need to provide "
					"a signature certificate";
		case SCEPE_MISSING_CERT_KEY:
			return "To request an existing certificate you need to provide "
					"the key for which it was created";
		case SCEPE_MISSING_CRL_CERT:
			return "To request a CRL you need to provide the certificate "
					"which you want to validate";
		case SCEPE_CURL:
			return "cURL error. See error log for more details";
		case SCEPE_INVALID_RESPONSE:
			return "Server response was invalid. Log contains more details";
		case SCEPE_NYI:
			return "Action is defined by protocol but client does not yet "
					"support it. See log for details on which action is "
					"responsible for this.";
		case SCEPE_OPENSSL:
			return "Error in OpenSSL. See error log for details.";
		case SCEPE_DUMMY_LAST_ERROR:
			return "Unknown error";
	}

	/**
	 * Nifty little trick stolen from libcurl: If an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}

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

SCEP_ERROR scep_send_request(SCEP *handle, char *operation, char *message,
		SCEP_REPLY **reply)
{
	SCEP_ERROR error = SCEPE_OK;
	char *full_url = NULL, *tmp_str = NULL;
	int url_length, query_items_count, tmp_str_len, chars_required = 0,
		chars_written;
	UriQueryListA *query_list = NULL, *query_list_start = NULL;
	CURL *curl_handle = NULL;
	SCEP_REPLY *local_reply = NULL;
	CURLcode curl_error;

	// first get everything UNTIL the query
	url_length = handle->configuration->url->pathTail->text.afterLast -
			handle->configuration->url->scheme.first + 1; // + 1 for '?'
	full_url = malloc(url_length); // already includes space for '\0'!
	strncpy(full_url, handle->configuration->url->scheme.first, url_length);

	// replace '\0' from strncpy with '?' for query
	full_url[url_length - 1] = '?';

	if(handle->configuration->url->query.first)
	{

		// now build the query list, i.e. all items that were part of the query
		if(uriDissectQueryMallocA(&query_list, &query_items_count,
				handle->configuration->url->query.first,
				handle->configuration->url->query.afterLast) != URI_SUCCESS)
		{
			error = SCEPE_MEMORY;
			goto finally;
		}
		query_list_start = query_list;

		// find the last element of the linked list
		do
		{
			if(strncmp(query_list->key, "operation", 9) == 0)
			{
				error = SCEPE_QUERY_OP;
				goto finally;
			}
			if(query_list->next == NULL)
				break;
			query_list = query_list->next;
		} while(1);

		// allocate memory for another element (our operation)
		if(!(query_list->next = malloc(sizeof(UriQueryListA))))
		{
			error = SCEPE_MEMORY;
			goto finally;
		}
		memset(query_list->next, 0, sizeof(UriQueryListA));
		// set this new object as the current working object
		query_list = query_list->next;
	} else {
		if(!(query_list = malloc(sizeof(UriQueryListA))))
		{
			error = SCEPE_MEMORY;
			goto finally;
		}
		memset(query_list, 0, sizeof(UriQueryListA));
		query_list_start = query_list;
	}

	// set key & value for operation
	if(!(tmp_str = malloc(10))) // strlen("operation") + 1
	{
		error = SCEPE_MEMORY;
		goto finally;
	}
	strncpy(tmp_str, "operation", 10);
	query_list->key = tmp_str;

	tmp_str_len = strlen(operation) + 1;
	if(!(tmp_str = malloc(tmp_str_len)))
	{
		error = SCEPE_MEMORY;
		goto finally;
	}
	strncpy(tmp_str, operation, tmp_str_len);
	query_list->value = tmp_str;
	scep_log(handle, INFO, "Set operation to %s\n", operation);

	if(message)
	{
		// allocate memory for another element (the message)
		if(!(query_list->next = malloc(sizeof(UriQueryListA))))
		{
			error = SCEPE_MEMORY;
			goto finally;
		}
		memset(query_list->next, 0, sizeof(UriQueryListA));
		// set this new object as the current working object
		query_list = query_list->next;

		// set key & value for message
		if(!(tmp_str = malloc(8))) // strlen("message") + 1
		{
			error = SCEPE_MEMORY;
			goto finally;
		}
		strncpy(tmp_str, "message", 8);
		query_list->key = tmp_str;

		tmp_str_len = strlen(message) + 1;
		if(!(tmp_str = malloc(tmp_str_len)))
		{
			error = SCEPE_MEMORY;
			goto finally;
		}
		strncpy(tmp_str, message, tmp_str_len);
		query_list->value = tmp_str;
		scep_log(handle, DEBUG, "Set message to %s\n", message);
	}

	// get length of query string
	if(uriComposeQueryCharsRequiredA(query_list_start, &chars_required) !=
			URI_SUCCESS)
	{
		error = SCEPE_QUERY_PARSE;
		goto finally;
	}

	// reserve more memory on the string so the query fits as well
	if(!(full_url = realloc(full_url, url_length + chars_required)))
	{
		error = SCEPE_MEMORY;
		goto finally;
	}

	// append the query to our URL. Our target string is offset to the end.
	if(uriComposeQueryA(full_url + url_length, query_list_start, chars_required + 1,
			&chars_written) != URI_SUCCESS)
	{
		error = SCEPE_QUERY_PARSE;
		goto finally;
	}
	scep_log(handle, INFO, "Full request URL including query: \"%s\"\n",
			full_url);

	curl_handle = curl_easy_init();
	if(!curl_handle)
	{
		error = SCEPE_CURL;
		goto finally;
	}

	local_reply = malloc(sizeof(SCEP_REPLY));
	memset(local_reply, 0, sizeof(SCEP_REPLY));

	curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, scep_recieve_data);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, local_reply);

	scep_log(handle, INFO, "Sending request...\n");
	if((curl_error = curl_easy_perform(curl_handle)) != CURLE_OK)
	{
		error = SCEPE_CURL;
		scep_log(handle, FATAL, "cURL error: %s\n",
				curl_easy_strerror(curl_error));
		goto finally;
	}

	curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE,
			&(local_reply->status));
	scep_log(handle, INFO, "Got reply status code %d\n", local_reply->status);
	if((curl_error = curl_easy_getinfo(curl_handle, CURLINFO_CONTENT_TYPE,
			&(tmp_str))) != CURLE_OK)
	{
		error = SCEPE_CURL;
		scep_log(handle, FATAL, "cURL error: %s\n",
				curl_easy_strerror(curl_error));
		goto finally;
	}

	tmp_str_len = strlen(tmp_str) + 1;
	local_reply->content_type = malloc(tmp_str_len);
	strncpy(local_reply->content_type, tmp_str, tmp_str_len);
	if(!local_reply->content_type)
	{
		error = SCEPE_INVALID_RESPONSE;
		scep_log(handle, FATAL, "Server did not send a content type.\n");
		goto finally;
	}

	scep_log(handle, INFO, "MIME content type: %s\n",
			local_reply->content_type);
	*reply = local_reply;
finally:
	if(error != SCEPE_OK)
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

SCEP_ERROR scep_calculate_transaction_id(SCEP *handle, EVP_PKEY *pubkey, char **transaction_id)
{
	SCEP_ERROR error = SCEPE_OK;
	BIO *bio;
	unsigned char *data, digest[SHA256_DIGEST_LENGTH];
	int len, i;
	EVP_MD_CTX *ctx;

#define OSSL_ERR(msg)                                   \
    do {                                                \
        error = SCEPE_OPENSSL;                          \
        ERR_print_errors(handle->configuration->log);   \
        scep_log(handle, FATAL, msg);                   \
        goto finally;                                   \
    } while(0)

	if(!(*transaction_id = malloc(2 * SHA256_DIGEST_LENGTH + 1)))
		return SCEPE_MEMORY;
	memset(*transaction_id, 0, 2 * SHA256_DIGEST_LENGTH + 1);

	if(!(bio = BIO_new(BIO_s_mem())))
	{
		error = SCEPE_MEMORY;
		goto finally;
	}
	
	if(!i2d_PUBKEY_bio(bio, pubkey))
		OSSL_ERR("Could not convert pubkey to DER.\n");

	len = BIO_get_mem_data(bio, &data);
	if(len == 0)
		OSSL_ERR("Could not get data from bio.\n");
	
	SHA256(data, len, digest);
	ctx = EVP_MD_CTX_create();
	if(ctx == NULL)
		OSSL_ERR("Could not create hash context.\n");

	if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 0)
		OSSL_ERR("Could not initialize hash context.\n");

	if(EVP_DigestUpdate(ctx, data, len) == 0)
		OSSL_ERR("Could not read data into context.\n");

	if(EVP_DigestFinal_ex(ctx, digest, NULL) == 0)
		OSSL_ERR("Could not finalize context.\n");

	for(i=0; i < SHA256_DIGEST_LENGTH; ++i)
		sprintf((*transaction_id) + i * 2, "%02X", digest[i]);
	scep_log(handle, INFO, "Generated transaction id %s\n", *transaction_id);
finally:
	if(error != SCEPE_OK)
		if(*transaction_id)
			free(*transaction_id);
	if(bio)
		BIO_free(bio);
	return error;
#undef OSSL_ERR
}

inline void _scep_log(SCEP *handle, SCEP_VERBOSITY verbosity, const char *file,
		int line, char *format, ...)
{
	char *full_message;
	char *message;
	int message_len, full_message_len;
	va_list args;
	char *filecopy, *filename;
	if(handle->configuration->log &&
			handle->configuration->verbosity > verbosity)
	{
		filecopy = strdup(file);
		filename = basename(filecopy);
		// create the message from format string and var args.
		va_start(args, format);
		message_len = vsnprintf(NULL, 0, format, args) + 1;
		va_end(args);
		message = malloc(message_len);
		va_start(args, format);
		vsnprintf(message, message_len, format, args);
		va_end(args);

		// this code is extended to be more readable, any decent compiler will
		// automatically add those constants
		full_message_len = strlen(message)
					 + strlen(filename)
					 + (int) log10(line)
					 + 1 // + 1 for log for an upper bound
					 + 2 // two colons
					 + 1 // one space after line number
					 + 1; // terminating null char

		// we don't handle any errors here. If there's not enough memory, there
		// are bigger issues at stake than logging
		if(!(full_message = malloc(full_message_len)))
			return;
		snprintf(full_message, full_message_len, "%s:%d: %s\n",
				filename, line, message);
		BIO_puts(handle->configuration->log, full_message);
		free(filecopy);
	}
}

void scep_reply_free(SCEP_REPLY *reply)
{
	if(reply)
	{
		if(reply->payload)
			free(reply->payload);
		if(reply->content_type)
			free(reply->content_type);
		free(reply);
	}
}
