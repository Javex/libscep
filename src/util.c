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
			return "Not enough memory available!";
		case SCEPE_INVALID_URL:
			return "The given URL is invalid.";
		case SCEPE_UNKNOWN_CONFIGURATION:
			return "This configuration option is not known.";
	}

	/**
	 * Nifty little trick stolen from libcurl: If an error is defined in
	 * an enum but not handled by switch, gcc will complain.
	 */
	return "Unknown error";
}


