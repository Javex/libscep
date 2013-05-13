#include <scep.h>

int main()
{
    SCEP *handle;
    SCEP_ERROR error = SCEPE_OK;

    if(scep_init(&handle) != SCEPE_OK)
        exit(1);

    // set up some options
	scep_log = BIO_new_fp(stdout, BIO_NOCLOSE);
	scep_conf_set(handle, SCEPCFG_LOG, scep_log);
	scep_conf_set(handle, SCEPCFG_VERBOSITY, INFO);
	scep_conf_set(handle, SCEPCFG_URL, "http://example.com/cgi-bin/scep/scep");

    // recieve server certificates
    if((error = scep_operation_getcacert(handle, &certs)) != SCEPE_OK)
        goto finally;

    // do anything you like with them
    // ...

finally:
    scep_cleanup(handle);
    BIO_flush(scep_log);
    BIO_free(scep_log);

    return error;
}
