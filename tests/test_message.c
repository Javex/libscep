#include <check.h>
#include <stdlib.h>
#include "scep.h"
#include "scep_tests.h"

Suite * scep_message_suite(void)
{
	Suite *s = suite_create("Message");
	/*test Certrep*/
	add_certrep(s);

	/* PKCSReq tests */
	add_pkcsreq(s);

	/* GetCertInitial tests */
	add_get_cert_initial(s);

	/* GetCert tests */
	add_get_cert(s);

	/* GetCRL tests */
	add_get_crl(s);

	return s;
}

int main(void)
{
	int number_failed;
	setenv("SOFTHSM_CONF", "softhsm.conf", 0);
	Suite *s = scep_message_suite();
	SRunner *sr = srunner_create(s);
	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
