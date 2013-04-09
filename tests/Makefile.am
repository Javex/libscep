TESTS = test_configuration test_scep 

check_PROGRAMS = test_configuration test_scep
check_LDADD = @CHECK_LIBS@ -lgcov

test_configuration_SOURCES = test_configuration.c $(top_builddir)/src/scep.h
test_configuration_CFLAGS = @CHECK_CFLAGS@
test_configuration_LDADD = $(top_builddir)/src/libscep-0.1.la $(check_LDADD)

test_scep_SOURCES = test_scep.c $(top_builddir)/src/scep.h
test_scep_CFLAGS = @CHECK_CFLAGS@
test_scep_LDADD = $(top_builddir)/src/libscep-0.1.la $(check_LDADD)

