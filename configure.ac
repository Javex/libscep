#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_SRCDIR([src/scep.c])

AC_INIT([libscep], [20121025], [https://github.com/javex/libscep/issues])
AM_INIT_AUTOMAKE(foreign -Wall -Werror 1.9.6)

LT_INIT

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_SED

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypto':
#AC_CHECK_LIB([crypto], [main])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([strmap.h scep.h string.h stdlib.h openssl/*.h])


m4_include([gcov.m4])
AC_TDD_GCOV
AC_SUBST(COVERAGE_CFLAGS)
AC_SUBST(COVERAGE_LDFLAGS)


# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([mempcpy memset strdup])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT

