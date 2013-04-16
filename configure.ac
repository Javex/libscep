#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_CONFIG_SRCDIR([src/scep.h])
AC_INIT([libscep], [0.1], [https://github.com/javex/libscep/issues])
AM_INIT_AUTOMAKE(foreign -Wall -Werror 1.9.6)

AC_CONFIG_MACRO_DIR([m4])
AM_PROG_AR
LT_INIT

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_SED

PKG_CHECK_MODULES([CHECK], [check >= 0.9.4])

AC_CHECK_LIB([crypto], [BIO_new])
AC_CHECK_LIB([curl], [curl_easy_init])
AC_CHECK_LIB([m], [log])
# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypto':
#AC_CHECK_LIB([crypto], [main]) 

# ===================
# Check for uriparser

URIPARSER_MISSING="Please install uriparser 0.6.4 or later.
   On a Debian-based system enter 'sudo apt-get install liburiparser-dev'."
AC_CHECK_LIB(uriparser, uriParseUriA,, AC_MSG_ERROR(${URIPARSER_MISSING}))
AC_CHECK_HEADER(uriparser/Uri.h,, AC_MSG_ERROR(${URIPARSER_MISSING}))

# uriparser OK
# ============

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([scep.h string.h stdlib.h stdarg.h openssl/*.h])


m4_include([gcov.m4])
AC_TDD_GCOV
AC_SUBST(COVERAGE_CFLAGS)
AC_SUBST(COVERAGE_LDFLAGS)

AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([mempcpy memset strdup])

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT

