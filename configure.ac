dnl Process this file with autoconf to produce a configure script.

AC_INIT([lmzca], [0.2])
AC_PREFIX_DEFAULT([/opt/LMZca])
AC_CONFIG_MACRO_DIR([aclocal])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_HEADER(auto_config.h)

AC_PROG_CC([gcc c99 cc])
dnl "If the -o option is present with -c or -E, the result is unspecified."
AM_PROG_CC_C_O
PKG_PROG_PKG_CONFIG()

AM_CONDITIONAL([CC_IS_GCC], [test "x$GCC" = "xyes"])

AC_CHECK_FILE([cryptlib/include/cryptlib.h],,[AC_MSG_ERROR([please put cryptlib.h in cryptlib/include])])
AC_CHECK_FILE([cryptlib/lib/libcl.a],,[AC_MSG_ERROR([please put libcl.a in cryptlib/lib])])

dnl fourth arg must be specified so configure does not search around for
dnl AC_INCLUDES_DEFAULT -> _AC_INCLUDES_DEFAULT_REQUIREMENTS ->
dnl AC_HEADER_STDC
dnl --- we assume stdc headers anyways
AC_CHECK_HEADER([sqlite3.h],,[AC_MSG_ERROR(please install sqlite3)],[ ])
dnl Add to libs only, do not define HAVE_LIBSQLITE3 (not necessary, hard requirement)
AC_CHECK_LIB([sqlite3],[sqlite3_libversion],[LIBS="-lsqlite3 $LIBS"],[AC_MSG_ERROR(please install sqlite3)])

dnl TODO how to set -L for this thing....
dnl AC_CHECK_LIB(cl,cryptInit,,[AC_MSG_ERROR(cannot find libcl)])

PKG_CHECK_MODULES(GTKGLADE, [gtk+-2.0 >= 2.6 libglade-2.0 >= 2.4],,[AC_MSG_ERROR(please install GTK 2 and Glade)])
AC_SUBST(GTKGLADE_CFLAGS)
AC_SUBST(GTKGLADE_LIBS)

dnl no longer need openssl since trans not built, ever.
dnl have_openssl=false
dnl PKG_CHECK_MODULES(OPENSSL, [openssl], [have_openssl=true],)
dnl AC_SUBST(OPENSSL_CFLAGS)
dnl AC_SUBST(OPENSSL_LIBS)
dnl AM_CONDITIONAL([HAVE_OPENSSL], [test x$have_openssl = xtrue])


AC_ARG_ENABLE(development, 
  [AS_HELP_STRING([--enable-development], 
    [enable running from build dir for development (default is no)])])
AM_CONDITIONAL(LMZ_DEVELOPMENT, [test "x$enable_development" = xyes])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
