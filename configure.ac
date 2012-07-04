dnl Process this file with autoconf to produce a configure script.
AC_INIT([pam-ocs], 0.1)
dnl AC_CONFIG_SRCDIR([src])

AM_INIT_AUTOMAKE([1.9 foreign no-dist-gzip dist-bzip2 tar-ustar])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_PREFIX_DEFAULT(/usr)

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])


dnl Check for programs
AC_PROG_CC
AC_PROG_MAKE_SET
AC_PROG_INSTALL
# per default don't build static libraries
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(LIBREST, rest-0.7)

dnl Check standard headers
AC_HEADER_STDC
AC_CHECK_HEADERS(stdlib.h pwd.h sys/types.h syslog.h sys/syslog.h string.h strings.h, , AC_MSG_ERROR(some basic headers are missing))
AC_CHECK_HEADERS(security/pam_appl.h security/pam_modules.h, , AC_MSG_ERROR(broken libpam installation))
AC_CHECK_HEADERS(security/pam_ext.h)

dnl Various function checking
AC_CHECK_FUNCS(fprintf snprintf syslog strncmp, , AC_MSG_ERROR(some basic C functions cannot be found))

AC_ARG_ENABLE(securedir,
        AS_HELP_STRING([--enable-securedir=DIR],[path to location of PAMs @<:@default=$libdir/security@:>@]),
        SECUREDIR=$enableval, SECUREDIR=/lib/security)
AC_SUBST(SECUREDIR)

AC_ARG_ENABLE(sconfigdir,
        AS_HELP_STRING([--enable-sconfigdir=DIR],[path to module conf files @<:@default=$sysconfdir/security@:>@]),
        SCONFIGDIR=$enableval, SCONFIGDIR=/etc/security)
AC_SUBST(SCONFIGDIR)

# i18n stuff
IT_PROG_INTLTOOL([0.41.0])

dnl Language Support
GETTEXT_PACKAGE=pam-ocs
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE",
           [The gettext translation domain])

AM_GLIB_GNU_GETTEXT

AC_CONFIG_FILES([
Makefile
src/Makefile
po/Makefile.in
])
AC_OUTPUT

