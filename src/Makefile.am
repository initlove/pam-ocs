CLEANFILES = *~
securelibdir = $(SECUREDIR)
secureconfdir = $(SCONFIGDIR)

AM_CFLAGS = $(LIBREST_CFLAGS)
AM_LDFLAGS = -no-undefined -avoid-version -module

securelib_LTLIBRARIES = pam_ocs.la
pam_ocs_la_LIBADD = -lpam \
    $(LIBREST_LIBS)

pam_ocs_la_SOURCES = pam_ocs.c

