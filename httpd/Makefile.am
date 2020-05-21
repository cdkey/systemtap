# Makefile.am --- automake input file for systemtap

SUBDIRS = docker

AUTOMAKE_OPTIONS = no-dist foreign subdir-objects

AM_CFLAGS = -Wall -Wextra -Werror -Wunused -W -Wformat=2
AM_CXXFLAGS = -Wall -Wextra -Werror -Wunused -W -Wformat=2
AM_CPPFLAGS = -D_GNU_SOURCE
AM_CPPFLAGS += -I$(srcdir)/../includes
AM_CPPFLAGS += -I$(builddir)/../includes/sys
AM_CPPFLAGS += -DBINDIR='"$(bindir)"' -DSYSCONFDIR='"$(sysconfdir)"' -DPKGDATADIR='"${pkgdatadir}"' -DPKGLIBDIR='"$(pkglibexecdir)"' -DLOCALEDIR='"$(localedir)"'

AM_CFLAGS += @PIECFLAGS@
AM_CXXFLAGS += @PIECXXFLAGS@
AM_LDFLAGS = @PIELDFLAGS@

if HAVE_HTTP_SUPPORT
pkglibexec_PROGRAMS = stap-httpd

stap_httpd_SOURCES = main.cxx server.cxx api.cxx backends.cxx utils.cxx nss_funcs.cxx ../util.cxx ../cmdline.cxx ../nsscommon.cxx ../privilege.cxx ../cscommon.cxx ../mdfour.c
stap_httpd_CFLAGS = $(AM_CFLAGS) $(nss_CFLAGS) $(debuginfod_CFLAGS)
stap_httpd_CXXFLAGS = $(AM_CXXFLAGS) $(nss_CFLAGS)
stap_httpd_CPPFLAGS = $(AM_CPPFLAGS) $(nss_CFLAGS)
stap_httpd_LDADD = -lpthread -lmicrohttpd -luuid -ljson-c $(nss_LIBS) $(debuginfod_LIBS)
stap_httpd_LDADD += $(openssl_LIBS)
stap_httpd_LDFLAGS =  $(AM_LDFLAGS)

# To run "buildah", the 'stap-server' user must be able to use sudo
# only on "buildah". So, we'll install a custom sudo rule that does
# this.
#
# Notice we're installing to $(sysconfdir)/sudoers.d. If your
# sysconfdir isn't "/etc", "sudo" won't see this installed file. By
# default, "sudo" only looks in /etc/sudoers.d.
SUDO_DATA_DIR = $(DESTDIR)/$(sysconfdir)/sudoers.d

install-data-local:
	$(INSTALL_DATA) -m 0600 -D $(srcdir)/stap-server.sudoers $(SUDO_DATA_DIR)/stap-server

uninstall-local:
	rm -f $(SUDO_DATA_DIR)/stap-server

endif

BUILT_SOURCES =
CLEANFILES =

# Arrange for the top-level git_version.h to be regenerated at every "make".
BUILT_SOURCES += git_version.stamp
git_version.stamp ../git_version.h:
	$(MAKE) -C .. $(notdir $@)
