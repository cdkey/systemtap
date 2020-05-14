# Makefile.am --- automake input file for systemtap runtime tools

AUTOMAKE_OPTIONS = subdir-objects

AM_CFLAGS = -Wall -Wextra -Werror -Wunused -W -Wformat=2
AM_CXXFLAGS = -Wall -Wextra -Werror -Wunused -W -Wformat=2
AM_CPPFLAGS = -D_GNU_SOURCE
AM_CPPFLAGS += -I$(srcdir)/../includes
AM_CPPFLAGS += -I$(builddir)/../includes/sys
AM_CPPFLAGS += -DBINDIR='"$(bindir)"' -DSYSCONFDIR='"$(sysconfdir)"' -DPKGDATADIR='"${pkgdatadir}"' -DPKGLIBDIR='"$(pkglibexecdir)"' -DLOCALEDIR='"$(localedir)"'

AM_CFLAGS += @PIECFLAGS@
AM_CXXFLAGS += @PIECXXFLAGS@
AM_LDFLAGS = @PIELDFLAGS@

if HAVE_BPF_DECLS
bin_PROGRAMS = stapbpf

man_MANS = stapbpf.8

stapbpf_SOURCES = stapbpf.cxx bpfinterp.cxx libbpf.c ../util.cxx
stapbpf_CPPFLAGS = $(AM_CPPFLAGS)
stapbpf_CFLAGS = $(AM_CFLAGS) $(debuginfod_CFLAGS)
stapbpf_CXXFLAGS = $(AM_CXXFLAGS)
stapbpf_LDFLAGS = $(AM_LDFLAGS)
stapbpf_LDADD = $(stapbpf_LIBS) -lpthread $(debuginfod_LIBS)

BUILT_SOURCES =
CLEANFILES =

# Arrange for the top-level git_version.h to be regenerated at every "make".
BUILT_SOURCES += git_version.stamp
git_version.stamp ../git_version.h:
	$(MAKE) -C .. $(notdir $@)

# Why the "id -u" condition?  This way, an unprivileged user can run
# make install, and have "sudo stap ...." or "sudo stapbpf ...." work later.
install-exec-hook:
	if [ `id -u` -eq 0 ] && (getent group stapusr >/dev/null \
	                         || groupadd -f -g 156 -r stapusr); then \
		chgrp stapusr "$(DESTDIR)$(bindir)/stapbpf" \
		&& chmod 04110 "$(DESTDIR)$(bindir)/stapbpf"; \
	fi
endif
