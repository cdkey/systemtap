dnl configure.ac --- autoconf input file for systemtap testsuite
dnl Process this file with autoconf to produce a configure script.

AC_INIT([systemtap], 4.6, systemtap@sourceware.org, systemtap)

AC_PREREQ(2.59)
AC_CONFIG_AUX_DIR(..)
AM_INIT_AUTOMAKE([dejagnu foreign])
AM_MAINTAINER_MODE

AC_ARG_ENABLE([dejazilla],
  AS_HELP_STRING([--enable-dejazilla@<:@=ARG@:>@],
    [enable dejazilla support to automatically email test results to a
     central public collection point (default is disabled).  Optional
     ARG overrides the default email address. Specifying a url for ARG
     will instead send the results to that url via http.]))
case "$enable_dejazilla" in
     no) dejazilla= ;;
     yes) dejazilla=dejazilla@elastic.org ;;
     *) dejazilla="$enable_dejazilla" ;;
esac
if test -n "$dejazilla"; then
   AC_MSG_NOTICE([A "make *check" will send results to $dejazilla])
fi
AC_SUBST(dejazilla)

# The configure above passed us several python-related variables. Make
# sure these get substituted in the Makefile.
AC_SUBST([python], [${python}])
AC_SUBST([pyexecdir], [${pyexecdir}])
AC_SUBST([python3], [${python3}])
AC_SUBST([py3execdir], [${py3execdir}])

apps=
for exp in $srcdir/systemtap.apps/*.exp
do
    app=`basename $exp .exp`
    apps="$app $apps"
done
AC_ARG_ENABLE([testapps],
  AC_HELP_STRING([--enable-testapps=foo bar or all],
    [enable rebuilding of large external apps for testing <sdt.h> markers]))
AC_MSG_NOTICE([Will test ${enable_testapps-no} apps from: $apps])
AC_SUBST(enable_testapps)

AC_CONFIG_FILES(Makefile)
AC_OUTPUT
