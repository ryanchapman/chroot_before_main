# configure.ac -- Process with 'autoreconf -if' to produce ./configure
# @start 1

AC_INIT

# Versioning
CHROOT_BEFORE_MAIN_MAJOR_VERSION=1
CHROOT_BEFORE_MAIN_MINOR_VERSION=0
CHROOT_BEFORE_MAIN_MICRO_VERSION=0
VERSION=$CHROOT_BEFORE_MAIN_MAJOR_VERSION.$CHROOT_BEFORE_MAIN_MINOR_VERSION.$CHROOT_BEFORE_MAIN_MICRO_VERSION
PACKAGE=chroot_before_main

AM_INIT_AUTOMAKE($PACKAGE, $VERSION)

# Enable $host_os checking
AC_CANONICAL_HOST

# Check for GNU cc
AC_PROG_CC

# Check OS (only Linux/Solaris ld.so support la_preinit as far as I know)
case "$host_os" in
linux*) ;;
*olaris*) ;;
*)
	AC_MSG_ERROR([Unsupported OS $host_os. Only Linux and Solaris are supported.])
	;;
esac

AC_LANG([C])

AC_ARG_ENABLE(root,
              [AC_HELP_STRING([--enable-root=@<:@yes/no@:>@],
                              [Allow the chrooted program to remain the root user (security concern) @<:@default=no@:>@])],
              [case "${enableval}" in
                yes) echo "ENABLE ROOTR" ; cond_root=true ;;
                no)  cond_root=false ;;
                *)   AC_MSG_ERROR(bad value ${enableval} for --enable-root) ;;
               esac],
              [cond_root=false])

AC_ARG_ENABLE(chroot,
              [AC_HELP_STRING([--enable-chroot=@<:@yes/no@:>@],
                              [Enable the chroot system call inside of the chrooted program @<:@default=no@:>@])],
              [case "${enableval}" in
		yes) cond_chroot=true ;;
		no)  cond_chroot=false ;;
		*)   AC_MSG_ERROR(bad value ${enableval} for --enable-chroot) ;;
		esac],
              [cond_chroot=false])

AC_FUNC_FORK
AC_FUNC_MALLOC
AC_PREREQ
AC_PROG_INSTALL
AC_TYPE_SIZE_T

AC_CHECK_FUNCS([memmove])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([setenv])

AC_CHECK_HEADERS([stdlib.h])

AM_CONDITIONAL([COND_ROOT],   [test x$cond_root = xtrue])
AM_CONDITIONAL([COND_CHROOT], [test x$cond_chroot = xtrue])

AC_CONFIG_FILES([Makefile])

AC_OUTPUT

# @end 1
