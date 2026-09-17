PHP_ARG_ENABLE([fuzzcache],
  [whether to enable fuzzcache support],
  [AS_HELP_STRING([--enable-fuzzcache],
    [Enable fuzzcache interpreter-level transparent data cache])],
  [no])

if test "$PHP_FUZZCACHE" != "no"; then
  AC_CHECK_LIB(rt, sem_open, [FUZZCACHE_SHARED_LIBADD="$FUZZCACHE_SHARED_LIBADD -lrt"])
  PHP_SUBST(FUZZCACHE_SHARED_LIBADD)
  PHP_NEW_EXTENSION(fuzzcache, fuzzcache.c, $ext_shared)
fi
