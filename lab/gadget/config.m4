PHP_ARG_ENABLE([pwn], [whether to enable the pwn test extension], [--enable-pwn], [no])
if test "$PHP_PWN" != "no"; then
  PHP_NEW_EXTENSION(pwn, pwn.c, $ext_shared)
fi
