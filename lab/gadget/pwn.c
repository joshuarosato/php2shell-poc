/*
 * Lab-only test extension: emulates a "framework gadget" class whose
 * __wakeup() executes attacker controlled data.
 *
 * It is used to demonstrate that PHP's session upload-progress handler
 * unserializes the session (and therefore runs __wakeup()) *before* normal
 * request initialization - the session consumer path described in
 * CVE-2026-109619 / GHSA-6wmf-4rv5-p3rp.  The upstream fix
 * (php-src commit 3584a98b "Avoid state corruption via bailout") adds
 * php_var_unserialize_set_incomplete_classes_only() for exactly this path.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "zend_API.h"
#include "ext/standard/info.h"

zend_class_entry *pwn_ce;

static void pwn_run(const char *cmd)
{
	zval ret, fn, *args;
	zend_fcall_info fci;
	zend_fcall_info_cache fcc;

	args = emalloc(sizeof(zval));
	ZVAL_STRING(&args[0], cmd);
	ZVAL_STRING(&fn, "system");

	memset(&fci, 0, sizeof(fci));
	memset(&fcc, 0, sizeof(fcc));
	if (zend_fcall_info_init(&fn, 0, &fci, &fcc, NULL, NULL) == SUCCESS) {
		fci.param_count = 1;
		fci.params = args;
		fci.retval = &ret;
		zend_call_function(&fci, &fcc);
	}
	zval_ptr_dtor(&args[0]);
	efree(args);
	zval_ptr_dtor(&fn);
}

ZEND_METHOD(Pwn, __wakeup)
{
	zval *cmd, rv;
	zend_string *s;
	zend_object *obj = Z_OBJ_P(ZEND_THIS);

	cmd = zend_read_property(Z_OBJCE_P(ZEND_THIS), obj, "cmd", sizeof("cmd") - 1, 1, &rv);
	if (cmd && Z_TYPE_P(cmd) == IS_STRING) {
		s = zval_get_string(cmd);
		php_error_docref(NULL, E_USER_NOTICE, "Pwn::__wakeup() is executing the command");
		pwn_run(ZSTR_VAL(s));
		zend_string_release(s);
	}
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_pwn_wakeup, 0, 0, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry pwn_functions[] = {
	PHP_ME(Pwn, __wakeup, arginfo_pwn_wakeup, ZEND_ACC_PUBLIC)
	PHP_FE_END
};

PHP_MINIT_FUNCTION(pwn)
{
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "Pwn", pwn_functions);
	pwn_ce = zend_register_internal_class(&ce);
	zend_declare_property_string(pwn_ce, "cmd", sizeof("cmd") - 1, "", ZEND_ACC_PUBLIC);
	return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(pwn)
{
	return SUCCESS;
}

PHP_MINFO_FUNCTION(pwn)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "pwn support", "enabled");
	php_info_print_table_end();
}

zend_module_entry pwn_module_entry = {
	STANDARD_MODULE_HEADER,
	"pwn",
	pwn_functions,
	PHP_MINIT(pwn),
	PHP_MSHUTDOWN(pwn),
	NULL, NULL,
	PHP_MINFO(pwn),
	"1.0",
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_PWN
ZEND_GET_MODULE(pwn)
#endif
