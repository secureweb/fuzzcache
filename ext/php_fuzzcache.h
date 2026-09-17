#ifndef PHP_FUZZCACHE_H
#define PHP_FUZZCACHE_H

#include "php.h"

extern zend_module_entry fuzzcache_module_entry;
#define phpext_fuzzcache_ptr &fuzzcache_module_entry

#define PHP_FUZZCACHE_VERSION "0.1.0"

#ifdef ZTS
#include "TSRM.h"
#endif

ZEND_BEGIN_MODULE_GLOBALS(fuzzcache)
    zend_bool enabled;
    zend_long shm_size;
    char *shm_name;
    zend_long network_ttl;      /* seconds, 0 = no expiry */
    zend_bool debug;

    /* runtime state, not exposed as ini */
    void *shm_base;
    size_t shm_mapped_size;
    void *sem;                 /* sem_t* */
    zend_bool shm_ready;

    zend_class_entry *result_ce;
    zend_class_entry *lazyconn_ce;
    zend_class_entry *stmt_ce;   /* FuzzCache\CachedStatement, for PDO::query() */

    HashTable curl_handles;      /* zend_object handle -> fc_curl_info* */
    HashTable pdo_stmt_templates; /* zend_object handle -> fc_pdo_stmt_info* */

    zend_bool reentrant;       /* set while we re-invoke a real mysqli/curl
                                  function ourselves, so our own hook does
                                  not intercept that inner call again */

    void (*orig_execute_internal)(zend_execute_data *execute_data, zval *return_value);
ZEND_END_MODULE_GLOBALS(fuzzcache)

#ifdef ZTS
#define FCG(v) ZEND_TSRMG(fuzzcache_globals_id, zend_fuzzcache_globals *, v)
#else
#define FCG(v) (fuzzcache_globals.v)
#endif

extern ZEND_DECLARE_MODULE_GLOBALS(fuzzcache)

#endif /* PHP_FUZZCACHE_H */
