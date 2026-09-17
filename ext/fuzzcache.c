/*
 * FuzzCache: interpreter-level transparent data cache for PHP web application fuzzing.
 *
 * This extension hooks zend_execute_internal (the same mechanism used by
 * xhprof/extension/xhprof.c in this repo) to intercept calls to a small set
 * of database (mysqli) and network (curl) functions. It requires no changes
 * to application source code and no PHP/mysqli/curl source modifications.
 *
 * Design mirrors the paper (FuzzCache, CCS'24 4.2-4.3):
 *  - Query-centric database cache keyed by the query string hash.
 *  - Coarse-grained table-level invalidation via per-table epoch counters
 *    (equivalent to the paper's dirty-bit, but O(1) to bump on writes
 *    instead of scanning every cache entry).
 *  - Lazy connection: mysqli_connect() does not actually connect; it
 *    returns a lightweight placeholder that only triggers a real connection
 *    on the first genuine cache miss.
 *  - Data prefetch: on a cache miss, all rows are fetched immediately and
 *    cached, and both the miss and hit paths hand back a uniform
 *    FuzzCache\CachedResult object so downstream mysqli_fetch_* calls
 *    behave identically either way.
 *  - Network cache keyed by URL (via curl_setopt(CURLOPT_URL, ...)
 *    interception), with an optional TTL.
 *  - Cache storage lives in a POSIX shared memory segment so it persists
 *    across the independent, short-lived processes used to serve fuzzing
 *    requests.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php_fuzzcache.h"
#include "ext/standard/php_var.h"
#include "ext/standard/info.h"
#include "Zend/zend_smart_str.h"
#include "Zend/zend_exceptions.h"
#include "Zend/zend_interfaces.h"

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

ZEND_DECLARE_MODULE_GLOBALS(fuzzcache)

/* ------------------------------------------------------------------ */
/* Shared memory cache layout                                          */
/* ------------------------------------------------------------------ */

#define FC_MAGIC            0x46437368554DULL
#define FC_NUM_SLOTS         16384
#define FC_NUM_TABLE_SLOTS   4096
#define FC_MAX_TABLES        4

typedef struct {
    uint64_t key_hash;
    uint64_t table_hashes[FC_MAX_TABLES];
    uint32_t table_epochs[FC_MAX_TABLES];
    uint8_t  num_tables;
    uint8_t  used;
    uint8_t  is_network;
    uint8_t  _pad;
    uint64_t expire_at;   /* unix seconds, 0 = never expires */
    uint64_t data_offset;
    uint64_t data_len;
} fc_slot;

typedef struct {
    uint64_t key;
    uint32_t epoch;
    uint8_t  used;
} fc_table_epoch_slot;

typedef struct {
    uint64_t magic;
    uint64_t total_size;
    uint64_t arena_size;
    uint64_t write_offset;
    uint32_t num_slots;
    uint32_t num_table_slots;
    fc_slot slots[FC_NUM_SLOTS];
    fc_table_epoch_slot table_epochs[FC_NUM_TABLE_SLOTS];
    unsigned char arena[];
} fc_shm_header;

#define FC_LOCK()   do { if (FCG(sem)) sem_wait((sem_t*)FCG(sem)); } while (0)
#define FC_UNLOCK() do { if (FCG(sem)) sem_post((sem_t*)FCG(sem)); } while (0)

static uint64_t fc_fnv1a64(const char *s, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char) s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t fc_fnv1a64_ci(const char *s, size_t len)
{
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char) s[i];
        if (c >= 'A' && c <= 'Z') c += 32;
        h ^= c;
        h *= 1099511628211ULL;
    }
    return h;
}

static uint32_t fc_table_epoch_get(fc_shm_header *hdr, uint64_t table_hash)
{
    uint32_t idx = (uint32_t) (table_hash % hdr->num_table_slots);
    for (uint32_t i = 0; i < hdr->num_table_slots; i++) {
        uint32_t j = (idx + i) % hdr->num_table_slots;
        fc_table_epoch_slot *s = &hdr->table_epochs[j];
        if (!s->used) return 0;
        if (s->key == table_hash) return s->epoch;
    }
    return 0;
}

static void fc_table_epoch_bump(fc_shm_header *hdr, uint64_t table_hash)
{
    uint32_t idx = (uint32_t) (table_hash % hdr->num_table_slots);
    uint32_t first_free = UINT32_MAX;
    for (uint32_t i = 0; i < hdr->num_table_slots; i++) {
        uint32_t j = (idx + i) % hdr->num_table_slots;
        fc_table_epoch_slot *s = &hdr->table_epochs[j];
        if (s->used && s->key == table_hash) { s->epoch++; return; }
        if (!s->used && first_free == UINT32_MAX) first_free = j;
    }
    if (first_free != UINT32_MAX) {
        fc_table_epoch_slot *s = &hdr->table_epochs[first_free];
        s->used = 1;
        s->key = table_hash;
        s->epoch = 1;
        return;
    }
    /* Table-epoch directory is completely full (extremely unlikely with
     * FC_NUM_TABLE_SLOTS entries). We cannot record a targeted
     * invalidation, so fail safe: flush the whole database cache instead
     * of risking a stale hit. */
    memset(hdr->slots, 0, sizeof(hdr->slots));
    hdr->write_offset = 0;
}

static int fc_db_lookup(fc_shm_header *hdr, uint64_t key_hash, char **out_buf, size_t *out_len)
{
    uint32_t idx = (uint32_t) (key_hash % hdr->num_slots);
    for (uint32_t i = 0; i < hdr->num_slots; i++) {
        uint32_t j = (idx + i) % hdr->num_slots;
        fc_slot *s = &hdr->slots[j];
        if (s->used && !s->is_network && s->key_hash == key_hash) {
            int valid = 1;
            for (int t = 0; t < s->num_tables; t++) {
                if (fc_table_epoch_get(hdr, s->table_hashes[t]) != s->table_epochs[t]) {
                    valid = 0;
                    break;
                }
            }
            if (!valid) return 0;
            *out_buf = emalloc(s->data_len ? s->data_len : 1);
            memcpy(*out_buf, (char *) hdr->arena + s->data_offset, s->data_len);
            *out_len = s->data_len;
            return 1;
        }
        if (!s->used) break;
    }
    return 0;
}

static void fc_db_store(fc_shm_header *hdr, uint64_t key_hash, uint64_t *table_hashes,
                         int num_tables, const char *data, size_t len)
{
    if (len > hdr->arena_size / 4) return;
    if (hdr->write_offset + len > hdr->arena_size) {
        memset(hdr->slots, 0, sizeof(hdr->slots));
        hdr->write_offset = 0;
    }
    uint64_t offset = hdr->write_offset;
    memcpy((char *) hdr->arena + offset, data, len);
    hdr->write_offset += len;

    uint32_t idx = (uint32_t) (key_hash % hdr->num_slots);
    fc_slot *target = NULL;
    for (uint32_t i = 0; i < hdr->num_slots; i++) {
        uint32_t j = (idx + i) % hdr->num_slots;
        fc_slot *s = &hdr->slots[j];
        if (s->used && !s->is_network && s->key_hash == key_hash) { target = s; break; }
        if (!s->used) { target = s; break; }
    }
    if (!target) target = &hdr->slots[idx];

    target->used = 1;
    target->is_network = 0;
    target->key_hash = key_hash;
    target->data_offset = offset;
    target->data_len = len;
    target->expire_at = 0;
    target->num_tables = (uint8_t) (num_tables > FC_MAX_TABLES ? FC_MAX_TABLES : num_tables);
    for (int t = 0; t < target->num_tables; t++) {
        target->table_hashes[t] = table_hashes[t];
        target->table_epochs[t] = fc_table_epoch_get(hdr, table_hashes[t]);
    }
}

static int fc_net_lookup(fc_shm_header *hdr, uint64_t key_hash, char **out_buf, size_t *out_len)
{
    uint32_t idx = (uint32_t) (key_hash % hdr->num_slots);
    for (uint32_t i = 0; i < hdr->num_slots; i++) {
        uint32_t j = (idx + i) % hdr->num_slots;
        fc_slot *s = &hdr->slots[j];
        if (s->used && s->is_network && s->key_hash == key_hash) {
            if (s->expire_at != 0 && (uint64_t) time(NULL) >= s->expire_at) return 0;
            *out_buf = emalloc(s->data_len ? s->data_len : 1);
            memcpy(*out_buf, (char *) hdr->arena + s->data_offset, s->data_len);
            *out_len = s->data_len;
            return 1;
        }
        if (!s->used) break;
    }
    return 0;
}

static void fc_net_store(fc_shm_header *hdr, uint64_t key_hash, const char *data, size_t len, uint64_t expire_at)
{
    if (len > hdr->arena_size / 4) return;
    if (hdr->write_offset + len > hdr->arena_size) {
        memset(hdr->slots, 0, sizeof(hdr->slots));
        hdr->write_offset = 0;
    }
    uint64_t offset = hdr->write_offset;
    memcpy((char *) hdr->arena + offset, data, len);
    hdr->write_offset += len;

    uint32_t idx = (uint32_t) (key_hash % hdr->num_slots);
    fc_slot *target = NULL;
    for (uint32_t i = 0; i < hdr->num_slots; i++) {
        uint32_t j = (idx + i) % hdr->num_slots;
        fc_slot *s = &hdr->slots[j];
        if (s->used && s->is_network && s->key_hash == key_hash) { target = s; break; }
        if (!s->used) { target = s; break; }
    }
    if (!target) target = &hdr->slots[idx];

    target->used = 1;
    target->is_network = 1;
    target->key_hash = key_hash;
    target->data_offset = offset;
    target->data_len = len;
    target->expire_at = expire_at;
    target->num_tables = 0;
}

static int fc_shm_attach(void)
{
    size_t total_size = (size_t) FCG(shm_size);
    if (total_size < (2u << 20)) total_size = 100 * 1024 * 1024;

    int fd = shm_open(FCG(shm_name), O_CREAT | O_RDWR, 0666);
    if (fd < 0) return FAILURE;

    struct stat st;
    if (fstat(fd, &st) == 0 && (size_t) st.st_size < total_size) {
        if (ftruncate(fd, (off_t) total_size) != 0) {
            close(fd);
            return FAILURE;
        }
    }

    void *base = mmap(NULL, total_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (base == MAP_FAILED) return FAILURE;

    char sem_name[256];
    snprintf(sem_name, sizeof(sem_name), "%s_lock", FCG(shm_name));
    sem_t *sem = sem_open(sem_name, O_CREAT, 0666, 1);
    if (sem == SEM_FAILED) {
        munmap(base, total_size);
        return FAILURE;
    }

    FCG(shm_base) = base;
    FCG(shm_mapped_size) = total_size;
    FCG(sem) = sem;

    fc_shm_header *hdr = (fc_shm_header *) base;
    sem_wait(sem);
    if (hdr->magic != FC_MAGIC) {
        memset(hdr, 0, sizeof(fc_shm_header));
        hdr->magic = FC_MAGIC;
        hdr->total_size = total_size;
        hdr->arena_size = total_size - offsetof(fc_shm_header, arena);
        hdr->write_offset = 0;
        hdr->num_slots = FC_NUM_SLOTS;
        hdr->num_table_slots = FC_NUM_TABLE_SLOTS;
    }
    sem_post(sem);

    FCG(shm_ready) = 1;
    return SUCCESS;
}

/* ------------------------------------------------------------------ */
/* SQL query classification: read vs. write, and affected table names  */
/* ------------------------------------------------------------------ */

typedef struct {
    int is_write;
    int num_tables;
    uint64_t table_hashes[FC_MAX_TABLES];
} fc_query_info;

static int fc_ident_char(char c)
{
    return isalnum((unsigned char) c) || c == '_' || c == '.' || c == '`';
}

static void fc_parse_query(const char *q, size_t len, fc_query_info *info)
{
    memset(info, 0, sizeof(*info));
    size_t i = 0;

    while (i < len && (isspace((unsigned char) q[i]) || q[i] == '(')) i++;

    size_t kstart = i;
    size_t kscan = i; /* rewound to here before the table-name scan below,
                         so a leading UPDATE is still seen as a trigger word */
    while (i < len && isalpha((unsigned char) q[i])) i++;
    size_t klen = i - kstart;

    info->is_write = 1;
    if ((klen == 6 && strncasecmp(q + kstart, "select", 6) == 0) ||
        (klen == 4 && strncasecmp(q + kstart, "show", 4) == 0) ||
        (klen == 8 && strncasecmp(q + kstart, "describe", 8) == 0) ||
        (klen == 7 && strncasecmp(q + kstart, "explain", 7) == 0)) {
        info->is_write = 0;
    }

    i = kscan;
    while (i < len) {
        while (i < len && !isalpha((unsigned char) q[i])) i++;
        size_t tstart = i;
        while (i < len && isalpha((unsigned char) q[i])) i++;
        size_t tlen = i - tstart;
        if (tlen == 0) continue;

        int trigger =
            (tlen == 4 && strncasecmp(q + tstart, "from", 4) == 0) ||
            (tlen == 4 && strncasecmp(q + tstart, "into", 4) == 0) ||
            (tlen == 4 && strncasecmp(q + tstart, "join", 4) == 0) ||
            (tlen == 5 && strncasecmp(q + tstart, "table", 5) == 0) ||
            (tlen == 6 && strncasecmp(q + tstart, "update", 6) == 0);

        if (trigger) {
            while (i < len && isspace((unsigned char) q[i])) i++;
            size_t nstart = i;
            while (i < len && fc_ident_char(q[i])) i++;
            size_t nlen = i - nstart;
            if (nlen > 0 && info->num_tables < FC_MAX_TABLES) {
                const char *ts = q + nstart;
                size_t tl = nlen;
                if (tl >= 2 && ts[0] == '`' && ts[tl - 1] == '`') { ts++; tl -= 2; }
                if (tl > 0) {
                    info->table_hashes[info->num_tables++] = fc_fnv1a64_ci(ts, tl);
                }
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* FuzzCache\CachedResult object: uniform stand-in for mysqli_result    */
/* ------------------------------------------------------------------ */

typedef struct {
    zend_long cursor;
    zval rows;
    zend_object std;
} fc_result_obj;

#define FC_RESULT_FROM_OBJ(obj) ((fc_result_obj *) ((char *) (obj) - XtOffsetOf(fc_result_obj, std)))

static zend_object_handlers fc_result_handlers;

static zend_object *fc_result_create(zend_class_entry *ce)
{
    fc_result_obj *intern = zend_object_alloc(sizeof(fc_result_obj), ce);
    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);
    ZVAL_UNDEF(&intern->rows);
    intern->cursor = 0;
    intern->std.handlers = &fc_result_handlers;
    return &intern->std;
}

static void fc_result_free(zend_object *object)
{
    fc_result_obj *intern = FC_RESULT_FROM_OBJ(object);
    zval_ptr_dtor(&intern->rows);
    zend_object_std_dtor(object);
}

static void fc_create_cached_result(zval *return_value, zval *rows)
{
    object_init_ex(return_value, FCG(result_ce));
    fc_result_obj *ro = FC_RESULT_FROM_OBJ(Z_OBJ_P(return_value));
    ZVAL_COPY_VALUE(&ro->rows, rows);
    ro->cursor = 0;

    zend_long n = (Z_TYPE(ro->rows) == IS_ARRAY) ? zend_hash_num_elements(Z_ARRVAL(ro->rows)) : 0;
    zend_update_property_long(FCG(result_ce), Z_OBJ_P(return_value), "num_rows", sizeof("num_rows") - 1, n);
}

/* ------------------------------------------------------------------ */
/* FuzzCache\LazyConnection object: deferred mysqli_connect()           */
/* ------------------------------------------------------------------ */

#define FC_MAX_CONNECT_ARGS 8

typedef struct {
    zend_bool connected;
    uint32_t num_args;
    zval args[FC_MAX_CONNECT_ARGS];
    zval real_conn;
    zend_object std;
} fc_lazyconn_obj;

#define FC_LAZYCONN_FROM_OBJ(obj) ((fc_lazyconn_obj *) ((char *) (obj) - XtOffsetOf(fc_lazyconn_obj, std)))

static zend_object_handlers fc_lazyconn_handlers;

static zend_object *fc_lazyconn_create(zend_class_entry *ce)
{
    fc_lazyconn_obj *intern = zend_object_alloc(sizeof(fc_lazyconn_obj), ce);
    zend_object_std_init(&intern->std, ce);
    object_properties_init(&intern->std, ce);
    intern->connected = 0;
    intern->num_args = 0;
    for (int i = 0; i < FC_MAX_CONNECT_ARGS; i++) ZVAL_UNDEF(&intern->args[i]);
    ZVAL_UNDEF(&intern->real_conn);
    intern->std.handlers = &fc_lazyconn_handlers;
    return &intern->std;
}

static void fc_lazyconn_free(zend_object *object)
{
    fc_lazyconn_obj *intern = FC_LAZYCONN_FROM_OBJ(object);
    for (uint32_t i = 0; i < intern->num_args; i++) zval_ptr_dtor(&intern->args[i]);
    zval_ptr_dtor(&intern->real_conn);
    zend_object_std_dtor(object);
}

/* ------------------------------------------------------------------ */
/* Helpers to re-invoke real internal functions                        */
/* ------------------------------------------------------------------ */

static void fc_call_orig(zend_execute_data *execute_data, zval *return_value)
{
    execute_data->func->internal_function.handler(execute_data, return_value);
}

static int fc_call_mysqli_query(zval *conn, zval *query, zval *retval)
{
    zval fname;
    ZVAL_STRING(&fname, "mysqli_query");
    zval args[2];
    ZVAL_COPY_VALUE(&args[0], conn);
    ZVAL_COPY_VALUE(&args[1], query);
    FCG(reentrant) = 1;
    int ok = (call_user_function(NULL, NULL, &fname, retval, 2, args) == SUCCESS);
    FCG(reentrant) = 0;
    zval_ptr_dtor(&fname);
    return ok;
}

static int fc_call_mysqli_fetch_all(zval *result, zval *out_rows)
{
    zend_long mode = 1; /* MYSQLI_ASSOC fallback value */
    zval *c = zend_get_constant_str("MYSQLI_ASSOC", sizeof("MYSQLI_ASSOC") - 1);
    if (c && Z_TYPE_P(c) == IS_LONG) mode = Z_LVAL_P(c);

    zval fname;
    ZVAL_STRING(&fname, "mysqli_fetch_all");
    zval args[2];
    ZVAL_COPY_VALUE(&args[0], result);
    ZVAL_LONG(&args[1], mode);
    FCG(reentrant) = 1;
    int ok = (call_user_function(NULL, NULL, &fname, out_rows, 2, args) == SUCCESS);
    FCG(reentrant) = 0;
    zval_ptr_dtor(&fname);
    if (ok && Z_TYPE_P(out_rows) != IS_ARRAY) {
        zval_ptr_dtor(out_rows);
        ok = 0;
    }
    return ok;
}

static int fc_lazyconn_ensure_connected(zval *conn_zv)
{
    fc_lazyconn_obj *lc = FC_LAZYCONN_FROM_OBJ(Z_OBJ_P(conn_zv));
    if (lc->connected) return Z_TYPE(lc->real_conn) == IS_OBJECT;

    zval fname;
    ZVAL_STRING(&fname, "mysqli_connect");
    FCG(reentrant) = 1;
    int ok = (call_user_function(NULL, NULL, &fname, &lc->real_conn, lc->num_args, lc->args) == SUCCESS);
    FCG(reentrant) = 0;
    zval_ptr_dtor(&fname);
    lc->connected = 1;
    return ok && Z_TYPE(lc->real_conn) == IS_OBJECT;
}

static int fc_unserialize_buf(const char *buf, size_t len, zval *out)
{
    php_unserialize_data_t ud;
    const unsigned char *p = (const unsigned char *) buf;
    PHP_VAR_UNSERIALIZE_INIT(ud);
    ZVAL_UNDEF(out);
    int ok = php_var_unserialize(out, &p, p + len, &ud);
    PHP_VAR_UNSERIALIZE_DESTROY(ud);
    if (!ok) {
        zval_ptr_dtor(out);
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* mysqli interception                                                  */
/* ------------------------------------------------------------------ */

static void fc_handle_mysqli_connect(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    object_init_ex(return_value, FCG(lazyconn_ce));
    fc_lazyconn_obj *lc = FC_LAZYCONN_FROM_OBJ(Z_OBJ_P(return_value));
    lc->num_args = argc > FC_MAX_CONNECT_ARGS ? FC_MAX_CONNECT_ARGS : argc;
    for (uint32_t i = 0; i < lc->num_args; i++) {
        zval *a = ZEND_CALL_ARG(execute_data, i + 1);
        ZVAL_COPY(&lc->args[i], a);
    }
}

static void fc_handle_mysqli_close(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    if (argc < 1) { fc_call_orig(execute_data, return_value); return; }
    zval *conn_zv = ZEND_CALL_ARG(execute_data, 1);

    if (Z_TYPE_P(conn_zv) == IS_OBJECT && Z_OBJCE_P(conn_zv) == FCG(lazyconn_ce)) {
        fc_lazyconn_obj *lc = FC_LAZYCONN_FROM_OBJ(Z_OBJ_P(conn_zv));
        if (lc->connected && Z_TYPE(lc->real_conn) == IS_OBJECT) {
            zval fname;
            ZVAL_STRING(&fname, "mysqli_close");
            zval args[1];
            ZVAL_COPY_VALUE(&args[0], &lc->real_conn);
            zval tmp_ret;
            FCG(reentrant) = 1;
            call_user_function(NULL, NULL, &fname, &tmp_ret, 1, args);
            FCG(reentrant) = 0;
            zval_ptr_dtor(&fname);
            zval_ptr_dtor(&tmp_ret);
        }
        ZVAL_TRUE(return_value);
        return;
    }
    fc_call_orig(execute_data, return_value);
}

static void fc_handle_mysqli_query(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    if (argc < 2) { fc_call_orig(execute_data, return_value); return; }

    zval *conn_zv = ZEND_CALL_ARG(execute_data, 1);
    zval *query_zv = ZEND_CALL_ARG(execute_data, 2);

    if (Z_TYPE_P(query_zv) != IS_STRING) { fc_call_orig(execute_data, return_value); return; }

    int is_lazy = (Z_TYPE_P(conn_zv) == IS_OBJECT && Z_OBJCE_P(conn_zv) == FCG(lazyconn_ce));

    fc_query_info qinfo;
    fc_parse_query(Z_STRVAL_P(query_zv), Z_STRLEN_P(query_zv), &qinfo);

    if (qinfo.is_write) {
        if (is_lazy) {
            if (!fc_lazyconn_ensure_connected(conn_zv)) { ZVAL_FALSE(return_value); return; }
            fc_lazyconn_obj *lc = FC_LAZYCONN_FROM_OBJ(Z_OBJ_P(conn_zv));
            fc_call_mysqli_query(&lc->real_conn, query_zv, return_value);
        } else {
            fc_call_orig(execute_data, return_value);
        }
        if (qinfo.num_tables > 0 && FCG(shm_ready)) {
            FC_LOCK();
            for (int t = 0; t < qinfo.num_tables; t++) {
                fc_table_epoch_bump((fc_shm_header *) FCG(shm_base), qinfo.table_hashes[t]);
            }
            FC_UNLOCK();
        }
        return;
    }

    if (qinfo.num_tables == 0 || !FCG(shm_ready)) {
        /* No known invalidation key (or cache unavailable): run normally
         * without caching, but still honor the lazy connection. */
        if (is_lazy) {
            if (!fc_lazyconn_ensure_connected(conn_zv)) { ZVAL_FALSE(return_value); return; }
            fc_lazyconn_obj *lc = FC_LAZYCONN_FROM_OBJ(Z_OBJ_P(conn_zv));
            fc_call_mysqli_query(&lc->real_conn, query_zv, return_value);
        } else {
            fc_call_orig(execute_data, return_value);
        }
        return;
    }

    uint64_t key_hash = fc_fnv1a64(Z_STRVAL_P(query_zv), Z_STRLEN_P(query_zv));
    char *cached_buf = NULL;
    size_t cached_len = 0;
    int hit;
    FC_LOCK();
    hit = fc_db_lookup((fc_shm_header *) FCG(shm_base), key_hash, &cached_buf, &cached_len);
    FC_UNLOCK();

    if (hit) {
        zval rows;
        int ok = fc_unserialize_buf(cached_buf, cached_len, &rows);
        efree(cached_buf);
        if (ok) {
            fc_create_cached_result(return_value, &rows);
            return;
        }
        /* corrupt entry: fall through to real execution below */
    }

    /* Cache miss: execute for real (this is where a lazy connection
     * finally, and only now, establishes its DB connection). */
    zval real_result;
    ZVAL_UNDEF(&real_result);
    if (is_lazy) {
        if (!fc_lazyconn_ensure_connected(conn_zv)) { ZVAL_FALSE(return_value); return; }
        fc_lazyconn_obj *lc = FC_LAZYCONN_FROM_OBJ(Z_OBJ_P(conn_zv));
        fc_call_mysqli_query(&lc->real_conn, query_zv, &real_result);
    } else {
        fc_call_orig(execute_data, &real_result);
    }

    if (Z_TYPE(real_result) != IS_OBJECT) {
        ZVAL_COPY_VALUE(return_value, &real_result);
        return;
    }

    zval rows;
    if (fc_call_mysqli_fetch_all(&real_result, &rows)) {
        smart_str buf = {0};
        php_serialize_data_t sd;
        PHP_VAR_SERIALIZE_INIT(sd);
        php_var_serialize(&buf, &rows, &sd);
        PHP_VAR_SERIALIZE_DESTROY(sd);
        if (buf.s) {
            FC_LOCK();
            fc_db_store((fc_shm_header *) FCG(shm_base), key_hash, qinfo.table_hashes, qinfo.num_tables,
                        ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
            FC_UNLOCK();
        }
        smart_str_free(&buf);

        zval_ptr_dtor(&real_result);
        fc_create_cached_result(return_value, &rows);
    } else {
        ZVAL_COPY_VALUE(return_value, &real_result);
    }
}

typedef enum { FC_FETCH_ASSOC, FC_FETCH_ARRAY, FC_FETCH_ROW, FC_FETCH_OBJECT, FC_FETCH_ALL } fc_fetch_kind;

/* Shared row-serving logic for FuzzCache\CachedResult / CachedStatement:
 * used both by the procedural mysqli_fetch_*() interception below and by
 * the native OOP methods (mysqli::query()'s result, PDOStatement) further
 * down, so cached rows are served identically regardless of call style. */

static zval *fc_result_next_row(fc_result_obj *ro)
{
    HashTable *rows = (Z_TYPE(ro->rows) == IS_ARRAY) ? Z_ARRVAL(ro->rows) : NULL;
    uint32_t nrows = rows ? zend_hash_num_elements(rows) : 0;
    if ((uint32_t) ro->cursor >= nrows) return NULL;
    zval *row = zend_hash_index_find(rows, ro->cursor);
    ro->cursor++;
    return row;
}

static void fc_result_fetch_all(fc_result_obj *ro, zval *return_value)
{
    if (Z_TYPE(ro->rows) == IS_ARRAY) { ZVAL_COPY(return_value, &ro->rows); } else { array_init(return_value); }
}

static void fc_result_fetch_assoc(fc_result_obj *ro, zval *return_value)
{
    zval *row = fc_result_next_row(ro);
    if (!row) { ZVAL_NULL(return_value); return; }
    ZVAL_COPY(return_value, row);
}

static void fc_result_fetch_row(fc_result_obj *ro, zval *return_value)
{
    zval *row = fc_result_next_row(ro);
    if (!row) { ZVAL_NULL(return_value); return; }
    array_init(return_value);
    if (Z_TYPE_P(row) == IS_ARRAY) {
        zval *v;
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(row), v) {
            zval tmp;
            ZVAL_COPY(&tmp, v);
            add_next_index_zval(return_value, &tmp);
        } ZEND_HASH_FOREACH_END();
    }
}

static void fc_result_fetch_array(fc_result_obj *ro, zval *return_value)
{
    zval *row = fc_result_next_row(ro);
    if (!row) { ZVAL_NULL(return_value); return; }
    array_init(return_value);
    if (Z_TYPE_P(row) == IS_ARRAY) {
        zend_string *key;
        zval *v;
        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(row), key, v) {
            if (key) {
                zval tmp;
                ZVAL_COPY(&tmp, v);
                add_assoc_zval(return_value, ZSTR_VAL(key), &tmp);
            }
        } ZEND_HASH_FOREACH_END();
        ZEND_HASH_FOREACH_VAL(Z_ARRVAL_P(row), v) {
            zval tmp;
            ZVAL_COPY(&tmp, v);
            add_next_index_zval(return_value, &tmp);
        } ZEND_HASH_FOREACH_END();
    }
}

static void fc_result_fetch_object(fc_result_obj *ro, zval *return_value)
{
    zval *row = fc_result_next_row(ro);
    if (!row) { ZVAL_NULL(return_value); return; }
    object_init(return_value);
    if (Z_TYPE_P(row) == IS_ARRAY) {
        zend_string *key;
        zval *v;
        ZEND_HASH_FOREACH_STR_KEY_VAL(Z_ARRVAL_P(row), key, v) {
            if (key) {
                zval tmp;
                ZVAL_COPY(&tmp, v);
                zend_update_property_ex(NULL, Z_OBJ_P(return_value), key, &tmp);
                zval_ptr_dtor(&tmp);
            }
        } ZEND_HASH_FOREACH_END();
    }
}

static void fc_handle_mysqli_fetch(zend_execute_data *execute_data, zval *return_value, fc_fetch_kind kind)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    if (argc < 1) { fc_call_orig(execute_data, return_value); return; }
    zval *result_zv = ZEND_CALL_ARG(execute_data, 1);

    if (Z_TYPE_P(result_zv) != IS_OBJECT || Z_OBJCE_P(result_zv) != FCG(result_ce)) {
        fc_call_orig(execute_data, return_value);
        return;
    }

    fc_result_obj *ro = FC_RESULT_FROM_OBJ(Z_OBJ_P(result_zv));
    switch (kind) {
        case FC_FETCH_ALL:    fc_result_fetch_all(ro, return_value); break;
        case FC_FETCH_ASSOC:  fc_result_fetch_assoc(ro, return_value); break;
        case FC_FETCH_ROW:    fc_result_fetch_row(ro, return_value); break;
        case FC_FETCH_ARRAY:  fc_result_fetch_array(ro, return_value); break;
        case FC_FETCH_OBJECT: fc_result_fetch_object(ro, return_value); break;
    }
}

static void fc_handle_mysqli_num_rows(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    if (argc < 1) { fc_call_orig(execute_data, return_value); return; }
    zval *result_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(result_zv) != IS_OBJECT || Z_OBJCE_P(result_zv) != FCG(result_ce)) {
        fc_call_orig(execute_data, return_value);
        return;
    }
    fc_result_obj *ro = FC_RESULT_FROM_OBJ(Z_OBJ_P(result_zv));
    zend_long n = (Z_TYPE(ro->rows) == IS_ARRAY) ? zend_hash_num_elements(Z_ARRVAL(ro->rows)) : 0;
    ZVAL_LONG(return_value, n);
}

static void fc_handle_mysqli_free_result(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    if (argc < 1) { fc_call_orig(execute_data, return_value); return; }
    zval *result_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(result_zv) != IS_OBJECT || Z_OBJCE_P(result_zv) != FCG(result_ce)) {
        fc_call_orig(execute_data, return_value);
        return;
    }
    ZVAL_NULL(return_value);
}

/* ------------------------------------------------------------------ */
/* mysqli OOP: FuzzCache\CachedResult native methods + mysqli::query()  */
/* ------------------------------------------------------------------ */

#define FC_THIS_RESULT_OBJ() FC_RESULT_FROM_OBJ(Z_OBJ_P(ZEND_THIS))

PHP_METHOD(FuzzCacheCachedResult, fetch_assoc)  { fc_result_fetch_assoc(FC_THIS_RESULT_OBJ(), return_value); }
PHP_METHOD(FuzzCacheCachedResult, fetch_array)  { fc_result_fetch_array(FC_THIS_RESULT_OBJ(), return_value); }
PHP_METHOD(FuzzCacheCachedResult, fetch_row)    { fc_result_fetch_row(FC_THIS_RESULT_OBJ(), return_value); }
PHP_METHOD(FuzzCacheCachedResult, fetch_object) { fc_result_fetch_object(FC_THIS_RESULT_OBJ(), return_value); }
PHP_METHOD(FuzzCacheCachedResult, fetch_all)    { fc_result_fetch_all(FC_THIS_RESULT_OBJ(), return_value); }

PHP_METHOD(FuzzCacheCachedResult, data_seek)
{
    zend_long offset = 0;
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_LONG(offset)
    ZEND_PARSE_PARAMETERS_END();
    FC_THIS_RESULT_OBJ()->cursor = offset;
    RETURN_TRUE;
}

PHP_METHOD(FuzzCacheCachedResult, free)
{
    ZEND_PARSE_PARAMETERS_NONE();
}

/* Iterator interface, so `foreach ($result as $row)` works the same as
 * on a real mysqli_result/PDOStatement (both implement Traversable). */
PHP_METHOD(FuzzCacheCachedResult, rewind) { FC_THIS_RESULT_OBJ()->cursor = 0; }
PHP_METHOD(FuzzCacheCachedResult, next)   { FC_THIS_RESULT_OBJ()->cursor++; }
PHP_METHOD(FuzzCacheCachedResult, key)    { RETURN_LONG(FC_THIS_RESULT_OBJ()->cursor); }
PHP_METHOD(FuzzCacheCachedResult, current)
{
    fc_result_obj *ro = FC_THIS_RESULT_OBJ();
    HashTable *rows = (Z_TYPE(ro->rows) == IS_ARRAY) ? Z_ARRVAL(ro->rows) : NULL;
    zval *row = rows ? zend_hash_index_find(rows, ro->cursor) : NULL;
    if (row) { ZVAL_COPY(return_value, row); } else { ZVAL_NULL(return_value); }
}
PHP_METHOD(FuzzCacheCachedResult, valid)
{
    fc_result_obj *ro = FC_THIS_RESULT_OBJ();
    HashTable *rows = (Z_TYPE(ro->rows) == IS_ARRAY) ? Z_ARRVAL(ro->rows) : NULL;
    uint32_t nrows = rows ? zend_hash_num_elements(rows) : 0;
    RETURN_BOOL((uint32_t) ro->cursor < nrows);
}

/* mysqli::query(): identical caching logic to the procedural
 * mysqli_query() handler, minus the lazy-connection branch — by the time
 * a method is called, $this is already a real, connected mysqli object,
 * so there is nothing to defer. Still gets the full read-cache /
 * write-invalidation benefit. */
static void fc_handle_mysqli_query_method(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    if (argc < 1) { fc_call_orig(execute_data, return_value); return; }
    zval *query_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(query_zv) != IS_STRING) { fc_call_orig(execute_data, return_value); return; }

    fc_query_info qinfo;
    fc_parse_query(Z_STRVAL_P(query_zv), Z_STRLEN_P(query_zv), &qinfo);

    if (qinfo.is_write) {
        fc_call_orig(execute_data, return_value);
        if (qinfo.num_tables > 0 && FCG(shm_ready)) {
            FC_LOCK();
            for (int t = 0; t < qinfo.num_tables; t++) {
                fc_table_epoch_bump((fc_shm_header *) FCG(shm_base), qinfo.table_hashes[t]);
            }
            FC_UNLOCK();
        }
        return;
    }

    if (qinfo.num_tables == 0 || !FCG(shm_ready)) {
        fc_call_orig(execute_data, return_value);
        return;
    }

    uint64_t key_hash = fc_fnv1a64(Z_STRVAL_P(query_zv), Z_STRLEN_P(query_zv));
    char *cached_buf = NULL;
    size_t cached_len = 0;
    int hit;
    FC_LOCK();
    hit = fc_db_lookup((fc_shm_header *) FCG(shm_base), key_hash, &cached_buf, &cached_len);
    FC_UNLOCK();

    if (hit) {
        zval rows;
        int ok = fc_unserialize_buf(cached_buf, cached_len, &rows);
        efree(cached_buf);
        if (ok) {
            fc_create_cached_result(return_value, &rows);
            return;
        }
    }

    zval real_result;
    ZVAL_UNDEF(&real_result);
    fc_call_orig(execute_data, &real_result);

    if (Z_TYPE(real_result) != IS_OBJECT) {
        ZVAL_COPY_VALUE(return_value, &real_result);
        return;
    }

    zval rows;
    if (fc_call_mysqli_fetch_all(&real_result, &rows)) {
        smart_str buf = {0};
        php_serialize_data_t sd;
        PHP_VAR_SERIALIZE_INIT(sd);
        php_var_serialize(&buf, &rows, &sd);
        PHP_VAR_SERIALIZE_DESTROY(sd);
        if (buf.s) {
            FC_LOCK();
            fc_db_store((fc_shm_header *) FCG(shm_base), key_hash, qinfo.table_hashes, qinfo.num_tables,
                        ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
            FC_UNLOCK();
        }
        smart_str_free(&buf);
        zval_ptr_dtor(&real_result);
        fc_create_cached_result(return_value, &rows);
    } else {
        ZVAL_COPY_VALUE(return_value, &real_result);
    }
}

/* ------------------------------------------------------------------ */
/* curl interception                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    char *url;
    zend_bool return_transfer;
} fc_curl_info;

static void fc_curl_info_pdtor(zval *el)
{
    fc_curl_info *info = (fc_curl_info *) Z_PTR_P(el);
    if (info) {
        if (info->url) efree(info->url);
        efree(info);
    }
}

static void fc_handle_curl_setopt(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    fc_call_orig(execute_data, return_value);
    if (argc < 3) return;

    zval *ch_zv = ZEND_CALL_ARG(execute_data, 1);
    zval *opt_zv = ZEND_CALL_ARG(execute_data, 2);
    zval *val_zv = ZEND_CALL_ARG(execute_data, 3);
    if (Z_TYPE_P(ch_zv) != IS_OBJECT || Z_TYPE_P(opt_zv) != IS_LONG) return;

    static zend_long curlopt_url = -1, curlopt_returntransfer = -1;
    if (curlopt_url == -1) {
        zval *c = zend_get_constant_str("CURLOPT_URL", sizeof("CURLOPT_URL") - 1);
        curlopt_url = (c && Z_TYPE_P(c) == IS_LONG) ? Z_LVAL_P(c) : 10002;
        c = zend_get_constant_str("CURLOPT_RETURNTRANSFER", sizeof("CURLOPT_RETURNTRANSFER") - 1);
        curlopt_returntransfer = (c && Z_TYPE_P(c) == IS_LONG) ? Z_LVAL_P(c) : 19913;
    }

    if (Z_LVAL_P(opt_zv) != curlopt_url && Z_LVAL_P(opt_zv) != curlopt_returntransfer) return;

    zend_ulong handle_id = Z_OBJ_HANDLE_P(ch_zv);
    fc_curl_info *info = zend_hash_index_find_ptr(&FCG(curl_handles), handle_id);
    if (!info) {
        info = ecalloc(1, sizeof(fc_curl_info));
        zend_hash_index_update_ptr(&FCG(curl_handles), handle_id, info);
    }

    if (Z_LVAL_P(opt_zv) == curlopt_url && Z_TYPE_P(val_zv) == IS_STRING) {
        if (info->url) efree(info->url);
        info->url = estrndup(Z_STRVAL_P(val_zv), Z_STRLEN_P(val_zv));
    } else if (Z_LVAL_P(opt_zv) == curlopt_returntransfer) {
        info->return_transfer = zend_is_true(val_zv);
    }
}

static void fc_handle_curl_exec(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    if (argc < 1) { fc_call_orig(execute_data, return_value); return; }
    zval *ch_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(ch_zv) != IS_OBJECT || !FCG(shm_ready)) { fc_call_orig(execute_data, return_value); return; }

    zend_ulong handle_id = Z_OBJ_HANDLE_P(ch_zv);
    fc_curl_info *info = zend_hash_index_find_ptr(&FCG(curl_handles), handle_id);
    if (!info || !info->url || !info->return_transfer) {
        fc_call_orig(execute_data, return_value);
        return;
    }

    uint64_t key_hash = fc_fnv1a64(info->url, strlen(info->url));
    char *buf = NULL;
    size_t len = 0;
    int hit;
    FC_LOCK();
    hit = fc_net_lookup((fc_shm_header *) FCG(shm_base), key_hash, &buf, &len);
    FC_UNLOCK();

    if (hit) {
        ZVAL_STRINGL(return_value, buf, len);
        efree(buf);
        return;
    }

    fc_call_orig(execute_data, return_value);
    if (Z_TYPE_P(return_value) == IS_STRING) {
        zend_long ttl = FCG(network_ttl);
        uint64_t expire_at = ttl > 0 ? (uint64_t) (time(NULL) + ttl) : 0;
        FC_LOCK();
        fc_net_store((fc_shm_header *) FCG(shm_base), key_hash, Z_STRVAL_P(return_value), Z_STRLEN_P(return_value), expire_at);
        FC_UNLOCK();
    }
}

static void fc_handle_curl_close(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    fc_call_orig(execute_data, return_value);
    if (argc < 1) return;
    zval *ch_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(ch_zv) == IS_OBJECT) {
        zend_hash_index_del(&FCG(curl_handles), Z_OBJ_HANDLE_P(ch_zv));
    }
}

/* ------------------------------------------------------------------ */
/* FuzzCache\CachedStatement: PDO-flavored twin of CachedResult, used as  */
/* the swap-in return value for PDO::query(). Same fc_result_obj layout  */
/* and object handlers as CachedResult, just PDO-style method names.     */
/* ------------------------------------------------------------------ */

PHP_METHOD(FuzzCacheCachedStatement, fetch)    { fc_result_fetch_assoc(FC_THIS_RESULT_OBJ(), return_value); }
PHP_METHOD(FuzzCacheCachedStatement, fetchAll) { fc_result_fetch_all(FC_THIS_RESULT_OBJ(), return_value); }
PHP_METHOD(FuzzCacheCachedStatement, rowCount)
{
    fc_result_obj *ro = FC_THIS_RESULT_OBJ();
    RETURN_LONG((Z_TYPE(ro->rows) == IS_ARRAY) ? zend_hash_num_elements(Z_ARRVAL(ro->rows)) : 0);
}
PHP_METHOD(FuzzCacheCachedStatement, closeCursor) { RETURN_TRUE; }

PHP_METHOD(FuzzCacheCachedStatement, rewind) { FC_THIS_RESULT_OBJ()->cursor = 0; }
PHP_METHOD(FuzzCacheCachedStatement, next)   { FC_THIS_RESULT_OBJ()->cursor++; }
PHP_METHOD(FuzzCacheCachedStatement, key)    { RETURN_LONG(FC_THIS_RESULT_OBJ()->cursor); }
PHP_METHOD(FuzzCacheCachedStatement, current)
{
    fc_result_obj *ro = FC_THIS_RESULT_OBJ();
    HashTable *rows = (Z_TYPE(ro->rows) == IS_ARRAY) ? Z_ARRVAL(ro->rows) : NULL;
    zval *row = rows ? zend_hash_index_find(rows, ro->cursor) : NULL;
    if (row) { ZVAL_COPY(return_value, row); } else { ZVAL_NULL(return_value); }
}
PHP_METHOD(FuzzCacheCachedStatement, valid)
{
    fc_result_obj *ro = FC_THIS_RESULT_OBJ();
    HashTable *rows = (Z_TYPE(ro->rows) == IS_ARRAY) ? Z_ARRVAL(ro->rows) : NULL;
    uint32_t nrows = rows ? zend_hash_num_elements(rows) : 0;
    RETURN_BOOL((uint32_t) ro->cursor < nrows);
}

/* ------------------------------------------------------------------ */
/* PDO interception                                                     */
/* ------------------------------------------------------------------ */

/* PDO::prepare() is never intercepted for its return value — a real
 * PDOStatement is driver-internal state that we cannot safely fabricate,
 * and userland code routinely calls bindValue()/bindParam()/bindColumn()
 * on it afterward, which we do not (and safely should not) reimplement.
 * Instead we only *observe* prepare() to remember the SQL template for
 * whichever real PDOStatement it returns, keyed by that object's handle,
 * then intercept PDOStatement::execute()/fetch()/fetchAll()/rowCount() on
 * the same, still-completely-real object. Any usage we can't safely
 * reason about (bindValue/bindParam workflows, unrecognized tables, a
 * missing side-table entry) always falls through to fully real,
 * untouched behavior — caching is strictly opportunistic, never a
 * correctness risk. */

typedef struct {
    char *sql;
    zend_bool serving_from_cache;
    zval rows;
    zend_long cursor;
} fc_pdo_stmt_info;

static void fc_pdo_stmt_info_pdtor(zval *el)
{
    fc_pdo_stmt_info *info = (fc_pdo_stmt_info *) Z_PTR_P(el);
    if (info) {
        if (info->sql) efree(info->sql);
        zval_ptr_dtor(&info->rows);
        efree(info);
    }
}

static fc_pdo_stmt_info *fc_pdo_stmt_info_for(zval *obj_zv, int create)
{
    zend_ulong handle = Z_OBJ_HANDLE_P(obj_zv);
    fc_pdo_stmt_info *info = zend_hash_index_find_ptr(&FCG(pdo_stmt_templates), handle);
    if (!info && create) {
        info = ecalloc(1, sizeof(fc_pdo_stmt_info));
        ZVAL_UNDEF(&info->rows);
        zend_hash_index_update_ptr(&FCG(pdo_stmt_templates), handle, info);
    }
    return info;
}

static void fc_handle_pdo_prepare(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    fc_call_orig(execute_data, return_value);
    if (argc < 1 || Z_TYPE_P(return_value) != IS_OBJECT) return;

    zval *sql_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(sql_zv) != IS_STRING) return;

    fc_pdo_stmt_info *info = fc_pdo_stmt_info_for(return_value, 1);
    if (info->sql) efree(info->sql);
    info->sql = estrndup(Z_STRVAL_P(sql_zv), Z_STRLEN_P(sql_zv));
    info->serving_from_cache = 0;
}

static void fc_handle_pdo_exec(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    fc_call_orig(execute_data, return_value);
    if (argc < 1 || !FCG(shm_ready)) return;

    zval *sql_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(sql_zv) != IS_STRING) return;

    fc_query_info qinfo;
    fc_parse_query(Z_STRVAL_P(sql_zv), Z_STRLEN_P(sql_zv), &qinfo);
    if (qinfo.num_tables > 0) {
        FC_LOCK();
        for (int t = 0; t < qinfo.num_tables; t++) {
            fc_table_epoch_bump((fc_shm_header *) FCG(shm_base), qinfo.table_hashes[t]);
        }
        FC_UNLOCK();
    }
}

static int fc_call_pdostmt_fetch_all(zval *stmt, zval *out_rows)
{
    zval fname;
    ZVAL_STRING(&fname, "fetchAll");
    zval args[1];
    ZVAL_LONG(&args[0], 2); /* PDO::FETCH_ASSOC == 2, stable across versions */
    FCG(reentrant) = 1;
    int ok = (call_user_function(NULL, stmt, &fname, out_rows, 1, args) == SUCCESS);
    FCG(reentrant) = 0;
    zval_ptr_dtor(&fname);
    if (ok && Z_TYPE_P(out_rows) != IS_ARRAY) {
        zval_ptr_dtor(out_rows);
        ok = 0;
    }
    return ok;
}

static void fc_handle_pdostmt_execute(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);

    fc_pdo_stmt_info *info = fc_pdo_stmt_info_for(&EX(This), 0);
    if (!info || !info->sql) { fc_call_orig(execute_data, return_value); return; }

    info->serving_from_cache = 0;

    /* Only attempt caching when execute() is given an explicit params
     * array — if bindValue()/bindParam() were used instead, we have no
     * visibility into the actual bound values and must not guess. */
    if (argc < 1 || !FCG(shm_ready)) { fc_call_orig(execute_data, return_value); return; }
    zval *params_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(params_zv) != IS_ARRAY) { fc_call_orig(execute_data, return_value); return; }

    fc_query_info qinfo;
    fc_parse_query(info->sql, strlen(info->sql), &qinfo);

    if (qinfo.is_write) {
        fc_call_orig(execute_data, return_value);
        if (qinfo.num_tables > 0) {
            FC_LOCK();
            for (int t = 0; t < qinfo.num_tables; t++) {
                fc_table_epoch_bump((fc_shm_header *) FCG(shm_base), qinfo.table_hashes[t]);
            }
            FC_UNLOCK();
        }
        return;
    }

    if (qinfo.num_tables == 0) { fc_call_orig(execute_data, return_value); return; }

    smart_str pbuf = {0};
    php_serialize_data_t psd;
    PHP_VAR_SERIALIZE_INIT(psd);
    php_var_serialize(&pbuf, params_zv, &psd);
    PHP_VAR_SERIALIZE_DESTROY(psd);

    uint64_t key_hash = fc_fnv1a64(info->sql, strlen(info->sql));
    if (pbuf.s) key_hash ^= fc_fnv1a64(ZSTR_VAL(pbuf.s), ZSTR_LEN(pbuf.s));
    smart_str_free(&pbuf);

    char *cached_buf = NULL;
    size_t cached_len = 0;
    int hit;
    FC_LOCK();
    hit = fc_db_lookup((fc_shm_header *) FCG(shm_base), key_hash, &cached_buf, &cached_len);
    FC_UNLOCK();

    if (hit) {
        zval rows;
        int ok = fc_unserialize_buf(cached_buf, cached_len, &rows);
        efree(cached_buf);
        if (ok) {
            zval_ptr_dtor(&info->rows);
            ZVAL_COPY_VALUE(&info->rows, &rows);
            info->cursor = 0;
            info->serving_from_cache = 1;
            RETVAL_TRUE;
            return;
        }
    }

    fc_call_orig(execute_data, return_value);
    if (Z_TYPE_P(return_value) != IS_TRUE && Z_TYPE_P(return_value) != IS_FALSE) return;
    if (!zend_is_true(return_value)) return;

    zval rows;
    if (fc_call_pdostmt_fetch_all(&EX(This), &rows)) {
        smart_str buf = {0};
        php_serialize_data_t sd;
        PHP_VAR_SERIALIZE_INIT(sd);
        php_var_serialize(&buf, &rows, &sd);
        PHP_VAR_SERIALIZE_DESTROY(sd);
        if (buf.s) {
            FC_LOCK();
            fc_db_store((fc_shm_header *) FCG(shm_base), key_hash, qinfo.table_hashes, qinfo.num_tables,
                        ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
            FC_UNLOCK();
        }
        smart_str_free(&buf);

        zval_ptr_dtor(&info->rows);
        ZVAL_COPY_VALUE(&info->rows, &rows);
        info->cursor = 0;
        info->serving_from_cache = 1;
    }
}

static void fc_handle_pdostmt_fetch(zend_execute_data *execute_data, zval *return_value)
{
    fc_pdo_stmt_info *info = fc_pdo_stmt_info_for(&EX(This), 0);
    if (!info || !info->serving_from_cache) { fc_call_orig(execute_data, return_value); return; }

    HashTable *rows = (Z_TYPE(info->rows) == IS_ARRAY) ? Z_ARRVAL(info->rows) : NULL;
    uint32_t nrows = rows ? zend_hash_num_elements(rows) : 0;
    if ((uint32_t) info->cursor >= nrows) { RETVAL_FALSE; return; }
    zval *row = zend_hash_index_find(rows, info->cursor);
    info->cursor++;
    if (row) { ZVAL_COPY(return_value, row); } else { RETVAL_FALSE; }
}

static void fc_handle_pdostmt_fetch_all(zend_execute_data *execute_data, zval *return_value)
{
    fc_pdo_stmt_info *info = fc_pdo_stmt_info_for(&EX(This), 0);
    if (!info || !info->serving_from_cache) { fc_call_orig(execute_data, return_value); return; }
    if (Z_TYPE(info->rows) == IS_ARRAY) { ZVAL_COPY(return_value, &info->rows); } else { array_init(return_value); }
}

static void fc_handle_pdostmt_row_count(zend_execute_data *execute_data, zval *return_value)
{
    fc_pdo_stmt_info *info = fc_pdo_stmt_info_for(&EX(This), 0);
    if (!info || !info->serving_from_cache) { fc_call_orig(execute_data, return_value); return; }
    ZVAL_LONG(return_value, (Z_TYPE(info->rows) == IS_ARRAY) ? zend_hash_num_elements(Z_ARRVAL(info->rows)) : 0);
}

/* PDO::query(): no prepare/execute split, so (unlike PDOStatement above)
 * we fully control the returned object and can use the same swap-in
 * CachedResult/CachedStatement trick as mysqli_query(). */
static void fc_handle_pdo_query(zend_execute_data *execute_data, zval *return_value)
{
    uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
    if (argc < 1) { fc_call_orig(execute_data, return_value); return; }
    zval *sql_zv = ZEND_CALL_ARG(execute_data, 1);
    if (Z_TYPE_P(sql_zv) != IS_STRING) { fc_call_orig(execute_data, return_value); return; }

    fc_query_info qinfo;
    fc_parse_query(Z_STRVAL_P(sql_zv), Z_STRLEN_P(sql_zv), &qinfo);

    if (qinfo.is_write || qinfo.num_tables == 0 || !FCG(shm_ready)) {
        fc_call_orig(execute_data, return_value);
        if (qinfo.is_write && qinfo.num_tables > 0 && FCG(shm_ready)) {
            FC_LOCK();
            for (int t = 0; t < qinfo.num_tables; t++) {
                fc_table_epoch_bump((fc_shm_header *) FCG(shm_base), qinfo.table_hashes[t]);
            }
            FC_UNLOCK();
        }
        return;
    }

    uint64_t key_hash = fc_fnv1a64(Z_STRVAL_P(sql_zv), Z_STRLEN_P(sql_zv));
    char *cached_buf = NULL;
    size_t cached_len = 0;
    int hit;
    FC_LOCK();
    hit = fc_db_lookup((fc_shm_header *) FCG(shm_base), key_hash, &cached_buf, &cached_len);
    FC_UNLOCK();

    if (hit) {
        zval rows;
        int ok = fc_unserialize_buf(cached_buf, cached_len, &rows);
        efree(cached_buf);
        if (ok) {
            object_init_ex(return_value, FCG(stmt_ce));
            fc_result_obj *ro = FC_RESULT_FROM_OBJ(Z_OBJ_P(return_value));
            ZVAL_COPY_VALUE(&ro->rows, &rows);
            ro->cursor = 0;
            return;
        }
    }

    zval real_stmt;
    ZVAL_UNDEF(&real_stmt);
    fc_call_orig(execute_data, &real_stmt);
    if (Z_TYPE(real_stmt) != IS_OBJECT) {
        ZVAL_COPY_VALUE(return_value, &real_stmt);
        return;
    }

    zval rows;
    if (fc_call_pdostmt_fetch_all(&real_stmt, &rows)) {
        smart_str buf = {0};
        php_serialize_data_t sd;
        PHP_VAR_SERIALIZE_INIT(sd);
        php_var_serialize(&buf, &rows, &sd);
        PHP_VAR_SERIALIZE_DESTROY(sd);
        if (buf.s) {
            FC_LOCK();
            fc_db_store((fc_shm_header *) FCG(shm_base), key_hash, qinfo.table_hashes, qinfo.num_tables,
                        ZSTR_VAL(buf.s), ZSTR_LEN(buf.s));
            FC_UNLOCK();
        }
        smart_str_free(&buf);
        zval_ptr_dtor(&real_stmt);

        object_init_ex(return_value, FCG(stmt_ce));
        fc_result_obj *ro = FC_RESULT_FROM_OBJ(Z_OBJ_P(return_value));
        ZVAL_COPY_VALUE(&ro->rows, &rows);
        ro->cursor = 0;
    } else {
        ZVAL_COPY_VALUE(return_value, &real_stmt);
    }
}

/* ------------------------------------------------------------------ */
/* Userland helper functions                                           */
/* ------------------------------------------------------------------ */

/* {{{ proto bool fuzzcache_reset()
   Clears the entire shared-memory cache (database + network entries).
   This is the supported way to reset the cache between fuzzing runs; the
   shared memory segment itself is not tied to any filesystem path (in
   particular, macOS has no /dev/shm to remove a file from). */
PHP_FUNCTION(fuzzcache_reset)
{
    ZEND_PARSE_PARAMETERS_NONE();

    if (!FCG(shm_ready)) {
        RETURN_FALSE;
    }

    fc_shm_header *hdr = (fc_shm_header *) FCG(shm_base);
    FC_LOCK();
    memset(hdr->slots, 0, sizeof(hdr->slots));
    memset(hdr->table_epochs, 0, sizeof(hdr->table_epochs));
    hdr->write_offset = 0;
    FC_UNLOCK();

    RETURN_TRUE;
}
/* }}} */

/* {{{ proto array fuzzcache_stats()
   Returns basic occupancy stats about the shared-memory cache. */
PHP_FUNCTION(fuzzcache_stats)
{
    ZEND_PARSE_PARAMETERS_NONE();

    array_init(return_value);
    add_assoc_bool(return_value, "ready", FCG(shm_ready));
    if (!FCG(shm_ready)) {
        return;
    }

    fc_shm_header *hdr = (fc_shm_header *) FCG(shm_base);
    uint32_t db_used = 0, net_used = 0;

    FC_LOCK();
    for (uint32_t i = 0; i < hdr->num_slots; i++) {
        if (!hdr->slots[i].used) continue;
        if (hdr->slots[i].is_network) net_used++; else db_used++;
    }
    zend_long write_offset = (zend_long) hdr->write_offset;
    zend_long arena_size = (zend_long) hdr->arena_size;
    FC_UNLOCK();

    add_assoc_long(return_value, "db_entries", db_used);
    add_assoc_long(return_value, "network_entries", net_used);
    add_assoc_long(return_value, "arena_used_bytes", write_offset);
    add_assoc_long(return_value, "arena_size_bytes", arena_size);
}
/* }}} */

ZEND_BEGIN_ARG_INFO(arginfo_fuzzcache_void, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry fuzzcache_functions[] = {
    PHP_FE(fuzzcache_reset, arginfo_fuzzcache_void)
    PHP_FE(fuzzcache_stats, arginfo_fuzzcache_void)
    PHP_FE_END
};

/* ------------------------------------------------------------------ */
/* Dispatch                                                             */
/* ------------------------------------------------------------------ */

static void fc_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
    zend_function *fbc = execute_data->func;

    if (FCG(enabled) && !FCG(reentrant) && fbc->common.function_name) {
        zend_string *fname = fbc->common.function_name;

        if (!fbc->common.scope) {
            if (zend_string_equals_literal(fname, "mysqli_query")) { fc_handle_mysqli_query(execute_data, return_value); return; }
            if (zend_string_equals_literal(fname, "mysqli_connect")) { fc_handle_mysqli_connect(execute_data, return_value); return; }
            if (zend_string_equals_literal(fname, "mysqli_close")) { fc_handle_mysqli_close(execute_data, return_value); return; }
            if (zend_string_equals_literal(fname, "mysqli_fetch_assoc")) { fc_handle_mysqli_fetch(execute_data, return_value, FC_FETCH_ASSOC); return; }
            if (zend_string_equals_literal(fname, "mysqli_fetch_array")) { fc_handle_mysqli_fetch(execute_data, return_value, FC_FETCH_ARRAY); return; }
            if (zend_string_equals_literal(fname, "mysqli_fetch_row")) { fc_handle_mysqli_fetch(execute_data, return_value, FC_FETCH_ROW); return; }
            if (zend_string_equals_literal(fname, "mysqli_fetch_object")) { fc_handle_mysqli_fetch(execute_data, return_value, FC_FETCH_OBJECT); return; }
            if (zend_string_equals_literal(fname, "mysqli_fetch_all")) { fc_handle_mysqli_fetch(execute_data, return_value, FC_FETCH_ALL); return; }
            if (zend_string_equals_literal(fname, "mysqli_num_rows")) { fc_handle_mysqli_num_rows(execute_data, return_value); return; }
            if (zend_string_equals_literal(fname, "mysqli_free_result")) { fc_handle_mysqli_free_result(execute_data, return_value); return; }
            if (zend_string_equals_literal(fname, "curl_setopt")) { fc_handle_curl_setopt(execute_data, return_value); return; }
            if (zend_string_equals_literal(fname, "curl_exec")) { fc_handle_curl_exec(execute_data, return_value); return; }
            if (zend_string_equals_literal(fname, "curl_close")) { fc_handle_curl_close(execute_data, return_value); return; }
        } else {
            zend_string *cname = fbc->common.scope->name;
            if (zend_string_equals_literal_ci(cname, "mysqli")) {
                if (zend_string_equals_literal_ci(fname, "query")) { fc_handle_mysqli_query_method(execute_data, return_value); return; }
            } else if (zend_string_equals_literal_ci(cname, "pdo")) {
                if (zend_string_equals_literal_ci(fname, "prepare")) { fc_handle_pdo_prepare(execute_data, return_value); return; }
                if (zend_string_equals_literal_ci(fname, "exec")) { fc_handle_pdo_exec(execute_data, return_value); return; }
                if (zend_string_equals_literal_ci(fname, "query")) { fc_handle_pdo_query(execute_data, return_value); return; }
            } else if (zend_string_equals_literal_ci(cname, "pdostatement")) {
                if (zend_string_equals_literal_ci(fname, "execute")) { fc_handle_pdostmt_execute(execute_data, return_value); return; }
                if (zend_string_equals_literal_ci(fname, "fetch")) { fc_handle_pdostmt_fetch(execute_data, return_value); return; }
                if (zend_string_equals_literal_ci(fname, "fetchAll")) { fc_handle_pdostmt_fetch_all(execute_data, return_value); return; }
                if (zend_string_equals_literal_ci(fname, "rowCount")) { fc_handle_pdostmt_row_count(execute_data, return_value); return; }
            }
        }
    }

    if (FCG(orig_execute_internal)) {
        FCG(orig_execute_internal)(execute_data, return_value);
    } else {
        execute_data->func->internal_function.handler(execute_data, return_value);
    }
}

/* ------------------------------------------------------------------ */
/* Module lifecycle                                                     */
/* ------------------------------------------------------------------ */

PHP_INI_BEGIN()
STD_PHP_INI_BOOLEAN("fuzzcache.enabled", "1", PHP_INI_ALL, OnUpdateBool, enabled, zend_fuzzcache_globals, fuzzcache_globals)
STD_PHP_INI_ENTRY("fuzzcache.shm_size", "104857600", PHP_INI_SYSTEM, OnUpdateLong, shm_size, zend_fuzzcache_globals, fuzzcache_globals)
STD_PHP_INI_ENTRY("fuzzcache.shm_name", "/fuzzcache_shm", PHP_INI_SYSTEM, OnUpdateString, shm_name, zend_fuzzcache_globals, fuzzcache_globals)
STD_PHP_INI_ENTRY("fuzzcache.network_ttl", "0", PHP_INI_ALL, OnUpdateLong, network_ttl, zend_fuzzcache_globals, fuzzcache_globals)
STD_PHP_INI_BOOLEAN("fuzzcache.debug", "0", PHP_INI_ALL, OnUpdateBool, debug, zend_fuzzcache_globals, fuzzcache_globals)
PHP_INI_END()

static void php_fuzzcache_init_globals(zend_fuzzcache_globals *g)
{
    memset(g, 0, sizeof(*g));
}

ZEND_BEGIN_ARG_INFO(arginfo_fc_void, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO(arginfo_fc_data_seek, 0)
    ZEND_ARG_INFO(0, offset)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_fc_ret_void, 0, 0, IS_VOID, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_fc_ret_mixed, 0, 0, IS_MIXED, 0)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(arginfo_fc_ret_bool, 0, 0, _IS_BOOL, 0)
ZEND_END_ARG_INFO()

static const zend_function_entry fc_cached_result_methods[] = {
    PHP_ME(FuzzCacheCachedResult, fetch_assoc,  arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, fetch_array,  arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, fetch_row,    arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, fetch_object, arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, fetch_all,    arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, data_seek,    arginfo_fc_data_seek, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, free,         arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, rewind,       arginfo_fc_ret_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, next,         arginfo_fc_ret_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, key,          arginfo_fc_ret_mixed, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, current,      arginfo_fc_ret_mixed, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedResult, valid,        arginfo_fc_ret_bool, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

static const zend_function_entry fc_cached_stmt_methods[] = {
    PHP_ME(FuzzCacheCachedStatement, fetch,       arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedStatement, fetchAll,    arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedStatement, rowCount,    arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedStatement, closeCursor, arginfo_fc_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedStatement, rewind,      arginfo_fc_ret_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedStatement, next,        arginfo_fc_ret_void, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedStatement, key,         arginfo_fc_ret_mixed, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedStatement, current,     arginfo_fc_ret_mixed, ZEND_ACC_PUBLIC)
    PHP_ME(FuzzCacheCachedStatement, valid,       arginfo_fc_ret_bool, ZEND_ACC_PUBLIC)
    PHP_FE_END
};

PHP_MINIT_FUNCTION(fuzzcache)
{
    zend_class_entry ce;

    memcpy(&fc_result_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    fc_result_handlers.offset = XtOffsetOf(fc_result_obj, std);
    fc_result_handlers.free_obj = fc_result_free;

    memcpy(&fc_lazyconn_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
    fc_lazyconn_handlers.offset = XtOffsetOf(fc_lazyconn_obj, std);
    fc_lazyconn_handlers.free_obj = fc_lazyconn_free;

    INIT_CLASS_ENTRY(ce, "FuzzCache\\CachedResult", fc_cached_result_methods);
    FCG(result_ce) = zend_register_internal_class(&ce);
    FCG(result_ce)->create_object = fc_result_create;
    zend_class_implements(FCG(result_ce), 1, zend_ce_iterator);
    zend_declare_property_long(FCG(result_ce), "num_rows", sizeof("num_rows") - 1, 0, ZEND_ACC_PUBLIC);

    INIT_CLASS_ENTRY(ce, "FuzzCache\\CachedStatement", fc_cached_stmt_methods);
    FCG(stmt_ce) = zend_register_internal_class(&ce);
    FCG(stmt_ce)->create_object = fc_result_create;
    zend_class_implements(FCG(stmt_ce), 1, zend_ce_iterator);

    INIT_CLASS_ENTRY(ce, "FuzzCache\\LazyConnection", NULL);
    FCG(lazyconn_ce) = zend_register_internal_class(&ce);
    FCG(lazyconn_ce)->create_object = fc_lazyconn_create;

    zend_hash_init(&FCG(curl_handles), 8, NULL, fc_curl_info_pdtor, 1);
    zend_hash_init(&FCG(pdo_stmt_templates), 8, NULL, fc_pdo_stmt_info_pdtor, 1);

    REGISTER_INI_ENTRIES();

    if (FCG(enabled)) {
        if (fc_shm_attach() != SUCCESS) {
            FCG(shm_ready) = 0;
            php_error_docref(NULL, E_WARNING, "fuzzcache: failed to attach shared memory cache; caching disabled");
        }
    }

    FCG(orig_execute_internal) = zend_execute_internal;
    zend_execute_internal = fc_execute_internal;

    return SUCCESS;
}

PHP_MSHUTDOWN_FUNCTION(fuzzcache)
{
    zend_execute_internal = FCG(orig_execute_internal);

    if (FCG(shm_base)) munmap(FCG(shm_base), FCG(shm_mapped_size));
    if (FCG(sem)) sem_close((sem_t *) FCG(sem));

    zend_hash_destroy(&FCG(curl_handles));
    zend_hash_destroy(&FCG(pdo_stmt_templates));

    UNREGISTER_INI_ENTRIES();
    return SUCCESS;
}

PHP_RSHUTDOWN_FUNCTION(fuzzcache)
{
    zend_hash_clean(&FCG(curl_handles));
    zend_hash_clean(&FCG(pdo_stmt_templates));
    return SUCCESS;
}

PHP_MINFO_FUNCTION(fuzzcache)
{
    php_info_print_table_start();
    php_info_print_table_header(2, "fuzzcache support", "enabled");
    php_info_print_table_row(2, "Version", PHP_FUZZCACHE_VERSION);
    php_info_print_table_end();
    DISPLAY_INI_ENTRIES();
}

zend_module_entry fuzzcache_module_entry = {
    STANDARD_MODULE_HEADER,
    "fuzzcache",
    fuzzcache_functions,
    PHP_MINIT(fuzzcache),
    PHP_MSHUTDOWN(fuzzcache),
    NULL,
    PHP_RSHUTDOWN(fuzzcache),
    PHP_MINFO(fuzzcache),
    PHP_FUZZCACHE_VERSION,
    PHP_MODULE_GLOBALS(fuzzcache),
    (void (*)(void *)) php_fuzzcache_init_globals,
    NULL,
    NULL,
    STANDARD_MODULE_PROPERTIES_EX
};

#ifdef COMPILE_DL_FUZZCACHE
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(fuzzcache)
#endif
