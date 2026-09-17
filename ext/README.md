# fuzzcache (interpreter-level)

This is an interpreter-level implementation of FuzzCache's data cache, as a
regular PHP extension. With it loaded, an **unmodified** application
transparently gets the cache — no wrapper functions, no source rewriting
(automatic or manual) required at all.

## How it works

PHP extensions can override the function-dispatch layer of the Zend engine
by replacing the global `zend_execute_internal` hook — the same mechanism
`xhprof/extension/xhprof.c` in this repo uses to profile every function call.
This extension uses that hook to intercept a small set of database
(`mysqli`, PDO) and network (`curl_*`) calls, without touching PHP, mysqli,
curl, or PDO source at all:

- **`mysqli_connect()`** does not connect. It returns a lightweight
  `FuzzCache\LazyConnection` placeholder that records the connection
  arguments. A real connection is only opened on the first genuine cache
  miss (or never, if every query on that connection hits the cache).
  `$mysqli->query(...)` (OOP style) and PDO connect eagerly, since by the
  time those calls happen there is already a real, live object that
  userland code may depend on (see "OOP and PDO" below) — only the query
  itself is skipped on a hit.
- **`mysqli_query()` / `$mysqli->query()`** classify the query (read vs.
  write) and extract the table name(s) it touches with a small tokenizer
  (`FROM`/`INTO`/`JOIN`/`TABLE`/`UPDATE`). Read queries are looked up by a
  hash of the query string in a shared-memory cache; on a hit, no
  connection, query, or fetch ever happens. On a miss, the real
  connect+query+fetch-all runs once, the rows are cached, and both the hit
  and miss paths return a uniform `FuzzCache\CachedResult` object.
- **`mysqli_fetch_assoc/array/row/object/all`, `mysqli_num_rows`,
  `mysqli_free_result`**, and the equivalent `FuzzCache\CachedResult`
  methods/`num_rows` property (it also implements `Iterator`, so
  `foreach ($result as $row)` works) serve rows from that object exactly
  like a real `mysqli_result` would.
- **Write queries** (`INSERT`/`UPDATE`/`DELETE`/DDL) always execute for
  real, then bump a per-table epoch counter in shared memory. A cached read
  entry stores the epoch of each table it depends on at cache-fill time,
  and is treated as invalid the moment any of those epochs changes — the
  same coarse, table-granularity invalidation the paper describes (§4.2.3),
  just implemented as O(1) version counters instead of an O(n) scan over
  every cache entry to flip a dirty bit.
- **`curl_setopt`/`curl_exec`/`curl_close`** cache network responses keyed
  by URL (captured from `CURLOPT_URL`), for calls using
  `CURLOPT_RETURNTRANSFER`, with an optional TTL.

### OOP and PDO

`$mysqli->query()` is handled exactly like `mysqli_query()`. PDO is
trickier because `PDOStatement` objects are real, driver-owned state that
userland code routinely calls `bindValue()`/`bindParam()` on — we never
touch or reimplement those, so real `PDOStatement`s stay fully native and
correct:

- **`PDO::query($sql)`** works like `mysqli_query()` — we fully control the
  returned object, so a hit/miss both return a `FuzzCache\CachedStatement`
  (PDO-flavored method names: `fetch()`, `fetchAll()`, `rowCount()`).
- **`PDO::prepare($sql)`** is only *observed* (the SQL template is
  remembered against the real, unmodified `PDOStatement` it returns) —
  `bindValue`/`bindParam`/everything else keeps working natively.
- **`PDOStatement::execute($params)`** is cached **only** when called with
  an explicit `$params` array (hashed together with the SQL template) —
  if params were bound earlier via `bindValue()`/`bindParam()` instead, we
  have no visibility into their actual values, so `execute()` always runs
  for real in that case rather than guessing. `fetch()`/`fetchAll()`/
  `rowCount()` then transparently serve cached rows only for an `execute()`
  call that was actually served from cache.
- **`PDO::exec($sql)`** is treated as a write: always runs for real, bumps
  the affected table(s)' epoch.

mysqli and PDO share the same table-epoch state, so a write through either
API correctly invalidates cached reads from the other.

Cache storage lives in a POSIX shared-memory segment (`shm_open`, default
100MB, matching the paper's §4.2.4 sizing rationale) so it survives across
the independent, short-lived worker processes that serve fuzzing requests —
the same requirement the userland library addresses with `shmop`, just used
here by the interpreter itself instead of by application code.

## Building

Requires PHP dev headers (`phpize`/`php-config`) with `mysqli` and `curl`
available (only their public PHP-level API is used — no internal
`ext/mysqli`/`ext/curl` headers are needed, and PHP/php-src itself is never
patched).

```sh
cd ext           # from the repo root
phpize
./configure --enable-fuzzcache
make
cd ..             # back to the repo root for the commands below
```

This produces `modules/fuzzcache.so`. Load it either ad hoc:

```sh
php -d extension=/path/to/ext/modules/fuzzcache.so your_script.php
```

or permanently via `php.ini`:

```ini
extension=/path/to/ext/modules/fuzzcache.so
```

## Configuration (php.ini)

| Directive                | Default             | Meaning |
|---------------------------|----------------------|---------|
| `fuzzcache.enabled`        | `1`                  | Master on/off switch. |
| `fuzzcache.shm_size`       | `104857600` (100MB)  | Shared memory cache size in bytes. |
| `fuzzcache.shm_name`       | `/fuzzcache_shm`     | POSIX shared memory segment name. |
| `fuzzcache.network_ttl`    | `0` (never expires)  | TTL in seconds for cached curl responses. |

Two userland helper functions are also registered:

- `fuzzcache_reset(): bool` — clears every cached entry (database and
  network) without disturbing table-epoch bookkeeping's correctness. This
  is the supported way to reset the cache between fuzzing runs. It does
  **not** rely on any filesystem path: on Linux, `shm_open` segments are
  visible under `/dev/shm/<name>`, but macOS has no `/dev/shm` at all —
  POSIX shared memory there is an anonymous, non-path-addressable kernel
  object, so `rm`-ing a path is not a valid way to reset the cache on
  macOS. `fuzzcache_reset()` works identically on both.
- `fuzzcache_stats(): array` — returns `ready`, `db_entries`,
  `network_entries`, `arena_used_bytes`, `arena_size_bytes` for quick
  visibility into cache occupancy.

The segment itself persists for as long as the OS keeps it alive — across
any number of independent PHP processes/requests (this is the point: it
survives the DB, curl target, or PHP process itself going away) — until
either `fuzzcache_reset()` is called, the machine reboots (it's RAM-backed,
not persisted to disk), or (on Linux only) someone manually deletes the
`/dev/shm/<name>` file.

## Demonstration

The existing `examples/demo.php` demo needs **no changes** — that's
the point:

```sh
php examples/demo.php
# Using time (10000 rounds)
# 0.72...

php -d extension=ext/modules/fuzzcache.so examples/demo.php
# Using time (10000 rounds)
# 0.01...
```

## Tests

`tests/*.phpt` are correctness tests (cache hit/miss staleness, invalidation
scope, OOP/PDO coverage) run through PHP's standard extension test harness:

```sh
(cd ext && make test)
```

They need the same demo database as above (`examples/db.sql`) and skip
themselves gracefully if it isn't reachable. They check correctness, not
timing — see the Demonstration section above for the speedup itself.

## Known limitations

- The SQL tokenizer is intentionally simple: it can miss table names in
  heavily nested/aliased queries. When it can't identify any table for a
  read query, that query is never cached, so this only costs hit rate, not
  correctness — write queries against unrecognized tables are always
  still executed for real, so no data-consistency guarantee is weakened.
- `curl_exec` caching only covers the common
  `CURLOPT_RETURNTRANSFER`-style usage; handles that stream output via
  `CURLOPT_FILE`/`CURLOPT_WRITEFUNCTION`, or `curl_multi_*`, pass straight
  through uncached.
- `PDOStatement::execute()` only caches the "params passed as an array to
  `execute()`" pattern, by design (see "OOP and PDO" above) — the
  `bindValue`/`bindParam` pattern always falls back to fully real behavior.
- Locking is a single global semaphore around the whole cache (coarse but
  simple/correct); on arena exhaustion the entire database cache is
  flushed rather than doing selective eviction, matching the paper's
  observation that the 100MB default is rarely exceeded in practice.
- Not implemented: the paper's SQL-injection Fault Escalation
  compatibility plugin (§4.5) — a fuzzer that detects SQLi via syntax
  errors from the real database could miss a vulnerability whose query
  would otherwise be served from cache. If your fuzzer relies on that
  detection technique, treat this cache as a throughput/coverage tool, not
  yet a vulnerability-detection-neutral one.
