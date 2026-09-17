# FuzzCache
FuzzCache is a software-based data cache mechanism that complements and optimizes dynamic web application fuzzing. It is based on a key observation that data fetch is often repeated, redundant, yet expensive during web application fuzzing. FuzzCache thus stores the data into software-based in-memory caches, eliminating the need for repeated and expensive operations. More technical details can be found in the paper.

In this repository, we provide the tool for profiling the execution dynamics of server-side web applications, and a data cache that transparently accelerates `mysqli`/PDO/`curl` calls during fuzzing.

## Prerequisites
- PHP with development headers/tools (`phpize`, `php-config`) and a C build toolchain (`cc`/`gcc`, `make`, `autoconf`, `libtool`) — e.g. the `php-dev` package on Debian/Ubuntu, `php-devel` on RHEL/Fedora, or `brew install php` on macOS (bundles these already).
- The `mysqli`, `pdo_mysql`, and `curl` PHP extensions enabled. The cache extension itself doesn't hard-depend on them to build or load, but there is nothing to cache without them.
- A MySQL or MariaDB server, for the demo database and the test suite.
- The `mysql` CLI client (optional) — two tests use it to prove genuine caching by mutating data completely outside the extension; they skip gracefully if it's absent.
- XHProf, only if you want the separate profiling workflow below — see its own install instructions.

Nothing here is scripted (no installer, no Dockerfile); setup is the manual steps below.

## Profiling
We used XHProf to profile the function-level execution dynamics of server-side web applications. At profiling time, XHProf records the execution statistic per request in a file. After profiling, its web interface reads the files and sorts it in a user-friendly form.

Install XHProf following the standard procedures listed [here](https://github.com/longxinH/xhprof/tree/master#installation), and then leverage a web scanner or fuzzer at your own preference to profile the web application. [Black-Widow](https://github.com/SecuringWeb/BlackWidow) is a good choice. To enable XHprof on the server side, one should first set up the environments/configurations at the beginning of serving requests. We provide an example at `xhprof/xhprof_enable.php`. The user should find an appropriate place to include the script so that it is always executed before processing requests. One can also try use preload functionality of PHP to realize this goal.

Using a browser to visit the web interface of XHProf, e.g., http://localhost/xhprof/xhprof_html/index.php (assuming you have installed xhprof_html under the document root of Apache), scroll down to the bottom, and the collected data can be viewed there.

## Data cache
FuzzCache's data cache lives in `ext` as a PHP extension. It hooks the Zend engine's function-dispatch layer directly, so it works against an **unmodified** application — no wrapper functions, no source rewriting, just loading the extension. It caches:
- `mysqli` reads (procedural and OOP: `mysqli_query()` and `$mysqli->query()`), with a lazy connection that's only ever established on a genuine cache miss;
- PDO reads (`$pdo->query()` and `$pdo->prepare()`+`execute($params)`); any usage it can't safely reason about (e.g. `bindValue`/`bindParam`) transparently falls back to normal, uncached behavior rather than risking incorrect results;
- `curl_exec()` responses, keyed by URL.

Writes always run for real and invalidate the cache at table granularity. The cache lives in shared memory, so it persists across the independent, short-lived processes that serve fuzzing requests.

See `ext/README.md` for build instructions, configuration, and known limitations.

### Demo
All commands below assume your shell is at the repo root.

1. Install a database, then create the `test` / `123456` demo user and import the schema:
    ```sh
    mysql -u root -e "CREATE USER IF NOT EXISTS 'test'@'localhost' IDENTIFIED BY '123456'; CREATE DATABASE IF NOT EXISTS cachedb; GRANT ALL PRIVILEGES ON cachedb.* TO 'test'@'localhost'; FLUSH PRIVILEGES;"
    mysql -u test -p123456 cachedb < examples/db.sql
    ```
    (adjust the `root` invocation for however your MySQL install expects admin access)
2. Build the extension once:
    ```sh
    (cd ext && phpize && ./configure --enable-fuzzcache && make)
    ```
3. Run the unmodified demo script with and without the extension:
    ```sh
    php examples/demo.php
    # Using time (10000 rounds)
    # 0.7...

    php -d extension=ext/modules/fuzzcache.so examples/demo.php
    # Using time (10000 rounds)
    # 0.01...
    ```
    Note that the actual time would differ on different machines.

## License
FuzzCache's own code is released under the [MIT License](LICENSE). The vendored `xhprof/` subproject is a separate project under its own license (Apache License 2.0) — see `xhprof/LICENSE`.

## Citation
```tex
@inproceedings{fuzzcache,
    title       = {FuzzCache: Optimizing Web Application Fuzzing Through Software-Based Data Cache},
    author      = {Li, Penghui and Zhang, Mingxue},
    booktitle   = {Proceedings of 31st ACM Conference on Computer and Communications Security (CCS)},
    month       = oct,
    year        = 2024
}
```
