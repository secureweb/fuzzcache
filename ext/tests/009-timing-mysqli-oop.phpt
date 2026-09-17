--TEST--
mysqli OOP ($mysqli->query()): cached repeated reads are measurably faster
--SKIPIF--
<?php
if (!extension_loaded('fuzzcache')) die('skip fuzzcache not loaded');
if (!extension_loaded('mysqli')) die('skip mysqli not available');
$c = @mysqli_connect('localhost', 'test', '123456', 'cachedb');
$r = $c ? @mysqli_query($c, 'SELECT 1') : false;
if (!$r) die('skip test database not available, see README demo setup');
?>
--FILE--
<?php
$conn = mysqli_connect('localhost', 'test', '123456', 'cachedb');
mysqli_query($conn, "DROP TABLE IF EXISTS fc_test_timing_oop");
mysqli_query($conn, "CREATE TABLE fc_test_timing_oop (id INT PRIMARY KEY, name VARCHAR(50))");
mysqli_query($conn, "INSERT INTO fc_test_timing_oop VALUES (1,'x')");
mysqli_close($conn);

const ROUNDS = 300;

function run_rounds() {
    // `new mysqli(...)` connects eagerly either way (see README: OOP
    // connect isn't lazy), so this isolates the win from caching the
    // query+fetch itself, not the connection.
    $m = new mysqli('localhost', 'test', '123456', 'cachedb');
    for ($i = 0; $i < ROUNDS; $i++) {
        $r = $m->query("SELECT * FROM fc_test_timing_oop WHERE id = 1");
        $r->fetch_assoc();
    }
    $m->close();
}

ini_set('fuzzcache.enabled', '0');
$t0 = microtime(true);
run_rounds();
$uncached = microtime(true) - $t0;

ini_set('fuzzcache.enabled', '1');
fuzzcache_reset();
$t0 = microtime(true);
run_rounds();
$cached = microtime(true) - $t0;

printf("uncached (%d rounds): %.4fs\n", ROUNDS, $uncached);
printf("cached   (%d rounds): %.4fs\n", ROUNDS, $cached);
$speedup = $cached > 0 ? $uncached / $cached : INF;
printf("speedup: %.1fx\n", $speedup);
printf("at least 2x faster: %s\n", $speedup >= 2.0 ? "yes" : "no");

ini_set('fuzzcache.enabled', '0');
$conn = mysqli_connect('localhost', 'test', '123456', 'cachedb');
mysqli_query($conn, "DROP TABLE fc_test_timing_oop");
mysqli_close($conn);
?>
--EXPECTF--
uncached (300 rounds): %fs
cached   (300 rounds): %fs
speedup: %fx
at least 2x faster: yes
