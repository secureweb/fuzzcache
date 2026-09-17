--TEST--
mysqli: cached repeated reads are measurably faster than uncached ones
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
mysqli_query($conn, "DROP TABLE IF EXISTS fc_test_timing");
mysqli_query($conn, "CREATE TABLE fc_test_timing (id INT PRIMARY KEY, name VARCHAR(50))");
mysqli_query($conn, "INSERT INTO fc_test_timing VALUES (1,'x')");
mysqli_close($conn);

const ROUNDS = 300;

function run_rounds() {
    for ($i = 0; $i < ROUNDS; $i++) {
        $c = mysqli_connect('localhost', 'test', '123456', 'cachedb');
        $r = mysqli_query($c, "SELECT * FROM fc_test_timing WHERE id = 1");
        mysqli_fetch_assoc($r);
        mysqli_close($c);
    }
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
mysqli_query($conn, "DROP TABLE fc_test_timing");
mysqli_close($conn);
?>
--EXPECTF--
uncached (300 rounds): %fs
cached   (300 rounds): %fs
speedup: %fx
at least 2x faster: yes
