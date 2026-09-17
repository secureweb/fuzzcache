--TEST--
PDO prepare()+execute($params): cached repeated reads are measurably faster
--SKIPIF--
<?php
if (!extension_loaded('fuzzcache')) die('skip fuzzcache not loaded');
if (!extension_loaded('pdo_mysql')) die('skip pdo_mysql not available');
try { new PDO('mysql:host=localhost;dbname=cachedb', 'test', '123456'); }
catch (Throwable $e) { die('skip test database not available, see README demo setup'); }
?>
--FILE--
<?php
$pdo = new PDO('mysql:host=localhost;dbname=cachedb', 'test', '123456');
$pdo->exec("DROP TABLE IF EXISTS fc_test_timing_pdop");
$pdo->exec("CREATE TABLE fc_test_timing_pdop (id INT PRIMARY KEY, name VARCHAR(50))");
$pdo->exec("INSERT INTO fc_test_timing_pdop VALUES (1,'x')");

const ROUNDS = 300;

function run_rounds($pdo) {
    // One prepare(), many execute()s with the same params -- the
    // dominant real-world pattern for prepared statements in a loop.
    $stmt = $pdo->prepare("SELECT * FROM fc_test_timing_pdop WHERE id = ?");
    for ($i = 0; $i < ROUNDS; $i++) {
        $stmt->execute([1]);
        $stmt->fetch(PDO::FETCH_ASSOC);
    }
}

ini_set('fuzzcache.enabled', '0');
$t0 = microtime(true);
run_rounds($pdo);
$uncached = microtime(true) - $t0;

ini_set('fuzzcache.enabled', '1');
fuzzcache_reset();
$t0 = microtime(true);
run_rounds($pdo);
$cached = microtime(true) - $t0;

printf("uncached (%d rounds): %.4fs\n", ROUNDS, $uncached);
printf("cached   (%d rounds): %.4fs\n", ROUNDS, $cached);
$speedup = $cached > 0 ? $uncached / $cached : INF;
printf("speedup: %.1fx\n", $speedup);
printf("at least 2x faster: %s\n", $speedup >= 2.0 ? "yes" : "no");

ini_set('fuzzcache.enabled', '0');
$pdo->exec("DROP TABLE fc_test_timing_pdop");
?>
--EXPECTF--
uncached (300 rounds): %fs
cached   (300 rounds): %fs
speedup: %fx
at least 2x faster: yes
