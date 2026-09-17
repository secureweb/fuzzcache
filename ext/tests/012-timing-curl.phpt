--TEST--
curl_exec(): cached repeated network reads are measurably faster
--SKIPIF--
<?php
if (!extension_loaded('fuzzcache')) die('skip fuzzcache not loaded');
if (!extension_loaded('curl')) die('skip curl not available');
if (!extension_loaded('posix')) { /* not required, just informational */ }
?>
--FILE--
<?php
$docroot = sys_get_temp_dir() . '/fc_curl_timing_' . getmypid();
mkdir($docroot);
file_put_contents($docroot . '/index.php', '<?php echo "hello";');

$port = 20000 + (getmypid() % 10000);
$descriptors = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
$proc = proc_open(
    [PHP_BINARY, '-S', "127.0.0.1:$port", '-t', $docroot],
    $descriptors,
    $pipes
);
if (!$proc) die("could not start built-in server\n");

// Wait for the server to actually accept connections.
$ready = false;
for ($i = 0; $i < 50; $i++) {
    $fp = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.1);
    if ($fp) { fclose($fp); $ready = true; break; }
    usleep(50000);
}
if (!$ready) {
    proc_terminate($proc);
    echo "server never became ready\n";
    exit;
}

const ROUNDS = 150;
$url = "http://127.0.0.1:$port/index.php";

function run_rounds($url) {
    for ($i = 0; $i < ROUNDS; $i++) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_exec($ch);
        curl_close($ch);
    }
}

ini_set('fuzzcache.enabled', '0');
$t0 = microtime(true);
run_rounds($url);
$uncached = microtime(true) - $t0;

ini_set('fuzzcache.enabled', '1');
fuzzcache_reset();
$t0 = microtime(true);
run_rounds($url);
$cached = microtime(true) - $t0;

printf("uncached (%d rounds): %.4fs\n", ROUNDS, $uncached);
printf("cached   (%d rounds): %.4fs\n", ROUNDS, $cached);
$speedup = $cached > 0 ? $uncached / $cached : INF;
printf("speedup: %.1fx\n", $speedup);
printf("at least 2x faster: %s\n", $speedup >= 2.0 ? "yes" : "no");

proc_terminate($proc);
proc_close($proc);
@unlink($docroot . '/index.php');
@rmdir($docroot);
?>
--EXPECTF--
uncached (150 rounds): %fs
cached   (150 rounds): %fs
speedup: %fx
at least 2x faster: yes
