--TEST--
mysqli procedural: query cache hit is genuine (never re-touches the DB) and write invalidates it
--SKIPIF--
<?php
if (!extension_loaded('fuzzcache')) die('skip fuzzcache not loaded');
if (!extension_loaded('mysqli')) die('skip mysqli not available');
$c = @mysqli_connect('localhost', 'test', '123456', 'cachedb');
$r = $c ? @mysqli_query($c, 'SELECT 1') : false;
if (!$r) die('skip test database not available, see README demo setup');
exec('mysql --version', $o, $rc);
if ($rc !== 0) die('skip mysql CLI client not available');
?>
--FILE--
<?php
fuzzcache_reset();

$conn = mysqli_connect('localhost', 'test', '123456', 'cachedb');
var_dump(get_class($conn)); // lazy placeholder, not yet connected

// Seed known state via a real write (writes always execute for real).
mysqli_query($conn, "UPDATE users SET username='t1_baseline' WHERE id=1");

$q = "SELECT * FROM users WHERE id = 1";
$row = mysqli_fetch_assoc(mysqli_query($conn, $q));
echo "first read: {$row['username']}\n";

// Mutate the row from a completely separate process, bypassing this
// extension entirely, so a stale read here can only mean genuine caching.
exec("mysql -u test -p123456 cachedb -e \"UPDATE users SET username='t1_mutated_outside' WHERE id=1\" 2>&1");

$row = mysqli_fetch_assoc(mysqli_query($conn, $q));
echo "second read (same process, should still be cached/stale): {$row['username']}\n";

// A write through OUR interception must invalidate it.
mysqli_query($conn, "UPDATE users SET username='t1_after_invalidate' WHERE id=1");
$row = mysqli_fetch_assoc(mysqli_query($conn, $q));
echo "third read (post-invalidation, must be fresh): {$row['username']}\n";

mysqli_close($conn);
?>
--EXPECT--
string(24) "FuzzCache\LazyConnection"
first read: t1_baseline
second read (same process, should still be cached/stale): t1_baseline
third read (post-invalidation, must be fresh): t1_after_invalidate
