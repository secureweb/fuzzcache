--TEST--
mysqli: table-level invalidation only affects the written table, not unrelated tables
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
fuzzcache_reset();
$conn = mysqli_connect('localhost', 'test', '123456', 'cachedb');

mysqli_query($conn, "DROP TABLE IF EXISTS fc_test_other");
mysqli_query($conn, "CREATE TABLE fc_test_other (id INT PRIMARY KEY, val VARCHAR(50))");
mysqli_query($conn, "INSERT INTO fc_test_other VALUES (1, 'other_baseline')");
mysqli_query($conn, "UPDATE users SET username='users_baseline' WHERE id=1");

$usersQ = "SELECT * FROM users WHERE id = 1";
$otherQ = "SELECT * FROM fc_test_other WHERE id = 1";

$row = mysqli_fetch_assoc(mysqli_query($conn, $usersQ));
echo "users (cached): {$row['username']}\n";
$row = mysqli_fetch_assoc(mysqli_query($conn, $otherQ));
echo "other (cached): {$row['val']}\n";

// Write to `users` only. `fc_test_other`'s cached read must be unaffected.
mysqli_query($conn, "UPDATE users SET username='users_updated' WHERE id=1");

$row = mysqli_fetch_assoc(mysqli_query($conn, $usersQ));
echo "users (after users write, must be fresh): {$row['username']}\n";
$row = mysqli_fetch_assoc(mysqli_query($conn, $otherQ));
echo "other (after users write, must be untouched/still cached): {$row['val']}\n";

// Now write to `fc_test_other`; only that table's cache entry should flip.
mysqli_query($conn, "UPDATE fc_test_other SET val='other_updated' WHERE id=1");
$row = mysqli_fetch_assoc(mysqli_query($conn, $otherQ));
echo "other (after other write, must be fresh): {$row['val']}\n";

mysqli_query($conn, "DROP TABLE fc_test_other");
mysqli_close($conn);
?>
--EXPECT--
users (cached): users_baseline
other (cached): other_baseline
users (after users write, must be fresh): users_updated
other (after users write, must be untouched/still cached): other_baseline
other (after other write, must be fresh): other_updated
