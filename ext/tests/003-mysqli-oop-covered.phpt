--TEST--
mysqli OOP (covered): $mysqli->query(), all fetch_* styles, num_rows, data_seek, foreach
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
$m = new mysqli('localhost', 'test', '123456', 'cachedb');

$m->query("DROP TABLE IF EXISTS fc_test_oop");
$m->query("CREATE TABLE fc_test_oop (id INT PRIMARY KEY, name VARCHAR(50))");
$m->query("INSERT INTO fc_test_oop VALUES (1,'a'),(2,'b'),(3,'c')");

$r = $m->query("SELECT * FROM fc_test_oop ORDER BY id");
echo "class: " . get_class($r) . "\n";
echo "num_rows: {$r->num_rows}\n";

echo "fetch_assoc: " . $r->fetch_assoc()['name'] . "\n"; // 'a', cursor -> 1

$r->data_seek(0);
echo "fetch_array after data_seek(0): " . $r->fetch_array()['name'] . "\n"; // 'a' again

$row = $r->fetch_row();
echo "fetch_row: " . implode(',', $row) . "\n"; // "2,b"

$obj = $r->fetch_object();
echo "fetch_object: {$obj->id} {$obj->name}\n"; // "3 c"

$r->data_seek(0);
$all = $r->fetch_all(MYSQLI_ASSOC);
echo "fetch_all count: " . count($all) . "\n";

$r->data_seek(0);
foreach ($r as $row) { echo "foreach: {$row['name']}\n"; }

$r->free();
$m->query("DROP TABLE fc_test_oop");
$m->close();
?>
--EXPECT--
class: FuzzCache\CachedResult
num_rows: 3
fetch_assoc: a
fetch_array after data_seek(0): a
fetch_row: 2,b
fetch_object: 3 c
fetch_all count: 3
foreach: a
foreach: b
foreach: c
