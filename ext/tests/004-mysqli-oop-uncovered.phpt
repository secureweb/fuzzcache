--TEST--
mysqli OOP (NOT covered, must still be correct): new mysqli() eager connect, mysqli_stmt prepare/bind/execute, real_query+store_result
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

// `new mysqli(...)` is not lazy: it must be a real, already-connected object.
$m = new mysqli('localhost', 'test', '123456', 'cachedb');
echo "class: " . get_class($m) . "\n";
var_dump($m->connect_errno === 0);

$m->query("DROP TABLE IF EXISTS fc_test_stmt");
$m->query("CREATE TABLE fc_test_stmt (id INT PRIMARY KEY, name VARCHAR(50))");
$m->query("INSERT INTO fc_test_stmt VALUES (1,'x'),(2,'y')");

// mysqli's own prepared-statement API: not intercepted, must work natively.
$stmt = $m->prepare("SELECT name FROM fc_test_stmt WHERE id = ?");
$stmt->bind_param('i', $id);
$id = 1;
$stmt->execute();
$stmt->bind_result($name);
$stmt->fetch();
echo "stmt id=1: {$name}\n";

$id = 2;
$stmt->execute();
$stmt->bind_result($name);
$stmt->fetch();
echo "stmt id=2: {$name}\n";
$stmt->close();

// real_query() + store_result(): also not intercepted, must work natively.
$m->real_query("SELECT * FROM fc_test_stmt ORDER BY id");
$res = $m->store_result();
echo "real_query num_rows: {$res->num_rows}\n";
$res->free();

$m->query("DROP TABLE fc_test_stmt");
$m->close();
?>
--EXPECT--
class: mysqli
bool(true)
stmt id=1: x
stmt id=2: y
real_query num_rows: 2
