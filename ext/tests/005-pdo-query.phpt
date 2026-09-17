--TEST--
PDO (covered): PDO::query() cache hit/miss return a uniform CachedStatement
--SKIPIF--
<?php
if (!extension_loaded('fuzzcache')) die('skip fuzzcache not loaded');
if (!extension_loaded('pdo_mysql')) die('skip pdo_mysql not available');
try { new PDO('mysql:host=localhost;dbname=cachedb', 'test', '123456'); }
catch (Throwable $e) { die('skip test database not available, see README demo setup'); }
?>
--FILE--
<?php
fuzzcache_reset();
$pdo = new PDO('mysql:host=localhost;dbname=cachedb', 'test', '123456');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$pdo->exec("DROP TABLE IF EXISTS fc_test_pdoq");
$pdo->exec("CREATE TABLE fc_test_pdoq (id INT PRIMARY KEY, name VARCHAR(50))");
$pdo->exec("INSERT INTO fc_test_pdoq VALUES (1,'a'),(2,'b')");

$stmt = $pdo->query("SELECT * FROM fc_test_pdoq ORDER BY id");
echo "class (miss): " . get_class($stmt) . "\n";
$rows = [];
while ($row = $stmt->fetch(PDO::FETCH_ASSOC)) { $rows[] = $row['name']; }
echo "rows (miss): " . implode(',', $rows) . "\n";

$stmt2 = $pdo->query("SELECT * FROM fc_test_pdoq ORDER BY id");
echo "class (hit): " . get_class($stmt2) . "\n";
echo "rowCount (hit): " . $stmt2->rowCount() . "\n";
$rows2 = $stmt2->fetchAll(PDO::FETCH_ASSOC);
echo "fetchAll count (hit): " . count($rows2) . "\n";

$pdo->exec("UPDATE fc_test_pdoq SET name='a2' WHERE id=1");
$stmt3 = $pdo->query("SELECT * FROM fc_test_pdoq ORDER BY id");
$row = $stmt3->fetch(PDO::FETCH_ASSOC);
echo "after write: " . $row['name'] . "\n";

$pdo->exec("DROP TABLE fc_test_pdoq");
?>
--EXPECT--
class (miss): FuzzCache\CachedStatement
rows (miss): a,b
class (hit): FuzzCache\CachedStatement
rowCount (hit): 2
fetchAll count (hit): 2
after write: a2
