--TEST--
PDO (covered): prepare()+execute($params) caches genuinely and invalidates on write
--SKIPIF--
<?php
if (!extension_loaded('fuzzcache')) die('skip fuzzcache not loaded');
if (!extension_loaded('pdo_mysql')) die('skip pdo_mysql not available');
try { new PDO('mysql:host=localhost;dbname=cachedb', 'test', '123456'); }
catch (Throwable $e) { die('skip test database not available, see README demo setup'); }
exec('mysql --version', $o, $rc);
if ($rc !== 0) die('skip mysql CLI client not available');
?>
--FILE--
<?php
fuzzcache_reset();
$pdo = new PDO('mysql:host=localhost;dbname=cachedb', 'test', '123456');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

$pdo->exec("DROP TABLE IF EXISTS fc_test_pdop");
$pdo->exec("CREATE TABLE fc_test_pdop (id INT PRIMARY KEY, name VARCHAR(50))");
$pdo->exec("INSERT INTO fc_test_pdop VALUES (1,'baseline'),(2,'other')");

$stmt = $pdo->prepare("SELECT * FROM fc_test_pdop WHERE id = ?");
echo "class stays real: " . get_class($stmt) . "\n";

$stmt->execute([1]);
echo "first: " . $stmt->fetch(PDO::FETCH_ASSOC)['name'] . "\n";

// Mutate from a fully separate process, bypassing this extension.
exec("mysql -u test -p123456 cachedb -e \"UPDATE fc_test_pdop SET name='mutated_outside' WHERE id=1\" 2>&1");

$stmt->execute([1]);
echo "second (same cached params, should still be stale): " . $stmt->fetch(PDO::FETCH_ASSOC)['name'] . "\n";

// Different params (id=2) must be an independent cache entry.
$stmt->execute([2]);
echo "different params (id=2): " . $stmt->fetch(PDO::FETCH_ASSOC)['name'] . "\n";

// A write through our interception invalidates it.
$pdo->exec("UPDATE fc_test_pdop SET name='after_invalidate' WHERE id=1");
$stmt->execute([1]);
echo "third (post-invalidation, must be fresh): " . $stmt->fetch(PDO::FETCH_ASSOC)['name'] . "\n";

$pdo->exec("DROP TABLE fc_test_pdop");
?>
--EXPECT--
class stays real: PDOStatement
first: baseline
second (same cached params, should still be stale): baseline
different params (id=2): other
third (post-invalidation, must be fresh): after_invalidate
