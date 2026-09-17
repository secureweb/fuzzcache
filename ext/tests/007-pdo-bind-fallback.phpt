--TEST--
PDO (NOT covered, must still be correct): bindValue/bindParam always falls back to real, fresh execution
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

$pdo->exec("DROP TABLE IF EXISTS fc_test_pdobind");
$pdo->exec("CREATE TABLE fc_test_pdobind (id INT PRIMARY KEY, name VARCHAR(50))");
$pdo->exec("INSERT INTO fc_test_pdobind VALUES (1,'one'),(2,'two')");

// bindValue(): must return a real PDOStatement (never our own class) and
// must never risk serving stale/wrong data, since execute() has no params
// array for us to key a cache entry on.
$stmt = $pdo->prepare("SELECT * FROM fc_test_pdobind WHERE id = :id");
$stmt->bindValue(':id', 1, PDO::PARAM_INT);
$stmt->execute();
echo "bindValue id=1: " . $stmt->fetch(PDO::FETCH_ASSOC)['name'] . "\n";

$stmt->bindValue(':id', 2, PDO::PARAM_INT);
$stmt->execute();
echo "bindValue id=2 (must differ, not a stale copy of id=1): " . $stmt->fetch(PDO::FETCH_ASSOC)['name'] . "\n";

// bindParam(): by-reference binding, value read at execute() time.
$stmt2 = $pdo->prepare("SELECT * FROM fc_test_pdobind WHERE id = ?");
$id = 1;
$stmt2->bindParam(1, $id, PDO::PARAM_INT);
$stmt2->execute();
echo "bindParam id=1: " . $stmt2->fetch(PDO::FETCH_ASSOC)['name'] . "\n";
$id = 2;
$stmt2->execute();
echo "bindParam id=2 (variable changed after bind): " . $stmt2->fetch(PDO::FETCH_ASSOC)['name'] . "\n";

$pdo->exec("DROP TABLE fc_test_pdobind");
?>
--EXPECT--
bindValue id=1: one
bindValue id=2 (must differ, not a stale copy of id=1): two
bindParam id=1: one
bindParam id=2 (variable changed after bind): two
