<?php

$startTime = microtime(true);
function no_fuzzcache()
{
    $servername = "localhost";
    $username = "test";
    $password = "123456";
    $dbname = "cachedb";
    $conn = mysqli_connect($servername, $username, $password, $dbname);
    if (!$conn) {
        die("Connection failed: " . mysqli_connect_error());
    }
    $result = mysqli_query($conn, "SELECT * FROM users");
    while ($row = mysqli_fetch_array($result)) {
    }
    mysqli_close($conn);
}
for ($i = 0; $i < 10000; $i++) {
    no_fuzzcache();
}
$endTime = microtime(true);
echo "Using time (10000 rounds)\n";
echo($endTime - $startTime);
echo "\n";
