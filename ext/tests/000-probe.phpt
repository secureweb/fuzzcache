--TEST--
fuzzcache: extension loads under the test harness
--SKIPIF--
<?php if (!extension_loaded('fuzzcache')) die('skip fuzzcache not loaded'); ?>
--FILE--
<?php
var_dump(extension_loaded('fuzzcache'));
var_dump(function_exists('fuzzcache_reset'));
?>
--EXPECT--
bool(true)
bool(true)
