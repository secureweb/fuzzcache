<?php
/*
 * Note that XHProf can only monitor execution after xhprof_enable()
 * so one should include this script at the very beginning of the execution
 */
// xhprof_enable(XHPROF_FLAGS_NO_BUILTINS | XHPROF_FLAGS_CPU);
// xhprof_enable(XHPROF_FLAGS_NO_BUILTINS);
xhprof_enable();

// when a request has been finished, call this call back function to dump results
register_shutdown_function(function() {
    $xhprof_data = xhprof_disable();
    // the process requries some libraries provided by xhprof
    // suppose it is at /var/www/xhprof
	$XHPROF_ROOT = "/var/www/xhprof";
    include_once $XHPROF_ROOT . "/xhprof_lib/utils/xhprof_lib.php";
	include_once $XHPROF_ROOT . "/xhprof_lib/utils/xhprof_runs.php";
	$xhprof_runs = new XHProfRuns_Default();
	// save the results to a file to the location specified in php.ini, e.g., /tmp/xhprof
    // add a key/namespace string "fuzzcache" to the file name
	$xhprof_runs->save_run($xhprof_data, "fuzzcache");
});

