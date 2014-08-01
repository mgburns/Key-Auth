<?php
/**
 * Bootstrap the plugin unit testing environment.
 *
 * @package WordPress
 * @subpackage JSON API Key Auth
 */

// Activates this plugin in WordPress so it can be tested.
$GLOBALS['wp_tests_options'] = array(
	'active_plugins' => array(
		basename( dirname( dirname( __FILE__ ) ) ) . '/key-auth.php',
		basename( dirname( dirname( getenv( 'WP_API_PLUGIN_PATH' ) ) ) ),
	),
);

// If the develop repo location is defined (as WP_DEVELOP_DIR), use that
// location. Otherwise, we'll just assume that this plugin is installed in a
// WordPress develop SVN checkout.

if( false !== getenv( 'WP_DEVELOP_DIR' ) ) {
	require getenv( 'WP_DEVELOP_DIR' ) . '/tests/phpunit/includes/bootstrap.php';
} else {
	require '../../../../tests/phpunit/includes/bootstrap.php';
}

// Include the plugin file.
require_once(dirname( dirname( __FILE__ ) ) . '/key-auth.php');
require_once(getenv( 'WP_API_PLUGIN_PATH' ) );