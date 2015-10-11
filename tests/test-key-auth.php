<?php

/**
 * Unit tests covering WP JSON API Key Auth functionality.
 *
 * @package WordPress
 * @subpackage JSON API
 */

class WP_TestKeyAuth extends WP_UnitTestCase {

	public function setUp() {
		parent::setUp();

		$this->user = $this->factory->user->create( array( 'role' => 'user' ) );
		$this->userapikey = 'asdf123';
		$this->usersecret = 'fdsa4321';

		update_user_meta( $this->user, 'json_api_key', $this->userapikey );
		update_user_meta( $this->user, 'json_shared_secret', $this->usersecret );
	}

	public function test_user_not_found() {
		$this->assertFalse( JSON_Key_Auth::findUserIdByKey( 'NOTAREALKEY' ) );
	}

	public function test_user_found() {
		$this->assertEquals( $this->user, JSON_Key_Auth::findUserIdByKey( $this->userapikey ) );
	}

	public function test_generate_signature_match() {
		$signature_args = array(
			'api_key' => $this->userapikey,
			'timestamp' => 1234567,
			'request_method' => 'GET',
			'request_uri' => 'example.org/wp-json',
		);
		$sent_signature = $this->generate_test_signature( $this->userapikey, $this->usersecret, $signature_args['timestamp'], $signature_args['request_method'], $signature_args['request_uri'] );

		$this->assertEquals( $sent_signature, JSON_Key_Auth::generateSignature( $signature_args, $this->usersecret ) );
	}

	public function test_auth_handler_success() {
		$key = $this->userapikey;
		$secret = $this->usersecret;
		$timestamp = time();
		$method = 'GET';
		$uri = '/wp-json/wp/v2/users/me';

		$this->setup_request( $key, $secret, $method, $uri, $timestamp );

		$this->assertEquals( $this->user, JSON_Key_Auth::authHandler( null ) );
	}

	public function setup_request( $key, $secret, $method, $uri, $timestamp ) {
		$_SERVER['HTTP_X_API_KEY'] = $key;
		$_SERVER['HTTP_X_API_SIGNATURE'] = $this->generate_test_signature( $key, $secret, $timestamp, $method, $uri );
		$_SERVER['HTTP_X_API_TIMESTAMP'] = $timestamp;
		$_SERVER['REQUEST_METHOD'] = $method;
		$_SERVER['REQUEST_URI'] = $uri;
	}

	public function generate_test_signature( $key, $secret, $timestamp, $method, $uri ) {
		$signature_args = array(
			'api_key' => $key,
			'timestamp' => $timestamp,
			'request_method' => $method,
			'request_uri' => $uri,
		);

		return hash_hmac( 'sha256', json_encode( $signature_args ), $secret );
	}
}