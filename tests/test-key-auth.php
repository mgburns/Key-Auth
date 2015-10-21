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

	/**
	 * @dataProvider post_provider
	 */
	public function test_normalized_body( $post, $expected ) {
		$_POST = $post;
		$this->assertEquals( $expected, JSON_Key_Auth::normalizedBody() );
	}

	/**
	 * @dataProvider success_provider
	 */
	public function test_auth_handler_pass( $method, $uri, $body, $timestamp, $version = null ) {
		$key = $this->userapikey;
		$secret = $this->usersecret;
		$this->setup_request( $key, $secret, $method, $uri, $body, $timestamp, $version );
		$this->assertEquals( $this->user, JSON_Key_Auth::authHandler( null ) );
	}

	/**
	 * @dataProvider fail_provider
	 */
	public function test_auth_handler_fail( $method, $uri, $body, $timestamp, $version = null ) {
		$key = $this->userapikey;
		$secret = $this->usersecret;
		$this->setup_request( $key, $secret, $method, $uri, $body, $timestamp, $version );
		$this->assertEquals( false, JSON_Key_Auth::authHandler( null ) );
	}

	public function post_provider() {
		return array(
			'normal'     => array( array( 'foo' => 'bar' ), http_build_query( array( 'foo' => 'bar' ) ) ),
			'slashed'    => array( array( 'foo' => 'this \"is\" \\\'slashed\\\'' ), http_build_query( array( 'foo' => 'this "is" \'slashed\'' ) ) ),
			'unsorted'   => array( array( 'uvw' => 'xyz', 'abc' => 'def' ), http_build_query( array( 'abc' => 'def', 'uvw' => 'xyz' ) ) ),
			'uppercased' => array( array( 'FOO' => 'bar' ), http_build_query( array( 'foo' => 'bar' ) ) ),
		);
	}

	public function success_provider() {
		return array(
			'get'  => array( 'GET', '/wp-json/wp/v2/users/me', array(), time() ),
			'get_v1'  => array( 'GET', '/wp-json/wp/v2/users/me', array(), time(), '1' ),
			'post' => array( 'POST', '/wp-json/wp/v2/posts', array( 'title' => 'Foo', 'content' => 'Bar' ), time() ),
			'post_v1' => array( 'POST', '/wp-json/wp/v2/posts', array( 'title' => 'Foo', 'content' => 'Bar' ), time(), '1' ),
			'almost_elapsed'  => array( 'GET', '/wp-json/wp/v2/users/me', array(), time() - 299 ),
		);
	}

	public function fail_provider() {
		return array(
			'elapsed'  => array( 'GET', '/wp-json/wp/v2/users/me', array(), time() - 301 ),
		);
	}

	public function setup_request( $key, $secret, $method, $uri, $body, $timestamp, $version = null ) {
		$_POST = $body;

		$_SERVER['REQUEST_METHOD'] = $method;
		$_SERVER['REQUEST_URI'] = $uri;

		$_SERVER['HTTP_X_API_KEY'] = $key;
		$_SERVER['HTTP_X_API_TIMESTAMP'] = $timestamp;
		$_SERVER['HTTP_X_API_VERSION'] = $version;

		$signature = JSON_Key_Auth::generateSignature( JSON_Key_Auth::generateCanonicalRequest( $version ), $secret, $version );

		$_SERVER['HTTP_X_API_SIGNATURE'] = $signature;

	}
}