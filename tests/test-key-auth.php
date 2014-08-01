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

		$this->fake_server = $this->getMock('WP_JSON_Server');
		$this->endpoint = new WP_JSON_Posts( $this->fake_server );
	}

	public function test_user_not_found() {
		$this->assertFalse( JSON_Key_Auth::findUserIdByKey( 'NOTAREALKEY' ) );
	}

	public function test_user_found() {
		$this->assertEquals( $this->user, JSON_Key_Auth::findUserIdByKey( $this->userapikey ) );
	}

	public function test_authentication_success() {
		$signature_args = array(
			'api_key' => $this->userapikey,
			'timestamp' => 1234567,
			'request_method' => 'GET',
			'request_uri' => 'example.org/wp-json',
		);
		$sent_signature = md5( json_encode( $signature_args ) . $this->usersecret );

		$this->assertEquals( $sent_signature, JSON_Key_Auth::generateSignature( $signature_args, $this->usersecret ) );


		// TODO: Add assertions for the actual request.
	}
}