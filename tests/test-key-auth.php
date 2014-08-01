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

		$this->author = $this->factory->user->create( array( 'role' => 'author' ) );
		$this->contributor = $this->factory->user->create( array( 'role' => 'contributor' ) );

		$this->authorapikey = 'asdf123';
		$this->contributorkey = 'asdfg12345';

		$this->authorsecret = 'fdsa4321';
		$this->contributorsecret = 'gfdsa54321';

		update_user_meta( $this->author, 'json_api_key', $this->authorapikey );
		update_user_meta( $this->author, 'json_shared_secret', $this->authorsecret );

		update_user_meta( $this->contributor, 'json_api_key', $this->contributorkey );
		update_user_meta( $this->contributor, 'json_shared_secret', $this->contributorsecret );
	}

	public function test_user_not_found() {
		$this->assertFalse( JSON_Key_Auth::findUserIdByKey( 'NOTAREALKEY' ) );
	}

	public function test_user_found() {
		$this->assertEquals( $this->author, JSON_Key_Auth::findUserIdByKey( $this->authorapikey ) );
	}
}