<?php
/**
 * Plugin Name: JSON API Key Authentication
 * Description: API/Secret Key Authentication handler for the JSON API
 * Author: Mike Burns, Paul Hughes and WP API Team
 * Author URI: https://github.com/mgburns
 * Version: 0.1
 * Plugin URI: https://github.com/mgburns/Key-Auth
 */

/**
 * Checks the HTTP request and authenticates a user using an API key and shared secret.
 *
 * @param mixed $user The current user passed in the filter.
 */

class JSON_Key_Auth {

	/**
	 * The primary handler for user authentication.
	 *
	 * @param mixed $user The current user (or bool) passing through the filter.
	 * @return mixed A user on success, or false on failure.
	 * @author Paul Hughes
	 */
	public static function authHandler( $user ) {
		// Don't authenticate twice
		if ( ! empty( $user ) ) {
			return $user;
		}

		if ( !isset( $_SERVER['HTTP_X_API_KEY'] ) || !isset( $_SERVER['HTTP_X_API_TIMESTAMP'] ) || !isset( $_SERVER['HTTP_X_API_SIGNATURE'] ) ) {
			return false;
		}

		$user_id = self::findUserIdByKey( $_SERVER['HTTP_X_API_KEY'] );
		if ( ! $user_id ) {
			return false;
		}

		$user_secret = get_user_meta( $user_id, 'json_shared_secret', true );
		if ( ! $user_secret ) {
			return false;
		}

		$version = isset( $_SERVER['HTTP_X_API_VERSION'] ) ? $_SERVER['HTTP_X_API_VERSION'] : false;

		$message = self::generateCanonicalRequest( $version );
		$signature_gen = self::generateSignature( $message, $user_secret, $version );
		$signature = $_SERVER['HTTP_X_API_SIGNATURE'];

		if ( $signature_gen != $signature ) {
			return false;
		}

		return $user_id;
	}

	/**
	 * Create a canonical request string to be signed.
	 * 
	 * @param  string $version Signature schema version. If no version is passed the original key auth schema is used.
	 * @return string
	 */
	public static function generateCanonicalRequest( $version = null ) {
		switch ( $version ) {
			case 1:
				$args = array(
					$_SERVER['HTTP_X_API_KEY'],
					(int) $_SERVER['HTTP_X_API_TIMESTAMP'],
					$_SERVER['REQUEST_METHOD'],
					$_SERVER['REQUEST_URI'],
					self::normalizedBody(),
				);
				$message = implode( "\n", $args );
				break;
			default:
				$args = array(
					'api_key' => $_SERVER['HTTP_X_API_KEY'],
					'timestamp' => $_SERVER['HTTP_X_API_TIMESTAMP'],
					'request_method' => $_SERVER['REQUEST_METHOD'],
					'request_uri' => $_SERVER['REQUEST_URI'],
				);
				$message = json_encode( $args );
				break;
		}

		return $message;
	}

	/**
	 * Return normalized string representation of HTTP request body ($_POST).
	 *
	 * Normalization operations include:
	 * - Strip slashes added by `wp_magic_quotes`
	 * - Ensure $_POST keys are lowercase
	 * - Sort $_POST by array keys
	 *
	 * The normalized array is then converted to a query string.
	 */
	public static function normalizedBody() {
		$payload = wp_unslash( $_POST );
		$payload = array_change_key_case( $payload, CASE_LOWER );
		ksort( $payload );
		return http_build_query( $payload );
	}

	/**
	 * Generate request signature.
	 *
	 * Sign the canonical request string with the shared secret associated
	 * with the requesters user ID.
	 *
	 * @param string $message Canonical request string to sign.
	 * @param string $secret The shared secret we are using to generate the hash.
	 * @return string
	 */
	public static function generateSignature( $message, $secret, $version ) {
		switch ( $version ) {
			case 1:
				$signature = hash_hmac( 'sha256', $message, $secret );
				break;
			default:
				$signature = md5( $message . $secret );
				break;
		}

		return $signature;
	}

	/**
	 * Fetches a user ID by API key.
	 *
	 * @param string $api_key The API key attached to a user.
	 * @return bool
	 */
	public static function findUserIdByKey( $api_key ) {
		$user_args = array(
			'meta_query' => array(
				array(
					'key' => 'json_api_key',
					'value' => $api_key,
				),
			),
			'number' => 1,
			'fields' => array( 'ID' ),
		);
		$user = get_users( $user_args );
		if ( is_array( $user ) && !empty( $user ) ) {
			return $user[0]->ID;
		}

		return false;
	}

	/**
	 * Display key auth management form on user profile page.
	 *
	 * @param  WP_User $user User object for profile being edited
	 */
	public static function editUser( $user ) {
		$key = get_user_meta( $user->ID, 'json_api_key', true );
		$secret = get_user_meta( $user->ID, 'json_shared_secret', true );
		$key_exists = ( ! empty( $key ) && ! empty( $secret ) );
		$action_label = ( $key_exists ) ? 'Revoke' : 'Generate';
?>
<h3><?php _e('API Keys'); ?></h3>
<table class="form-table">
	<tr class="key-auth-key-wrap">
		<th><label for="key-auth-key"><?php _e( 'Access Key' ); ?></label></th>
		<td>
			<input type="text" name="key-auth-key" id="key-auth-key" class="regular-text" value="<?php esc_attr_e( $key ); ?>" data-pw="<?php esc_attr_e( wp_generate_password( 12, false ) ); ?>" />
			<p class="description hide-if-js">Should be 12 characters long.</p>
		</td>
	</tr>
	<tr class="key-auth-secret-wrap">
		<th><label for="key-auth-secret"><?php _e( 'Shared Secret' ); ?></label></th>
		<td>
			<input type="password" name="key-auth-secret" id="key-auth-secret" class="regular-text hide-if-js" value="<?php esc_attr_e( $secret ); ?>" data-pw="<?php esc_attr_e( wp_generate_password( 48, false ) ); ?>" />
			<input type="text" class="regular-text hide-if-no-js" id="key-auth-secret-text" readonly="readonly" value="<?php esc_attr_e( $secret ); ?>">
			<p class="description hide-if-js">Should be 48 characters long.</p>
			<button type="button" id="key-auth-secret-toggle" class="button button-secondary wp-hide-pw hide-if-no-js" data-toggle="0" aria-label="Hide shared secret">
				<span class="dashicons dashicons-hidden"></span>
				<span class="text">Hide</span>
			</button>
		</td>
	</tr>
	<tr class="key-auth-actions-wrap">
		<th></th>
		<td>
			<button id="key-auth-action" type="button" class="button button-secondary hide-if-no-js"><?php esc_html_e( $action_label ); ?></button>
		</td>
	</tr>
</table>
<script type="text/javascript">
(function ($) {
	var $key = $('#key-auth-key'), $secret = $('#key-auth-secret'),
		$secretToggle = $('#key-auth-secret-toggle'),
		$secretText = $('#key-auth-secret-text');

	$('#key-auth-action').on('click', function (e) {
		var $button = $(e.target);
		e.preventDefault();
		if ('Generate' == $button.text()) {
			$key.val($key.data('pw'));
			$secret.val($secret.data('pw'));
			$secretText.val($secret.data('pw'));
			$secretToggle.show();
			$button.text('Revoke');
		} else if ('Revoke' == $button.text()) {
			$key.val('');
			$secret.val('');
			$secretText.val('');
			$secretToggle.hide();
			$button.text('Generate');
		}
	});

	$secretToggle.on('click', function (e) {
		e.preventDefault();
		$secret.toggle();
		$secretText.toggle();

		if (1 == parseInt($secretToggle.data('toggle'))) {
			$secretToggle
				.data('toggle', 0)
				.attr('aria-label', 'Hide shared secret')
				.find('> .text').text('Hide').end()
				.find('> .dashicons')
					.addClass('dashicons-hidden')
					.removeClass('dashicons-visibility');
		} else {
			$secretToggle
				.data('toggle', 1)
				.attr('aria-label', 'Show shared secret')
				.find('> .text').text('Show').end()
				.find('> .dashicons')
					.addClass('dashicons-visibility')
					.removeClass('dashicons-hidden');
		}
	});

	// Reverse no-js defaults
	$key.prop('readonly', 'readonly');
	$secret.prop('readonly', 'readonly');
	$secretToggle.trigger('click');

	// Hide shared secret toggle if no secret is set
	if (!$secret.val()) {
		$secretToggle.hide();
	}

}) (jQuery);
</script>
<?php
	}

	/**
	 * Handle key auth form submissions from user profile page.
	 *
	 * @param  int $user_id User being updated.
	 */
	public static function updateProfile( $user_id ) {
		if ( isset( $_POST['key-auth-key'] ) ) {
			$key = sanitize_text_field( $_POST['key-auth-key'] );
			update_user_meta( $user_id, 'json_api_key', $key );
		}
		if ( isset( $_POST['key-auth-secret'] ) ) {
			$secret = sanitize_text_field( $_POST['key-auth-secret'] );
			update_user_meta( $user_id, 'json_shared_secret', $secret );
		}
	}
}

add_filter( 'determine_current_user', array( 'JSON_Key_Auth', 'authHandler' ), 20 );

add_action( 'edit_user_profile_update', array( 'JSON_Key_Auth', 'updateProfile' ) );
add_action( 'personal_options_update', array( 'JSON_Key_Auth', 'updateProfile' ) );

add_action( 'show_user_profile', array( 'JSON_Key_Auth', 'editUser' ) );
add_action( 'edit_user_profile', array( 'JSON_Key_Auth', 'editUser' ) );
