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
			return $user;
		}

		$user_id = self::findUserIdByKey( $_SERVER['HTTP_X_API_KEY'] );
		$user_secret = get_user_meta( $user_id, 'json_shared_secret', true );

		// Check for the proper HTTP Parameters
		$signature_args = array(
			'api_key' => $_SERVER['HTTP_X_API_KEY'],
			'timestamp' => $_SERVER['HTTP_X_API_TIMESTAMP'],
			'request_method' => $_SERVER['REQUEST_METHOD'],
			'request_uri' => $_SERVER['REQUEST_URI'],
		);

		$signature_gen = self::generateSignature( $signature_args, $user_secret );
		$signature = $_SERVER['HTTP_X_API_SIGNATURE'];

		if ( $signature_gen != $signature ) {
			return false;
		}

		return $user_id;
	}

	/**
	 * @param array $args The arguments used for generating the signature. They should be, in order:
	 *                    'api_key', 'timestamp', 'request_method', and 'request_uri'.
	 *                    Timestamp should be the timestamp passed in the reques.
	 * @param string $secret The shared secret we are using to generate the hash.
	 * @return string
	 */
	public static function generateSignature( $args, $secret ) {
		return hash_hmac( 'sha256',  json_encode( $args ), $secret );
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
		$action_label = ( ! empty( $key ) && ! empty( $secret ) ) ? 'Revoke' : 'Generate';
?>
<h3><?php _e('API Keys'); ?></h3>
<table class="form-table">
	<tr class="key-auth-key-wrap">
		<th><label for="key-auth-key"><?php _e( 'Access Key' ); ?></label></th>
		<td>
			<input type="text" name="key-auth-key" id="key-auth-key" class="regular-text" value="<?php esc_attr_e( $key ); ?>" readonly="readonly" data-pw="<?php esc_attr_e( wp_generate_password( 12, false ) ); ?>" />
		</td>
	</tr>
	<tr class="key-auth-secret-wrap">
		<th><label for="key-auth-secret"><?php _e( 'Shared Secret' ); ?></label></th>
		<td>
			<input type="text" name="key-auth-secret" id="key-auth-secret" class="regular-text" value="<?php esc_attr_e( $secret ); ?>" readonly="readonly" data-pw="<?php esc_attr_e( wp_generate_password( 48, false ) ); ?>" />
		</td>
	</tr>
	<tr class="key-auth-actions-wrap">
		<th></th>
		<td>
			<button id="key-auth-action" type="button" class="button button-secondary"><?php esc_html_e( $action_label ); ?></button>
		</td>
	</tr>
</table>
<script type="text/javascript">
(function ($) {
	var $key = $('#key-auth-key'), $secret = $('#key-auth-secret');
	$('#key-auth-action').on('click', function (e) {
		var $button = $(e.target);
		e.preventDefault();
		if ('Generate' == $button.text()) {
			$key.val($key.data('pw'));
			$secret.val($secret.data('pw'));
			$button.text('Revoke');
		} else if ('Revoke' == $button.text()) {
			$key.val('');
			$secret.val('');
			$button.text('Generate');
		}
	});
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

