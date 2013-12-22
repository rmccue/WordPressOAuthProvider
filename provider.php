<?php
/**
 * Plugin Name: WP OAuth Provider
 * Description: Enable WordPress to act as an OAuth provider!
 *
 * A massive thanks to Morten Fangel, as without his guide, this would
 * have taken a lot longer to write.
 */

if (!class_exists('OAuthServer')) {
	require_once(dirname(__FILE__) . '/oauth.php');
}

class WPOAuthProvider {
	protected static $data;
	protected static $server;

	const PATH_AUTHORIZE = '/oauth/authorize/';

	public static function bootstrap() {
		self::$data = new WPOAuthProvider_DataStore();
		self::$server = new OAuthServer(self::$data);

		$hmac = new OAuthSignatureMethod_HMAC_SHA1();
		self::$server->add_signature_method($hmac);

		// only allow plaintext if we're over a secure connection
		if (is_ssl()) {
			$plaintext = new OAuthSignatureMethod_PLAINTEXT();
			self::$oauth->add_signature_method($plaintext);
		}

		register_activation_hook(__FILE__, array(get_class(), 'activate'));
		register_deactivation_hook(__FILE__, array(get_class(), 'deactivate'));

		add_action('admin_menu', array(__CLASS__, 'menu'), -100);

		add_filter('authenticate', array(get_class(), 'authenticate'), 15, 3);
		// add_filter('plugins_loaded', array(get_class(), 'plugins_loaded'));
		add_filter('rewrite_rules_array', array(get_class(), 'rewrite_rules_array'));
		add_filter('query_vars', array(get_class(), 'query_vars'));
		add_filter('redirect_canonical', array(get_class(), 'redirect_canonical'), 10, 2);
		add_action('template_redirect', array(get_class(), 'template_redirect'));

		add_action('login_form', array(get_class(), 'setup_register_mangle'));
		add_action('register_form', array(get_class(), 'setup_register_mangle'));
		add_action('lostpassword_form', array(get_class(), 'setup_register_mangle'));

		add_action('update_user_metadata', array(get_class(), 'after_register_autologin'), 10, 4);
	}

	public static function activate() {
		global $wp_rewrite;
		$wp_rewrite->flush_rules();
	}

	public static function deactivate() {
		global $wp_rewrite;
		remove_filter('rewrite_rules_array', array(get_class(), 'rewrite_rules_array'));
		$wp_rewrite->flush_rules();
	}

	/**
	 * Add our menu page
	 *
	 * @wp-action admin_menu
	 */
	public static function menu() {
		add_dashboard_page('OAuth Keys', 'OAuth Keys', 'manage_options', 'wpoaprovider', array(__CLASS__, 'oauth_config'));
	}

	/**
	 * OAuth configuration page
	 *
	 * Hooked via `add_dashboard_page()`
	 * @see menu()
	 * @param WP_User $user Current user
	 */
	public static function oauth_config($user) {
		#delete_option('wpoa_consumers');
		if (!empty($_POST['action'])) {
			if ($_POST['action'] === 'create') {
				check_admin_referer('wpoa_create_consumer', 'wpoa_nonce');
				$name = $description = '';

				if (!empty($_POST['consumer_name']))
					$name = stripslashes($_POST['consumer_name']);

				if (!empty($_POST['consumer_desc']))
					$description = stripslashes($_POST['consumer_desc']);

				$key = WPOAuthProvider::create_consumer($name, $description);
			}
			elseif ($_POST['action'] === 'delete' && !empty($_POST['key'])) {
				check_admin_referer('wpoa_delete_consumer', 'wpoa_nonce');
				WPOAuthProvider::delete_consumer($_POST['key']);
			}
		}

		$consumers = self::$data->get_consumers();
?>
	<h2><?php _e('OAuth Details' , 'wpoaprovider'); ?></h2>
<?php

?>
	<table class="widefat">
		<thead>
			<tr>
				<th>Name</th>
				<th>Description</th>
				<th>Key</th>
				<th>Secret</th>
				<th>Action</th>
			</tr>
		</head>
		<tbody>
<?php
		if (!empty($consumers)) {
			foreach ($consumers as $key => $consumer) {
?>
			<tr>
				<td><?php echo $consumer->name ?></td>
				<td><?php echo $consumer->description ?></td>
				<td><code><?php echo $consumer->key ?></code></td>
				<td><code><?php echo $consumer->secret ?></code></td>
				<td>
					<form action="" method="POST">
						<?php wp_nonce_field('wpoa_delete_consumer', 'wpoa_nonce') ?>
						<input type="hidden" name="action" value="delete" />
						<input type="hidden" name="key" value="<?php echo esc_attr($consumer->key) ?>" />
						<input type="submit"
							class="button button-small"
							value="<?php esc_attr_e('Delete', 'wpoaprovider') ?>" />
					</form>
				</td>
			</tr>
<?php
			}
		}
		else {
?>
			<tr>
				<td colspan="5"><?php _e('No consumers found.', 'wpoaprovider') ?></td>
			</tr>
<?php
		}
?>
		</tbody>
	</table>

	<form action="" method="POST">
		<h3><?php _e('Add New Consumer', 'wpoaprovider') ?></h3>
		<table class="form-table">
			<tr>
				<th scope="row"><label for="wpoa_consumer_name"><?php _ex('Name', 'form label', 'wpoaprovider') ?></label></th>
				<td><input type="text" class="regular-text" name="consumer_name" id="wpoa_consumer_name" /></td>
			</tr>
			<tr>
				<th scope="row"><label for="wpoa_consumer_desc"><?php _ex('Description', 'form label', 'wpoaprovider') ?></label></th>
				<td><input type="text" class="regular-text" name="consumer_desc" id="wpoa_consumer_desc" /></td>
			</tr>
		</table>

		<?php wp_nonce_field('wpoa_create_consumer', 'wpoa_nonce') ?>
		<input type="hidden" name="action" value="create" />
		<p class="submit"><input type="submit" class="button button-primary" value="<?php esc_attr_e('Add Consumer', 'wpoaprovider') ?>" /></p>
	</form>
<?php
	}

	public static function rewrite_rules_array($rules) {
		$newrules = array();
		$newrules['oauth/authorize$'] = 'index.php?oauth=authorize';
		return array_merge($newrules, $rules);
	}

	public static function query_vars($vars) {
		$vars[] = 'oauth';
		return $vars;
	}

	public static function redirect_canonical($new, $old) {
		if (strlen(get_query_var('oauth')) > 0) {
			return false;
		}

		return $new;
	}

	public static function template_redirect() {
		$page = get_query_var('oauth');
		if (!$page) {
			return;
		}

		switch ($page) {
			case 'authorize':
				self::authorize();
				break;
			default:
				global $wp_query;
				$wp_query->set_404();
				return;
		}

		die();
	}

	public static function setup_register_mangle() {
		add_filter('site_url', array(get_class(), 'register_mangle'), 10, 3);
		add_filter('lostpassword_url', array(get_class(), 'login_mangle'));
		add_filter('login_url', array(get_class(), 'login_mangle'));
	}

	public static function after_register_autologin($metaid, $userid, $key, $value) {
		// We only care about the password nag event. Ignore anything else.
		if ( 'default_password_nag' !== $key || true != $value) {
			return;
		}

		// Set the current user variables, and give him a cookie. 
		wp_set_current_user( $userid );
		wp_set_auth_cookie( $userid );

		// If we're redirecting, ensure they know we are
		if (!empty($_POST['redirect_to'])) {
			$_POST['redirect_to'] = add_query_arg('checkemail', 'registered', $_POST['redirect_to']);
		}
	}


	/**
	 * Ensure the redirect_to parameter is carried through to registration
	 *
	 * @wp-filter site_url
	 */
	public static function register_mangle($url, $path, $scheme) {
		if ($scheme !== 'login' || $path !== 'wp-login.php?action=register' || empty($_REQUEST['redirect_to'])) {
			return $url;
		}

		$url = add_query_arg('redirect_to', urlencode($_REQUEST['redirect_to']), $url);
		return $url;
	}
	public static function login_mangle($url) {
		if (empty($_REQUEST['redirect_to'])) {
			return $url;
		}

		$url = add_query_arg('redirect_to', urlencode($_REQUEST['redirect_to']), $url);
		return $url;
	}

	public static function get_consumer($key) {
		return self::$data->lookup_consumer($key);
	}

	public static function create_consumer($name, $description) {
		return self::$data->new_consumer($name, $description);
	}

	public static function delete_consumer($key) {
		return self::$data->delete_consumer($key);
	}

	public static function request_token($request) {
		$token = self::$server->fetch_request_token($request);

		$data = array(
			'oauth_token' => OAuthUtil::urlencode_rfc3986($token->key),
			'oauth_token_secret' => OAuthUtil::urlencode_rfc3986($token->secret)
		);

		$token->callback = $request->get_parameter('oauth_callback');
		if (!empty($token->callback)) {
			$data['oauth_callback_confirmed'] = 'true';
			$token->save();
		}

		return $data;
	}

	public static function authorize() {
		if (empty($_REQUEST['oauth_token'])) {
			wp_die('No OAuth token found in request. Please ensure your client is configured correctly.', 'OAuth Error', array('response' => 400));
		}

		$request = OAuthRequest::from_request();
		$url = home_url('/oauth/authorize');
		$url = add_query_arg('oauth_token', $request->get_parameter('oauth_token'), $url);

		if (!is_user_logged_in()) {
			wp_redirect(wp_login_url($url));
			die();
		}

		try {
			list($token, $data) = self::authorize_handler($url, $request->get_parameter('oauth_token'), $request->get_parameter('oauth_callback'), $request->get_parameter('wpoauth_nonce'), $request->get_parameter('wpoauth_button'));

			// Page output?
			if ($token === false) {
				echo $data;
				return;
			}
			else {
				if (!empty($token->callback) && $token->callback !== 'oob') {
					$callback = add_query_arg($data, $token->callback);
					wp_redirect($callback);
					die();
				}

				header('Content-Type: text/plain');
				echo http_build_query($data, null, '&');
				die();
			}
		}
		catch (WPOAuthProvider_Exception $e) {
			switch ($e->getType()) {
				case 'authorize.no_login':
					// Shouldn't hit this, as we covered it before
					break;

				case 'authorize.invalid_nonce':
					status_header(400);
					wp_die('Invalid request.');
					break;

				default:
					status_header(500);
					wp_die(sprintf('An error occurred while authorizing: %s (%s)', $e->getMessage(), $e->getType()));
					break;
			}
		}
	}

	public static function authorize_handler($url, $token_key, $callback = null, $nonce = null, $action = null) {
		if (!is_user_logged_in()) {
			throw new WPOAuthProvider_Exception('User is not logged in', 'authorize.no_login');
		}

		$token = get_option( 'wpoa_' . $token_key );
		if (empty($token)) {
			throw new WPOAuthProvider_Exception('Invalid token', 'authorize.invalid_token');
		}

		$consumer = self::$data->lookup_consumer($token->consumer);

		if (empty($nonce) || empty($action)) {
			$page = self::authorize_page($consumer, $token_key, $token, $url);
			return array(false, $page);
		}

		if (!wp_verify_nonce($nonce, 'wpoauth')) {
			throw new WPOAuthProvider_Exception('Invalid nonce', 'authorize.invalid_nonce');
		}

		$current_user = wp_get_current_user();
		switch ($action) {
			case 'authorize':
				$token->user = $current_user->ID;
				$token->verifier = wp_generate_password(8, false);
				$token->authorize();

				$data = array(
					'oauth_token' => $token_key,
					'oauth_verifier' => $token->verifier
				);
				break;
			case 'cancel':
				$token->delete();

				$data = array(
					'denied' => true
				);
				break;
			default:
				throw new WPOAuthProvider_Exception('Invalid action', 'authorize.invalid_action');
		}

		if (empty($token->callback) && $callback) {
			$token->callback = $callback;
			$token->save();
		}

		return array($token, $data);
	}

	protected static function authorize_page($consumer, $token, $request, $current_page) {
		$domain = parse_url($request->callback, PHP_URL_HOST);

		$template = locate_template('oauth/authorize.php');

		ob_start();
		include ($template);
		return ob_get_clean();
	}

	public static function access_token($request) {
		$token = self::$server->fetch_access_token($request);

		header('Content-Type: application/x-www-form-urlencoded');
		return sprintf(
			'oauth_token=%s&oauth_token_secret=%s',
			OAuthUtil::urlencode_rfc3986($token->key),
			OAuthUtil::urlencode_rfc3986($token->secret)
		);
	}

	public static function authenticate($user, $username, $password) {
		if (is_a($user, 'WP_User') || PHP_SAPI === 'cli') {
			return $user;
		}

		try {
			$request = OAuthRequest::from_request();
			list($consumer, $token) = self::$server->verify_request($request);

			$user = new WP_User($token->user);
		}
		catch (OAuthException $e) {
			// header('WWW-Authenticate: OAuth realm="' . site_url() . '"');
		}

		return $user;
	}

	public static function plugins_loaded() {
		if (PHP_SAPI === 'cli') {
			return;
		}

		if (empty($_REQUEST['oauth_consumer_key']) && empty($_SERVER['HTTP_AUTHORIZATION'])) {
			return;
		}

		try {
			$request = OAuthRequest::from_request();
			list($consumer, $token) = self::$server->verify_request($request);

			wp_set_current_user($token->user);
		}
		catch (OAuthException $e) {
			if ( ! isset($GLOBALS['bk_auth_request']) || $GLOBALS['bk_auth_request'] !== true ) {
				status_header(400);
				throw $e;
			}
			// header('WWW-Authenticate: OAuth realm="' . site_url() . '"');
		}
	}
}

class WPOAuthProvider_DataStore {
	const RETAIN_TIME = 3600; // retain nonces for 1 hour

	/**
	 * Get all consumers
	 *
	 * @return array Associative array of consumer key to WPOAuthProvider_Consumer object
	 */
	public function get_consumers() {
		return get_option('wpoa_consumers', array());
	}

	/**
	 * @param string $consumer_key
	 * @return WPOAuthProvider_Consumer Has properties "key" and "secret"
	 */
	public function lookup_consumer($consumer_key) {
		$consumers = get_option('wpoa_consumers', array());
		if (!isset($consumers[$consumer_key])) {
			return null;
		}

		return $consumers[$consumer_key];
	}

	/**
	 * @return string|boolean Consumer key
	 */
	public function new_consumer($name, $description) {
		$key    = wp_generate_password(12, false);
		$secret = self::generate_secret();

		$consumer = new WPOAuthProvider_Consumer($key, $secret);
		$consumer->name = $name;
		$consumer->description = $description;

		$consumers = get_option('wpoa_consumers', false);

		// Ensure that we don't autoload the option, as this causes problems
		// since the class isn't defined at that point
		if ($consumers === false) {
			$consumers = array();
			$consumers[$key] = $consumer;
			$result = add_option('wpoa_consumers', $consumers, null, 'no');
		}
		else {
			$consumers[$key] = $consumer;
			$result = update_option('wpoa_consumers', $consumers);
		}

		if (!$result) {
			return false;
		}

		return $key;
	}

	/**
	 * @param string $consumer_key
	 * @return boolean
	 */
	public function delete_consumer($consumer_key) {
		$consumers = get_option('wpoa_consumers', array());
		unset($consumers[$consumer_key]);
		return update_option('wpoa_consumers', $consumers);
	}

	/**
	 * @param WPOAuthProvider_Consumer $consumer
	 * @return WPOAuthProvider_Token_Request|null
	 */
	public function new_request_token($consumer) {
		$key    = self::generate_key('rt');
		$secret = self::generate_secret();

		$token = new WPOAuthProvider_Token_Request($key, $secret);
		$token->consumer = $consumer->key;
		$token->authorized = false;

		if (!$token->save()) {
			return null;
		}

		return $token;
	}

	/**
	 * @param WPOAuth_Provider_Token_Request
	 * @param WPOAuthProvider_Consumer $consumer
	 * @param string $verifier
	 * @return WPOAuthProvider_Token_Access|null
	 */
	public function new_access_token($token, $consumer, $verifier) {
		if (!$token->authorized) {
			throw new OAuthException('Unauthorized access token');
		}
		if ($token->verifier !== $verifier) {
			throw new OAuthException('Verifier does not match');
		}

		$key    = self::generate_key('at');
		$secret = self::generate_secret();

		$access = new WPOAuthProvider_Token_Access($key, $secret);
		$access->consumer = $consumer->key;
		$access->user = $token->user;

		$access->save();
		$token->delete();

		return $access;
	}

	/**
	 * @param WPOAuthProvider_Consumer $consumer
	 * @param string $token_type Either 'request' or 'access'
	 * @return WPOAuthProvider_Token|null
	 */
	public function lookup_token($consumer, $token_type, $token) {
		switch ($token_type) {
			case 'access':
			case 'request':
				$token = get_option('wpoa_' . $token);
				break;
			default:
				throw new OAuthException('Invalid token type');
				break;
		}

		if ($token === false || $token->consumer !== $consumer->key) {
			return null;
		}

		return $token;
	}

	/**
	 * @param WPOAuthProvider_Consumer $consumer
	 * @param WPOAuthProvider_Token $token
	 * @param string $nonce
	 * @param int $timestamp
	 * @return bool
	 */
	public function lookup_nonce($consumer, $token, $nonce, $timestamp) {
		if ($timestamp < (time() - self::RETAIN_TIME)) {
			return true;
		}

		if ($token !== null) {
			$real = sha1($nonce . $consumer->key . $token->key . $timestamp);
		}
		else {
			$real = sha1($nonce . $consumer->key . 'notoken' . $timestamp);
		}

		$nonces = get_option('wpoa_nonces', array());

		if ( isset( $nonces[ $real ] ) ) {
			return true;
		}

		foreach ( $nonces as $key => $nonce_expire ) {
			if ( $nonce_expire < (time() - self::RETAIN_TIME) ) {
				unset($nonces[$key]);
			}
		}

		$nonces[$real] = $timestamp;
		delete_option('wpoa_nonces');
		add_option('wpoa_nonces', $nonces, null, 'no');

		return false;
	}

	/**
	 * Generate an OAuth key
	 *
	 * The max key length is 43 characters, we use 24 to play it safe.
	 * @param string $type Either 'at' or 'rt' (access/request resp.)
	 * @return string
	 */
	protected function generate_key($type = 'at') {
		// 
		return $type . '_' . wp_generate_password(24, false);
	}

	/**
	 * Generate an OAuth secret
	 *
	 * @return string
	 */
	protected function generate_secret() {
		return wp_generate_password(48, false);
	}
}

/**
 * WordPress OAuth token class
 */
abstract class WPOAuthProvider_Token extends OAuthToken {
	/*
	public $key;
	public $secret;
	*/
	public $consumer;

	/**
	 * Save token
	 *
	 * @return bool
	 */
	public function save() {
		delete_option('wpoa_' . $this->key);
		return add_option('wpoa_' . $this->key, $this, null, 'no');
	}

	/**
	 * Remove token
	 *
	 * @return bool
	 */
	public function delete() {
		return delete_option('wpoa_' . $this->key);
	}
}

/**
 * WordPress OAuth request token class
 */
class WPOAuthProvider_Token_Request extends WPOAuthProvider_Token {
	/*
	public $key;
	public $secret;
	public $consumer;
	*/
	public $authorized = false;
	public $callback;
	public $verifier;

	/**
	 * How long should we keep request tokens?
	 */
	const RETAIN_TIME = 86400; // keep for 24 hours

	/**
	 * Authorize a token
	 */
	public function authorize() {
		$this->authorized = true;
	}
}

/**
 * WordPress OAuth access token class
 */
class WPOAuthProvider_Token_Access extends WPOAuthProvider_Token {
	/*
	public $key;
	public $secret;
	public $consumer;
	*/
	public $user;
}

class WPOAuthProvider_Consumer extends OAuthConsumer {
	public $name = '';
	public $description = '';
}

class WPOAuthProvider_Exception extends OAuthException {
	public function __construct($name, $type) {
		$this->type = $type;
		parent::__construct($name);
	}

	public function getType() {
		return $this->type;
	}
}

WPOAuthProvider::bootstrap();