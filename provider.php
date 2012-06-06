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

		add_filter('authenticate', array(get_class(), 'authenticate'), 15, 3);
		add_filter('plugins_loaded', array(get_class(), 'plugins_loaded'));
		add_filter('rewrite_rules_array', array(get_class(), 'rewrite_rules_array'));
		add_filter('query_vars', array(get_class(), 'query_vars'));
		add_filter('redirect_canonical', array(get_class(), 'redirect_canonical'), 10, 2);
		add_action('template_redirect', array(get_class(), 'template_redirect'));
		add_action('login_form', array(get_class(), 'setup_register_mangle'));
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

		$url = add_query_arg('redirect_to', $_REQUEST['redirect_to'], $url);
		return $url;
	}

	public static function get_consumer($key) {
		return self::$data->lookup_consumer($key);
	}

	public static function create_consumer() {
		return self::$data->new_consumer();
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

		$token    = get_transient('wpoa_' . $request->get_parameter('oauth_token'));
		$consumer = self::$data->lookup_consumer($token->consumer);

		if (empty($_POST['wpoauth_nonce']) || empty($_POST['wpoauth_button'])) {
			return self::authorize_page($consumer, $request->get_parameter('oauth_token'), $token);
		}

		if (!wp_verify_nonce($_POST['wpoauth_nonce'], 'wpoauth')) {
			status_header(400);
			wp_die('Invalid request.');
		}

		$current_user = wp_get_current_user();
		switch (strtolower($_POST['wpoauth_button'])) {
			case 'authorize':
				$token->user = $current_user->ID;
				$token->verifier = wp_generate_password(8, false);
				$token->authorize();

				$data = array(
					'oauth_token' => $request->get_parameter('oauth_token'),
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
				// wtf?
				status_header(500);
				wp_die('Weird');
				break;
		}

		if (empty($token->callback) && $request->get_parameter('oauth_callback')) {
			$token->callback = $request->get_parameter('oauth_callback');
			$token->save();
		}

		if (!empty($token->callback) && $token->callback !== 'oob') {
			$callback = add_query_arg($data, $token->callback);
			wp_redirect($callback);
			die();
		}


		header('Content-Type: text/plain');
		echo http_build_query($data, null, '&');
		die();
	}

	protected static function authorize_page($consumer, $token, $request) {
		$domain = parse_url($request->callback, PHP_URL_HOST);
?>
<!DOCTYPE html>
<html>
<head>
	<title>Authorize Renku</title>
	<style>
		body {
			padding: 20px;
			font: 14px/1.4 Helvetica, Arial, sans-serif;
			background: #f0f0f0;
			text-align: center;
		}
		code {
			font: 13px Consolas, monospace;
			background: #fff;
			padding: 6px 5px;
			margin: 0 4px;
		}
		.success {
			background: #DFF0D8;
			color: #468847;
			border: 1px solid #D6E9C6;
			-webkit-border-radius: 4px;
			-moz-border-radius: 4px;
			border-radius: 4px;
			margin-top: -10px;
			margin-bottom: 0;
			padding: 8px 35px 8px 14px;
			text-shadow: 0 1px 0 rgba(255, 255, 255, 0.5);
		}

		.btn {
			display: inline-block;
			*display: inline;
			padding: 4px 10px 4px;
			margin-bottom: 0;
			*margin-left: .3em;
			font-size: 13px;
			line-height: 18px;
			*line-height: 20px;
			color: #333;
			text-align: center;
			text-shadow: 0 -1px 0 rgba(0, 0, 0, 0.25);
			vertical-align: middle;
			cursor: pointer;
			background-color: #f5f5f5;
			*background-color: #e6e6e6;
			background-image: -ms-linear-gradient(top, #ffffff, #e6e6e6);
			background-image: -webkit-gradient(linear, 0 0, 0 100%, from(#ffffff), to(#e6e6e6));
			background-image: -webkit-linear-gradient(top, #ffffff, #e6e6e6);
			background-image: -o-linear-gradient(top, #ffffff, #e6e6e6);
			background-image: linear-gradient(top, #ffffff, #e6e6e6);
			background-image: -moz-linear-gradient(top, #ffffff, #e6e6e6);
			background-repeat: repeat-x;
			border: 1px solid #cccccc;
			*border: 0;
			border-color: #ccc;
			border-color: rgba(0, 0, 0, 0.1) rgba(0, 0, 0, 0.1) rgba(0, 0, 0, 0.25);
			border-bottom-color: #b3b3b3;
			-webkit-border-radius: 4px;
				 -moz-border-radius: 4px;
							border-radius: 4px;
			filter: progid:dximagetransform.microsoft.gradient(startColorstr='#ffffff', endColorstr='#e6e6e6', GradientType=0);
			filter: progid:dximagetransform.microsoft.gradient(enabled=false);
			*zoom: 1;
			-webkit-box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2), 0 1px 2px rgba(0, 0, 0, 0.05);
				 -moz-box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2), 0 1px 2px rgba(0, 0, 0, 0.05);
							box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.2), 0 1px 2px rgba(0, 0, 0, 0.05);
		}

		.btn:active {
			background-color: #e6e6e6;
			*background-color: #d9d9d9;
			background-color: #d9d9d9 \9;
			background-image: none;
			outline: 0;
			-webkit-box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.15), 0 1px 2px rgba(0, 0, 0, 0.05);
				 -moz-box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.15), 0 1px 2px rgba(0, 0, 0, 0.05);
							box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.15), 0 1px 2px rgba(0, 0, 0, 0.05);
			color: rgba(255, 255, 255, 0.75);
		}

		.btn:hover {
			text-decoration: none;
			background-color: #e6e6e6;
			*background-color: #d9d9d9;
			/* Buttons in IE7 don't get borders, so darken on hover */

			background-position: 0 -15px;
			-webkit-transition: background-position 0.1s linear;
				 -moz-transition: background-position 0.1s linear;
					-ms-transition: background-position 0.1s linear;
					 -o-transition: background-position 0.1s linear;
							transition: background-position 0.1s linear;
		}

		.btn:focus {
			outline: thin dotted #333;
			outline: 5px auto -webkit-focus-ring-color;
			outline-offset: -2px;
		}

		.btn-success {
			color: #fff;
			background-color: #5bb75b;
			*background-color: #51a351;
			background-image: -ms-linear-gradient(top, #62c462, #51a351);
			background-image: -webkit-gradient(linear, 0 0, 0 100%, from(#62c462), to(#51a351));
			background-image: -webkit-linear-gradient(top, #62c462, #51a351);
			background-image: -o-linear-gradient(top, #62c462, #51a351);
			background-image: -moz-linear-gradient(top, #62c462, #51a351);
			background-image: linear-gradient(top, #62c462, #51a351);
			background-repeat: repeat-x;
			border-color: #51a351 #51a351 #387038;
			border-color: rgba(0, 0, 0, 0.1) rgba(0, 0, 0, 0.1) rgba(0, 0, 0, 0.25);
			filter: progid:dximagetransform.microsoft.gradient(startColorstr='#62c462', endColorstr='#51a351', GradientType=0);
			filter: progid:dximagetransform.microsoft.gradient(enabled=false);
		}

		.btn-success:hover,
		.btn-success:active {
			background-color: #51a351;
			*background-color: #499249;
			color: #fff;
		}

		.btn-success:active {
			background-color: #408140 \9;
		}
	</style>
</head>
<body>
<?php
if (isset($_GET['checkemail'])):
?>
	<p class="success">Registration complete. Please check your e-mail for your password.</p>
<?php
endif;
?>
	<form action="<?php echo home_url('/oauth/authorize') ?>" method="POST">
		<h1>Link Account</h1>
		<p>Link <code><?php echo esc_html($domain) ?></code> to your <?php bloginfo('name') ?> account?</p>
		<?php wp_nonce_field('wpoauth', 'wpoauth_nonce') ?>
		<input type="hidden" name="oauth_token" value="<?php echo esc_attr($token) ?>" />

		<input type="submit" name="wpoauth_button" class="btn btn-success" value="Authorize" />
		<input type="submit" name="wpoauth_button" class="btn btn-danger" value="Cancel" />
	</form>
</body>
</html>
<?php
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
		if (is_a($user, 'WP_User')) {
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
		try {
			$request = OAuthRequest::from_request();
			list($consumer, $token) = self::$server->verify_request($request);

			global $current_user;
			$current_user = new WP_User($token->user);
		}
		catch (OAuthException $e) {
			// header('WWW-Authenticate: OAuth realm="' . site_url() . '"');
		}
	}
}

class WPOAuthProvider_DataStore {
	const RETAIN_TIME = 3600; // retain nonces for 1 hour

	/**
	 * @param string $consumer_key
	 * @return object Has properties "key" and "secret"
	 */
	public function lookup_consumer($consumer_key) {
		$secret = get_option('wpoa_c_' . $consumer_key, false);
		if (!$secret) {
			return null;
		}

		$consumer = new OAuthConsumer($consumer_key, $secret);
		return $consumer;
	}

	/**
	 * @return string Consumer key
	 */
	public function new_consumer() {
		$key    = wp_generate_password(12, false);
		$secret = self::generate_secret();

		$result = update_option('wpoa_c_' . $key, $secret);
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
		return delete_option('wpoa_c_' . $consumer_key, false);
	}

	/**
	 * @param OAuthConsumer $consumer
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
	 * @param OAuthConsumer $consumer
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
	 * @param OAuthConsumer $consumer
	 * @param string $token_type Either 'request' or 'access'
	 * @return WPOAuthProvider_Token|null
	 */
	public function lookup_token($consumer, $token_type, $token) {
		switch ($token_type) {
			case 'access':
				$token = get_option('wpoa_' . $token);
				break;
			case 'request':
				$token = get_transient('wpoa_' . $token);
				break;
			default:
				throw new OAuthException('Invalid token type');
				break;
		}

		if ($token->consumer !== $consumer->key) {
			return null;
		}

		return $token;
	}

	/**
	 * @param OAuthConsumer $consumer
	 * @param WPOAuthProvider_Token $token
	 * @param string $nonce
	 * @param int $timestamp
	 * @return bool
	 */
	public function lookup_nonce($consumer, $token, $nonce, $timestamp) {
		if ($timestamp < (time() - self::RETAIN_TIME)) {
			return true;
		}

		$real = sha1($nonce . $consumer->id . $token->key . $timestamp);

		$existing = get_transient('wpoa_n_' . $real);

		if ($existing !== false) {
			return true;
		}

		set_transient('wpoa_n_' . $real, true);
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
	abstract public function save();

	/**
	 * Remove token
	 *
	 * @return bool
	 */
	abstract public function delete();
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
		$this->save();
	}

	/**
	 * Save token
	 *
	 * @return bool
	 */
	public function save() {
		return set_transient('wpoa_' . $this->key, $this, self::RETAIN_TIME);
	}

	/**
	 * Remove token
	 *
	 * @return bool
	 */
	public function delete() {
		return delete_transient('wpoa_' . $this->key);
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

	/**
	 * Save token
	 *
	 * @return bool
	 */
	public function save() {
		return update_option('wpoa_' . $this->key, $this);
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

WPOAuthProvider::bootstrap();