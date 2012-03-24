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
		$url = site_url('/oauth/authorize');
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
			case 'yes':
				$token->user = $current_user->ID;
				$token->verifier = wp_generate_password(8, false);
				$token->authorize();

				$data = array(
					'oauth_token' => $request->get_parameter('oauth_token'),
					'oauth_verifier' => $token->verifier
				);
				break;
			case 'no':
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
		}
		code {
			font: 13px Consolas, monospace;
			background: #f0f0f0;
			padding: 6px 5px;
			margin: 0 4px;
		}
	</style>
</head>
<body>
	<form action="<?php echo site_url('/oauth/authorize') ?>" method="POST">
		<h1>Link Account</h1>
		<p>Link <code><?php echo esc_html($domain) ?></code> to your <?php bloginfo('name') ?> account?</p>
		<?php wp_nonce_field('wpoauth', 'wpoauth_nonce') ?>
		<input type="hidden" name="oauth_token" value="<?php echo esc_attr($token) ?>" />

		<input type="submit" name="wpoauth_button" value="Yes" />
		<input type="submit" name="wpoauth_button" value="No" />
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