<?php

class Rotor_Controller_Auth {
	/**
	 * Obtain a request token
	 *
	 * Endpoint: /auth/request_token
	 */
	public static function request_token() {
		try {
			$request = OAuthRequest::from_request();
			$data = WPOAuthProvider::request_token($request);

			header('Content-Type: application/x-www-form-urlencoded');
			echo http_build_query($data, null, '&');
		}
		catch (OAuthException $e) {
			throw new Exception($e->getMessage(), 401);
		}
	}

	/**
	 * Request authorisation for the given token
	 *
	 * Endpoint: /auth/authorize
	 * @param string $oauth_token Request token
	 */
	public static function authorize($oauth_token) {
		try {
			$request = OAuthRequest::from_request();
			$url = '/auth/authorize';

			$data = WPOAuthProvider::authorize($request, $url);

			header('Content-Type: text/plain');
			echo http_build_query($data, null, '&');
		}
		catch (OAuthException $e) {
			throw new Exception($e->getMessage(), 401);
		}
	}

	/**
	 * Exchange the request token for an access token
	 *
	 * Endpoint: /auth/access_token
	 */
	public static function access_token() {
		try {
			$request = OAuthRequest::from_request();
			$result = WPOAuthProvider::access_token($request);

			header('Content-Type: application/x-www-form-urlencoded');
			echo $result;
		}
		catch (OAuthException $e) {
			throw new Exception($e->getMessage(), 401);
		}
	}
}