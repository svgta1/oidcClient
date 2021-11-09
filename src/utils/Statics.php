<?php
namespace svgtautils\oidc\utils;
use svgtautils\oidc\Exception;
use svgtautils\oidc\utils\param;

class Statics{
	const OIDC_CONFIG = '/.well-known/openid-configuration';
	const OIDC_CONFIG_KEY = 'openid_configuration';
	const DEFAULT_SCOPE = ['openid'];
	const DEFAULT_PARAMS = [
		'authentication_type' => 'code', //code or implicit or hybrid
		'scope' => 'openid',
		'pkce' => false,
		'response_type' => 'code',
		'flow_automation' => [
			'State',
			'Nonce',
		],
		'guzzle' => [
			'debug' => false,
			'http_errors' => true,
			'proxy' => false,
			'verify' => true,
		],
	];
	const SCOPE_DELIMITER = ' ';
	private static $param = null;
	private static $guzzle = null;

	public static function setGuzzleClient($client){
		self::$guzzle = $client;
	}
	public static function getGuzzleClient(){
		if(self::$guzzle === null)
			throw new Exception('Guzzle Client not set');
		return self::$guzzle;
	}
	public static function getParam(){
		if(!self::$param)
			self::$param = new param();
		return self::$param;
	}

	public static function getRandom($len = 16): string {
		if (function_exists('random_bytes')) {
			return bin2hex(random_bytes($len));
		}
		if (function_exists('openssl_random_pseudo_bytes')) {
			return bin2hex(openssl_random_pseudo_bytes($len));
		}
		throw new Exception('No secure random function found');
	}
	public static function getThisUri(): string {
		if (isset($_SERVER["HTTP_UPGRADE_INSECURE_REQUESTS"]) && ($_SERVER['HTTP_UPGRADE_INSECURE_REQUESTS'] == 1)) {
			$protocol = 'https';
		} else {
			$protocol = @$_SERVER['HTTP_X_FORWARDED_PROTO']
				?: @$_SERVER['REQUEST_SCHEME']
				?: ((isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == "on") ? "https" : "http");
		}

		$port = @intval($_SERVER['HTTP_X_FORWARDED_PORT'])
			?: @intval($_SERVER["SERVER_PORT"])
			?: (($protocol === 'https') ? 443 : 80);

		$host = @explode(":", $_SERVER['HTTP_HOST'])[0]
			?: @$_SERVER['SERVER_NAME']
			?: @$_SERVER['SERVER_ADDR'];

		$port = (443 == $port) || (80 == $port) ? '' : ':' . $port;

		return sprintf('%s://%s%s/%s', $protocol, $host, $port, @trim(reset(explode("?", $_SERVER['REQUEST_URI'])), '/'));
	}
	public static function isJson(string $string): bool {
		json_decode($string);
		return json_last_error() === JSON_ERROR_NONE;
	}
	public static function guzzleParams(): array{
		$param = self::getParam();
		return $param->guzzle();
	}
	public static function getConfFile($iss): array {
		try{
			$res = self::getGuzzleClient()->request('GET', $iss, self::guzzleParams());
			if(Statics::isJson((string)$res->getBody()))
				return json_decode((string)$res->getBody(), true);
		}catch(\GuzzleHttp\Exception\ClientException $e){
		}
		$res = self::getGuzzleClient()->request('GET', $iss . self::OIDC_CONFIG, self::guzzleParams());
		if(Statics::isJson((string)$res->getBody()))
			return json_decode((string)$res->getBody(), true);

		throw new Exception('Invalid conf wellknown found');
	}
}