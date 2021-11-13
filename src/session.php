<?php
namespace svgta\oidc;
use svgta\oidc\Exception;
use svgta\oidc\utils\Statics;
use svgta\oidc\utils\Crypto;

class session{
	const SESSION_KEY = 'svgta_oidc';
	const TO_STORE = [
		'state',
		'nonce',
		'authentication_type',
		'pkce',
		'code_verifier',
		'code_challenge',
		'code_challenge_method',
		'access_token',
		'id_token',
		'refresh_token',
		'token',
		'isAuthorize',
	];

	public static function store(): void{
		if(isset($_SESSION[self::SESSION_KEY]))
			unset($_SESSION[self::SESSION_KEY]);
		$p = Statics::getParam();
		foreach(self::TO_STORE as $v)
			self::setValue($v, $p->get($v));
	}
	public static function retrieve(): void{
		$p = Statics::getParam();
		$session = self::getSession();
		if($session)
		foreach($session as $k => $v)
			$p->set($k, self::getValue($k));
	}
	public static function getValue(string $key){
		$session = self::getSession();
		if(!isset($session[$key])){
			throw new Exception('Key not set : ' . $key);
		}
		try{
			return Crypto::aesDecrypt($session[$key]);
		}catch(Exception $e){
			self::deleteSession();
			return false;
		}
	}
	public static function setValue($key, $value): void {
		$session = self::getSession();
		$session[$key] = Crypto::aesEncrypt($value);
		self::setSession($session);
	}
	public static function deleteSession(): void {
		self::ctrlSession();
		if(isset($_SESSION[self::SESSION_KEY]))
			unset($_SESSION[self::SESSION_KEY]);
	}
	private static function setSession($session): void {
		$_SESSION[self::SESSION_KEY] = serialize($session);
	}
	public static function getSession(): ?array {
		self::ctrlSession();
		if(!$_SESSION[self::SESSION_KEY])
			return $_SESSION[self::SESSION_KEY];

		return unserialize($_SESSION[self::SESSION_KEY]);
	}
	private static function ctrlSession(): void {
		if(!self::isSession()){
			if(!session_start([
				'name' => self::SESSION_KEY,
				'cookie_secure' => true,
				'cookie_httponly' => true,
				'cookie_samesite' => 'Lax',
			]))
				throw new Exception('Session not enable');
		}
		if(!isset($_SESSION[self::SESSION_KEY]))
			$_SESSION[self::SESSION_KEY] = null;
	}
	private static function isSession(): bool {
		if ( php_sapi_name() !== 'cli' ) {
			if ( version_compare(phpversion(), '5.4.0', '>=') ) {
				if(session_status() === PHP_SESSION_DISABLED)
					throw new Exception('Session not enable');
				return session_status() === PHP_SESSION_ACTIVE ? TRUE : FALSE;
			} else {
				return session_id() === '' ? FALSE : TRUE;
			}
		}
		throw new Exception('Cli mode : No Session can be started');
	}
}
