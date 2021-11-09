<?php
namespace svgtautils\oidc\utils;
use svgtautils\oidc\Exception;
class Crypto{
	public static function getSecretSalt(){
		$file = dirname(__FILE__) . '/../salt.txt';
		if(!is_file($file))
			return null;
		return file_get_contents($file);
	}
	public static function aesEncrypt($data){
		if(!$salt = self::getSecretSalt())
			return $data;
		
		return bin2hex(self::aesEncryptInternal(serialize($data), $salt));
	}
	public static function aesDecrypt($ciphertext){
		if(!$salt = self::getSecretSalt())
			return $ciphertext;
		return unserialize(self::aesDecryptInternal(hex2bin($ciphertext), $salt));
	}
	private static function aesEncryptInternal(string $data, string $secret): string{
		if (!function_exists("openssl_encrypt")) {
			throw new Exception('The openssl PHP module is not loaded.');
		}
		$key = openssl_digest($secret, 'sha512');
		$iv = openssl_random_pseudo_bytes(16);
		$ciphertext = openssl_encrypt(
			$data,
			'AES-256-CBC',
			substr($key, 0, 64),
			defined('OPENSSL_RAW_DATA') ? OPENSSL_RAW_DATA : 1,
			$iv
		);
		if ($ciphertext === false) {
			throw new Exception("Failed to encrypt plaintext.");
		}
		return hash_hmac('sha256', $iv . $ciphertext, substr($key, 64, 64), true) . $iv . $ciphertext;
	}
	private static function aesDecryptInternal(string $ciphertext, string $secret): string{
		$len = mb_strlen($ciphertext, '8bit');
		if ($len < 48) {
			throw new Exception('Input parameter "$ciphertext" must be a string with more than 48 characters.');
		}
		if (!function_exists("openssl_decrypt")) {
			throw new Exception("The openssl PHP module is not loaded.");
		}
		$key  = openssl_digest($secret, 'sha512');
		$hmac = mb_substr($ciphertext, 0, 32, '8bit');
		$iv   = mb_substr($ciphertext, 32, 16, '8bit');
		$msg  = mb_substr($ciphertext, 48, $len - 48, '8bit');
		if (self::secureCompare(hash_hmac('sha256', $iv . $msg, substr($key, 64, 64), true), $hmac)) {
			$plaintext = openssl_decrypt(
				$msg,
				'AES-256-CBC',
				substr($key, 0, 64),
				defined('OPENSSL_RAW_DATA') ? OPENSSL_RAW_DATA : 1,
				$iv
			);
			if ($plaintext !== false) {
				return $plaintext;
			}
		}
		throw new Exception("Failed to decrypt ciphertext.");
	}
	public static function secureCompare($known, $user){
		return hash_equals($known, $user);
	}
}