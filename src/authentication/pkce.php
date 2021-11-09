<?php
namespace svgtautils\oidc\authentication;
use svgtautils\oidc\utils\Statics;
use svgtautils\oidc\Exception;

class pkce{
	const CODE_CHALLENGE_DEFAULT_ALGO = 'S256';
	const HASH_ALGO = [
		'S256' => 'sha256',
		'plain' => false,
	];

	private $algo = null;
	public function setAlgo($algo): void{
		if(!isset(self::HASH_ALGO[$algo]))
			throw new Exception('Algo not known : ' . $algo);
		$this->algo = $algo;
	}
	public function getCode(): array {
		if(!($algo = $this->algo))
			$algo = self::CODE_CHALLENGE_DEFAULT_ALGO;

		$code = Statics::getRandom(64);
		if(self::HASH_ALGO[$algo]){
			$h = hash(self::HASH_ALGO[$algo], $code, true);
			$hcode = strtr(rtrim(base64_encode($h), '='), '+/', '-_');
		}else{
			$hcode = $code;
		}
		return [
			'code_verifier' => $code,
			'code_challenge' => $hcode,
			'code_challenge_method' => $algo,
		];
	}
}