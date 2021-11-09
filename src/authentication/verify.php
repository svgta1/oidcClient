<?php
namespace svgtautils\oidc\authentication;
use svgtautils\oidc\Exception;
use svgtautils\oidc\utils\Statics;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class verify{
	private $param = null;
	private $request = null;

	const GRANT_TYPE = 'authorization_code'; 
	const HASH_ALGO = [
		'RS256' => 'sha256',
		'ES256' => 'sha256',
		'HS256' => 'sha256',
		'HS384' => 'sha384',
		'HS512' => 'sha512',
	];

	public function __construct($request){
		$this->param = Statics::getParam();
		$this->request = $request;
	}

	public function code(array $token = null){
		$this->isError();
		$oidcConf =  Statics::OIDC_CONFIG_KEY;
		if(!isset($this->param->$oidcConf))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		$gParams = Statics::guzzleParams();
		if($token === null){
			if(!isset($this->request['code']))
				throw new Exception('code not received');
			$param = [
				'client_id' => $this->param->client_id,
				'client_secret' => $this->param->client_secret,
				'code' => $this->request['code'],
				'grant_type' => self::GRANT_TYPE,
				'redirect_uri' => $this->param->redirect_uri,
			];
			if($this->param->pkce)
				$param['code_verifier'] = $this->param->code_verifier;
			$_gparams = $gParams;
			$_gparams['headers'] = [
				'Content-Type' => 'application/x-www-form-urlencoded',
			];
			$_gparams['form_params'] = $param;

			$res = Statics::getGuzzleClient()->request('POST', $this->param->$oidcConf->token_endpoint, $_gparams);
			$token = (array)JWT::jsonDecode((string)$res->getBody());
		}
		if(isset($token['error'])){
			$er = (isset($token['error_description'])) ? $token['error_description'] : 'Error ' . $token['error'];
			throw new Exception($er);
		}
		if(!isset($token['id_token']))
			throw new Exception('id_token not received');
		if(!isset($token['access_token']))
			throw new Exception('access_token not received');

		$id_token = $token['id_token'];
		$res = Statics::getGuzzleClient()->request('GET', $this->param->$oidcConf->jwks_uri, $gParams);
		$keys = json_decode((string)$res->getBody(), true);
		$decode = (array)JWT::decode($id_token, JWK::parseKeySet($keys), $this->param->$oidcConf->id_token_signing_alg_values_supported);  //exp, iat and nbf verified by JWT::decode
		if(!$decode['iss'] == $this->param->iss)
			throw new Exception('Bad issuer');
		if(is_string($decode['aud']) AND !($decode['aud'] == $this->param->client_id))
			throw new Exception('Bad audience');
		if(is_array($decode['aud']) AND !(in_array($this->param->client_id, $decode['aud'], true)))
			throw new Exception('Bad audience');
		if(is_array($decode['aud']) AND (!isset($decode['azp']) OR !($decode['azp'] == $this->param->client_id)))
			throw new Exception('Bad azp');
		if(isset($decode['nonce']) AND !($decode['nonce'] === $this->param->nonce))
			throw new Exception('Nonce not same');
		if(isset($decode['at_hash'])){
			$t = explode('.', $id_token);
			$sign = json_decode(JWT::urlsafeB64Decode($t[0]), TRUE);
			$this->verifyHash($decode['at_hash'], $token['access_token'], $sign['alg']);
		}

		$this->param->set('id_token', $id_token);
		$this->param->set('access_token', $token['access_token']);
		if(isset($token['refresh_token']))
			$this->param->set('refresh_token', $token['refresh_token']);
		$this->param->unset('state');
		return $decode;			
	}
	private function setAsh($alg = null, $value): string {
		if(!$alg)
			throw new Exception('Algo not knwon');
		if(!isset(self::HASH_ALGO[$alg]))
			throw new Exception('Algo not supported');
		$halg = self::HASH_ALGO[$alg];
		if(!$halg)
			return $value;
		$hash = hash($halg, $value, true);
		return $hash;
	}
	private function verifyHash($verify, $value, $alg = null): void {
		$hash = $this->setAsh($alg, $value);
		$ath = substr($hash, 0, strlen($hash) / 2);
		if(!($verify == JWT::urlsafeB64Encode($ath)))
			throw new Exception('Bad verify Hash');		
	}
	private function isError(): void {
		if(isset($this->request['error'])){
			throw new Exception('Error detected : ' . $this->request['error'] . ' -> ' . $this->request['error_description'] );
		}
	}

}