<?php
namespace svgta\oidc\token;
use svgta\oidc\utils\Statics;
use svgta\oidc\Exception;
use Firebase\JWT\JWK;
use Firebase\JWT\JWT;

class refresh{
	private $param = null;
	const GRANT_TYPE = 'refresh_token';
	public function __construct(){
		$this->param = Statics::getParam();
	}
	public function new(?string $refresh_token = null): array {
		if(!$refresh_token)
			throw new Exception('refresh_token needed');
		$oidcConf = Statics::OIDC_CONFIG_KEY;
		if(!isset($this->param->$oidcConf))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		if(!in_array('client_secret_post', $this->param->$oidcConf->token_endpoint_auth_methods_supported))
			throw new Exception('Method POST not supported for refresh token');
		$_gparams = array_merge(Statics::guzzleParams(), [
			'form_params' => [
				'client_id' => $this->param->client_id,
				'client_secret' => $this->param->client_secret,
				'grant_type' => self::GRANT_TYPE,
				'refresh_token' => $refresh_token,
			],
			'headers' => [
				'Content-Type' => 'application/x-www-form-urlencoded'
			],
		]);
		$res = Statics::getGuzzleClient()->request('POST', $this->param->$oidcConf->token_endpoint, $_gparams);
		$ret = (array)JWT::jsonDecode((string)$res->getBody());
		$this->param->set('token', $ret);
		return $ret;
	}
}
