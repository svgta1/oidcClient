<?php
namespace svgta\oidc\token;
use svgta\oidc\utils\Statics;
use svgta\oidc\Exception;
class revoke{
	private $param = null;
	public function __construct(){
		$this->param = Statics::getParam();
	}
	public function refresh($token = null): array{
		return $this->revoke($token, 'refresh_token');
	}
	public function access($token = null): array{
		if($token === null)
			$token = $this->param->access_token;
		return $this->revoke($token, 'access_token');
	}
	private function revoke($token = null, $hint = null): array{
		if(!$token)
			throw new Exception('Token not given');
		$oidcConf =  Statics::OIDC_CONFIG_KEY;
		if(!isset($this->param->$oidcConf))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		if(!isset($this->param->$oidcConf->revocation_endpoint))
			throw new Exception('Revocation Endpoint not set');

		$param = [
			'token' => $token,
		];
		if(!$hint)
			$param['token_type_hint'] = 'access_token';
		else
			$param['token_type_hint'] = $hint;

		$gParams = Statics::guzzleParams();
		$_gparams = $gParams;
		$_gparams['headers'] = [
				'Content-Type' => 'application/x-www-form-urlencoded',
				'Authorization' => 'Basic' .  base64_encode(urlencode($this->param->client_id) . ':' . urlencode($this->param->client_secret))
		];
		$_gparams['form_params'] = $param;
		$res = Statics::getGuzzleClient()->request('POST', $this->param->$oidcConf->revocation_endpoint, $_gparams);
		return json_decode((string)$res->getBody(), TRUE);
	}
}