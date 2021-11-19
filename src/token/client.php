<?php
namespace svgta\oidc\token;
use svgta\oidc\utils\Statics;
use svgta\oidc\token\revoke;
use svgta\oidc\token\refresh;
use svgta\oidc\token\introspect;
use svgta\oidc\session;
use svgta\oidc\Exception;

class client{
	private $param = null;
	public $revoke = null;
	public $refresh = null;
	public $introspect = null;
	const METHOD = [
		'get' => 'client_secret_basic',
		'post' => 'client_secret_post',
	];
	public function __construct(){
		$this->param = Statics::getParam();
		$this->revoke = new revoke();
		$this->refresh = new refresh();
		$this->introspect = new introspect();
	}
	public function logout(?string $redirect = null, ?string $idToken = null): void{
		session::deleteSession();
		$oidcConf =  Statics::OIDC_CONFIG_KEY;
		if(!isset($this->param->$oidcConf))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		if(!isset($this->param->$oidcConf->end_session_endpoint))
			throw new Exception('End Session endpoint not set');
		if(!$idToken )
			$idToken = $this->param->id_token;
		if(!$redirect)
			$redirect = $this->param->redirect_uri;
		$params = [
			'id_token_hint' => $idToken,
			'client_id' => $this->param->client_id,
			'post_logout_redirect_uri' => $redirect,
		];
		if(isset($this->param->flow_automation['state'])){
			$this->param->set('state', Statics::getRandom());
			$params['state'] = $this->param->state;
		}
		session::store();
		$url = $this->param->$oidcConf->end_session_endpoint . '?' . http_build_query($params);
		header('Location: ' . $url);
        	exit;
	}
	public function getUserInfo(?string $accessToken = null): array {
		$oidcConf =  Statics::OIDC_CONFIG_KEY;
		if(!isset($this->param->$oidcConf))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		$this->userInfoCtrl();
		if(!in_array(self::METHOD['get'], $this->param->$oidcConf->token_endpoint_auth_methods_supported))
			throw new Exception('Method GET not supported to get user info');
		if(!$accessToken)
			$accessToken = $this->param->access_token;
		$gParams = Statics::guzzleParams();
		$_gparams = $gParams;
		$_gparams['headers'] = [
			'Authorization' => 'Bearer ' . $accessToken,
			'Accept' => 'application/json',
		];
		try{
			$res = Statics::getGuzzleClient()->request('GET', $this->param->$oidcConf->userinfo_endpoint, $_gparams);
			return json_decode((string)$res->getBody(), TRUE);
		}catch(\GuzzleHttp\Exception\ClientException $e){
			return $this->getUserInfoPost($accessToken);
		}
	}
	public function getUserInfoPost(?string $accessToken = null): array {
		$oidcConf =  Statics::OIDC_CONFIG_KEY;
		if(!isset($this->param->$oidcConf))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		$this->userInfoCtrl();
		if(!in_array(self::METHOD['post'], $this->param->$oidcConf->token_endpoint_auth_methods_supported))
			throw new Exception('Method POST not supported to get user info');
		if(!$accessToken)
			$accessToken = $this->param->access_token;
		$gParams = Statics::guzzleParams();
		$_gparams = $gParams;
		$_gparams['headers'] = [
			'Content-Type' => 'application/x-www-form-urlencoded',
		];
		$_gparams['form_params'] = [
			'access_token' => $accessToken,
		];
		$res = Statics::getGuzzleClient()->request('POST', $this->param->$oidcConf->userinfo_endpoint, $_gparams);
		return json_decode((string)$res->getBody(), TRUE);
	}
	private function userInfoCtrl(): void{
		$oidcConf =  Statics::OIDC_CONFIG_KEY;
		if(!isset($this->param->$oidcConf))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		if(!isset($this->param->$oidcConf->userinfo_endpoint))
			throw new Exception('No clientinfo endpoint');
		if(!isset($this->param->$oidcConf->token_endpoint_auth_methods_supported))
			throw new Exception('No token endpoint auth methods supported');
	}
}
