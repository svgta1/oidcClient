<?php
namespace svgta\oidc;
use svgta\oidc\Exception;
use svgta\oidc\utils\Statics;
use svgta\oidc\session;
use svgta\oidc\authentication\flows;
use svgta\oidc\authentication\pkce;
use svgta\oidc\authentication\verify;
use svgta\oidc\token\client as tokenClient;
use GuzzleHttp\Client as Guzzle;

class client{
	private $request = null;
	private $scope = [];
	public $param = null;
	public $token = null;
	public $verify = null;

	public function __construct($a, ...$c){
		$this->param = Statics::getParam();
		session::retrieve();
		if(is_array($a)){
			if(!$a['iss'] OR !filter_var($a['iss'], FILTER_VALIDATE_URL))
				throw new Exception('iss not set in array');
			if(!$a['client_id'])
				throw new Exception('client_id not set in array');
			if(!$a['client_secret'])
				throw new Exception('client_secret not set in array');
			$this->param->set($a);
		}else if(is_string($a) AND filter_var($a, FILTER_VALIDATE_URL)){
			if(!count($c) === 2)
				throw new Exception('To much or to few parameters sent');
			$this->param->client_id = $c[1];
			$this->param->client_secret = $c[1];
			$this->param->iss = $a;
		}else{
			throw new Exception('Bad parameters');
		}
		foreach(Statics::DEFAULT_PARAMS as $k=>$v)
			$this->param->$k = $v;
		$this->param->redirect_uri = Statics::getThisUri();
		$this->request = $_REQUEST;
		$guzzle = new Guzzle([
			'base_uri' => $this->param->iss,
		]);
		Statics::setGuzzleClient($guzzle);
		$this->token = new tokenClient();
		$this->verify = new verify($this->request);
	}
	public function logout(?string $idToken = null, ?string $redirect = null): void{
		$this->token->logout($redirect, $idToken);
	}
	public function getUserInfo(?string $token = null): array{
		return $this->token->getUserInfo($token);
	}
	public function authentication(?string $url = null): array{
		if(!$this->param->get(Statics::OIDC_CONFIG_KEY))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		if(!$this->param->isAuthorize)
			$this->location($url);
		if($this->param->authentication_type === 'code'){
			if(!isset($this->request['code']))
				throw new Exception('Code flow : not get code in request');
		}
		if($this->param->authentication_type === 'implicit'){
			if(!isset($this->request['id_token']))
				throw new Exception('Can not get fragment from URI for implicit flow. Use client side backend as javascript.');
		}
		if($this->param->authentication_type === 'hybrid'){
			if(!isset($this->request['code']))
				throw new Exception('Can not get fragment from URI for hybrid flow. Use client side backend as javascript.');
		}
		if(isset($this->param->state)){
			if(!isset($this->request['state']))
				$this->location($url);
			if(!($this->param->state === $this->request['state']))
				$this->location($url);
		}
		if(isset($this->param->token) AND ($this->param->token->exp <= \time())){
			if(isset($this->param->refresh_token)){
				$this->token->refresh->new($this->param->refresh_token);
			}else{
				session::deleteSession();
				$this->location($url);
			}
		}
		if(!isset($this->param->token)){
			$flowType = $this->param->get('authentication_type');
			$ret = $this->verify->$flowType();
			$this->param->token = $ret;
		}
		session::store();
		return $this->param->token();
	}
	private function location(?string $url = null): void{
		if(!$url)
			$url = $this->authorization();
		header('Location: ' . $url);
        	exit;
	}

	public function authorization(): string{
		if(!$this->param->get(Statics::OIDC_CONFIG_KEY))
			$this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
		if(!($endpoint = $this->param->get(Statics::OIDC_CONFIG_KEY, 'authorization_endpoint')))
			throw new Exception('Authorization endpoint not set');
		if($this->param->get('pkce') === true){
			$pkce = new pkce();
			$pkce->setAlgo("S256");
			foreach($pkce->getCode() as $k=>$v)
				$this->param->set($k, $v);
		}
		$automation = $this->param->flow_automation;
		if($automation)
		foreach($automation as $auto){
			$g = 'get'.$auto;
			$s = 'set'.$auto;
			if(!$this->$g())
				$this->$s();
		}
		$flow = new flows();
		$flowType = $this->param->get('authentication_type');
		$params = $flow->$flowType();
		$this->param->set('isAuthorize', true);
		session::store();
		$url = $endpoint . '?' . http_build_query($params);
		return $url;
	}
	public function usePkce(){
		$this->param->set('pkce', true);
	}
	public function setState(): void{
		$this->param->set('state', Statics::getRandom());
	}
	public function setNonce(): void{
		$this->param->set('nonce', Statics::getRandom());
	}
	private function getState(): ?string{
		return $this->param->get('state');
	}
	private function getNonce(): ?string{
		return $this->param->get('nonce');
	}
	public function setScope(array $scope): void{
		$scope = array_merge($scope, Statics::DEFAULT_SCOPE);
		foreach($scope as $s)
			if(!in_array($s, $this->scope))
				array_push($this->scope, $s);
		$this->param->set('scope', $this->getScope());
	}
	private function getScope(){
		return implode(Statics::SCOPE_DELIMITER, $this->scope);
	}
}
