<?php
namespace svgtautils\oidc\authentication;
use svgtautils\oidc\utils\Statics;
use svgtautils\oidc\Exception;

class flows{
	const DEFAULT_PARAMS = [
		'scope',
		'response_type',
		'client_id',
		'redirect_uri',
		'state',
		'response_mode', /* query | fragment */
		'nonce',
		'display',  //page, popup, touch, wap
		'prompt', //none, login, consent, select_account
		'max_age',
		'ui_locales',
		'id_token_hint',
		'login_hint',
		'acr_values',
		'code_challenge_method',
		'code_challenge',
	];

	const PKCE = [
		'code_challenge_method',
		'code_challenge',
	];
	const REFRESH = [
		'prompt' => 'consent',
		'access_type' => 'offline',
	];
	const RESPONSE_TYPE = [
		'code' => ['code'],
		'implicit' => ['id_token token', 'id_token'],
		'hybrid' => ['code id_token', 'code token', 'code id_token token'],
	];

	private $param = null;

	public function __construct(){
		$this->param = Statics::getParam();
	}
	public function code(): array{
		$require = [
			'scope',
			'response_type',
			'client_id',
			'redirect_uri',
		];
		if($this->param->get('pkce') === true)
			$require = array_merge($require, self::PKCE);
		$param = $this->getParams();
		foreach($require as $p)
			if(!isset($param[$p]))
				throw new Exception('Flow core : missing parameter : ' . $p);
		if(!in_array($param['response_type'], self::RESPONSE_TYPE['code']))
			throw new Exception('Flow core : bad response_type ');
		if($this->param->forceRefreshToken)
			foreach(self::REFRESH as $k=>$v)
				$param[$k] = $v;
		return $param;
	}
	public function implicit(): array{
		$require = [
			'scope',
			'response_type',
			'client_id',
			'redirect_uri',
			'nonce', 
		];
		$param = $this->getParams();
		foreach($require as $p)
			if(!isset($param[$p]))
				throw new Exception('Flow implicite : missing parameter : ' . $p);
		if(!in_array($param['response_type'], self::RESPONSE_TYPE['implicit']))
			throw new Exception('Flow implicit : bad response_type');
		if(!is_string($param['nonce']))
			throw new Exception('Flow implicit : bad nonce format');
		$u = parse_url($param['redirect_uri']);
		if(($u['scheme'] == 'http') AND !($u['host'] == 'localhost'))
			throw new Exception('Flow implicit : bad url scheme');
		if($this->param->forceRefreshToken)
			foreach(self::REFRESH as $k=>$v)
				$param[$k] = $v;
		return $param;
	}
	public function hybrid(): array{
		$require = [
			'scope',
			'response_type',
			'client_id',
			'redirect_uri',
		];
		if($this->param->get('pkce') === true)
			$require = array_merge($require, self::PKCE);
		$param = $this->getParams();
		foreach($require as $p)
			if(!isset($param[$p]))
				throw new Exception('Flow hybrid : missing parameter : ' . $p);
		if(!in_array($param['response_type'], self::RESPONSE_TYPE['hybrid']))
			throw new Exception('Flow hybrid : bad response_type');
		if($this->param->forceRefreshToken)
			foreach(self::REFRESH as $k=>$v)
				$param[$k] = $v;
		return $param;
	}
	private function getParams(): array{
		$param = [];
		foreach(self::DEFAULT_PARAMS as $p)
			if($p AND ($v = $this->param->get($p)))
				$param[$p] = $v;
		return $param;
	}
}