<?php
namespace svgta\oidc\token;
use svgta\oidc\utils\Statics;
use svgta\oidc\Exception;
use svgta\oidc\session;
class introspect{
  private $param = null;
  private $endpoint = null;

  const END_POINT = 'introspection_endpoint';
  public function __construct(){
    session::retrieve();
    $this->param = Statics::getParam();
    $endPoint = self::END_POINT;
    $oidcConf = Statics::OIDC_CONFIG_KEY;
    if(!$this->param->get(Statics::OIDC_CONFIG_KEY))
      $this->param->set(Statics::OIDC_CONFIG_KEY, Statics::getConfFile($this->param->iss));
    $this->endpoint = $this->param->$oidcConf->$endPoint;
  }
  public function id($token = null): array{
    if($token === null)
      $token = $this->param->id_token;
    return $this->introspect($token, 'id_token');
  }
  public function access($token = null): array{
    if($token === null)
      $token = $this->param->access_token;
    return $this->introspect($token, 'access_token');
  }
  private function introspect($token = null, $hint = null): array{
    if(!$token)
      throw new Exception('Token not given');
    if(!$this->endpoint)
      throw new Exception('endpoint not defined');
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
        'Authorization' => 'Basic' .  base64_encode(urlencode($this->param->client_id) . ':' . urlencode($this->param->client_secret)),
        'Accept' => 'application/json',
    ];
    $_gparams['form_params'] = $param;
    $res = Statics::getGuzzleClient()->request('POST', $this->endpoint, $_gparams);
    return json_decode((string)$res->getBody(), TRUE);
  }
}
