<?php
namespace svgta\oidc\token;
use svgta\oidc\utils\Statics;
use svgta\oidc\Exception;
class introspect{
  private $param = null;
  private $endpoint = null;

  const END_POINT = 'introspection_endpoint';
  public function __construct(){
    $this->param = Statics::getParam();
    $endPoint = self::END_POINT;
    $this->endpoint = $this->param->openid_configuration->$endPoint;
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
