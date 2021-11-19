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
    $this->param = Statics::getParam();
    $endPoint = self::END_POINT;
    $oidcConf = Statics::OIDC_CONFIG_KEY;
    $this->endpoint = $this->param->$oidcConf->$endPoint;
  }
  public function refresh($token = null): array{
    if($token === null)
      $token = $this->param->refresh_token;
    return $this->introspect($token, 'refresh_token');
  }
  public function access($token = null): array{
    if($token === null)
      $token = $this->param->access_token;
    return $this->introspect($token, 'access_token');
  }
  private function introspect($token = null, $hint = null): array{
    $oidcConf = Statics::OIDC_CONFIG_KEY;
    $endPoint = self::END_POINT;
    if(!$token)
      throw new Exception('Token not given');
    if(!$this->endpoint)
      throw new Exception('endpoint not defined', [
        $this->param->$oidcConf,
        $endPoint,
        $this->param->$oidcConf->endPoint,
      ]);
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
    try{
      $res = Statics::getGuzzleClient()->request('POST', $this->endpoint, $_gparams);
    }catch(\GuzzleHttp\Exception\ClientException $e){
      throw new Exception($e->getMessage(), $_gparams);
    }
    return json_decode((string)$res->getBody(), TRUE);
  }
}
