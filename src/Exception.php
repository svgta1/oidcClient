<?php
namespace svgta\oidc;

class Exception extends \Exception{
  private $info;
  public function __construct($message, $info = null, $code = 0, Throwable $previous = null){
    $msg = [
      "message" => $message,
      "info" => $info,
    ];
    parent::__construct(json_encode($msg), $code, $previous);
  }
}
