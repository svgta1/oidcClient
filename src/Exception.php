<?php
namespace svgta\oidc;

class Exception extends \Exception{
  private $info;
  public fuction __construct($message, $info = null, $code = 0, Throwable $previous = null){
    $msg = [
      "message" => $message,
      "info" => $info,
    ];
    parent::__construct($message, $code, $previous);
  }
}
