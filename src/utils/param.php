<?php
namespace svgtautils\oidc\utils;
class param{
	private static $paramsList = [];
	public function destruct(){
		self::$paramsList = [];
	}
	public function set(string|array $key, $value = null): void{
		if(is_string($key)){
			if(is_array($value) OR is_object($value)){
				foreach($value as $k=>$v)
					self::$paramsList[$key][$k] = $v;
			}else{
				self::$paramsList[$key] = $value;
			}
		}
		if(is_array($key))
			foreach($key as $k => $v)
				self::$paramsList[$k] = $v;
	}
	public function unset(string $key = null): void{
		if($key AND isset(self::$paramsList[$key]))
			unset(self::$paramsList[$key]);
	}
	public function get(string $key = null, string $_key = null): string|array|null|bool {
		if(!$key)
			return self::$paramsList;
		if(!isset(self::$paramsList[$key]))
			return null;
		if(!$_key)
			return self::$paramsList[$key];
		if(!is_array(self::$paramsList[$key]))
			return self::$paramsList[$key];
		if(!isset(self::$paramsList[$key][$_key]))
			return null;
		return self::$paramsList[$key][$_key];
	}
	public function getObj($key): object|null|string|bool|array {
		$obj = json_decode(json_encode($this->get($key)));
		return $obj;
	}
	public function __call($name, $arguments){
		if($arguments)
			$arg = $arguments[0];
		else
			$arg = null;
		return $this->get($name, $arg);
	}
	public function __get($name){
		return $this->getObj($name);
	}
	public function __set($name, $value){
		$this->set($name, $value);
	}
	public function __unset($name){
		$this->unset($name);
	}
	public function __isset($name){
		if($this->get($name))
			return true;
		return false;
	}
}