# oidcClient

A PHP library to be used as OIDC client for projects.

  * [Installation](#installation)
  * [How To Use](#how-to-use)
    + [Initiate](#initiate)
    + [Set Parameters](#set-parameters)
    + [Authentication](#authentication)
    + [User Info](#user-info)
    + [Logout](#logout)
  * [Tokens](#tokens)
    + [Get tokens](#get-tokens)
    + [Revoke a token](#revoke-a-token)
    + [Force OP to give the refresh-token](#force-op-to-give-the-refresh-token)
    + [Refresh a token](#refresh-a-token)
    + [Get user info with an access token](#get-user-info-with-an-access-token)
  * [Parameters](#parameters)
    + [GET params](#get-params)
    + [SET params](#set-params)
    + [UNSET a param](#unset-a-param)
  * [Guzzle](#guzzle)



## Installation

Use composer

```php
composer require svgta/oidcclient
```

To encrypt the datas saved in the session, run the shell command : 

```shell
openssl rand -base64 32 > ...pathOfYourProject/vendor/svgtautils/oidcclient/src/salt.txt
```

A default salt.txt file is in the library. But it's insecure to use it.

This library use :

- firebase/php-jwt to deal with JWT tokens : https://github.com/firebase/php-jwt
- guzzlehttp/guzzle to request the OP : https://docs.guzzlephp.org/en/stable/overview.html



## How To Use

### Initiate 

With variables : 

```php
<?PHP
/***
.... your own code with include/require the vendor/autoload.php
***/
use svgtautils\oidc;

$iss = 'your OP url';
$client_id = 'your OIDC client id';
$client_secret = 'your OIDC client secret';
$oidc = new oidc\client($iss, $client_id, $client_secret);
```

With array : 

```php
<?PHP
/***
.... your own code with include/require the vendor/autoload.php
***/
use svgtautils\oidc;

$oidc = new oidc\client([
    'iss' => 'your OP url',
    'client_id' => 'your OIDC client id',
    'client_secret' => 'your OIDC client secret'
]);
```



### Set Parameters

<u>Use proxy</u> : 

```php
...
$oidc->param->guzzle->proxy = "myProxyinfo";
...
```

<u>Not verify SSL/TLS</u>

```php
...
$oidc->param->guzzle->verify = false;
...
```

<u>Redirect URI</u>

```php
...
$oidc->param->redirect_uri = "myRedirectURI";
...
```

<u>Use PKCE</u>

```php
...
$oidc->param->pkce = true;
//OR
$oidc->usePKCE();
...
```

<u>Authentication type</u> : (default "code")

```php
...
$oidc->param->authentication_type = "code"; //code OR implicit OR hybrid
...
```

<u>Scope</u> : (default only openid) -> set with an array

```php
...
$oidc->setScope([
    'scope1',
    'scope2',
    'scope3'
]);
...
```

This method don't remove the scopes already set, but add just the new.



### Authentication

```php
...
$oidc->authentication();
...
```



### User Info

```php
...
$uInfo = $oidc->getUserInfo();
...
```



### Logout

```php
...
$oidc->logout();
...
```

The logout method logout from the OP, but not from your app. Set the code you need to do that.

After the logout, you can erase the session datas for this OIDC client with this : 

```
...
svgtautils\oidc\session::deleteSession();
...
```



## Tokens

### Get tokens

After authentifcation, some tokens are set in the parameters :

* access_token
* id_token
* token : the JWT token
* refresh_token : can not be present, depend on the OP

To get a token :

```php
...
$accessToken = $oidc->param->access_token;
$idToken = $oidc->param->id_token;
$token = $oidc->param->token;
...
```



### Revoke a token

Only for access_token and refresh_token.

```php
...
$oidc->token->revoke->refresh($refreshToken); //revoke refresh token given
$oidc->token->revoke->access($accessToken); //revoke access token given
...
```

If the token is not given, the one find in the parameters will be used. If no token is found in parameters, an exception will result.



### Force OP to give the refresh-token

Some OP don't give the refresh token. You can force to have it, and store it in a database to reuse it after.

Before the authentication step, you have to set the param :

```php
...
$oidc->param->forceRefreshToken = true;
...
```

you will get the refresh token after authentication :

```php
...
$refreshToken = $oidc->param->refresh_token;
...
```



### Refresh a token

You need to have the refresh token to do that. Authentication type must be "code"

```php
...
$newToken = $oidc->token->refresh->new($refreshToken);
$oidc->authentication->verify->code($newToken);
$newAccessToken = $this->param->access_token;
...
```



### Get user info with an access token

```php
...
$userInfo = $oidc->getUserInfo($accessToken);
...
```



## Parameters

### GET params

**Get all parameters**

After having initiate, you can see the defaults parameters set :

```php
...
$params = $oidc->param->get();  // $params will be an array
var_dump($params);
...
```

In any case, you can see all the parameters set with the the command.



**Get one parameter**

```php
...
$myParam = $oidc->param->myParam; //return an object or the result of the object;
//OR
$myParam = $oidc->param->myParam(); // return an array or the reslt of the array;
//OR 
$myParam = $oidc->param->get('myParam'); //same result as $oidc->param->myParam()
```



**Concret example with default guzzle parameters :** 

```php
...
$guzzle = $oidc->param->guzzle;
/* the var_dump($guzzle) will return : 
object(stdClass)#21 (4) {
  ["debug"]=>
  bool(false)
  ["http_errors"]=>
  bool(true)
  ["proxy"]=>
  bool(false)
  ["verify"]=>
  bool(true)
}
*/

$guzzle = $oidc->param->guzzle(); // or $guzzle = $oidc->param->get('guzzle');
/* the var_dump($guzzle) will return : 
array(4) {
  ["debug"]=>
  bool(false)
  ["http_errors"]=>
  bool(true)
  ["proxy"]=>
  bool(false)
  ["verify"]=>
  bool(true)
}
*/

$verify = $oidc->param->guzzle->verify; // -> true in this case
//OR
$verify = $oidc->param->guzzle('verify'); // can have only one parameter
//OR
$verify = $oidc->param->get('guzzle','verify'); // can have only two parameters

...
```



### SET params

As for GET, you can set parameters in more than one maner

**Object : ** 

```php
...
$oidc->param->myParam1 = 'myValue';
//OR
$oidc->param->myParam1->myParam2 = 'value2'; //myParam1 need to be set before 
//OR
$oidc->param->myParm1 = ['myParam2' => 'value2', 'myParam3' => 'value3'];
...
```

**Method** :

```php
...
$oidc->param->set('myParam1', 'myValue');
//OR
$oidc->param->set('myParam1', ['myParam2' => 'value2', 'myParam3' => 'value3']);
...
```



### UNSET a param

Only a root parameter can be unset

```php
...
$oidc->param->unset('myParm');
...
```



## Guzzle

This library use guzzle. Default parameters have been set. You can read this page https://docs.guzzlephp.org/en/stable/request-options.html#cert to see the differents parameters you can set. They must be set in $oidc->param->guzzle to be active.



