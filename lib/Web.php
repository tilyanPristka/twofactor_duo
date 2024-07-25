<?php
namespace OCA\TwoFactorDuo;

class Web {
  public $duo_ikey;
	public $duo_skey;
  public $duo_host;
  public $callback;
  
  const DUO_CERTS     = "apps/twofactor_duo/lib/duo_certs.pem";
  const URL_TOKEN     = "/oauth/v1/token";
  const URL_HEALTH    = "/oauth/v1/health_check";
  const URL_AUTHORIZE = "/oauth/v1/authorize";
  const LEEWAY        = 60;
	
	function __construct($ikey, $skey, $host, $call){
		$this->duo_ikey = $ikey;
		$this->duo_skey = $skey;
		$this->duo_host = $host;
		$this->callback = $call;
	}
	public function duo_auth($username){
    $check = $this->check();
    if($check['stat'] == 'OK'){
      $duo_link = $this->auth($username);
      header('Location: '.$duo_link);
      exit();
    }
  }
	
  private function gen_duo($payload, $sec){
    $segments = [];
    $header = array('alg'=>'HS512','typ'=>'JWT');
    $segments[] = $this->base64UrlEncode(json_encode($header));
    $segments[] = $this->base64UrlEncode(json_encode($payload));
    $signing_input = implode('.', $segments);
    $signature = hash_hmac('SHA512', $signing_input, $sec, true);
    $segments[] = $this->base64UrlEncode($signature);
    return implode('.', $segments);
	}
  private function val_duo($token, $sec) {
    global $fn;
    $tokenParts = explode('.', $token);
    $header = base64_decode($tokenParts[0]);
    $payload = base64_decode($tokenParts[1]);
    $signatureProvided = $tokenParts[2];

    $base64UrlHeader = $this->base64UrlEncode($header);
    $base64UrlPayload = $this->base64UrlEncode($payload);
    $signature = hash_hmac('SHA512', $base64UrlHeader . "." . $base64UrlPayload, $sec, true);
    $base64UrlSignature = $this->base64UrlEncode($signature);
    
    $signatureValid = ($base64UrlSignature === $signatureProvided);
    $payloadData = json_decode($payload, true);
    $currentTime = time() + self::LEEWAY;
    if(isset($payloadData['exp']) && $payloadData['exp'] < $currentTime){
      return null;
    }
    return $signatureValid ? $payloadData : null;
  }
  private function base64UrlEncode($text, $mode=true){
    if($mode) return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($text));
    else return str_replace('=', '', strtr(base64_encode($input), '+/', '-_'));
  }
  
  private function curl_duo_v4($endpoint, $request, $user_agent=null){
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, "https://".$this->duo_host.$endpoint);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $request);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
    curl_setopt($ch, CURLOPT_CAINFO, self::DUO_CERTS);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    if($user_agent !== null) {
      curl_setopt($ch, CURLOPT_USERAGENT, $user_agent);
    }
    $res = curl_exec($ch);
    curl_close($ch);
    return json_decode($res, true);
  }
  private function jwt_payload($audience){
    $current_date = time();
    $payload = ["iss" => $this->duo_ikey, "sub" => $this->duo_ikey,
                "aud" => $audience, "jti" => $this->rand_str(),
                "iat" => $current_date, "exp" => $current_date + 300];
    return $this->gen_duo($payload, $this->duo_skey);
  }
  private function rand_str($state_length=36){
    $ALPHANUMERICS = array_merge(range('A', 'Z'), range('a', 'z'), range(0, 9));
    $state = "";
    for($i = 0; $i < $state_length; ++$i) {
      $state = $state.$ALPHANUMERICS[random_int(0, count($ALPHANUMERICS) - 1)];
    }
    return $state;
  }

  public function check(){
    $audience = "https://".$this->duo_host.self::URL_HEALTH;
    $payload = $this->jwt_payload($audience);
    $request = ["client_id" => $this->duo_ikey, "client_assertion" => $payload];
    $result = $this->curl_duo_v4(self::URL_HEALTH, $request);
    return $result;
  }
  public function auth($username, $state=false){
    if(!$state) $state = $this->rand_str();
    $current_date = time();
    $payload = [
      'scope' => 'openid',
      'redirect_uri' => $this->callback,
      'client_id' => $this->duo_ikey,
      'iss' => $this->duo_ikey,
      'aud' => "https://".$this->duo_host,
      'exp' => $current_date + 300,
      'state' => $state,
      'response_type' => 'code',
      'duo_uname' => $username,
      'use_duo_code_attribute' => true
    ];

    $request = $this->gen_duo($payload, $this->duo_skey);
    $allArgs = [
      'response_type' => 'code',
      'client_id' => $this->duo_ikey,
      'scope' => 'openid',
      'redirect_uri' => $this->callback,
      'request' => $request
    ];

    $arguments = http_build_query($allArgs);
    return "https://".$this->duo_host.self::URL_AUTHORIZE."?".$arguments;
  }
  public function get_result($duoCode, $username){
    $audience = "https://".$this->duo_host.self::URL_TOKEN;
    $useragent = "duo_universal_php/1.0.2 php/".phpversion()." ".php_uname();
    $payload = $this->jwt_payload($audience);
    $request = ["grant_type" => 'authorization_code',
                "code" => $duoCode,
                "redirect_uri" => $this->callback,
                "client_id" => $this->duo_ikey,
                "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion" => $payload];
    $result = $this->curl_duo_v4(self::URL_TOKEN, $request, $useragent);
    return $result;
  }
  public function decode($duoCode, $username){
    $res = $this->get_result($duoCode, $username);
    
    if(isset($res['error'])) return $res;
    else {
      $err_msg = "null";
      $required_keys = ["id_token", "access_token", "expires_in", "token_type"];
      foreach($required_keys as $key) {
        if(!isset($res[$key])) {
          $err_msg = "Result missing expected data.";
        }
      }
      if($res["token_type"] !== "Bearer"){
        $err_msg = "Result missing expected data.";
      }
      
      $token = $this->val_duo($res['id_token'], $this->duo_skey);
      
      $required_token_key = ["exp", "iat", "iss", "aud"];
      foreach($required_token_key as $key) {
        if(!isset($token[$key])) {
          $err_msg = "Result missing expected data.";
        }
      }
      if($token['aud'] !== $this->duo_ikey) {
        $err_msg = "Result missing expected data.";
      }
      if(!isset($token['preferred_username']) || $token['preferred_username'] !== $username) {
        $err_msg = "The username is invalid.";
      }
      $token['err_msg'] = $err_msg;
      return $token;
    }
  }
}
