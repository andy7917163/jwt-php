<?php 
$playload = array(
    'name' => 'andy',
    'email' => 'andy@gmail.com'
);
$key = 'andy';

// echo encode($playload,$key);
echo '123';
$newlogin = new login;
echo $jwt =  $newlogin->encode($playload, $key);
print_r($newlogin->decode($jwt,$key));


class login
{
    
    function __construct()
    {
        # code...
    }
    public function encode($payload, $key, $alg = 'SHA256')
    {
        $key = md5($key);
        $jwt = base64_encode(json_encode(['typ' => 'JWT', 'alg' => $alg])) . '.' . base64_encode(json_encode($payload));
        return $jwt . '.' . self::signature($jwt, $key, $alg);
    }
    public function signature($input, $key, $alg)
    {
        return hash_hmac($alg, $input, $key);
    }

    public function decode($jwt, $key)
    {
        $tokens = explode('.', $jwt);
        $key    = md5($key);

        if (count($tokens) != 3)
            return false;

        list($header64, $payload64, $sign) = $tokens;

        $header = json_decode(base64_decode($header64), JSON_OBJECT_AS_ARRAY);
        if (empty($header['alg']))
            return false;

        if (self::signature($header64 . '.' . $payload64, $key, $header['alg']) !== $sign)
            return false;

        $payload = json_decode(base64_decode($payload64), JSON_OBJECT_AS_ARRAY);

        $time = $_SERVER['REQUEST_TIME'];
        if (isset($payload['iat']) && $payload['iat'] > $time)
            return false;

        if (isset($payload['exp']) && $payload['exp'] < $time)
            return false;

        return $payload;
    }
}

?>