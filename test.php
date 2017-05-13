<?php
/*
b3ecb60efb7145bfb87e077c27e7c207
AppKey : b3ecb60efb7145bfb87e077c27e7c207
Encrypted + Encoded AppKey : 
g3Gn6+dPOckHrlNH8pGgKuWTLXu/qiNOZ/p/gDK4Ay5iUwFU8Cukz+I5eba+KAuEW4s4a4ERq9yEFMuLD3kA0r4Fa8bhKoNO1pokEF1X3gh/Hyty8yJMmyP6xMTrpdZq+GPWbAG6i3ePKKU3cActxWm5DZ9jKgPl405I8aSYrPi2dTt0n/GYDZYJvzaXieSXuft2RBF/Jy023PRBar8Ebs89XfuT+fx5kPGodLL7vid7VvNpWk0pwjlZ8f4jOjK14KZrkrR+pOc/Wt6NxI6OAZ2LzXrCO8n0Sr4IIuhyrT2GX4GryFCyl4BgbwB6IzBBW9Mb01ojocn7Zt+hY4jAkg==

aa2cc65c-5a8d-46ec-b356-e09503af
app_key = aa2cc65c-5a8d-46ec-b356-e09503af

-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtaD9+J2aWX5AAZ8neJfK
5X1/TN+2OQteqDR8Y4GQwwuNvDGOkWlzNkjRVlBBEcsVNsZ51qhZaz6LiexxCflg
rDEOHU+igvJ7Llg1rnWKa8gvru8ptF4ESHCOgSUxf6YJJ3sSlz5/AecYA+Fw1yyv
sM1okIYX7crcpXblXgzBsASX7Mnh665GzwhwON3PE8yHdeBNa4keRVH4UesBN1pI
VR05Bh7vQsQQh7gwpBglkJuk7dew0eUU0oAJWsBFKgvfdHcKx9V2NW8bpc9EJ5vU
LsoLPbMmB1rrcEEEeC5lF/PVyhLUUUVkKekfaZl6JAgWf1T7UniSFwpeUNIVuMz0
nQIDAQAB
-----END PUBLIC KEY-----


MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtaD9+J2aWX5AAZ8neJfK5X1/TN+2OQteqDR8Y4GQwwuNvDGOkWlzNkjRVlBBEcsVNsZ51qhZaz6LiexxCflgrDEOHU+igvJ7Llg1rnWKa8gvru8ptF4ESHCOgSUxf6YJJ3sSlz5/AecYA+Fw1yyvsM1okIYX7crcpXblXgzBsASX7Mnh665GzwhwON3PE8yHdeBNa4keRVH4UesBN1pIVR05Bh7vQsQQh7gwpBglkJuk7dew0eUU0oAJWsBFKgvfdHcKx9V2NW8bpc9EJ5vULsoLPbMmB1rrcEEEeC5lF/PVyhLUUUVkKekfaZl6JAgWf1T7UniSFwpeUNIVuMz0nQIDAQAB

YYjD4mYXIfG+vziSAbivJCLHrK185XM34NfrGOV7fH2eKfuAf+45XD1kPJOmy76qzN+Pyk41jFobrKOU1KvijGbZIkTekbgQJrgFtrvwvqVMFRb9592+nMvt8ja5KzmiJo10a3sd0Tval+R+oLKQ2bn+/Q3C6UFFdiQNAKfJfBX+0wUjfs9roJlYGGJNf2FoDTA6cFL2/RlfDYmBnQJ23O7DJW4/RN6LdhHxz+nxUMpb6Eht+h/Uu1GC9vnn8Eanq8suv3J0oZAFPdfwrFw0yf5U6NB+gfG9Gi3GakzVotlLa98+1d9t/pGNKbFH7AkJmXqoKE5VWPb/qiJJGqysow==

*/
//echo base64_encode("102030");

//exit;
//$app_key =  base64_encode("b3ecb60efb7145bfb87e077c27e7c207");

/*$fp=fopen("GSTN_PublicKey.cer","r");
  $pub_key_string=fread($fp,8192);
  fclose($fp);
  $key_resource = openssl_get_publickey($pub_key_string);

print_r ($key_resource);
openssl x509 -inform der -in GSTN_PublicKey.cer -out certificate.pem

echo openssl_encrypt('102030',"AES-256-ECB",$app_key);
echo "\n\n";
*/


function pkcs5_pad ($text, $blocksize) { 
  $pad = $blocksize - (strlen($text) % $blocksize); 
  return $text . str_repeat(chr($pad), $pad); 
}

function getEncrypt($sStr, $sKey) {
  return base64_encode(
    mcrypt_encrypt(
        MCRYPT_RIJNDAEL_256, 
        $sKey,
        $sStr,
        MCRYPT_MODE_ECB
    )
  );
}
/*


rYk/VopIMpr8nvLUQRKZhACUqBlu+t1tZeW4J6+v0YiIibq6UzZXxP5OGL85yZiRTYHuMeJ4OL2MuIIu1bbQ15vSga6E4daAyOdGOiWksaAVpAUrUBugbm3zcv9KcymA1TzVQAZLUE5PoCsueco7zfvCq+fyEhuUgp/jTxJNgsqUNsHa9a5fcJSgyAeMYYuwr504H9k2XBXjU/4uWi1bWuP6C5KsOi9lUxjrwSg174rrc2a97mu/afXgjRufon3JQsvMSDhV+7UkERLseJa77O1Ol3Ff/u+9RClW4iCXBtSi4OPWorh31C0pZ2yzzLpZ9m1AhiuqJ9+dCu5oO77noQ


b3ecb60efb7145bfb87e077c27e7c207
*/


$pub_key = openssl_pkey_get_public(file_get_contents('certificate.pem'));
$keyData = openssl_pkey_get_details($pub_key);
print_r ($keyData);
/*//print_r ($keyData);
//file_put_contents('./key.pub', $keyData['key']);



echo $public_key;
echo "<br><br>";
echo getEncrypt(pkcs5_pad($app_key, 16), $public_key);
*/

/*$public_key =pack('H*',"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtaD9+J2aWX5AAZ8neJfK5X1/TN+2OQteqDR8Y4GQwwuNvDGOkWlzNkjRVlBBEcsVNsZ51qhZaz6LiexxCflgrDEOHU+igvJ7Llg1rnWKa8gvru8ptF4ESHCOgSUxf6YJJ3sSlz5/AecYA+Fw1yyvsM1okIYX7crcpXblXgzBsASX7Mnh665GzwhwON3PE8yHdeBNa4keRVH4UesBN1pIVR05Bh7vQsQQh7gwpBglkJuk7dew0eUU0oAJWsBFKgvfdHcKx9V2NW8bpc9EJ5vULsoLPbMmB1rrcEEEeC5lF/PVyhLUUUVkKekfaZl6JAgWf1T7UniSFwpeUNIVuMz0nQIDAQAB
");
$iv = openssl_random_pseudo_bytes(16);

echo openssl_encrypt($app_key,"AES-256-ECB",$public_key, OPENSSL_RAW_DATA, $iv);

b3ecb60efb7145bfb87e077c27e7c207
*/
define('APP_KEY','b3ecb60efb7145bfb87e077c27e7c207');
define ('USERNAME', 'GSTSPICETESTUSER1');
define ('GSTIN', '04AABFN9870CMZT');

define('CLIENT_ID','l7xxdf2b47b7d728426699a05c8d1ec33a60');
define('CLIENT_SEC','30a28162eb024f6e859a12bbb9c31725');

//define('HOST','http://devapi.gstsystem.co.in');
define ('HOST','https://api.spicegsp.com:8443');

function generateappKey ()
{
    //openssl x509 -inform der -in GSTN_PublicKey.cer -out certificate.pem
    //$app_key="";
    openssl_public_encrypt(APP_KEY, $encrypted,file_get_contents('certificate.pem') );
    return base64_encode($encrypted);   //encrypted string
}
function encryptOTP ()
{
  /*$byte_array = unpack('C*', '102030');
  print_r ($byte_array);
  */
  return base64_encode(openssl_encrypt('102030',"AES-256-ECB",APP_KEY, OPENSSL_RAW_DATA));
  
  //return getEncrypt(pkcs5_pad("102030", 16), APP_KEY);
  
}

function encryptData ($data,  $key)
{
      return base64_encode(openssl_encrypt($data,"AES-256-ECB",$key, OPENSSL_RAW_DATA));
      
}

function mac256($ent,$key)
{
    /*
    String generated_hmac=generateHmac(decrypted_data,NEW_EK);
    */
    $res = hash_hmac('sha256', $ent, $key, true);//(PHP 5 >= 5.1.2)
    return $res;
}

function decryptData($data, $key)
{
   return openssl_decrypt(base64_decode($data),"AES-256-ECB",$key, OPENSSL_RAW_DATA);
}


function decodeJsonResponse ($out, $rek, $ek )
{
    $apiEK = decryptData($rek, $ek);
    //echo $apiEK."\n";
    return base64_decode(decryptData($out, $apiEK));
   
}
function authenticate ()
{
      $appKey = generateappKey();
      $otp    = encryptOTP ();
      echo "APPKEY = [$appKey]\n";
      echo "OTP    = [$otp]\n";
   
      $headers = array ('Content-Type: application/json','clientid:  l7xxdf2b47b7d728426699a05c8d1ec33a60','client-secret: 30a28162eb024f6e859a12bbb9c31725','ip-usr: 115.248.189.69','txn: '.uniqid('SPI_'), 'state-cd: 11');
 
      /*
	OTP  Request API
      */
      echo "Testing  OTPREQUEST API \n";
      $data['action'] = "OTPREQUEST";
      $data['appkey'] = $appKey;
      $data['username'] = USERNAME; 
      
      $ch = curl_init();
	curl_setopt($ch, CURLOPT_URL,HOST."/taxpayerapi/v0.1/authenticate");
	curl_setopt($ch, CURLOPT_POST, 1);
	curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
	curl_setopt($ch, CURLOPT_VERBOSE, 1);
	$response = curl_exec($ch);

	curl_close($ch);

	var_dump($response);
	
	  /*
    Authenticate OTP 
    */
    echo "Testing  AUTHTOKEN API  \n";
    $data['action'] = "AUTHTOKEN";
    $data['appkey'] = $appKey;
    $data['username'] = USERNAME; 
    $data['otp']      = $otp;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,HOST."/taxpayerapi/v0.1/authenticate");
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_VERBOSE, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);

    echo $response."\n\n";
    
    $outData = json_decode($response);
    print_r ($outData);
    
    return $outData;
     
}
authenticate ();

exit (0);

FileGSTR1 ();
function FileGSTR1 ()
{
    
    $headers = array ('Content-Type: application/json','clientid: l7xxdf2b47b7d728426699a05c8d1ec33a60','client-secret: 30a28162eb024f6e859a12bbb9c31725','ip-usr: 115.248.189.69','txn: '.uniqid('SPI_'), 'state-cd: 11');
    
    
    $outData   = authenticate ();
    $authToken = $outData->auth_token;
    $sek       = $outData->sek; 
    
    
    $ek =  decryptData ($sek, APP_KEY);
    
    array_push($headers, 'auth-token: '.$authToken);
    array_push($headers, 'username: '.USERNAME); 
    
    unset ($data);
    
    $saveData='{"gstin":"37ABCDE9552F3Z4","ret_pd":"072016","checksum":"AflJufPlFStqKBZ","ttl_inv":1000,"ttl_tax":500,"ttl_igst":124.99,"ttl_sgst":5589.87,"ttl_cgst":3423,"sec_sum":[{"sec_nm":"b2b","checksum":"AflJufPlFStqKBZ","ttl_inv":1000,"ttl_tax":500,"ttl_igst":124.99,"ttl_sgst":5589.87,"ttl_cgst":3423,"cpty_sum":[{"ctin":"20GRRHF2562D3A3","checksum":"AflJufPlFStqKBZ","ttl_inv":1000,"ttl_tax":500,"ttl_igst":124.99,"ttl_sgst":5589.87,"ttl_cgst":3423}]}]}';
    
    
    $data['sign']='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';
    $data['st']  = 'ESIGN';
    $data['sid']    = '123456789012';
 
    
    $data['action'] = "RETSUBMIT";
    $data['data']  = encryptData ($saveData, $ek);
    //$data['hmac']  = base64_encode(mac256($saveData, $ek));   // HMAC-SHA256 of base64 data using EK   
    $data['hmac']  = 'da93785710c5c96daa03e175fbaadab5724edf8c2e9c503a11c4eb9c5f9bab81';
    
    print_r ($data);
    //http://".HOST."/taxpayerapi/v0.1/returns/gstr1
    //taxpayerapi/v0.1/returns/gstr1a
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,HOST."/taxpayerapi/v0.1/returns/gstr1a");
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_VERBOSE, 1);
  
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $response = curl_exec($ch);
    $outData = json_decode($response);
    curl_close($ch);
       
    var_dump (decodeJsonResponse($outData->data,$outData->rek, $ek ));
    

}
saveGSTR1GET ();

function saveGSTR1GET ()
{

   //$otp    = "G60y+4WG3hqKtbQOpcUVgBFQOEY4PgZM82uQQjlg6xs=";
   
    $headers = array ('Content-Type: application/json','clientid:  l7xxdf2b47b7d728426699a05c8d1ec33a60','client-secret: 30a28162eb024f6e859a12bbb9c31725','ip-usr: 115.248.189.69','txn: '.uniqid('SPI_'), 'state-cd: 11');
    
    
    $outData   = authenticate ();
    $authToken = $outData->auth_token;
    $sek       = $outData->sek; 
    
    
    $ek =  decryptData ($sek, APP_KEY);
    
    array_push($headers, 'auth-token: '.$authToken);
    array_push($headers, 'username: '.USERNAME); 
    
    //print_r ($headers);
      
    
    $saveData = '{"gstin":"SDL123123123123","fp":"112016","gt":"23423423","b2b":[{"ctin":"SDL321321321321","inv":[{"inum":"212315","idt":"02-10-2016","val":"20000","pos":"11","rchrg":"No","pro_ass":"N","itms":[{"num":"1","status":"A","ty":"G","hsn_sc":"19059020","txval":"10000","irt":"10","iamt":"1000","crt":"10","camt":"1000","srt":"10","samt":"1000"},{"num":"2","status":"A","ty":"G","hsn_sc":"19059020","txval":"20000","irt":"10","iamt":"2000","crt":"5","camt":"1000","srt":"5","samt":"1000"},{"num":"3","status":"A","ty":"G","hsn_sc":"19059020","txval":"10000","irt":"10","iamt":"1000","crt":"10","camt":"1000","srt":"10","samt":"1000"},{"num":"4","status":"A","ty":"G","hsn_sc":"19059020","txval":"20000","irt":"10","iamt":"2000","crt":"5","camt":"1000","srt":"5","samt":"1000"}]},{"inum":"212316","idt":"02-10-2016","val":"10000","pos":"11","rchrg":"No","pro_ass":"N","itms":[{"num":"1","status":"A","ty":"G","hsn_sc":"19059020","txval":"10000","irt":"10"," iamt":"1000","crt":"10","camt":"1000","srt":"10","samt":"1000"},{"num":"2","status":"A","ty":"G","hsn_sc":"19059020","txval":"20000","irt":"10","iamt":"2000","crt":"5","camt":"1000","srt":"5","samt":"1000"}]}]},{"ctin":"SDL321321321322","inv":[{"inum":"212316","idt":"03-10-2016","val":"30000","pos":"11","rchrg":"No","pro_ass":"N","itms":[{"num":"1","status":"A","ty":"G","hsn_sc":"19059020","txval":"10000","irt":"10","iamt":"1000","crt":"10","camt":"1000","srt":"10","samt":"1000"},{"num":"2","status":"A","ty":"G","hsn_sc":"19059020","txval":"20000","irt":"10","iamt":"2000","crt":"5","camt":"1000","srt":"5","samt":"1000"}]}]}]}';
    
    echo "Testing GST1 Invoices Save API\n";
    
    unset ($data);
    $data['action'] = "RETSAVE";
    $data['data']  = encryptData ($saveData, $ek);
    //$data['hmac']  = base64_encode(mac256($saveData, $ek));   // HMAC-SHA256 of base64 data using EK   
    $data['hmac']  = 'da93785710c5c96daa03e175fbaadab5724edf8c2e9c503a11c4eb9c5f9bab81';
    
    print_r ($data);
    //http://".HOST."/taxpayerapi/v0.1/returns/gstr1
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,HOST."/taxpayerapi/v0.1/returns/gstr1");
    //curl_setopt($ch, CURLOPT_POST, 1);
    //curl_setopt($ch, CURLOPT_PUT, 1);
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "PUT");
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    //curl_setopt($ch, CURLOPT_VERBOSE, 1);
  
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $response = curl_exec($ch);
    $outData = json_decode($response);
    curl_close($ch);
    
   
    var_dump (decodeJsonResponse($outData->data,$outData->rek, $ek ));
    
    
    /*
    Get Return Report
    /taxpayerapi/v0.1/returns/gstr1?action=B2B&ret_period=112016&gstin=04AABFN9870CMZT&action_required=Y
    http://".HOST."/taxpayerapi/v0.1/returns/gstr1?action=B2B&ret_period=112016&gstin=04AABFN9870CMZT&action_required=Y
    */
    echo "Testing GST1 Detailed Invoices\n";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,HOST."/taxpayerapi/v0.1/returns/gstr1?action=B2B&ret_period=112016&gstin=".GSTIN."&action_required=Y");
    
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
   // curl_setopt($ch, CURLOPT_VERBOSE, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    $outData = json_decode($response);
    print_r ($outData);
    
    var_dump (decodeJsonResponse($outData->data,$outData->rek, $ek ));
    
}




function receivedData()
{
    /*
    String decrypted_appkey = "41+sD/gm9DWQeZbJm98qb3ss9Eu96XkClU5a4hyfaAw=";
    String receivedSEK = "yDWrI0m6juY+MKsPNtWkBYJAVsE0XIQvAJwv+P2T9DgOLzbTmU1E5NkewRcnIsK2";
    String gotREK = "QdwtOmbHgs5+T6XguaXrJtXyc1EpapQzuV5wWgEiDbUdShGCyOtl6JelLUI/R5xt";
    String data="czI9UduToC0S2M/Z8NxmD6AaiCHqK/wN4cLnpjje1LCgo7hXhoGvSUac0BB9umkBnWEO+osui4ZZHZIHrO8bvMlQI5mmyuqDxqLTg5IkgYCzUnDWGV6qP/6ei2J8eCKLxqv0XALN228h0QhNK4nr3Q9n4HVGngdXJf1dSIcxNVXQaJTctti1w7n6bm5Ht2FlMVKsIT7O8bwD9OyJtV0Z0jZa45DoWMxIwbRQKTnBCzC7+gCWSBriGW1Bsc4AGMzQks8qE0y1rQscgtPp8D6/eHjIT5e3jwn9EWYZdgDb+y1sCaUL77AEvKm9inM3fyfj3yw11I31NX79KVFzKCOFA3gfuz2RhTZ5QnxuUABGuHXDrLKaYkkxa6f0GPBDJmUqs5/R1w2YjpOzdDG+i0zRjPvIdSpM4wzVt0dB449TplAftdPkLCmVKBovrLe8OwE58nI5j63Kr8JMFc/V8XBFDpRDZl4EgdLeKWX4rop67GeWUVjdIyyAuiOiXTi/v9r1EGpFzybDJE2Z9S2/ntK5iVsPT6Bn4MaqkTiOG5D3eh5aDNuM3mToDC6LSD7PkX9Ekt1R/T1dLeKDOnEo5aQqCcqm/v5A9AZw86nyzFPfdjLfl9TOem4/hSP8Xslx645jnhUlr3kkshw5LzRpx5KaC32PC+eOcRq6MEeVF6vStvA/XA/9dRazxwvPnS4z09gtSdZRozls1UmNjBkhSoh4tDSU0lQXIsrmr/tGtLSsj1fH7h5De+qBvhyvY3LOw6CGfq3dKUFcE0n4yLosMIm2xbtVzROGdNXgDmUPUmk9wXHLc5UA8GNY9rq1z1ypCBbYpHLCQ9NHLncweF2FOK2obqF3kioypUbPxndgtd4cbVReXf9XBL9YkkxDCvNjH44bz0ciVnhg9jwGETLU6z40/s3ew8dDrNCbUmrGK42YxB44Ljwk5RQBRa5uMJnrFKiR8dnUJZai12moHO6GzIg5yiYEEa65rbzgdJOozcjTXgLl2Mf1uR4jN3Y7+u/e4OcYNHlF2Jd/7EGH+sJ9aOIYsq0K8f82o4jbbInhSg37pv2Kf5fm6urd4UoQUJ01fGGOHytSegKX2wO9vlKhHyrbu1+zMnfjEXabjENTlLWS5npkDhO7CaVsK4XsxTucsSdXKg3w7n82C05acOwrvewHCMNWD1IZuuKKcHWLhd7khs0gGRSQR4eKbN17fuYg2aTkQM/n1/8/NZP35UsMt+w9zpewE1wQr6C4guFoiIS1IUReJwFqCBAHsyXCnSdVjZlzZu40KYGWjR3TmkG4vVZA22cxsq83Oc/aykrflL0f1QI6txyfqSZAlpNEqKHerDR/iGAgwYa5f9y8Id7hnyK1lU0NnkAbKbBh9GWuvtBiNL7AvrDNMLt2lStyuDhh0TTscAqFv26jjAtz2MoEZ9HPvoBPDAsxq0HGFeoypyeQKZI0/xTh+iVcsMxgqY5FeOEiWEW/cBBJZOP402+319jDlDoSRerbUKwP63TLxE/zL2j4YyxHTEWi9PUiF+JosUHmza9PiyTdbIxyrhxXDfKVoQ==";
    
    
    byte[] authEK = decrypt(receivedSEK, decodeBase64StringTOByte(decrypted_appkey));
    System.out.println("Encoded Auth EK (Received):"+ encodeBase64String(authEK));
    
    byte[] apiEK = decrypt(gotREK, authEK);
    System.out.println("Encoded Api EK (Received):"+ encodeBase64String(apiEK));
    String jsonData = new String(decodeBase64StringTOByte(new String(decrypt(data, apiEK))));
    System.out.println(jsonData);
    
    Encoded Auth EK (Received):WPYDKz5DVjGTW9UVNoWJBW2p09hOzub5nc9UYX/ejCo=
    Encoded Api EK (Received):GEoP/gZDnqeTNTAxUcmUTxAYUx+E2vRcCKYv6wD5Qfc=
    {"b2b":[{"ctin":"37ABCDE9552F3Z4","inv":[{"inum":"S008400","idt":"09-04-2016","val":861786.91,"pos":"6","rchrg":"No","pro_ass":"Y","itms":[{"num":1,"itm_det":{"ty":"S","hsn_sc":"H724","txval":5589.87,"irt":0.0,"iamt":0.0,"crt":87.92,"camt":5.7947562568E8,"srt":86.56,"samt":50.74}},{"num":2,"itm_det":{"ty":"S","hsn_sc":"H863","txval":2509.27,"irt":0.0,"iamt":0.0,"crt":12.99,"camt":26144.48,"srt":31.81,"samt":276654.5}}]}]},{"ctin":"76ABCDE2148F9Z9","inv":[{"chksum":"AflJufPlFStqKBZ","inum":"S008400","idt":"24-11-2016","val":729248.16,"pos":"6","rchrg":"No","pro_ass":"Y","itms":[{"num":1,"itm_det":{"ty":"S","hsn_sc":"S8590","txval":8196.88,"irt":0.0,"iamt":0.0,"crt":42.44,"camt":202.86,"srt":40.99,"samt":0.02}},{"num":2,"itm_det":{"ty":"S","hsn_sc":"H357","txval":6760.14,"irt":0.0,"iamt":0.0,"crt":23.89,"camt":6.8214986738E8,"srt":60.95,"samt":0.03}}]}]}]}

    */
    $auth_token = "8a227e0ba56042a0acdf98b3477d2c03";
    $sek        = "md8o69God+N6rfobLBIaOrTwr/TC8tISla+neJR6zXVN8WqviEiqJkkcl3/pihtk";
    $data 	= "mguEvuY5RscRLepZfmU4b28voA2y4PE4vxW7duH4V0hTUk+VTDTRdGBhM6UWsiKDegLs75xos6rsw4ASqlAwk534NSFTtFnZqPbbFaaEXvy1yTflaPvOfr8JK1nSy98Er9aSfOw7BhXHHaf6MBwS1wCJOSbsbLhKF8sTnweE49BOs8MJR3V4ubWAPFlB3w91okH5zA+BP04mCxIP4I3cBSOHEb24ki5vuF0XEs9c38Lzj796ujjINwM2dm/NWuWxxO6rdIaJhW3K9S+OoLEzbT8YdbkEgjYwZspjkOb9XIHOYpV6Itslwp+1o15haaaN+QPWrBKfdemYLPsx+ePIwe1bW9liArc8sa4dDnvKakrpbunGuwmZsa+fAqrYP141f/UsTqKATlkT89QRuCsNpwU5wIiraL3jQKhRrIY0RUBRNZiieAX4aws7QCvZo5rVm+vYDdpO4prfFtcsX21TKRBfvSDAedvcKLxBpn5A6rEDInrKeh3jqjJcMAZZ9lHzZZGRcq3UocozYV6g4pGkFHhoTlBG7y7OARsxZZYwBwAgPtXMQVDv6J7Io/VUhBtLfrXO/KBLEJ8j88IsVob7/SNLtwr8mLrjoOp/cMYhpMMHbEQAkc8mSb8EYCeatjwjn5iILvt00G4OWrB01zxv7E2S7NTKMe/HADWrXtjtwR6Zn+xiddDydUx6SxzGE9Z4C9s0f6ApPnsqyd/Uq6Wz4H4/kG8bAHzRIliXGGdfTdG9DA00WG/gBhz97EJSXkh/MgkoaWR+FxVbIBtmwltKYrvk7B2/u5/8cLCSWTbehQiVCuNKGvTQ3IO1Z+k9gADQi7g+hh432YserDYEwm46O91xQAGAQLnD9VSeUJ/cRwwzxF60+m+I9AuToSxdm8gY3+/l4zbTAdjWlLg8Gk3DZ/hEn8taqY2f3iDTBahffGwfNAYxnSL370VwTaYO+zvMip2EVRwyg9AjAlrhx1G8BGsllHNjHXxmfrS0AOlUtJv1mzJPCmIRPWALHNMlbkfxZR8L19YHMDAdF63fMXl6+CJLDxCn7/TEsIrEm0f8OJiNa5/3SA8aKIDnyfZgr1hoUV+FWaxG6YPUX6k6gCie3cEI/ECo8j8JWyVeNnFAOTJ9E36LwAFW//RWE74aIcY9HGO2ndcH7pGEB1SJFc1VokG61ss3qwyEF3YB0Nv5scoi1HVBfttsFHbmoA73DBxRX4YrgMKlzzn2k3N4ZekeS8DY6LSgjXeiq++hyFe75RRp3kI0FLVh4woZyiGHWPqbRLcDkj3nCqrN4GgZra3k6XaMIL2d/9YG+8jnFdF5omseEYA5WF6KeW8afne6WHhBuW+PSUKHn2mtJCaEbhzr0fek/aXXWci2eKKHpC7g9slc7jSML5x4hH78xTn0YGVGQGlJoCIgJtoZssGq1bKXlv/tQtQU0ofc5hJz6q+g7fFXpwiKEVd/pHQHDebt6vM9ljHbHxO4tyFkMZjwHwDaK3VsHFsKUFe5LboOcTEaa29AiuSqVYC3DpCRETKe8hpeVw/N5TPCktsM/bV7mKnxrw==";
    $rek  = "r4IblJNQcoJ7jZsUkX+9muCwmUSXxY3eOrG4WjNQUc2QyoSXXXjRwZbcJzy24nvl";
    
    
    $app_key         = "41+sD/gm9DWQeZbJm98qb3ss9Eu96XkClU5a4hyfaAw=";
    $sek 	     = "yDWrI0m6juY+MKsPNtWkBYJAVsE0XIQvAJwv+P2T9DgOLzbTmU1E5NkewRcnIsK2";
    $data	     = "czI9UduToC0S2M/Z8NxmD6AaiCHqK/wN4cLnpjje1LCgo7hXhoGvSUac0BB9umkBnWEO+osui4ZZHZIHrO8bvMlQI5mmyuqDxqLTg5IkgYCzUnDWGV6qP/6ei2J8eCKLxqv0XALN228h0QhNK4nr3Q9n4HVGngdXJf1dSIcxNVXQaJTctti1w7n6bm5Ht2FlMVKsIT7O8bwD9OyJtV0Z0jZa45DoWMxIwbRQKTnBCzC7+gCWSBriGW1Bsc4AGMzQks8qE0y1rQscgtPp8D6/eHjIT5e3jwn9EWYZdgDb+y1sCaUL77AEvKm9inM3fyfj3yw11I31NX79KVFzKCOFA3gfuz2RhTZ5QnxuUABGuHXDrLKaYkkxa6f0GPBDJmUqs5/R1w2YjpOzdDG+i0zRjPvIdSpM4wzVt0dB449TplAftdPkLCmVKBovrLe8OwE58nI5j63Kr8JMFc/V8XBFDpRDZl4EgdLeKWX4rop67GeWUVjdIyyAuiOiXTi/v9r1EGpFzybDJE2Z9S2/ntK5iVsPT6Bn4MaqkTiOG5D3eh5aDNuM3mToDC6LSD7PkX9Ekt1R/T1dLeKDOnEo5aQqCcqm/v5A9AZw86nyzFPfdjLfl9TOem4/hSP8Xslx645jnhUlr3kkshw5LzRpx5KaC32PC+eOcRq6MEeVF6vStvA/XA/9dRazxwvPnS4z09gtSdZRozls1UmNjBkhSoh4tDSU0lQXIsrmr/tGtLSsj1fH7h5De+qBvhyvY3LOw6CGfq3dKUFcE0n4yLosMIm2xbtVzROGdNXgDmUPUmk9wXHLc5UA8GNY9rq1z1ypCBbYpHLCQ9NHLncweF2FOK2obqF3kioypUbPxndgtd4cbVReXf9XBL9YkkxDCvNjH44bz0ciVnhg9jwGETLU6z40/s3ew8dDrNCbUmrGK42YxB44Ljwk5RQBRa5uMJnrFKiR8dnUJZai12moHO6GzIg5yiYEEa65rbzgdJOozcjTXgLl2Mf1uR4jN3Y7+u/e4OcYNHlF2Jd/7EGH+sJ9aOIYsq0K8f82o4jbbInhSg37pv2Kf5fm6urd4UoQUJ01fGGOHytSegKX2wO9vlKhHyrbu1+zMnfjEXabjENTlLWS5npkDhO7CaVsK4XsxTucsSdXKg3w7n82C05acOwrvewHCMNWD1IZuuKKcHWLhd7khs0gGRSQR4eKbN17fuYg2aTkQM/n1/8/NZP35UsMt+w9zpewE1wQr6C4guFoiIS1IUReJwFqCBAHsyXCnSdVjZlzZu40KYGWjR3TmkG4vVZA22cxsq83Oc/aykrflL0f1QI6txyfqSZAlpNEqKHerDR/iGAgwYa5f9y8Id7hnyK1lU0NnkAbKbBh9GWuvtBiNL7AvrDNMLt2lStyuDhh0TTscAqFv26jjAtz2MoEZ9HPvoBPDAsxq0HGFeoypyeQKZI0/xTh+iVcsMxgqY5FeOEiWEW/cBBJZOP402+319jDlDoSRerbUKwP63TLxE/zL2j4YyxHTEWi9PUiF+JosUHmza9PiyTdbIxyrhxXDfKVoQ==";
    $rek             = "QdwtOmbHgs5+T6XguaXrJtXyc1EpapQzuV5wWgEiDbUdShGCyOtl6JelLUI/R5xt";
    
    
    $authEK = decryptData ($sek, base64_decode($app_key));
    
    echo "Auth EK = ".base64_encode($authEK)."\n";
    
   
    
    $apiEK  = decryptData  ($rek , $authEK);
    
    echo "API  EK = ".base64_encode($apiEK)."\n";
    
    $data   = decryptData ($data, $apiEK);
    
    print_r ($data);
    
}





//receivedData ();

?>
