<?php


define('APP_KEY','b3ecb60efb7145bfb87e077c27e7c207');

/*

define ('GSTIN', '04AABFN9870CMZT');
*/
/* Brillio  System */

define ('CLIENT_ID','l7xxcee286da778b41e6b7ecc31b159ebb38');
define ('CLIENT_SEC','2362055e8b66414b98e96e93ddebd789');
define ('USERNAME','brillio.tn.1');
//define ('USERNAME', 'GSTSPICETESTUSER1');
define ('GSTIN', '33GSPTN0561G1ZD');

/*
Client Id: l7xxcee286da778b41e6b7ecc31b159ebb38
Client Secret : 2362055e8b66414b98e96e93ddebd789
Username : Brillio.TN.1   brillio.tn.1
GSTN ID: 33GSPTN0561G1ZD
*/


define('BASE_URL', 'http://devapi.gstsystem.co.in/taxpayerapi/v0.1/');


function generateappKey ()
{
    //$app_key="";
    openssl_public_encrypt(APP_KEY, $encrypted,file_get_contents('GSTN_Public_Key/certificate.pem') );
    return base64_encode($encrypted);   //encrypted string
    //return $encrypted;
}
function encryptOTP ()
{
  
  return base64_encode(openssl_encrypt('102030',"AES-256-ECB",APP_KEY, OPENSSL_RAW_DATA));
     
}

function encryptData ($data,  $key)
{
      return base64_encode(openssl_encrypt($data,"AES-256-ECB",$key, OPENSSL_RAW_DATA));
      
}

function mac256($ent,$key)
{
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
    
    return base64_decode(decryptData($out, $apiEK));
   
}

function getSek ()
{
  
}
function testOTPReqAPICall ()
{

   $appKey = generateappKey();
   $otp    = encryptOTP ();
   //$otp    = "G60y+4WG3hqKtbQOpcUVgBFQOEY4PgZM82uQQjlg6xs=";
   
   echo "APPKEY = [$appKey]\n";
   echo "OTP    = [$otp]\n";
   
   $headers = array ('Content-Type: application/json','clientid: '.CLIENT_ID,'client-secret: '.CLIENT_SEC,'ip-usr: 12.8.91.80','txn: '.uniqid('SPI_'), 'state-cd: 33');
   
   /*
    OTP  Request API
   */
   echo "Testing  OTPREQUEST API \n";
   $data['action'] = "OTPREQUEST";
   $data['app_key'] = $appKey;
   $data['username'] = USERNAME; 
   
   
    print_r ($data);
    
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,"http://devapi.gstsystem.co.in/taxpayerapi/v0.2/authenticate");
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_VERBOSE, 1);
    $response = curl_exec($ch);

    
    curl_close($ch);

    print_r($response);
    
    /*
    Authenticate OTP 
    */
    echo "Testing  AUTHTOKEN API  \n";
    $data['action'] = "AUTHTOKEN";
    $data['appkey'] = $appKey;
    $data['username'] = USERNAME; 
    $data['otp']      = $otp;
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,"http://devapi.gstsystem.co.in/taxpayerapi/v0.2/authenticate");
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    //curl_setopt($ch, CURLOPT_VERBOSE, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);

    echo $response."\n\n";
    
    $outData = json_decode($response);
    print_r ($outData);
    
    return; // only authenticate the system

    
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
    //http://devapi.gstsystem.co.in/taxpayerapi/v0.1/returns/gstr1
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,"http://devapi.gstsystem.co.in/taxpayerapi/v0.1/returns/gstr1");
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
    http://devapi.gstsystem.co.in/taxpayerapi/v0.1/returns/gstr1?action=B2B&ret_period=112016&gstin=04AABFN9870CMZT&action_required=Y
    */
    echo "Testing GST1 Detailed Invoices\n";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL,"http://devapi.gstsystem.co.in/taxpayerapi/v0.1/returns/gstr1?action=B2B&ret_period=112016&gstin=".GSTIN."&action_required=Y");
    
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
   // curl_setopt($ch, CURLOPT_VERBOSE, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    
    $response = curl_exec($ch);
    curl_close($ch);
    
    $outData = json_decode($response);
    print_r ($outData);
    
    var_dump (decodeJsonResponse($outData->data,$outData->rek, $ek ));
    
}

testOTPReqAPICall();
?>
