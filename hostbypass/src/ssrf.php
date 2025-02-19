<?php
function curl($url) {
    $x = parse_url($url); 
        if (!preg_match('/localhost|127\.0\.0\.1/', $x['host'])) {
            $ch = curl_init();
            curl_setopt($ch, CURLOPT_URL, $url);
            curl_setopt($ch, CURLOPT_HEADER, 0);
            curl_exec($ch);
            curl_close($ch);
        }
        else die();
}
$url = $_POST['url'];
curl($url);  
?>