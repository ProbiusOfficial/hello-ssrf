<?php
function curl($url){  
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HEADER, 0);
    curl_exec($ch);
    var_dump(curl_error($ch) );//如果执行curl过程中出现异常，可打开此开关，以便查看异常内容
    curl_close($ch);
}
$url = $_POST['url'];
curl($url);  
?>