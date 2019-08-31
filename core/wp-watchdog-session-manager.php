<?php

if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

class WP_Watchdog_SessionManager {

    private static $detectionMode;

    /**
     *  For singleton pattern and also setting the
     *  session ending reason
     *  
     *  $detection:
     *      -> 'WAF' = "Web Application Firewall Detection"
     *      -> 'IPB' = "IP Blacklisting Detection"
     *      -> 'AFB' = "Anti-Flood Blocker Detection"
     *      -> 'UAB' = "User-Agent Blocker Detection"
     */
    private static $instance = null;
    private function __construct() {}

    private function printHeader() {
        
        header('HTTP/1.0 403 Forbidden');
        echo '<!DOCTYPE html><html lang="en" xmlns="//www.w3.org/1999/xhtml"><head><style>.app-header,body{text-align:center }.btn,button.btn,input.btn{border:0;outline:0;display:inline-block;vertical-align:middle;border-radius:5em;background-color:#609f43;color:#fff;padding:5px 12px;background-repeat:no-repeat;font-size:14px }.btn:hover{background-color:#58913d }.clearfix:after,.clearfix:before,footer,header,section{display:block }.clearfix:after,.clearfix:before,.row:after{clear:both;content:"" }.clearfix:after,.clearfix:before,.logo-neartext:before,.row:after{content:"" }*{margin:0;padding:0 }html{box-sizing:border-box;font-family:"Open Sans",sans-serif }body,html{height:100% }*,:after,:before{box-sizing:inherit }body{background-color:#e8e8e8;font-size:14px;color:#222;line-height:1.6;padding-bottom:60px }h1{font-size:36px;margin-top:0;line-height:1;margin-bottom:30px }h2{font-size:25px;margin-bottom:10px }a{color:#1e7d9d;text-decoration:none }a:hover{text-decoration:underline }.access-denied .btn:hover,.site-link,footer a{text-decoration:none }.color-green{color:#609f43 }.color-gray{color:grey }hr{border:0;margin:20px auto;border-top:1px #e2e2e2 solid }[class*=icon-circle-]{display:inline-block;width:14px;height:14px;border-radius:50%;margin:-5px 8px 0 0;vertical-align:middle }.icon-circle-red{background-color:#db1802 }#main-container{min-height:100%;position:relative }.app-header{background-color:#333;min-height:50px;padding:0 25px }.app-header .logo{display:block;width:100px;height:24px;float:left;background-size:100px 24px;position:absolute;left:0;top:12px }.logo-neartext{display:inline-block;margin-top:3px;color:#fff;font-size:25px;font-weight:600 }.site-link{color:#8a8a8a;font-size:11px;position:absolute;top:15px;right:0 }#recaptcha_image,.box,.captcha,.wrap{position:relative }.wrap{max-width:1090px;margin:auto }.app-content{max-width:580px;margin:40px auto 0;text-align:left;text-align:center }.box{border-radius:10px;background-color:#fff;padding:35px;box-shadow:0 1px 0 0 #d4d4d4;margin:0 4% 35px }#block-details{margin-bottom:35px;margin-top:25px }.row:first-child{border-top:0!important }.row:last-child{border-bottom:0!important }.row:nth-child(even){border:1px solid #e2e2e2;border-left:0;border-right:0;background:#fafafa }.row:after{display:block }.row>div{float:left;padding:12px;word-wrap:break-word }.row>div:first-child{width:15%;font-weight:700 }.row>div:last-child{width:85% }.code-snippet{border:1px solid grey;background-color:#f7f7f7;box-shadow:0 1px 4px 0 rgba(0,0,0,.2);border-radius:8px;padding:18px;margin:30px 0 45px }.medium-text{font-size:16px;clear:both }footer{margin-top:50px;margin-bottom:50px;font-size:13px;color:grey }#privacy-policy{padding-left:25px }@media (max-width:979px){h1{font-size:30px }h2{font-size:20px }.row>div{float:none;width:100%!important }}.captcha{background-color:#fff;width:370px;margin:auto;padding:25px 35px 35px;border-radius:10px;box-shadow:0 1px 0 0 #d4d4d4;border:1px solid #bfbfbf }.captcha-title{text-align:left;margin-bottom:15px;font-size:13px;line-height:1 }table.recaptchatable{margin-left:-14px!important }table#recaptcha_table input[type=text]{height:37px;display:block;width:300px!important;padding:10px!important;border-color:#b8b8b8;font-size:14px;margin-top:20px!important }table#recaptcha_table input[type=text]:focus{background-color:#f9f9f9;border-color:#222;outline:0 }table#recaptcha_table td{display:block;background:0!important;padding:0!important;height:auto!important;position:static!important }#recaptcha_image{border:1px solid #b8b8b8!important;padding:5px;height:60px!important;margin-bottom:25px!important;left:-2px;overflow:hidden;-moz-box-sizing:border-box!important;-webkit-box-sizing:border-box!important;box-sizing:border-box!important }#recaptcha_image img{position:absolute;left:0;top:0 }#recaptcha_reload_btn,#recaptcha_switch_audio_btn,#recaptcha_whatsthis_btn{position:absolute;top:25px }#recaptcha_reload_btn{right:78px }#recaptcha_switch_audio_btn{right:52px }#recaptcha_whatsthis_btn{right:28px }.recaptcha_input_area{margin-left:-7px!important }button.ajax-form{width:300px;cursor:pointer;height:37px;padding:0!important }#recaptcha_privacy{position:absolute!important;top:105px!important;display:block;margin:auto;width:300px;text-align:center }#recaptcha_privacy a{color:#1e7d9d!important }.what-is-firewall{width:100%;padding:35px;background-color:#f7f7f7;-moz-box-sizing:content-box;-webkit-box-sizing:content-box;box-sizing:content-box;margin-left:-35px;margin-bottom:-35px;border-radius:0 0 15px 15px }.access-denied .center{display:table;margin-left:auto;margin-right:auto }.width-max-940{max-width:940px }.access-denied{max-width:none;text-align:left }.access-denied h1{font-size:25px }.access-denied .font-size-xtra{font-size:36px }.access-denied table{margin:25px 0 35px;border-spacing:0;box-shadow:0 1px 0 0 #dfdfdf;border:1px solid #b8b8b8;border-radius:8px;width:100%;background-color:#fff }.access-denied table:first-child{margin-top:0 }.access-denied table:last-child{margin-bottom:0 }.access-denied th{background-color:#ededed;text-align:left;white-space:nowrap }.access-denied th:first-child{border-radius:8px 0 0 }.access-denied th:last-child{border-radius:0 8px 0 0 }.access-denied td{border-top:1px #e2e2e2 solid;vertical-align:top;word-break:break-word }.access-denied td,.access-denied th{padding:12px }.access-denied td:first-child{padding-right:0 }.access-denied tbody tr:first-child td{border-color:#c9c9c9;border-top:0 }.access-denied tbody tr:last-child td:first-child{border-bottom-left-radius:8px }.access-denied tbody tr:last-child td:last-child{border-bottom-right-radius:8px }.access-denied tbody tr:nth-child(2n){background-color:#fafafa }table.property-list td:first-child,table.property-table td:first-child{font-weight:700;width:1%;white-space:nowrap }.overflow-break-all{-ms-word-break:break-all;word-break:break-all;}</style>';
    }

    private function printTitle() {
        
        switch ( self::$detectionMode ) {

            case 'IPB' : 
                $tabTitle = 'Banned from this website'; 
                $componentName = 'IP Blacklister'; 
                break;

            case 'WAF' : 
                $tabTitle = 'Code injection attempt detected'; 
                $componentName = 'Web Application Firewall'; 
                break;

            case 'AFB' : 
                $tabTitle = 'Flood attempt detected'; 
                $componentName = 'Anti-Flood'; 
                break;

            case 'UAB' : 
                $tabTitle = 'Bad User-Agent detected'; 
                $componentName = 'User-Agent Blocker'; 
                break;

        }

        echo '<section class="center clearfix"><meta name="viewport" content="width=device-width, initial-scale=1.0" /><title>'.$tabTitle.'</title><link href="//fonts.googleapis.com/css?family=Open+Sans:400,300,600,700" rel="stylesheet" type="text/css"></head><body><div id="main-container"><header class="app-header clearfix"><div class="wrap"><span class="logo-neartext">WordPress Watchdog Security '.$componentName.'</span></div></header>';
    }

    private function printExplaining() {

        switch ( self::$detectionMode ) {

            case 'IPB' : 
                $explain = 'This IP is banned'; 
                break;

            case 'WAF' : 
                $explain = 'Web Application Firewall Detection'; 
                break;

            case 'AFB' : 
                $explain = 'Flood attempt detected'; 
                break;

            case 'UAB' : 
                $explain = 'Bad User-Agent detected'; 
                break;

        }

        echo '<section class="app-content access-denied clearfix"><div class="box center width-max-940"><h1 class="brand-font font-size-xtra no-margin" style="text-align:center !important"><i class="icon-circle-red"></i> '.$explain.' <i class="icon-circle-red"></i></h1>';
    }

    public static function initialize( $detection ) {
        
        if ( self::$instance == null ) {
            self::$instance = new WP_Watchdog_SessionManager();
        }

        self::$detectionMode = $detection;
        
        return self::$instance;
    }

    private function endSessionWAF( $typeOfVuln ) {
        
        $this->printHeader();
        $this->printTitle();
        $this->printExplaining();

        echo '<table class="property-table overflow-break-all line-height-16"><tr><td>Your IP:</td><td><span>'. $_SERVER['REMOTE_ADDR'] .'</span></td></tr><tr><td>URL:</td><td><span>'. htmlspecialchars($_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8') .'</tr><tr><td>Browser: </td><td><span>'.htmlspecialchars($_SERVER['HTTP_USER_AGENT'], ENT_QUOTES, 'UTF-8') . '<tr><td>Block reason:</td><td><span>An attempted ' . htmlentities($typeOfVuln) . ' was detected and blocked.</span></td></tr><tr><td>Time:</td><td><span>' . date('d-m-Y H:i:s').'</tr></table></div></section>';

        @session_destroy();
        wp_die();
        exit;
    }

    private function endSessionIPBlacklist( $blockReason ) {
        
        $this->printHeader();
        $this->printTitle();
        $this->printExplaining();

        echo '<table class="property-table overflow-break-all line-height-16"><tr><td>Your IP:</td><td><span>'. $_SERVER['REMOTE_ADDR'] .'</span></td></tr><tr><td>URL:</td><td><span>'. htmlspecialchars($_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8') .'</tr><tr><td>Block reason:</td><td><span>'.$blockReason.'</span></td></tr><tr><td>Time:</td><td><span>' . date('d-m-Y H:i:s').'</tr></table></div></section>';

        @session_destroy();
        wp_die();
        exit;
    }

    private function endSessionAntiFlood( $IPAddr ) {

        $entry = (WP_Watchdog_AntiFloodManager::getInstance())->findOne( $IPAddr );

        $this->printHeader();

        $this->printTitle();

        $this->printExplaining();
        
        // Table
        echo '<table class="property-table overflow-break-all line-height-16"><tr><td>Your IP:</td><td><span>'. $IPAddr .'</span></td></tr><tr><td>URL:</td><td><span>'. htmlspecialchars($_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8') .'</tr><tr><td>Block reason:</td><td><span> A flooding attempt was detected and blocked. The number of allowed requests per minute has been exceeded. You have been banned from this website for limited time.</span></td></tr><tr><td>Ban ending: </td><td><span>'.date('d-m-Y H:i:s', $entry['BAN_ENDS_AT']).'</span></td></tr><tr><td>Time:</td><td><span>' . date('d-m-Y H:i:s').'</tr></table></div></section>';

        // @session_destroy();
        wp_die();
        exit;

    }

    private function endSessionUserAgentBlocker( $detectedUA ) {
        
        $IPAddr = $_SERVER['REMOTE_ADDR'];

        $this->printHeader();

        $this->printTitle();

        $this->printExplaining();

        // Table
        echo '<table class="property-table overflow-break-all line-height-16"><tr><td>Your IP:</td><td><span>'. $IPAddr .'</span></td></tr><tr><td>URL:</td><td><span>'. htmlspecialchars($_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'], ENT_QUOTES, 'UTF-8') .'</tr><tr><td>Block reason:</td><td><span> Illegal user agent detected </span></td></tr><tr><td> Bad user agent detected </td><td><span>'.$detectedUA.'</span></td></tr><tr><td>Browser user agent</td><td><span>'.$_SERVER['HTTP_USER_AGENT'].'</span></td></tr><tr><td>Access time:</td><td><span>' . date('d-m-Y H:i:s').'</tr></table></div></section>';

        @session_destroy();
        wp_die();
        exit;
    }

    /**
     *  Used for overloading 'endSession' function call
     *  The static member $detectionMode must be set before
     *  'endSession' function call by using 'initialize()'
     */
    public function __call($method, $arguments) {
        
        if ( $method == 'endSession') {

            switch ( self::$detectionMode ) {

                case 'IPB': return call_user_func_array(array($this,'endSessionIPBlacklist'),       $arguments);
                case 'WAF': return call_user_func_array(array($this,'endSessionWAF'),               $arguments);
                case 'AFB': return call_user_func_array(array($this,'endSessionAntiFlood'),         $arguments);
                case 'UAB': return call_user_func_array(array($this,'endSessionUserAgentBlocker'),  $arguments);
            
            }
        }
    }
}