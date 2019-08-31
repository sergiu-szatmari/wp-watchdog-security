<?php

if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

class WP_WATCHDOG_Initializer {

    public static function createParentGUI() {
        add_menu_page( 'WP Watchdog Security', 'WP Watchdog Security', 'manage_options', 'wp-watchdog-security', 'WP_WATCHDOG_Utils::createParentGUI' );
    }

    public static function createBlacklistingGUI() {
        add_submenu_page( 'wp-watchdog-security', 'WP Watchdog IP Blacklisting', 'IP Blacklisting', 'manage_options', 'wp-watchdog-security', 'WP_WATCHDOG_IPBlacklist::createGUI' );
    }

    public static function createWAFGUI() {
        add_submenu_page(  'wp-watchdog-security', 'WP Watchdog WAF', 'Web Application Firewall', 'manage_options', 'wp-watchdog-waf', 'WP_WATCHDOG_WAF::createGUI');
    }

    public static function createAntiFloodGUI() {
        add_submenu_page(  'wp-watchdog-security', 'WP Watchdog Anti-Flood', 'Anti-Flood', 'manage_options', 'wp-watchdog-af', 'WP_WATCHDOG_AntiFlood::createGUI');
    }

    public static function createUserAgentBlockerGUI() {
        add_submenu_page( 'wp-watchdog-security', 'WP Watchdog User-Agent Blocker', 'User-Agent Blocker', 'manage_options', 'wp-watchdog-uab', 'WP_WATCHDOG_UserAgentBlocker::createGUI');
    }

    public static function startBlacklisting() {

        $blacklist = WP_WATCHDOG_IPBlacklist::getInstance();
        $blacklist->start();
    }

    public static function startWAF() {

        $waf = WP_WATCHDOG_WAF::getInstance();
        $waf->start();
    }

    public static function startWAFComment( $commentID ) {
    
        $waf = WP_WATCHDOG_WAF::getInstance();
        $waf->verifyComment( $commentID );
    }

    public static function startAntiFlood() {

        $af = WP_WATCHDOG_AntiFlood::getInstance();
        $af->start();
    }

    public static function startUserAgentBlocker() {

        $uab = WP_WATCHDOG_UserAgentBlocker::getInstance();
        $uab->start();
    }
    
}