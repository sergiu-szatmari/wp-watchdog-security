<?php

/**
 * Plugin Name: WordPress Watchdog Security
 * Plugin URI: --
 * Description: The plugin enhanches the WordPress website's security
 * Author: Sergiu-Ludovic Szatmari
 * Author URI: --
 * Version: 1.1
 * Text Domain: wp-watchdog-security
 */


 
if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

date_default_timezone_set('Europe/Athens');

require_once( __DIR__ . '/core/wp-watchdog-blacklist.php' );
require_once( __DIR__ . '/core/wp-watchdog-waf.php' );
require_once( __DIR__ . '/core/wp-watchdog-antiflood.php' );
require_once( __DIR__ . '/core/wp-watchdog-user-agent-blocker.php' );
require_once( __DIR__ . '/core/wp-watchdog-initializer.php' );

// WP Watchdog User Interface Parent Container
add_action( 'admin_menu',           'WP_Watchdog_Initializer::createParentGUI' );               

// WP Watchdog IP Blacklisting Hooks
add_action( 'wp',                   'WP_Watchdog_Initializer::startBlacklisting' );             
add_action( 'login_init',           'WP_Watchdog_Initializer::startBlacklisting' );             
add_action( 'admin_menu',           'WP_Watchdog_Initializer::startBlacklisting' );             
add_action( 'admin_menu',           'WP_Watchdog_Initializer::createBlacklistingGUI' );         

// WP Watchdog Web Application Firewall Hooks
add_action( 'wp',                   'WP_Watchdog_Initializer::startWAF' );                      
add_action( 'login_init',           'WP_Watchdog_Initializer::startWAF' );                      
add_action( 'parse_request',        'WP_Watchdog_Initializer::startWAF' );                      
add_action( 'wp_insert_comment',    'WP_Watchdog_Initializer::startWAFComment') ;               
add_action( 'comment_post',         'WP_Watchdog_Initializer::startWAFComment' );               
add_action( 'admin_menu',           'WP_Watchdog_Initializer::createWAFGUI' );                  

// WP Watchdog Anti Flood Hooks
add_action( 'wp',                   'WP_Watchdog_Initializer::startAntiFlood' );                
add_action( 'wp_login',             'WP_Watchdog_Initializer::startAntiFlood' );                
add_action( 'login_init',           'WP_Watchdog_Initializer::startAntiFlood' );                
add_action( 'admin_menu',           'WP_Watchdog_Initializer::createAntiFloodGUI');             

// WP Watchdog User Agent Blocker Hooks
add_action( 'wp',                   'WP_Watchdog_Initializer::startUserAgentBlocker');          
add_action( 'login_init',           'WP_Watchdog_Initializer::startUserAgentBlocker');          
add_Action( 'admin_menu',           'WP_Watchdog_Initializer::createUserAgentBlockerGUI' );     
