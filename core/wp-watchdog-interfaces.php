<?php

if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

interface iWP_WATCHDOG_SecurityComponentManager {

    public static function getInstance();

    public function add( $entity );

    public function remove( $entity );

    public function get();

    public function check( $entity );

    public function log();

    public function getLogs();
}

interface iWP_WATCHDOG_SecurityComponent {

    public static function getInstance();

    public function start();

    public function createGUI();
}