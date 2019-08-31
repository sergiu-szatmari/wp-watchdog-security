<?php

if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

class WP_Watchdog_Utils {

    public const tableNamePrefix = "watchdog_";

    public static function flattenArray( array $array ) {

        $flatten = array();
        array_walk_recursive(
            $array, 
            function($value) use(&$flatten) {
                $flatten[] = $value;
            }
        );

        return $flatten;
    }

    public static function isHTML( $string ) {
        
        return $string != strip_tags($string) ? true : false;
    }

    public static function secondsToTimeFormat( $seconds ) {

        $hours = floor( $seconds / 3600 );
        $mins = floor( $seconds / 60 % 60 );
        $secs = floor( $seconds % 60 );

        return sprintf( '%02d:%02d:%02d', $hours, $mins, $seconds );
    }

    public static function createParentGUI() {
        echo '';
    }

}