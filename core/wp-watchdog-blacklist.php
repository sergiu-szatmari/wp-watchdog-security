<?php

if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
require_once( __DIR__ . '/wp-watchdog-interfaces.php' );

global $wpdb;


class WP_Watchdog_IPBlacklistManager implements iWP_Watchdog_SecurityComponentManager {

    private static $instance = null;

    private $gTableName;
    private $gLogTableName;

    private function __construct() {
        
        global $wpdb;
        $this->gTableName       = $wpdb->prefix . WP_Watchdog_Utils::tableNamePrefix . 'blacklist';
        $this->gLogTableName    = $wpdb->prefix . WP_Watchdog_Utils::tableNamePrefix . 'blacklist_log';

        $this->initialize();
    }

    public static function getInstance() {

        if ( self::$instance == null ) {
            self::$instance = new WP_Watchdog_IPBlacklistManager();
        }

        return self::$instance;
    }

    private function initializeBlacklistTable() {
        
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        // See if the $gTableName exists in WP Database
        if ( $wpdb->get_var("SHOW TABLES LIKE '$this->gTableName'") != $this->gTableName ) {
            
            // Table is not in the WPDB
            // It must be created
            $sql = "CREATE TABLE $this->gTableName (
                ip VARCHAR(40) NOT NULL,
                PRIMARY KEY  (ip)
            ) $charset_collate;";
            dbDelta( $sql );

            // echo 'Table has been created';

        } else {
            // The table exists
            // No further action is needed for initialization
        }
    }

    private function initializeLogTable() {

        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        // See if the $gLogTableName exists in WP Database
        if ( $wpdb->get_var("SHOW TABLES LIKE '$this->gLogTableName'") != $this->gLogTableName ) {
            
            // Table is not in the WPDB
            // It must be created
            $sql = "CREATE TABLE $this->gLogTableName (
                entry_id BIGINT NOT NULL AUTO_INCREMENT,
                ip VARCHAR(40) NOT NULL,
                accessed_url VARCHAR(300) NOT NULL,
                date_time INT NOT NULL,
                PRIMARY KEY  (entry_id)
            ) $charset_collate;";
            dbDelta( $sql );

            // echo 'Table has been created';

        } else {
            // The table exists
            // No further action is needed for initialization
        }
    }

    private function initialize() {
        
        $this->initializeBlacklistTable();
        $this->initializeLogTable();
    }
    
    public function log() {
        
        global $wpdb;

        $IPAddr = $_SERVER['REMOTE_ADDR'];
        $currentTime = time();
        $url = htmlspecialchars( $_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'] );

        $wpdb->insert(
            $this->gLogTableName,
            array(
                'ip' => $IPAddr,
                'accessed_url' => $url,
                'date_time' => $currentTime
            )
        );
    }

    public function getLogs() {
        global $wpdb;
        $logs = $wpdb->get_results("SELECT * FROM $this->gLogTableName", ARRAY_A );

        return $logs;
    }

    public function populateDatabase() {

        global $wpdb;

        $mockIPs = array(
            // XXX.XXX.XXX.XXX 
            // IP addresses can
            // be entered manually
            // here 
        );

        foreach ( $mockIPs as $IP ) {

            $wpdb->insert(
                $this->gTableName,
                array(
                    'ip' => $IP
                )
            );
        }
    }

    public function add( $badIP ) {

        global $wpdb;
        if ( ! filter_var($badIP, FILTER_VALIDATE_IP) ) {
            throw new Exception('WordPress Watchdog Plugin Exception: Invalid IP address format for "'.$badIP.'"');
        }

        $wpdb->insert(
            $this->gTableName,
            array( 
                'ip' => $badIP
            )
        );
    }

    public function remove( $IPAddr ) {

        global $wpdb;
        if ( ! filter_var($IPAddr, FILTER_VALIDATE_IP) ) {
            throw new Exception('WordPress Watchdog Plugin Exception: Invalid IP address format');
        }

        $wpdb->delete(
            $this->gTableName,
            array( 'ip' => $IPAddr )
        );
    }

    private function createResult( $dbResult ) {

        $blacklistedIPs = array_values($dbResult);
        $ret = array();
        foreach ($blacklistedIPs as $IP) {

            array_push( $ret, $IP['ip'] );
        }

        return $ret;
    }

    public function get() {

        global $wpdb;
        $dbResult = $wpdb->get_results("SELECT * FROM $this->gTableName", ARRAY_A );
        
        $blacklistedIPs = $this->createResult( $dbResult );
        return $blacklistedIPs;
    }

    public function check( $IP ) {

        if ( ! filter_var($IP, FILTER_VALIDATE_IP) ) {
            throw new Exception('WordPress Watchdog Plugin Exception: Invalid IP address format for IP "'.$IP.'".');
        }
        
        $blacklistedIPs = $this->get();
        foreach ($blacklistedIPs as $key => $value)
            if ( strcmp($value, $IP) == 0 ) 
                return true;
        return false;
    }
}

class WP_Watchdog_IPBlacklist implements iWP_Watchdog_SecurityComponent {

    private static $instance = null;

    private $ipbManager;
    
    private function __construct() {
        $this->ipbManager = WP_Watchdog_IPBlacklistManager::getInstance();
        $this->ipbManager->populateDatabase();
    }

    public static function getInstance() {

        if (self::$instance == null) {
            self::$instance = new WP_Watchdog_IPBlacklist();
        }

        return self::$instance;
    }

    public function start() {

        $IPAddr = $_SERVER['REMOTE_ADDR'];

        if ( $this->ipbManager->check($IPAddr) ) {
        
            $this->ipbManager->log();
            ((WP_Watchdog_SessionManager::initialize('IPB'))->endSession('Your IP has been banned from accessing this website.'));
        }
    }

    public function createGUI() {

        self::getInstance(); // to avoid any null pointer situation

?>
        <div id="wp_watchdog_blacklist_gui" style="text-align:center;">
            <h1> IP Blacklisting Administration Panel </h1>
            <br>
            <h3> Banned IP Access Report </h3>
            <div>
            <table class="widefat fixed" style="text-align: center;width: 80%;margin: 0 auto;" cellpadding="10">
                <tr bgcolor="#b8dfff">
                    <td id="columnname" class="manage-column column-columnname" > IP </td>
                    <td id="columnname" class="manage-column column-columnname" > Accessed URL </td>
                    <td id="columnname" class="manage-column column-columnname" > Date and time </td>
                </tr >
			</table>
			<div style="overflow:scroll; overflow-x:hidden; height: 400px;width: 80%;margin: 0 auto;">
                <table class="widefat fixed" style="text-align: center;" cellpadding="10">
					<?php $logs = WP_Watchdog_IPBlacklistManager::getInstance()->getLogs(); foreach ($logs as $idx => $log): ?>
					<?php if ( $idx % 2 == 0 ): ?>
						<tr>
							<td> <?php echo $log['ip']; ?> </td>
							<td> <?php echo $log['accessed_url']; ?> </td>
							<td> <?php echo date('d-m-Y H:i:s', $log['date_time']); ?> </td>
						</tr>
					<?php else: ?> 
						<tr bgcolor="#dae8ff">
							<td> <?php echo $log['ip']; ?> </td>
							<td> <?php echo $log['accessed_url']; ?> </td>
							<td> <?php echo date('d-m-Y H:i:s', $log['date_time']); ?> </td>
						</tr>
					<?php endif; ?>
					<?php endforeach; ?>
				</table>
            </div>
            <br><br>
            <hr style="border-width: 2px;">
            
            <h3> Blacklist: </h3>
            <table class="widefat fixed" style="text-align: center; width: 70%; margin: 0 auto;" cellpadding="10">
                <tr bgcolor="#b8dfff">
                    <td id="columnname" class="manage-column column-columnname" > Index </td>
                    <td id="columnname" class="manage-column column-columnname" > IP </td>
                </tr>
            </table>
            <div style="overflow:scroll; overflow-x:hidden; height: 200px;width: 70%;margin: 0 auto;">
            <table class="widefat fixed" style="text-align: center;" 
                <?php $IPs = WP_Watchdog_IPBlacklistManager::getInstance()->get(); foreach ( $IPs as $i => $IP ): ?>
                <?php if ( $i % 2 == 0 ): ?>
                    <tr>
                        <td class="column-columnname"> <?php echo $i+1 ?> </td>
                        <td class="column-columnname"> <?php echo $IP  ?> </td>
                    </tr>
                <?php else: ?> 
                    <tr bgcolor="#dae8ff">
                        <td class="column-columnname"> <?php echo $i+1 ?> </td>
                        <td class="column-columnname"> <?php echo $IP  ?> </td>
                    </tr>

                <?php endif; ?>
                <?php endforeach; ?>
            </table>
            </div>
            <br/><br/>
            <?php 
                if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
                    if ( isset($_POST['WP_Watchdog_INPUT_IP']) ) {
                
                        try {
                            $IPAddr = $_POST['WP_Watchdog_INPUT_IP'];

                            if ( strcmp($IPAddr, '') != 0 ) {
                            
                                $blacklist = WP_Watchdog_IPBlacklistManager::getInstance();
                                $isBlacklisted = $blacklist->check( $IPAddr );
                                if ( $isBlacklisted ) {
                                    echo '<script> alert("The IP '.$IPAddr.' is already in the Blacklist.");</script>';
                                } else {
                                    $blacklist->add( $IPAddr );
                                    echo '<script> alert("The IP '.$IPAddr.' has been added to the blacklist.");</script>';
                                }
                            }
                        } catch (Exception $ex) {
                            echo '<script> alert("' . $ex->getMessage() . '");</script>';
                        }
                    } 
                    if ( isset($_POST['WP_Watchdog_INPUT_REMOVEIP'])) {

                        try {
                            $IPAddr = $_POST['WP_Watchdog_INPUT_REMOVEIP'];

                            if ( strcmp($IPAddr, '') != 0 ) {

                                $blacklist = WP_Watchdog_IPBlacklistManager::getInstance();
                                $isBlacklisted = $blacklist->check( $IPAddr );
                                if ( ! $isBlacklisted ) {
                                    echo '<script> alert("The IP '.$IPAddr.' is not on the blacklist.");</script>';
                                } else {
                                    $blacklist->remove( $IPAddr );
                                    echo '<script> alert("The IP '.$IPAddr.' has been removed from the blacklist.");</script>';
                                }

                            }
                        } catch (Exception $ex) {
                            echo '<script> alert("' . $ex->getMessage() . '");</script>';
                        }
                    }
                    echo '<script> location.reload(); </script>';
                }
            ?>
            <div style="text-align: center; vertical-align: middle;">
            <form action="" method="post" enctype="multipart/form-data">
                <input type='text' name='WP_Watchdog_INPUT_IP' placeholder="IP Address to be added" class="input"/>
                <br><br>
                <input type='text' name='WP_Watchdog_INPUT_REMOVEIP' placeholder="IP Address to be removed" />
                <br><br>
                <button type="submit" class="button-primary"> Do action </button>
                <br><br>
            </form>
            </div>
            <!-- <hr style="border-width: 2px;"> -->
        </div>
<?php
    }

}


