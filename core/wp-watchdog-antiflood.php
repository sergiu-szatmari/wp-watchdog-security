<?php

if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
require_once( __DIR__ . '/wp-watchdog-interfaces.php' );
require_once( __DIR__ . '/wp-watchdog-utils.php' );

require_once( __DIR__ . '/wp-watchdog-session-manager.php' );

class WP_Watchdog_AntiFloodObject {

    public static function create($initialAccess, $accessCount, $lastAccess, $banEndsAt = 0) {

        if ( isset($afObject) ) { unset($afObject); }
        
        $afObject['INITIAL_ACCESS'] = $initialAccess;
        $afObject['ACCESS_COUNT'] = $accessCount;
        $afObject['LAST_ACCESS'] = $lastAccess;
        $afObject['BAN_ENDS_AT'] = $banEndsAt;
        
        return $afObject;
    }
    
    public static function fromDbObject( $dbObject ) {
        
        if ( isset($afObject) ) { unset($afObject); }

        $afObject['INITIAL_ACCESS']  = $dbObject['initial_access'];
        $afObject['ACCESS_COUNT']    = $dbObject['access_count'];
        $afObject['LAST_ACCESS']     = $dbObject['last_access'];
        $afObject['BAN_ENDS_AT']     = $dbObject['ban_ends_at'];

        return $afObject;
    }
}

class WP_Watchdog_AntiFloodManager implements iWP_Watchdog_SecurityComponentManager {

    private const MAX_REQ_COUNT_DEFAULT     =     5;
    private const BAN_INTERVAL_DEFAULT      =    40;
    private const TIMEOUT_INTERVAL_DEFAULT  =    10;
    private const TIMEOUT_HISTORY_DEFAULT   = 86400;    // 86.400s = 1440m = 24h = 1day

    private $maxRequestCount;   // Max request count
    private $timeoutInterval;   // Time Inverval (Seconds)
    private $banInterval;       // Time to elapse until an IP is unbanned (seconds)
    private $IPHistoryTimeout;  // How much time the history will be kept for an IP address
    
    private $metaTableName;
    private $entryTableName;
    private $logTableName;

    private static $instance = null;

    private function __construct() {
        
        global $wpdb;
        $this->metaTableName    = $wpdb->prefix . WP_Watchdog_Utils::tableNamePrefix . 'antiflood_meta';
        $this->entryTableName   = $wpdb->prefix . WP_Watchdog_Utils::tableNamePrefix . 'antiflood_entries';
        $this->logTableName     = $wpdb->prefix . WP_Watchdog_Utils::tableNamePrefix . 'antiflood_log';
        
        $this->initialize();
    }

    public static function getInstance() {

        if ( self::$instance == null ) {
            self::$instance = new WP_Watchdog_AntiFloodManager();
        }

        return self::$instance;
    }

    private function initializeMetaTable() {

        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        // See if $this->metaTableName exists
        if ( $wpdb->get_var("SHOW TABLES LIKE '$this->metaTableName'") != $this->metaTableName ) {

            // Table does not exist in DB
            $sql = "CREATE TABLE $this->metaTableName (
                id INT NOT NULL,
                maxrequestcnt INT NOT NULL,
                baninterval BIGINT NOT NULL,
                timeoutinterval BIGINT NOT NULL,
                historytimeout BIGINT NOT NULL,
                PRIMARY KEY  (id)
            ) $charset_collate;";
            dbDelta( $sql );

            $wpdb->insert(
                $this->metaTableName,
                array(
                    'maxrequestcnt'     => self::MAX_REQ_COUNT_DEFAULT,   
                    'baninterval'       => self::BAN_INTERVAL_DEFAULT,
                    'timeoutinterval'   => self::TIMEOUT_INTERVAL_DEFAULT,
                    'historytimeout'    => self::TIMEOUT_HISTORY_DEFAULT
                )
            );

        }

        // The table exists
        // Setting the data
        
        $dbResult = $wpdb->get_results("SELECT * FROM $this->metaTableName", ARRAY_A );
        $this->maxRequestCount  = $dbResult[0]['maxrequestcnt'];
        $this->banInterval      = $dbResult[0]['baninterval'];
        $this->timeoutInterval  = $dbResult[0]['timeoutinterval'];
        $this->IPHistoryTimeout = $dbResult[0]['historytimeout'];
    }

    private function initializeEntryTable() {

        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        // See if $this->entryTableName exists
        if ( $wpdb->get_var("SHOW TABLES LIKE '$this->entryTableName'") != $this->entryTableName ) {

            // Table does not exist in DB
            $sql = "CREATE TABLE $this->entryTableName (
                ip VARCHAR(40) NOT NULL,
                initial_access INT NOT NULL,
                access_count INT NOT NULL,
                last_access INT NOT NULL,
                ban_ends_at INT DEFAULT 0,
                PRIMARY KEY  (ip)
            ) $charset_collate;";
            dbDelta( $sql );
        }
    }

    private function initializeLogTable() {

        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        // See if $this->entryTableName exists
        if ( $wpdb->get_var("SHOW TABLES LIKE '$this->logTableName'") != $this->logTableName ) {

            // Table does not exist in DB
            $sql = "CREATE TABLE $this->logTableName (
                entry_id BIGINT NOT NULL AUTO_INCREMENT,
                ip VARCHAR(40) NOT NULL,
                accessed_url VARCHAR(300) NOT NULL,
                access_time INT NOT NULL,
                ban_ends_at INT NOT NULL,
                PRIMARY KEY  (entry_id)
            ) $charset_collate;";
            dbDelta( $sql );
        }
    }

    public function log() {

        global $wpdb;
        
        $IPAddr = $_SERVER['REMOTE_ADDR'];
        $url = htmlspecialchars( $_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'] );
        $afObject = $this->findOne( $IPAddr );
        if ( !$afObject ) { echo 'Empty obj: antiflood:line167'; die; }

        $wpdb->insert(
            $this->logTableName,
            array(
                'ip' => $IPAddr,
                'accessed_url' => $url,
                'access_time' => time(),
                'ban_ends_at' => $afObject['BAN_ENDS_AT'],
            )
        );
    }

    public function getLogs() {

        global $wpdb;
        $logs = $wpdb->get_results( "SELECT * FROM $this->logTableName", ARRAY_A );
        
        return $logs;
    }

    private function initialize() {
        $this->initializeMetaTable();
        $this->initializeEntryTable();
        $this->initializeLogTable();
        $this->dumpOldData();
    }

    public function getMaxRequestCount() {
        return $this->maxRequestCount;
    }

    public function getTimeout() {
        return $this->timeoutInterval;
    }

    public function getBanInterval() {
        return $this->banInterval;
    }

    public function getHistoryTimeout() {
        return $this->IPHistoryTimeout;
    }

    public function setMaxRequestCount( $maxRequestCount ) {

        global $wpdb;

        $this->maxRequestCount = $maxRequestCount;
        $wpdb->update(
            $this->metaTableName,
            array( 'maxrequestcnt' => $maxRequestCount ),
            array( 'id' => 0 )
        );
    }

    public function setTimeout( $timeInterval ) {
        
        global $wpdb;

        $this->timeoutInterval = $timeInterval;
        $wpdb->update(
            $this->metaTableName,
            array( 'timeoutinterval' => $timeInterval ),
            array( 'id' => 0 )
        );
    }

    public function setBanInterval( $banInterval ) {
        
        global $wpdb;

        $this->banInterval = $banInterval;
        $wpdb->update(
            $this->metaTableName,
            array( 'baninterval' => $banInterval ),
            array( 'id' => 0 )
        );
    }

    public function setHistoryTimeout( $historyTimeout ) {

        global $wpdb;

        $this->IPHistoryTimeout = $historyTimeout;
        $wpdb->update(
            $this->metaTableName,
            array( 'historytimeout' => $historyTimeout ),
            array( 'id' => 0 )
        );
    }

    /**
     *  Return value:
     *      -> "null" = $IPAddr does not exist
     *      -> WP_Watchdog_AntiFloodObject = obj. containing all the details for the IP
     */
    public function findOne( $IPAddr ) {

        global $wpdb;
        $entry = $wpdb->get_results("SELECT * FROM $this->entryTableName WHERE ip='$IPAddr'", ARRAY_A );

        if ( !$entry ) {
            return null;
        }

        return WP_Watchdog_AntiFloodObject::fromDbObject( $entry[0] );
    }

    public function get() {

        global $wpdb;
        $result = $wpdb->get_results("SELECT * FROM $this->entryTableName", ARRAY_A );

        return $result;
    }

    public function add( $afObject ) {

        global $wpdb;
        $IPAddr = $_SERVER['REMOTE_ADDR'];

        $wpdb->insert(
            $this->entryTableName,
            array(
                'ip' => $IPAddr,
                'initial_access'    => $afObject['INITIAL_ACCESS'],
                'access_count'      => $afObject['ACCESS_COUNT'],
                'last_access'       => $afObject['LAST_ACCESS'],
                'ban_ends_at'       => $afObject['BAN_ENDS_AT']
            )
        );

    }

    private function update( $IPAddr, $afObject ) {

        global $wpdb;

        $wpdb->update(
            $this->entryTableName,
            array( 
                'initial_access'    => $afObject['INITIAL_ACCESS'],
                'access_count'      => $afObject['ACCESS_COUNT'],
                'last_access'       => $afObject['LAST_ACCESS'],
                'ban_ends_at'       => $afObject['BAN_ENDS_AT'] 
            ), 
            array( 'ip' => $IPAddr )
        );
    }

    public function remove( $IPAddr ) {

        global $wpdb;

        $wpdb->delete(
            $this->entryTableName,
            array( 'ip' => $IPAddr )
        );
    }

    /**
     *  Return value:
     *      - true: IP should be banned
     *      - false: IP is free to access the page
     */
    public function check( $IPAddr ) {
 
        if ( !filter_var($IPAddr, FILTER_VALIDATE_IP) ) {
            throw new Exception('WordPress Watchdog Plugin Exception: Invalid IP address format for "'.$IPAddr.'"');
        }

        $this->dumpOldData();

        $entry = $this->findOne( $IPAddr );
        $currentTime = time();

        if ( !$entry ) {
            // IP's first time on the page -> OK
            $this->add( WP_Watchdog_AntiFloodObject::create($currentTime, 0, $currentTime) );
            return false;
        }

        if ( $entry['BAN_ENDS_AT'] > 0 ) {
            // IP is banned
            // Check if ban time is over
            if ( $currentTime < $entry['BAN_ENDS_AT'] ) {
                return true;
            } else {
                $this->update( $IPAddr, WP_Watchdog_AntiFloodObject::create($currentTime, 0, $currentTime) );
            }
        }

        // IP is not banned (/anymore?)
        $this->update( 
            $IPAddr, 
            WP_Watchdog_AntiFloodObject::create(
                $entry['INITIAL_ACCESS'], 
                $entry['ACCESS_COUNT'] + 1, 
                $currentTime
            )
        );

        // Refreshing local "entry"
        $entry['ACCESS_COUNT'] += 1;
        $entry['LAST_ACCESS'] = $currentTime;

        if ( $entry['INITIAL_ACCESS'] < time() - $this->timeoutInterval ) {
            // $this->timeoutInterval seconds have passed sine the IP's first access
            // OK, normal user
            // Counter must be refreshed
            $this->update(
                $IPAddr,
                WP_Watchdog_AntiFloodObject::create(
                    $currentTime,
                    1,
                    $currentTime
                )
            );
            return false;

        } elseif ( $entry['ACCESS_COUNT'] > $this->maxRequestCount ) {

            if ( $entry['BAN_ENDS_AT'] == 0 ) {
                $this->update(
                    $IPAddr,
                    WP_Watchdog_AntiFloodObject::create(
                        $entry['INITIAL_ACCESS'], 
                        $entry['ACCESS_COUNT'],
                        $entry['LAST_ACCESS'],
                        $currentTime + $this->banInterval
                    )
                );
            }
            $this->log();
            return true;
        }
        
        
        return false;
    }

    private function dumpOldData() {

        $entries = $this->get();
        foreach ( $entries as $entry ) {
            $lastAccess = $entry['last_access'];
            if ( $lastAccess < time() - $this->IPHistoryTimeout ) {
                if ( $banEnd <= time() ) {
                    $this->remove( $entry['ip'] );
                }
            }
        }
    }
}

class WP_Watchdog_AntiFlood implements iWP_Watchdog_SecurityComponent {

    private $afManager;
    
    private static $instance = null;

    private function __construct() {
        $this->afManager = WP_Watchdog_AntiFloodManager::getInstance();
    }

    public static function getInstance() {

        if (self::$instance == null) {
            self::$instance = new WP_Watchdog_AntiFlood();
        }

        return self::$instance;
    }

    public function start() {
        
        @session_start();
        $IPAddr = $_SERVER['REMOTE_ADDR'];

        if ( $this->afManager->check($IPAddr) ) {
            
            (WP_Watchdog_SessionManager::initialize('AFB'))->endSession( $IPAddr );
        }
    }

    public function createGUI() {

        self::getInstance();

?>
        <div id="wp_watchdog_af_gui" style="text-align:center;">
            <h1> Anti-Flood Administration Panel </h1>
            <br>
            <h3> Anti-Flood Detection Report </h3>
            <br>
            <div style="overflow:hidden; overflow-x:hidden;">
                <table class="widefat fixed" style="text-align: center;width: 80%;margin: 0 auto;" cellpadding="10">
                    <tr bgcolor="#b8dfff">
                        <td> IP Address </td>
                        <td> Accessed URL </td>
                        <td> Access time </td>
                        <td> Ban ends at </td>
                    </tr>
                </table>
            </div>
            <div style="overflow:scroll; overflow-x:hidden; height: 400px;width: 80%;margin: 0 auto;">
                <table class="widefat fixed" style="text-align: center;" cellpadding="10">
                    <?php $logs = (WP_Watchdog_AntiFloodManager::getInstance())->getLogs(); foreach ( $logs as $idx => $log ): ?>
                        <?php if ( $idx % 2 == 0 ): ?>
                            <tr>
                                <td> <?php echo $log['ip']; ?> </td>
                                <td> <?php echo $log['accessed_url']; ?> </td>
                                <td> <?php echo date('d-m-Y H:i:s', $log['access_time']); ?> </td>
                                <td> <?php echo date('d-m-Y H:i:s', $log['ban_ends_at']); ?> </td>
                            </tr>
                        <?php else: ?>
                            <tr bgcolor="#dae8ff">
                                <td> <?php echo $log['ip']; ?> </td>
                                <td> <?php echo $log['accessed_url']; ?> </td>
                                <td> <?php echo date('d-m-Y H:i:s', $log['access_time']); ?> </td>
                                <td> <?php echo date('d-m-Y H:i:s', $log['ban_ends_at']); ?> </td>
                            </tr>
                        <?php endif; ?>
                    <?php endforeach; ?>
                </table>
            </div>
            <br/><br/>
            <hr style="border-width: 2px;">
            <br/>
            <h3> Anti-Flood Options </h3>
            <br>
            <div style="overflow:hidden; overflow-x:hidden;">
            <table class="widefat fixed" style="text-align: center;width: 70%;margin: 0 auto;" >
                <tr bgcolor="#b8dfff">
                    <td> Max. Requests Count </td>
                    <td> Ban interval (seconds) </td>
                    <td> Timeout since the first access (seconds) </td>
                    <td> IP History Timeout (seconds) </td>
                </tr>
                <tr>
                    <td> Maximum number of accepted requests by an IP address in a certain amount of time </td>
                    <td> How many seconds of banning does an IP get if it exceeds the max number of allowed requests </td>
                    <td> The time in which an IP address can request up to MAX requests (where max is described below) </td>
                    <td> How much time an Anti-Flood Database Entry will remain stored </td>
                </tr>
                <tr bgcolor="#dae8ff">
                    <?php $wpaf = WP_Watchdog_AntiFloodManager::getInstance(); ?>
                    <td> <?php echo $wpaf->getMaxRequestCount(); ?></td>
                    <td> <?php echo $wpaf->getBanInterval(); ?></td>
                    <td> <?php echo $wpaf->getTimeout(); ?></td>
                    <td> <?php echo $wpaf->getHistoryTimeout(); ?></td>
                </tr>
            </table>
            <br/><br/>
            <?php
                if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
                    if ( isset($_POST['WP_Watchdog_INPUT_NEWMAXREQUESTC']) ) {
                        
                        try {
                            $newMaxRequestCount = $_POST['WP_Watchdog_INPUT_NEWMAXREQUESTC'];
                            if ( filter_var($newMaxRequestCount, FILTER_VALIDATE_INT) ) {
                                $af = WP_Watchdog_AntiFloodManager::getInstance();
                                $af->setMaxRequestCount( $newMaxRequestCount );
                            } else {
                                echo '<script> alert("Invalid number for max request count"); </script>';
                            }
                        } catch (Exception $ex) {
                            echo '<script> alert("'.$ex->getMessage().'"); </script>';
                        }
                    }
                    if ( isset($_POST['WP_Watchdog_INPUT_NEWBANINT']) ) {

                        try {
                            $newBanInterval = $_POST['WP_Watchdog_INPUT_NEWBANINT'];
                            if ( filter_var($newBanInterval, FILTER_VALIDATE_INT) ) {
                                $af = WP_Watchdog_AntiFloodManager::getInstance();
                                $af->setBanInterval( $newBanInterval );
                            } else {
                                echo '<script> alert("Invalid number for new banning interval"); </script>';
                            }
                        } catch (Exception $ex) {
                            echo '<script> alert("'.$ex->getMessage().'"); </script>';
                        }
                    }
                    if ( isset($_POST['WP_Watchdog_INPUT_NEWTIMEOUT']) ) {

                        try {
                            $newTimeout = $_POST['WP_Watchdog_INPUT_NEWTIMEOUT'];
                            if ( filter_var($newTimeout, FILTER_VALIDATE_INT) ) {
                                $af = WP_Watchdog_AntiFloodManager::getInstance();
                                $af->setTimeout( $newTimeout );
                            } else {
                                echo '<script> alert("Invalid number for new timeout interval"); </script>';
                            }
                        } catch (Exception $ex) {
                            echo '<script> alert("'.$ex->getMessage().'"); </script>';
                        }  
                    }
                    if ( isset($_POST['WP_Watchdog_INPUT_HISTORYTIMEOUT']) ) {

                        try {
                            $newHistoryTimeout = $_POST['WP_Watchdog_INPUT_HISTORYTIMEOUT'];
                            if ( filter_var($newHistoryTimeout, FILTER_VALIDATE_INT) ) {
                                $af = WP_Watchdog_AntiFloodManager::getInstance();
                                $af->setHistoryTimeout( $newHistoryTimeout );
                            } else {
                                echo '<script> alert("Invalid number for new history timeout interval"); </script>';
                            }
                        } catch (Exception $ex) {
                            echo '<script> alert("'.$ex->getMessage().'"); </script>';
                        }
                    }
                    echo '<script> location.reload(); </script>';
                }
            ?>
            <div style="text-align: center; vertical-align: middle;">
            <form action="" method="post" ectype="multipart/form-data">
                <input type="text" name="WP_Watchdog_INPUT_NEWMAXREQUESTC" placeholder="New Max Request Count" />
                <!-- <br />
                <br /> -->
                <input type="text" name="WP_Watchdog_INPUT_NEWBANINT" placeholder="New Ban Interval (seconds)" />
                <br />
                <br />
                <input type="text" name="WP_Watchdog_INPUT_NEWTIMEOUT" placeholder="New Timeout (seconds)" />
                <!-- <br />
                <br /> -->
                <input type="text" name="WP_Watchdog_INPUT_HISTORYTIMEOUT" placeholder="New History Timeout (seconds)" />
                <br />
                <br />
                <button type="submit" class="button-primary"> Update information </button>
            </form>
            </div>
        </div>

<?php
    }
}
