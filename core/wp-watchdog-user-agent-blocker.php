<?php

if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

require_once( __DIR__ . '/wp-watchdog-interfaces.php');

class WP_Watchdog_UserAgentBlockerManager implements iWP_Watchdog_SecurityComponentManager {

    private static $instance = null;

    private $gLogTableName;
    private $gBadUserAgentsTableName;

    private $badUserAgentDetected;

    private $badUserAgents;

    private function __construct() {

        global $wpdb;
        $this->gLogTableName            = $wpdb->prefix . WP_Watchdog_Utils::tableNamePrefix . 'useragent_log';
        $this->gBadUserAgentsTableName  = $wpdb->prefix . WP_Watchdog_Utils::tableNamePrefix . 'useragent_bad_uas';
        $this->badUserAgents            = $this->readFile( __DIR__ . '/../assets/wp-watchdog-default-bad-uas.txt' );
        $this->initialize();
    }

    public static function getInstance() {

        if ( self::$instance == null ) {
            self::$instance = new WP_Watchdog_UserAgentBlockerManager();
        }

        return self::$instance;
    }

    /**
     *  Returns an array of bad UAs
     */
    private function readFile( $filepath ) {

        $file = fopen( $filepath, 'r' );
        $UAs = array();
        if ( $file ) {
            while ( ($line = fgets($file)) !== false ) {
                array_push( $UAs, trim($line) );
            }
            fclose( $file );
        } else {
            throw new Exception('Error opening file: '.$filename.'.');
        }

        return $UAs;
    }

    private function initializeBadUserAgentTable() {
        
        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        if ( $wpdb->get_var("SHOW TABLES LIKE '$this->gBadUserAgentsTableName'") != $this->gBadUserAgentsTableName ) {

            // Table does not exists in DB
            // Must be created and populated
            $sql = "CREATE TABLE $this->gBadUserAgentsTableName (
                entry_id BIGINT NOT NULL AUTO_INCREMENT,
                useragent varchar(100) NOT NULL,
                PRIMARY KEY  (entry_id)
            ) $charset_collate;";
            dbDelta( $sql );

            foreach ( $this->badUserAgents as $badUserAgent ) {
                $wpdb->insert(
                    $this->gBadUserAgentsTableName,
                    array( 'useragent' => $badUserAgent )
                );
            }
        } else {

            $this->refreshBadUserAgents();
        }
    }

    private function initializeLogTable() {

        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        // See if table exists
        if ( $wpdb->get_var("SHOW TABLES LIKE '$this->gLogTableName'") != $this->gLogTableName ) {

            // Table is not in the DB
            // Must be created
            $sql = "CREATE TABLE $this->gLogTableName (
                entry_id BIGINT NOT NULL AUTO_INCREMENT,
                ip VARCHAR(40) NOT NULL,
                accessed_url VARCHAR(300),
                bad_user_agent_detected VARCHAR(300),
                http_user_agent VARCHAR(300),
                date_time varchar(40),
                PRIMARY KEY  (entry_id)
            ) $charset_collate;";
            dbDelta( $sql );
        
        } else {
            // The table exists
            // No further action is needed
        }
    }

    private function initialize() {
        
        $this->initializeLogTable();
        $this->initializeBadUserAgentTable();
    }

    private function refreshBadUserAgents() {

        $this->badUserAgents = $this->get();
    }

    public function add( $userAgent ) {

        global $wpdb;
        $res = $wpdb->insert(
            $this->gBadUserAgentsTableName,
            array( 'useragent' => trim($userAgent) )
        );
      
        $this->refreshBadUserAgents();
    }

    public function remove( $userAgent ) {

        global $wpdb;
        $res = $wpdb->delete(
            $this->gBadUserAgentsTableName,
            array( 'useragent' => trim($userAgent) )
        );
        
        $this->refreshBadUserAgents();
    }

    public function get() {

        global $wpdb;
        $result = $wpdb->get_results("SELECT * FROM $this->gBadUserAgentsTableName", ARRAY_A );

        $userAgents = array();
        foreach ( array_values($result) as $dbEntry ) {
            array_push( $userAgents, trim($dbEntry['useragent']) );
        }

        return $userAgents;
    }

    public function findOne( $userAgent ) {

        foreach ( $this->badUserAgents as $badUserAgent ) {
            if ( strcmp(strtolower(trim($badUserAgent)), strtolower(trim($userAgent))) == 0 ) {

                return true;
            }
        }
        return false;
    }

    public function check( $userAgent ) {

        if ( strcmp($userAgent, '') == 0 ) {
            $this->badUserAgentDetected = 'Empty User-Agent Value';
            return true;
        }

        foreach ( $this->badUserAgents as $badUserAgent ) {
            if ( stripos(trim($userAgent), trim($badUserAgent)) !== false ) {
                $this->badUserAgentDetected = $badUserAgent;
                return true;
            }
        }
        return false;
    }

    public function getDetectedUserAgent() {
        
        return $this->badUserAgentDetected;
    }

    public function log() {
        
        global $wpdb;

        $IPAddr = $_SERVER['REMOTE_ADDR'];
        $browserUA = $_SERVER['HTTP_USER_AGENT'];
        $url = $_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
        $datetime = (new DateTime())->format("d-m-Y H:i:s");

        $wpdb->insert(
            $this->gLogTableName,
            array(
                'ip' => $IPAddr,
                'accessed_url' => $url,
                'bad_user_agent_detected' => $this->badUserAgentDetected,
                'http_user_agent' => $browserUA,
                'date_time' => $datetime,
            )
        );

    }

    public function getLogs() {

        global $wpdb;
        $result = $wpdb->get_results("SELECT * FROM $this->gLogTableName", ARRAY_A );

        return $result;
    }

}

class WP_Watchdog_UserAgentBlocker implements iWP_Watchdog_SecurityComponent {

    private static $instance = null;

    private $uabManager;

    private function __construct() {

        $this->uabManager = WP_Watchdog_UserAgentBlockerManager::getInstance();
    }

    public static function getInstance() {

        if ( self::$instance == null ) {
            self::$instance = new WP_Watchdog_UserAgentBlocker();
        }
        return self::$instance;
    }

    public function start() {
        
        $userAgent = $_SERVER['HTTP_USER_AGENT'];

        if ( $this->uabManager->check($userAgent) ) {
            $this->uabManager->log();
            (WP_Watchdog_SessionManager::initialize('UAB'))->endSession( $this->uabManager->getDetectedUserAgent() );
        }
    }

    function createGUI() {
        
        self::getInstance(); // to avoid nullptr

?>
        <div id="wp_watchdog_uab_gui" style="text-align:center;">
            <h1> User-Agent Blocker Administration Panel </h1>
            <br>
            <h3> Bad User-Agent Access Blocking Report </h3>
            <table class="widefat fixed" style="text-align: center;width: 80%;margin: 0 auto;" cellpadding="10">
                <tr bgcolor="#b8dfff">
                    <td id="columnname" class="manage-column column-columnname" > IP </td>
                    <td id="columnname" class="manage-column column-columnname" > Accessed URL </td>
                    <td id="columnname" class="manage-column column-columnname" > Bad User-Agent detected </td>
                    <td id="columnname" class="manage-column column-columnname" > Browser User-Agent </td>
                    <td id="columnname" class="manage-column column-columnname" > Date and time </td>
                </tr >
            </table>
            <div style="overflow:scroll; overflow-x:hidden; height: 400px;width: 80%;margin: 0 auto;">
                <table class="widefat fixed" style="text-align: center;" cellpadding="10">
                    <?php $reports = WP_Watchdog_UserAgentBlockerManager::getInstance()->getLogs(); foreach ( $reports as $idx => $report ): ?>
                    <?php if ( $idx % 2 == 0 ): ?>
                        <tr>
                            <td> <?php echo $report['ip']; ?> </td>
                            <td> <?php echo $report['accessed_url']; ?> </td>
                            <td> <?php echo $report['bad_user_agent_detected']; ?> </td>
                            <td> <?php echo $report['http_user_agent']; ?> </td>
                            <td> <?php echo $report['date_time']; ?> </td>
                        </tr>
                    <?php else: ?> 
                        <tr bgcolor="#dae8ff">
                            <td> <?php echo $report['ip']; ?> </td>
                            <td> <?php echo $report['accessed_url']; ?> </td>
                            <td> <?php echo $report['bad_user_agent_detected']; ?> </td>
                            <td> <?php echo $report['http_user_agent']; ?> </td>
                            <td> <?php echo $report['date_time']; ?> </td>
                        </tr>
                    <?php endif; ?>
                    <?php endforeach; ?>
                </table>
            </div>
            <br><br>
            <hr style="border-width: 2px;">
            <h3> Bad user agents </h3>
            <table class="widefat fixed" style="text-align: center;width: 80%;margin: 0 auto;" cellpadding="10">
                <tr bgcolor="#b8dfff">
                    <td id="columnname" class="manage-column column-columnname" > Bad User-Agents </td>
                </tr>
            </table>
            <div style="overflow:scroll; overflow-x:hidden; height: 400px;width: 80%;margin: 0 auto;">
                <table class="widefat fixed" style="text-align: center;" cellpadding="10">
                    <?php $badUAs = WP_Watchdog_UserAgentBlockerManager::getInstance()->get(); $n = count($badUAs); for ($i = 0; $i < $n; $i += 14): ?>
                        <tr>
                            <td> <?php echo ($i   < $n) ? $badUAs[$i] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+1 < $n) ? $badUAs[$i+1] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+2 < $n) ? $badUAs[$i+2] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+3 < $n) ? $badUAs[$i+3] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+4 < $n) ? $badUAs[$i+4] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+5 < $n) ? $badUAs[$i+5] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+6 < $n) ? $badUAs[$i+6] : '&nbsp;'; ?> </td>
                        </tr>
                        <tr bgcolor="#dae8ff">
                            <td> <?php echo ($i+7  < $n) ? $badUAs[$i+7 ] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+8  < $n) ? $badUAs[$i+8 ] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+9  < $n) ? $badUAs[$i+9 ] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+10 < $n) ? $badUAs[$i+10] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+11 < $n) ? $badUAs[$i+11] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+12 < $n) ? $badUAs[$i+12] : '&nbsp;'; ?> </td>
                            <td> <?php echo ($i+13 < $n) ? $badUAs[$i+13] : '&nbsp;'; ?> </td>
                        </tr>
                    <?php endfor; ?>
                </table>
            </div>
            <?php
                if ( $_SERVER['REQUEST_METHOD'] == 'POST' ) {
                    if ( isset($_POST['WP_Watchdog_ADD_USER_AGENT']) ) {

                        try {
                            $userAgent = $_POST['WP_Watchdog_ADD_USER_AGENT'];

                            if ( strcmp(trim($userAgent), '') != 0 ) {
                                
                                $uab = WP_Watchdog_UserAgentBlockerManager::getInstance();
                                if ( $uab->findOne($userAgent) ) {
                                    echo '<script> alert("User-Agent already exists"); </script>';
                                } else {
                                    $uab->add( $userAgent );
                                    echo '<script> alert("The User-Agent value has been added"); </script>';
                                }
                            }
                        } catch (Exception $ex) {
                            echo '<script> alert("'.$ex->getMessage().'");</script>';
                        }
                    }
                    if ( isset($_POST['WP_Watchdog_REMOVE_USER_AGENT']) ) {

                        try {
                            $userAgent = $_POST['WP_Watchdog_REMOVE_USER_AGENT'];
                            
                            if ( strcmp($userAgent, '') != 0 ) {

                                $uab = WP_Watchdog_UserAgentBlockerManager::getInstance();
                                if ( $uab->findOne($userAgent) ) {
                                    $uab->remove( $userAgent );
                                    echo '<script> alert("The User-Agent value has been removed."); </script>';
                                } else {
                                    echo '<script> alert("User-Agent does not exist in the list"); </script>';
                                }
                            }
                        } catch (Exception $ex) {
                            echo '<script> alert("'.$ex->getMessage().'"); </script>';
                        }
                    }
                    echo '<script> location.reload(); </script>';
                }
            ?>
            <br/><br/>
            <div style="text-align: center; vertical-align: middle;">
                <form action="" method="post" enctype="multipart/form-data">
                    <input type='text' name='WP_Watchdog_ADD_USER_AGENT' placeholder="User-Agent value to be added" class="input"/>
                    <br><br>
                    <input type='text' name='WP_Watchdog_REMOVE_USER_AGENT' placeholder="User-Agent value to be removed" />
                    <br><br>
                    <button type="submit" class="button-primary"> Do action </button>
                    <br><br>
                </form>
            </div>
        </div>

<?php
    }
}
