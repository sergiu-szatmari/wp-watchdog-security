<?php

if ( !defined('ABSPATH') ) {
    die('WordPress Watchdog Security: Access is not allowed!');
}

require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
require_once( __DIR__ . '/wp-watchdog-interfaces.php' );
require_once( __DIR__ . '/wp-watchdog-utils.php' );

global $wpdb;


class WP_Watchdog_WAFManager implements iWP_Watchdog_SecurityComponentManager {

    private static $instance = null;
    private $gTableName;
    private $gBlockReason;
    private $gAttemptedMethod;

    private function __construct() {

        global $wpdb;
        $this->gTableName = $wpdb->prefix . WP_Watchdog_Utils::tableNamePrefix . 'waf_log';
        $this->initialize();
    }

    public static function getInstance() {

        if ( self::$instance == null ) {
            self::$instance = new WP_Watchdog_WAFManager();
        }

        return self::$instance;
    }

    private function initialize() {

        global $wpdb;
        $charset_collate = $wpdb->get_charset_collate();

        // See if the $gTableName exists in WP Database
        if ( $wpdb->get_var("SHOW TABLES LIKE '$this->gTableName'") != $this->gTableName ) {

            // Table does not exist in DB
            $sql = "CREATE TABLE $this->gTableName (
                entry_id BIGINT NOT NULL AUTO_INCREMENT,
                ip VARCHAR(40) NOT NULL,
                block_reason VARCHAR(40),
                method VARCHAR(20),
                accessed_url VARCHAR(300),
                user_agent VARCHAR(300),
                date_time VARCHAR(40),
                PRIMARY KEY  (entry_id)
            ) $charset_collate;";
            dbDelta( $sql );

        } else {
            // The table exists
            // No further action is needed for initialization
        }
    }

    public function setBlockReason( $blockReason ) {
        $this->gBlockReason = $blockReason;
    }

    public function setAttemptedMethod( $method ) {
        $this->gAttemptedMethod = $method;
    }

    public function add( $IPAddr ) {

        global $wpdb;
        if ( ! filter_var($IPAddr, FILTER_VALIDATE_IP) ) {
            throw new Exception('WordPress Watchdog Plugin Exception: Invalid IP address format for "'.$IPAddr.'"');
        }

        $blockReason = $this->gBlockReason;
        $attemptedMethod = $this->gAttemptedMethod;
        $url = $_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI'];
        $userAgent = $_SERVER['HTTP_USER_AGENT'];
        $datetime = (new DateTime())->format("d-m-Y H:i:s");

        $wpdb->insert(
            $this->gTableName,
            array( 
                'ip' => $IPAddr,
                'block_reason' => $blockReason,
                'method' => $attemptedMethod,
                'accessed_url' => $url,
                'user_agent' => $userAgent,
                'date_time' => $datetime
            )
        );
    }

    public function remove( $IPAddr ) {

        throw new Exception('WP_Watchdog_WAFManager::remove() is not yet implemented.');
    }

    public function get() {

        global $wpdb;
        $dbResult = $wpdb->get_results("SELECT * FROM $this->gTableName", ARRAY_A );
        
        //$blacklistedIPs = $this->createResult( $dbResult );
        return $dbResult;
    }

    public function check( $IP ) {

        throw new Exception('WP_Watchdog_WAFManager::check() is not yet implemented.');
    }

    public function log() {

        $this->add( $_SERVER['REMOTE_ADDR'] );
    }

    public function getLogs() {

        return $this->get();
    }

}

/**
 * WAF component was inspired by:
 * Alemalakra's "xWAF" project on GitHub: https://github.com/Alemalakra/xWAF
 */
class WP_Watchdog_WAF {

    private static $instance = null;
    private $suspiciousIPs;

    private function __construct() {
        
        $this->suspiciousIPs = WP_Watchdog_WAFManager::getInstance();
    }

    public static function getInstance() {

        if (self::$instance == null) {
            self::$instance = new WP_Watchdog_WAF();
        }

        return self::$instance;
    }

    function getBadwords( $type ) {
        
        switch ($type) {

            case 'SQL' :
                return array(
                    "' or",
                    'or 1=1',
                    'select *',
                    'select * from',
                    'from wp_users',
                    'from wp_options',
                    'from wp_',
                    'from users',
                    'union select',
                    "admin' --",
                    "admin' #",
                    "admin'/*",
                    "' or 1=1--",
                    "' or 1=1#",
                    "' or 1=1/*",
                    "') or '1'='1--",
                    "') or ('1'='1--",
                    "' HAVING 1=1 --"
                );
                break;

            case 'XSS' : 
                return array(
                    '<script>',
                    '<script ',
                    'script>',
                    '</script>',

                    'src=',
                    '<img>',
                    '<img src=',
                    '<img ',
                    '</img>',

                    'window.location',
                    'document.cookie',
                    'alert(',

                    '<iframe ',
                    '<iframe>',
                    'iframe>',

                    '<div ',
                    '<div>',

                    'javascript:',

                    '<style ',
                    '<link rel=',
                    '<meta ',
                    '<TABLE BACKGROUND=',
                    '<EMBED SRC=',
                );
                break;

            default:
                return false;
                break;
        }
    }

    function SQLCheck( $value ) {

        $replace = array("domnu'" => "domnul",
                         );
        
        foreach ($replace as $key => $value_rep) {
            $value = str_replace($key, $value_rep, $value);
        }       
        
        // -------------- Removing all entries like   "/*[content]*/"    if they are found --------------
        $commentStartPos = strpos($value, '/*');
        $commentEndPos = strpos($value, '*/');
        while ( $commentStartPos != 0 && $commentEndPos != 0 ) {

            $valuePre = substr( $value, 0, $commentStartPos);
            $valuePost = substr( $value, $commentEndPos + 2);

            $value = $valuePre . $valuePost;
            $commentStartPos = strpos($value, '/*');
            $commentEndPos = strpos($value, '*/');
        }

        $badwords = $this->getBadwords('SQL');
        foreach ($badwords as $badword) {
            if ( strpos(strtolower($value), strtolower($badword)) !== false ) {
                return true;
            }
        }

        return false;
    }

    function XSSCheck( $value ) {

        $replace = array("<3" => ":heart:");

        foreach ($replace as $key => $value_rep) {
            $value = str_replace($key, $value_rep, $value);
        }

        $badwords = $this->getBadwords('XSS');
        foreach ($badwords as $badword)
        {
            if ( strpos(strtolower($value), strtolower($badword)) !== false )
            {
                return true;
            }
        }

        return false;
    }

    function HTMLCheck( $value ) {

        return ( WP_Watchdog_Utils::isHTML(strtolower($value)) !== false);
    }

    /**
     *  Return:
     *      -> 0 : Clear
     *      -> 1 : SQLi
     *      -> 2 : XSS
     *      -> 3 : HTML
     */
    function checkGet() {

        foreach ($_GET as $key => $value) {
            if ( is_array($value) ) {

                $flattened = WP_Watchdog_Utils::flattenArray($value);
                foreach ($flattened as $sub_key => $sub_value) {
                    if ( $this->SQLCheck ($sub_value) ) {
                        return 1;
                    } elseif ( $this->XSSCheck ($sub_value) ) {
                        return 2;
                    }
                    elseif ( $this->HTMLCheck($sub_value) ) {
                        return 3;
                    }
                }
            } else {

                if ( $this->SQLCheck ($value) )  {
                    return 1;
                } elseif ( $this->XSSCheck ($value) ) {
                    return 2;
                } elseif ( $this->HTMLCheck($value) ) {
                    return 3;
                }
            }
        }

        return 0;
    }

    /**
     *  Return:
     *      -> 0 : Clear
     *      -> 1 : SQLi
     *      -> 2 : XSS
     *      -> 3 : HTML
     */
    function checkPost() {

        foreach ($_POST as $key => $value) {
            if ( is_array($value) ) {

                $flattened = WP_Watchdog_Utils::flattenArray($value);
                foreach ($flattened as $sub_key => $sub_value) {
                    if ( $this->SQLCheck ($sub_value) ) 
                        return 1;
                    elseif ( $this->XSSCheck ($sub_value) )
                        return 2;
                    elseif ( $this->HTMLCheck($sub_value) ) {
                        return 3;
                    }
                }
            } 
            else {
                if ( $this->SQLCheck ($value) ) {
                    return 1;
                } elseif ( $this->XSSCheck ($value) ) {
                    return 2;
                } elseif ( $this->HTMLCheck($value) ) {
                    return 3;
                }
            }
        }

        return 0;
    }

    /**
     *  Return:
     *      -> 0 : Clear
     *      -> 1 : SQLi
     *      -> 2 : XSS
     *      -> 3 : HTML
     */
    function checkCookie() {

        foreach ($_COOKIE as $key => $value) {
            if ( is_array($value) ) {

                $flattened = WP_Watchdog_Utils::flattenArray($value);
                foreach ($flattened as $sub_key => $sub_value) {

                    if ( $this->SQLCheck ($sub_value) ) 
                        return 1;
                    elseif ( $this->XSSCheck ($sub_value) )
                        return 2;
                    elseif ( $this->HTMLCheck($sub_value) ) {
                        return 3;
                    }
                }
            } else {
                if ( $this->SQLCheck ($value) ) {
                    return 1;
                } elseif ( $this->XSSCheck ($value) ) {
                    return 2;
                } elseif ( $this->HTMLCheck($value) ) {
                    return 3;
                }
            }
        }

        return 0;
    }

    private function blockRequest( $detectionResult, $attemptedMethod, $commentID ) {
        
        switch ($detectionResult) {
            case 1: $this->suspiciousIPs->setBlockReason('SQLi'); break;
            case 2: $this->suspiciousIPs->setBlockReason('XSS'); break;
            case 3: $this->suspiciousIPs->setBlockReason('XSS-HTML'); break;
        }

        $this->suspiciousIPs->setAttemptedMethod( $attemptedMethod );
        $this->suspiciousIPs->add( $_SERVER['REMOTE_ADDR']);
        $this->suspiciousIPs->log();

        if ( $commentID !== null ) {
            wp_delete_comment( $commentID, true );
        }

        switch ($detectionResult) {
            case 1: 
                (WP_Watchdog_SessionManager::initialize('WAF'))->endSession('SQL Injection'); 
                break;

            case 2: 
                (WP_Watchdog_SessionManager::initialize('WAF'))->endSession('XSS (Cross-Site Scripting)'); 
                break;

            case 3: 
                (WP_Watchdog_SessionManager::initialize('WAF'))->endSession('XSS (HTML)'); 
                break;

        }
    }

    function verifyComment( $commentID ) {
        @session_start();
        $detectionResult = @$this->checkGet();
        if ($detectionResult > 0) {
            $this->blockRequest( $detectionResult, 'GET', $commentID );
        }
        
        $detectionResult = @$this->checkPost();
        if ($detectionResult > 0) {
            $this->blockRequest( $detectionResult, 'POST', $commentID );
        }
        
        $detectionResult = @$this->checkCookie();
        if ($detectionResult > 0) {
            $this->blockRequest( $detectionResult, 'COOKIE', $commentID );
        }
    }

    function start() {

        @session_start();
        $detectionResult = @$this->checkGet();
        if ($detectionResult > 0) {
            $this->blockRequest( $detectionResult, 'GET', null );
        }

        $detectionResult = @$this->checkPost();
        if ($detectionResult > 0) {
            $this->blockRequest( $detectionResult, 'POST', null );
        }

        $detectionResult = @$this->checkCookie();
        if ($detectionResult > 0) {
            $this->blockRequest( $detectionResult, 'COOKIE', null );
        }
    }

    public function createGUI() {

        self::getInstance(); // to avoid nullptr

?>
        <div id="wp_watchdog_waf_gui" style="text-align:center;">
            <h1> Web Application Firewall Administration Panel </h1>
            <br>
            <h3> WAF Report </h3>
            <!-- <div style="overflow:scroll; overflow-x:hidden; height: 300px;"> -->
            <table class="widefat fixed" style="text-align: center;width: 80%;margin: 0 auto;" cellpadding="10">
                <tr bgcolor="#b8dfff">
                    <td id="columnname" class="manage-column column-columnname" > IP </td>
                    <td id="columnname" class="manage-column column-columnname" > Block reason </td>
                    <td id="columnname" class="manage-column column-columnname" > Attempted by </td>
                    <td id="columnname" class="manage-column column-columnname" > Accessed URL </td>
                    <td id="columnname" class="manage-column column-columnname" > User agent </td>
                    <td id="columnname" class="manage-column column-columnname" > Date and time </td>
                </tr >
			</table>
			<div style="overflow:scroll; overflow-x:hidden; height: 400px;width: 80%;margin: 0 auto;">
                <table class="widefat fixed" style="text-align: center;" cellpadding="10">
					<?php $reports = WP_Watchdog_WAFManager::getInstance()->get(); foreach ($reports as $idx => $report): ?>
					<?php if ( $idx % 2 == 0 ): ?>
						<tr>
							<td> <?php echo $report['ip']; ?> </td>
							<td> <?php echo $report['block_reason']; ?> </td>
							<td> <?php echo $report['method']; ?> </td>
							<td> <?php echo $report['accessed_url']; ?> </td>
							<td> <?php echo $report['user_agent']; ?> </td>
							<td> <?php echo $report['date_time']; ?> </td>
						</tr>
					<?php else: ?> 
						<tr bgcolor="#dae8ff">
							<td> <?php echo $report['ip']; ?> </td>
							<td> <?php echo $report['block_reason']; ?> </td>
							<td> <?php echo $report['method']; ?> </td>
							<td> <?php echo $report['accessed_url']; ?> </td>
							<td> <?php echo $report['user_agent']; ?> </td>
							<td> <?php echo $report['date_time']; ?> </td>
						</tr>
					<?php endif; ?>
					<?php endforeach; ?>
				</table>
            </div>
            <br><br>
            <!-- <hr style="border-width: 2px;"> -->
        </div>
<?php

    }
}
