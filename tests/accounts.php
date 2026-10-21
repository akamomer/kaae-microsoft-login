<?php
/** Standalone provisioning tests. No WordPress bootstrap or real network/database. */
if ( PHP_SAPI !== 'cli' ) { http_response_code( 404 ); exit; }
define( 'ABSPATH', __DIR__ );
class WP_User {
    public function __construct( public int $ID, public string $user_email, public array $roles = array( 'subscriber' ) ) {}
}
class WP_Error {}
class TestDatabase {
    public string $users = 'offline_users';
    public bool $lock = true;
    public int $releases = 0;
    public function prepare( $query, $lock ) { return $query; }
    public function get_var( $query ) {
        if ( str_contains( $query, 'RELEASE_LOCK' ) ) { ++$this->releases; return '1'; }
        return $this->lock ? '1' : '0';
    }
}
$wpdb = new TestDatabase();
$users = array();
$meta = array();
$count = 0;
$remote = array();
$insert_error = false;
$multisite = false;
function check( $condition, $message ) { ++$GLOBALS['count']; if ( ! $condition ) { throw new RuntimeException( $message ); } }
function rejects( callable $call, string $message ) { try { $call(); } catch ( KAAE_MS_Account_Error $e ) { check( true, $message ); return; } check( false, $message ); }
function is_email( $email ) { return filter_var( $email, FILTER_VALIDATE_EMAIL ); }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function is_multisite() { return $GLOBALS['multisite']; }
function wp_remote_get( $url, $args ) {
    check( 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,userType' === $url, 'Graph endpoint was not fixed.' );
    check( 0 === $args['redirection'], 'Bearer-token request allowed redirects.' );
    check( 'Bearer offline-token' === $args['headers']['Authorization'], 'Missing delegated token.' );
    return $GLOBALS['remote'];
}
function wp_remote_retrieve_response_code( $response ) { return $response['status']; }
function wp_remote_retrieve_body( $response ) { return json_encode( $response['body'] ); }
function get_users( $args ) {
    return array_values( array_filter( array_map( static function ( $user ) use ( $args ) {
        if ( isset( $args['meta_key'] ) ) {
            return ( $GLOBALS['meta'][ $user->ID ][ $args['meta_key'] ] ?? '' ) === $args['meta_value'] ? $user->ID : null;
        }
        return strtolower( $user->user_email ) === strtolower( $args['search'] ) ? $user : null;
    }, $GLOBALS['users'] ), static fn( $value ) => null !== $value ) );
}
function get_userdata( $id ) { return $GLOBALS['users'][ $id ] ?? false; }
function is_user_member_of_blog( $id ) { return isset( $GLOBALS['users'][ $id ] ); }
function get_user_meta( $id, $key, $single ) { return $GLOBALS['meta'][ $id ][ $key ] ?? ''; }
function add_user_meta( $id, $key, $value, $unique ) {
    if ( isset( $GLOBALS['meta'][ $id ][ $key ] ) ) { return false; }
    $GLOBALS['meta'][ $id ][ $key ] = $value;
    return true;
}
function sanitize_text_field( $value ) { return strip_tags( $value ); }
function wp_generate_password( $length, $special, $extra ) { return str_repeat( 'random', 11 ); }
function wp_insert_user( $data ) {
    $GLOBALS['last_insert'] = $data;
    if ( $GLOBALS['insert_error'] ) { return new WP_Error(); }
    $id = count( $GLOBALS['users'] ) + 100;
    $GLOBALS['users'][ $id ] = new WP_User( $id, $data['user_email'], array( $data['role'] ) );
    $GLOBALS['meta'][ $id ] = $data['meta_input'];
    return $id;
}
require dirname( __DIR__ ) . '/includes/class-kaae-accounts.php';
$oid = '33333333-3333-3333-3333-333333333333';
$identity = '11111111-1111-1111-1111-111111111111:' . $oid;
$claims = array( 'oid' => $oid );
$profile = array( 'id' => $oid, 'userPrincipalName' => 'STAFF@KAAE.ORG', 'userType' => 'Member' );
$remote = array( 'status' => 200, 'body' => $profile );
check( 'staff@kaae.org' === KAAE_MS_Accounts::directory_email( $claims, 'offline-token' ), 'Valid directory member rejected.' );
foreach ( array( array( 'userType' => 'Guest' ), array( 'userPrincipalName' => 'staff@kaae.org.evil.test' ), array( 'id' => 'other-object' ), array( 'userPrincipalName' => 'staff@example.test' ), array( 'userType' => null ) ) as $change ) {
    $remote['body'] = array_merge( $profile, $change );
    rejects( static fn() => KAAE_MS_Accounts::directory_email( $claims, 'offline-token' ), 'Invalid directory member accepted.' );
}
$remote['status'] = 403;
rejects( static fn() => KAAE_MS_Accounts::directory_email( $claims, 'offline-token' ), 'Missing Graph permission accepted.' );
rejects( static fn() => KAAE_MS_Accounts::directory_email( $claims, '' ), 'Missing access token accepted.' );
$users[7] = new WP_User( 7, 'staff@kaae.org', array( 'administrator' ) );
$user = KAAE_MS_Accounts::resolve( $identity, 'staff@kaae.org', 'Staff' );
check( 7 === $user->ID && array( 'administrator' ) === $user->roles, 'Existing role or account changed.' );
check( $identity === $meta[7][KAAE_MS_Accounts::IDENTITY], 'Existing account did not connect.' );
check( 7 === KAAE_MS_Accounts::resolve( $identity, 'renamed@kaae.org', 'Staff' )->ID, 'Linked identity did not survive UPN change.' );
rejects( static fn() => KAAE_MS_Accounts::resolve( 'other-identity', 'staff@kaae.org', 'Other' ), 'Existing connection was overwritten.' );
$users[8] = new WP_User( 8, 'duplicate@kaae.org' );
$users[9] = new WP_User( 9, 'duplicate@kaae.org' );
rejects( static fn() => KAAE_MS_Accounts::resolve( 'new-identity', 'duplicate@kaae.org', 'Duplicate' ), 'Duplicate emails were linked.' );
$users[10] = new WP_User( 10, 'different@kaae.org' );
$meta[10][KAAE_MS_Accounts::IDENTITY] = $identity;
rejects( static fn() => KAAE_MS_Accounts::resolve( $identity, 'staff@kaae.org', 'Duplicate identity' ), 'Duplicate identity accepted.' );
unset( $users[10], $meta[10] );
$new = KAAE_MS_Accounts::resolve( 'tenant:new-object', 'new@kaae.org', '<b>New Staff</b>' );
check( array( 'subscriber' ) === $new->roles, 'New user was not Subscriber.' );
check( 1 === $meta[ $new->ID ][KAAE_MS_Accounts::PASSWORD_DISABLED], 'New user could use local password.' );
check( 'tenant:new-object' === $meta[ $new->ID ][KAAE_MS_Accounts::IDENTITY], 'New user was not identity-bound.' );
check( 'New Staff' === $last_insert['display_name'], 'Display name was not sanitized.' );
$number = count( $users );
check( $new->ID === KAAE_MS_Accounts::resolve( 'tenant:new-object', 'new@kaae.org', 'New Staff' )->ID && count( $users ) === $number, 'Repeated login created duplicate account.' );
$insert_error = true;
$before = $wpdb->releases;
rejects( static fn() => KAAE_MS_Accounts::resolve( 'tenant:failed', 'failed@kaae.org', 'Failed' ), 'Failed insert allowed login.' );
check( $wpdb->releases === $before + 1, 'Enrollment lock was not released on failure.' );
$insert_error = false;
$wpdb->lock = false;
rejects( static fn() => KAAE_MS_Accounts::resolve( 'tenant:lock', 'lock@kaae.org', 'Locked' ), 'Account creation continued without lock.' );
check( count( $users ) === $number, 'Failed enrollment mutated users.' );
$wpdb->lock = true;
$multisite = true;
rejects( static fn() => KAAE_MS_Accounts::resolve( 'tenant:multi', 'multi@kaae.org', 'Multi' ), 'Multisite enrollment allowed.' );
echo $count . " directory and provisioning checks passed.\n";
