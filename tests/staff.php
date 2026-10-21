<?php
/** Offline staff-directory/management tests, with no real users, network or DB. */
if ( PHP_SAPI !== 'cli' ) { http_response_code( 404 ); exit; }
define( 'ABSPATH', __DIR__ );
define( 'MINUTE_IN_SECONDS', 60 );
if ( 'recovery' === ( $argv[1] ?? '' ) ) { define( 'KAAE_MS_PASSWORD_RECOVERY', true ); }
class WP_User { public function __construct( public int $ID, public string $user_email, public array $roles = array( 'subscriber' ) ) {} }
class WP_Error {}
class StaffStop extends RuntimeException {}
class KAAE_MS_Login { public static function settings(): array { return $GLOBALS['settings']; } }
class StaffDatabase {
    public string $users = 'offline_users'; public bool $lock = true; public int $released = 0;
    public function prepare( $query, $lock ) { return $query; }
    public function get_var( $query ) { if ( str_contains( $query, 'RELEASE_LOCK' ) ) { ++$this->released; return '1'; } return $this->lock ? '1' : '0'; }
}
class WP_Session_Tokens {
    public function __construct( private int $id ) {}
    public static function get_instance( $id ) { return new self( $id ); }
    public function destroy_all() { $GLOBALS['destroyed'][] = $this->id; }
}
$wpdb = new StaffDatabase();
$tenant = '11111111-1111-1111-1111-111111111111';
$settings = array( 'tenant' => $tenant, 'client' => '22222222-2222-2222-2222-222222222222', 'secret' => 'offline-secret', 'approved_staff_only' => false );
$options = array(); $cache = array(); $ttl = array(); $meta = array(); $destroyed = array(); $users = array();
$allowed = true; $edit_allowed = true; $nonce = true; $session = 'first-session'; $multisite = false; $write_failure = false;
$responses = array(); $requests = array(); $count = 0;
$id_a = '33333333-3333-3333-3333-333333333333';
$id_b = '44444444-4444-4444-4444-444444444444';
$id_c = '55555555-5555-5555-5555-555555555555';
$id_admin = '66666666-6666-6666-6666-666666666666';
function check( $condition, $message ) { ++$GLOBALS['count']; if ( ! $condition ) { throw new RuntimeException( $message ); } }
function rejects( callable $call, $message ) { try { $call(); } catch ( KAAE_MS_Account_Error $error ) { check( true, $message ); return; } check( false, $message ); }
function current_user_can( $cap, ...$args ) { return $GLOBALS['allowed'] && ( 'edit_user' !== $cap || $GLOBALS['edit_allowed'] ); }
function is_multisite() { return $GLOBALS['multisite']; }
function is_email( $email ) { return filter_var( $email, FILTER_VALIDATE_EMAIL ); }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function get_option( $key, $default = false ) { return $GLOBALS['options'][$key] ?? $default; }
function update_option( $key, $value, $autoload ) { if ( ! $GLOBALS['write_failure'] ) { $GLOBALS['options'][$key] = $value; } }
function get_current_user_id() { return 7; }
function wp_get_session_token() { return $GLOBALS['session']; }
function wp_parse_url( $url ) { return parse_url( $url ); }
function get_transient( $key ) { return $GLOBALS['cache'][$key] ?? false; }
function set_transient( $key, $value, $ttl ) { $GLOBALS['cache'][$key] = $value; $GLOBALS['ttl'][$key] = $ttl; }
function delete_transient( $key ) { unset( $GLOBALS['cache'][$key] ); }
function wp_remote_get( $url, $args ) {
    $GLOBALS['requests'][] = $url;
    check( str_starts_with( $url, 'https://graph.microsoft.com/v1.0/users?' ) && 0 === $args['redirection'], 'Directory request could leak a token.' );
    check( 'Bearer DO_NOT_PERSIST_THIS_TOKEN' === $args['headers']['Authorization'], 'Missing delegated token.' );
    return array_shift( $GLOBALS['responses'] );
}
function wp_remote_retrieve_response_code( $r ) { return $r['status']; }
function wp_remote_retrieve_body( $r ) { return json_encode( $r['body'] ); }
function sanitize_text_field( $v ) { return strip_tags( $v ); }
function get_users( $args ) {
    $result = array();
    foreach ( $GLOBALS['users'] as $user ) {
        if ( isset( $args['meta_key'] ) ) { if ( ( $GLOBALS['meta'][$user->ID][$args['meta_key']] ?? '' ) === $args['meta_value'] ) { $result[] = $user->ID; } }
        elseif ( strtolower( $user->user_email ) === strtolower( $args['search'] ) ) { $result[] = $user; }
    }
    return $result;
}
function get_userdata( $id ) { return $GLOBALS['users'][$id] ?? false; }
function is_user_member_of_blog( $id ) { return isset( $GLOBALS['users'][$id] ); }
function get_user_meta( $id, $key, $single ) { return $GLOBALS['meta'][$id][$key] ?? ''; }
function update_user_meta( $id, $key, $value ) { $GLOBALS['meta'][$id][$key] = $value; }
function delete_user_meta( $id, $key ) { unset( $GLOBALS['meta'][$id][$key] ); }
function add_user_meta( $id, $key, $value, $unique ) { if ( isset( $GLOBALS['meta'][$id][$key] ) ) { return false; } $GLOBALS['meta'][$id][$key] = $value; return true; }
function wp_generate_password( ...$args ) { return str_repeat( 'random', 11 ); }
function wp_insert_user( $data ) { $id = count( $GLOBALS['users'] ) + 100; $GLOBALS['users'][$id] = new WP_User( $id, $data['user_email'], array( $data['role'] ) ); $GLOBALS['meta'][$id] = $data['meta_input']; return $id; }
function check_admin_referer( $action ) { if ( ! $GLOBALS['nonce'] ) { throw new StaffStop( 'nonce' ); } }
function wp_die( $message, ...$args ) { throw new StaffStop( $message ); }
function wp_safe_redirect( $url ) { throw new StaffStop( 'redirect' ); }
function admin_url( $path ) { return 'https://example.test/wp-admin/' . $path; }
function esc_html( $v ) { return htmlspecialchars( $v, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $v ) { return esc_html( $v ); }
function esc_url( $v ) { return esc_html( $v ); }
function wp_nonce_field( $action ) { echo '<input name="_wpnonce" value="offline">'; }
function wp_unslash( $v ) { return $v; }
function add_query_arg( $args, $url ) { return $url . '?' . http_build_query( $args ); }
require dirname( __DIR__ ) . '/includes/class-kaae-accounts.php';
require dirname( __DIR__ ) . '/includes/class-kaae-staff.php';
$users[7] = new WP_User( 7, 'admin@kaae.org', array( 'administrator' ) );
$meta[7][KAAE_MS_Accounts::IDENTITY] = $tenant . ':' . $id_admin;
$users[8] = new WP_User( 8, 'ada@kaae.org', array( 'editor' ) );
$row_a = array( 'id' => $id_a, 'email' => 'ada@kaae.org', 'name' => 'Ada', 'mail' => 'ada@kaae.org' );
$row_b = array( 'id' => $id_b, 'email' => 'bea@kaae.org', 'name' => 'Bea', 'mail' => '' );
$row_c = array( 'id' => $id_c, 'email' => 'cy@kaae.org', 'name' => 'Cy', 'mail' => '' );
$row_admin = array( 'id' => $id_admin, 'email' => 'admin@kaae.org', 'name' => 'Admin', 'mail' => '' );
$identity_a = $tenant . ':' . $id_a;
if ( defined( 'KAAE_MS_PASSWORD_RECOVERY' ) ) {
    $meta[8][KAAE_MS_Staff::BLOCKED] = $identity_a;
    $settings['approved_staff_only'] = true;
    check( KAAE_MS_Staff::user_allowed( $users[8] ), 'Recovery did not bypass local staff restrictions.' );
    KAAE_MS_Staff::assert_identity_access( $identity_a );
    check( 8 === KAAE_MS_Staff::validate_session( 8 ), 'Recovery did not restore the administrator recovery path.' );
    echo $count . " staff recovery checks passed.\n"; exit;
}
check( array() === KAAE_MS_Staff::state( $identity_a ) && KAAE_MS_Staff::user_allowed( $users[8] ), 'Default policy changed existing access.' );
$allowed = false;
rejects( static fn() => KAAE_MS_Staff::load_directory( 'DO_NOT_PERSIST_THIS_TOKEN' ), 'Non-admin loaded directory.' );
check( ! $requests && ! $cache, 'Denied directory request accessed Graph/cache.' );
$allowed = true;
$responses = array(
    array( 'status' => 200, 'body' => array( 'value' => array( array( 'id' => $id_a, 'displayName' => '<b>Ada</b>', 'mail' => 'ada@kaae.org', 'userPrincipalName' => 'ADA@KAAE.ORG' ), array( 'id' => $id_c, 'userPrincipalName' => 'outside@example.test' ) ), '@odata.nextLink' => 'https://graph.microsoft.com/v1.0/users?$skiptoken=next' ) ),
    array( 'status' => 200, 'body' => array( 'value' => array( array( 'id' => $id_b, 'displayName' => 'Bea', 'userPrincipalName' => 'bea@kaae.org' ) ) ) ),
);
$before_users = $users;
KAAE_MS_Staff::load_directory( 'DO_NOT_PERSIST_THIS_TOKEN' );
$directory = KAAE_MS_Staff::directory();
check( 2 === count( $directory ) && 'Ada' === $directory[$id_a]['name'] && 'ada@kaae.org' === $directory[$id_a]['email'], 'Directory paging/filtering/sanitizing failed.' );
check( $users === $before_users && ! $options && ! str_contains( serialize( $cache ), 'DO_NOT_PERSIST_THIS_TOKEN' ), 'Directory loading enrolled users or stored a token.' );
check( in_array( 900, $ttl, true ), 'Directory snapshot is not limited to fifteen minutes.' );
$session = 'other-browser-session';
check( array() === KAAE_MS_Staff::directory(), 'Directory snapshot leaked across administrator sessions.' );
$session = 'first-session';
$settings['secret'] = 'rotated';
check( array() === KAAE_MS_Staff::directory(), 'Old directory snapshot survived credential rotation.' );
$settings['secret'] = 'offline-secret';
$before_cache = $cache;
$responses = array( array( 'status' => 200, 'body' => array( 'value' => array(), '@odata.nextLink' => 'https://untrusted.test/v1.0/users?$skiptoken=evil' ) ) );
$before_requests = count( $requests );
rejects( static fn() => KAAE_MS_Staff::load_directory( 'DO_NOT_PERSIST_THIS_TOKEN' ), 'Untrusted paging link received bearer token.' );
check( count( $requests ) === $before_requests + 1 && $before_cache === $cache, 'Partial/unsafe directory replaced the snapshot.' );
$responses = array( array( 'status' => 403, 'body' => array( 'error' => 'SECRET_PROVIDER_BODY' ) ) );
rejects( static fn() => KAAE_MS_Staff::load_directory( 'DO_NOT_PERSIST_THIS_TOKEN' ), 'Consent failure was accepted.' );
$responses = array( array( 'status' => 200, 'body' => array( 'value' => 'bad' ) ) );
rejects( static fn() => KAAE_MS_Staff::load_directory( 'DO_NOT_PERSIST_THIS_TOKEN' ), 'Malformed directory was accepted.' );

KAAE_MS_Staff::apply_action( 'enroll', $row_a );
check( array( 'editor' ) === $users[8]->roles && $identity_a === $meta[8][KAAE_MS_Accounts::IDENTITY] && KAAE_MS_Staff::approved( $identity_a ), 'Existing enrollment changed role or failed to approve.' );
KAAE_MS_Staff::apply_action( 'enroll', $row_b );
$new = KAAE_MS_Staff::matching_user( $row_b );
check( $new && array( 'subscriber' ) === $new->roles && $meta[$new->ID][KAAE_MS_Accounts::PASSWORD_DISABLED], 'New enrollment was not a Microsoft-only Subscriber.' );
$settings['approved_staff_only'] = true;
check( KAAE_MS_Staff::user_allowed( $users[8] ) && ! KAAE_MS_Staff::user_allowed( $users[7] ), 'Approved-only policy did not distinguish enrolled staff.' );
check( 0 === KAAE_MS_Staff::validate_session( 7 ), 'Unapproved existing session was not denied.' );
$users[9] = new WP_User( 9, 'external@example.test' );
check( KAAE_MS_Staff::user_allowed( $users[9] ), 'Approved-only policy captured an external password user.' );
rejects( static fn() => KAAE_MS_Staff::assert_identity_access( $tenant . ':' . $id_c ), 'Unapproved identity passed access gate.' );
KAAE_MS_Staff::apply_action( 'block', $row_a );
check( ! KAAE_MS_Staff::user_allowed( $users[8] ) && 0 === KAAE_MS_Staff::validate_session( 8 ) && in_array( 8, $destroyed, true ), 'Block did not deny access and destroy sessions.' );
check( ! KAAE_MS_Staff::approved( $identity_a ) && true === KAAE_MS_Staff::state( $identity_a )['approved'], 'Block lost prior approval history.' );
rejects( static fn() => KAAE_MS_Staff::assert_identity_access( $identity_a ), 'Blocked Microsoft identity passed gate.' );
rejects( static fn() => KAAE_MS_Staff::apply_action( 'enroll', $row_a ), 'Enroll silently removed a block.' );
KAAE_MS_Staff::apply_action( 'unblock', $row_a );
check( KAAE_MS_Staff::approved( $identity_a ) && KAAE_MS_Staff::user_allowed( $users[8] ) && array( 'editor' ) === $users[8]->roles, 'Unblock did not restore previous access/role.' );
$before_count = count( $users );
KAAE_MS_Staff::apply_action( 'block', $row_c );
check( count( $users ) === $before_count, 'Blocking an unenrolled person created an account.' );
KAAE_MS_Staff::apply_action( 'unblock', $row_c );
rejects( static fn() => KAAE_MS_Staff::assert_identity_access( $tenant . ':' . $id_c ), 'Unblock granted approval to an unapproved person.' );
rejects( static fn() => KAAE_MS_Staff::apply_action( 'block', $row_admin ), 'Administrator could block themself.' );
check( empty( KAAE_MS_Staff::state( $tenant . ':' . $id_admin )['blocked'] ), 'Self-block mutated state.' );
$allowed = false;
rejects( static fn() => KAAE_MS_Staff::apply_action( 'block', $row_a ), 'Non-admin changed staff access.' );
$allowed = true; $edit_allowed = false;
rejects( static fn() => KAAE_MS_Staff::apply_action( 'block', $row_a ), 'Missing per-user edit permission was ignored.' );
$edit_allowed = true; $wpdb->lock = false;
rejects( static fn() => KAAE_MS_Staff::apply_action( 'block', $row_a ), 'Staff action continued without locking.' );
$wpdb->lock = true;
$write_failure = true;
rejects( static fn() => KAAE_MS_Staff::apply_action( 'block', $row_a ), 'Failed state persistence reported success.' );
$write_failure = false;
$meta[8][KAAE_MS_Accounts::IDENTITY] = 'other-tenant:other-identity';
rejects( static fn() => KAAE_MS_Staff::apply_action( 'enroll', $row_a ), 'Conflicting identity was overwritten.' );
$meta[8][KAAE_MS_Accounts::IDENTITY] = $identity_a;

$_SERVER['REQUEST_METHOD'] = 'POST';
$_POST = array( 'staff_action' => 'block', 'staff_ids' => array( $id_a, 'forged-id' ) );
$before_options = $options;
try { KAAE_MS_Staff::handle_action(); } catch ( StaffStop $error ) {}
check( $before_options === $options, 'Invalid bulk selection partially performed actions.' );
$_POST['staff_ids'] = array( $id_a );
$allowed = false;
try { KAAE_MS_Staff::handle_action(); } catch ( StaffStop $error ) {}
check( $before_options === $options, 'Unauthorized bulk action changed access.' );
$allowed = true;
$_SERVER['REQUEST_METHOD'] = 'GET';
try { KAAE_MS_Staff::handle_action(); } catch ( StaffStop $error ) {}
check( $before_options === $options, 'GET request changed staff access.' );
$_SERVER['REQUEST_METHOD'] = 'POST';
$saved_cache = $cache;
$cache = array();
try { KAAE_MS_Staff::handle_action(); } catch ( StaffStop $error ) {}
check( $before_options === $options, 'Expired directory snapshot authorized an action.' );
$cache = $saved_cache;
$nonce = false;
try { KAAE_MS_Staff::handle_action(); } catch ( StaffStop $error ) { check( 'nonce' === $error->getMessage(), 'Invalid nonce was not rejected.' ); }
check( $before_options === $options, 'Invalid nonce changed staff access.' );
$nonce = true;
try { KAAE_MS_Staff::handle_action(); } catch ( StaffStop $error ) { check( 'redirect' === $error->getMessage(), 'Bulk action did not redirect.' ); }
check( ! KAAE_MS_Staff::user_allowed( $users[8] ), 'Bulk block did not apply.' );
$before_requests = count( $requests );
ob_start(); KAAE_MS_Staff::render(); $html = ob_get_clean();
check( str_contains( $html, 'KAAE Staff' ) && str_contains( $html, 'staff_ids[]' ) && str_contains( $html, 'Blocked' ) && str_contains( $html, 'editor' ), 'Directory controls/status/roles were not rendered.' );
check( count( $requests ) === $before_requests && ! str_contains( $html, 'DO_NOT_PERSIST_THIS_TOKEN' ), 'Rendering fetched Graph or exposed a token.' );
echo $count . " offline staff directory/access checks passed.\n";
