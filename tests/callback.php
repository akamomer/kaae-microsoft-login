<?php
/** End-to-end callback with signed test tokens and in-memory WordPress doubles. */
if ( PHP_SAPI !== 'cli' ) { http_response_code( 404 ); exit; }
define( 'ABSPATH', __DIR__ );
define( 'HOUR_IN_SECONDS', 3600 );
$scenario = $argv[1] ?? 'existing';
if ( ! in_array( $scenario, array( 'existing', 'new', 'manual', 'guest', 'wrong-tenant', 'wrong-nonce', 'conflicting', 'redirect-report', 'redirect-relative', 'redirect-external', 'redirect-array', 'redirect-query-only', 'redirect-query-injection', 'profile-link' ), true ) ) { exit( 2 ); }
class WP_User {
    public function __construct( public int $ID, public string $user_email, public array $roles = array( 'subscriber' ), public string $user_login = 'staff' ) {}
}
class WP_Error {}
class CallbackDatabase {
    public string $users = 'offline_users';
    public function prepare( $query, $lock ) { return $query; }
    public function get_var( $query ) { return '1'; }
}
$wpdb = new CallbackDatabase();
$tenant = '11111111-1111-1111-1111-111111111111';
$client = '22222222-2222-2222-2222-222222222222';
$oid = '33333333-3333-3333-3333-333333333333';
$identity = $tenant . ':' . $oid;
$settings = array( 'tenant' => $tenant, 'client' => $client, 'secret' => 'offline-secret', 'microsoft_only' => true, 'automatic_accounts' => 'manual' !== $scenario );
$users = 'new' === $scenario ? array() : array( 7 => new WP_User( 7, 'staff@kaae.org', array( 'editor' ) ) );
$meta = array();
if ( 'manual' === $scenario ) { $meta[7]['_kaae_ms_identity'] = $identity; }
if ( 'conflicting' === $scenario ) { $meta[7]['_kaae_ms_identity'] = 'another-tenant:another-object'; }
$state = str_repeat( 'a', 64 );
$browser = str_repeat( 'b', 64 );
$flow = array( 'browser' => hash( 'sha256', $browser ), 'nonce' => 'expected-nonce', 'verifier' => 'offline-verifier', 'uid' => 0, 'session' => '', 'tenant' => $tenant, 'client' => $client, 'automatic_accounts' => $settings['automatic_accounts'] );
$reports = 'https://example.test/reports/?status=open&team=Finance%20%26%20Admin&search=A%2BB&page=2';
$expected_destination = 'https://example.test/wp-admin/';
switch ( $scenario ) {
    case 'redirect-report':
    case 'redirect-query-injection':
        $flow['redirect_to'] = $reports;
        $expected_destination = $reports;
        break;
    case 'redirect-relative':
        $flow['redirect_to'] = '/reports/?status=open&team=Finance';
        $expected_destination = $flow['redirect_to'];
        break;
    case 'redirect-external': $flow['redirect_to'] = 'https://untrusted.test/reports/'; break;
    case 'redirect-array': $flow['redirect_to'] = array( '/reports/' ); break;
    case 'profile-link':
        $flow['uid'] = 7;
        $flow['session'] = hash( 'sha256', 'offline-session' );
        $flow['redirect_to'] = $reports;
        $expected_destination = 'https://example.test/wp-admin/profile.php';
        break;
}
$_GET = array( 'state' => $state, 'code' => 'offline-code' );
// Even a same-site callback query must not override the stored login destination.
if ( in_array( $scenario, array( 'redirect-query-only', 'redirect-query-injection' ), true ) ) { $_GET['redirect_to'] = 'https://example.test/other-page/?injected=1'; }
$_REQUEST = $_GET;
$_COOKIE = array( '__Host-kaae_ms' => $browser );
$private = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
$details = openssl_pkey_get_details( $private );
function b64( $value ) { return rtrim( strtr( base64_encode( $value ), '+/', '-_' ), '=' ); }
$keys = array( array( 'kid' => 'offline', 'kty' => 'RSA', 'use' => 'sig', 'n' => b64( $details['rsa']['n'] ), 'e' => b64( $details['rsa']['e'] ) ) );
$claims = array( 'iss' => 'https://login.microsoftonline.com/' . $tenant . '/v2.0', 'tid' => 'wrong-tenant' === $scenario ? $client : $tenant, 'aud' => $client, 'oid' => $oid, 'sub' => 'offline-subject', 'nonce' => 'wrong-nonce' === $scenario ? 'bad' : 'expected-nonce', 'exp' => time() + 300, 'nbf' => time() - 10, 'iat' => time() - 10, 'preferred_username' => 'staff@kaae.org', 'name' => 'Staff Member' );
$input = b64( json_encode( array( 'alg' => 'RS256', 'kid' => 'offline' ) ) ) . '.' . b64( json_encode( $claims ) );
openssl_sign( $input, $signature, $private, OPENSSL_ALGO_SHA256 );
$token = $input . '.' . b64( $signature );
$authenticated = false;
$login_hook = false;
$policy_hook = false;
$state_deleted = false;
function insist( $condition, $message ) { if ( ! $condition ) { fwrite( STDERR, $message . "\n" ); exit( 1 ); } }
function get_option( $key, $default = false ) { return $GLOBALS['settings']; }
function wp_parse_args( $args, $defaults ) { return array_merge( $defaults, $args ); }
function is_ssl() { return true; }
function nocache_headers() {}
function wp_unslash( $value ) { return $value; }
function get_current_user_id() { return 'profile-link' === $GLOBALS['scenario'] ? 7 : 0; }
function wp_get_session_token() { return 'offline-session'; }
function wp_validate_redirect( $requested, $fallback = '' ) {
    $parts = parse_url( $requested );
    if ( false === $parts || ( isset( $parts['scheme'] ) && ! in_array( $parts['scheme'], array( 'http', 'https' ), true ) ) || ( isset( $parts['host'] ) && 'example.test' !== $parts['host'] ) ) { return $fallback; }
    return $requested;
}
function get_transient( $key ) { return str_starts_with( $key, 'kaae_ms_keys_' ) ? $GLOBALS['keys'] : $GLOBALS['flow']; }
function delete_transient( $key ) { $GLOBALS['state_deleted'] = true; }
function set_transient( ...$args ) { return true; }
function is_wp_error( $value ) { return $value instanceof WP_Error; }
function site_url( $path, $scheme = '' ) { return 'https://example.test/' . $path; }
function add_query_arg( $key, $value, $url ) { return $url . '?' . $key . '=' . $value; }
function wp_remote_post( $url, $args ) {
    insist( $url === 'https://login.microsoftonline.com/' . $GLOBALS['tenant'] . '/oauth2/v2.0/token', 'Wrong token endpoint.' );
    insist( 'offline-verifier' === $args['body']['code_verifier'], 'PKCE verifier missing.' );
    insist( 'https://example.test/wp-login.php?action=kaae_ms_callback' === $args['body']['redirect_uri'], 'Registered callback URI changed.' );
    return array( 'status' => 200, 'body' => array( 'id_token' => $GLOBALS['token'], 'access_token' => 'offline-access' ) );
}
function wp_remote_get( $url, $args ) {
    insist( 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,userType' === $url, 'Wrong Graph endpoint.' );
    insist( 0 === $args['redirection'] && 'Bearer offline-access' === $args['headers']['Authorization'], 'Unsafe Graph token handling.' );
    return array( 'status' => 200, 'body' => array( 'id' => $GLOBALS['oid'], 'userPrincipalName' => 'staff@kaae.org', 'userType' => 'guest' === $GLOBALS['scenario'] ? 'Guest' : 'Member' ) );
}
function wp_remote_retrieve_response_code( $response ) { return $response['status']; }
function wp_remote_retrieve_body( $response ) { return json_encode( $response['body'] ); }
function is_email( $email ) { return filter_var( $email, FILTER_VALIDATE_EMAIL ); }
function is_multisite() { return false; }
function get_users( $args ) {
    $matches = array();
    foreach ( $GLOBALS['users'] as $user ) {
        if ( isset( $args['meta_key'] ) ) {
            if ( ( $GLOBALS['meta'][ $user->ID ][ $args['meta_key'] ] ?? '' ) === $args['meta_value'] ) { $matches[] = $user->ID; }
        } elseif ( strtolower( $user->user_email ) === strtolower( $args['search'] ) ) { $matches[] = $user; }
    }
    return $matches;
}
function get_userdata( $id ) { return $GLOBALS['users'][ $id ] ?? false; }
function get_user_meta( $id, $key, $single ) { return $GLOBALS['meta'][ $id ][ $key ] ?? ''; }
function add_user_meta( $id, $key, $value, $unique ) { if ( isset( $GLOBALS['meta'][ $id ][ $key ] ) ) { return false; } $GLOBALS['meta'][ $id ][ $key ] = $value; return true; }
function update_user_meta( $id, $key, $value ) { $GLOBALS['meta'][ $id ][ $key ] = $value; }
function is_user_member_of_blog( $id ) { return isset( $GLOBALS['users'][ $id ] ); }
function sanitize_text_field( $value ) { return strip_tags( $value ); }
function wp_generate_password( ...$args ) { return str_repeat( 'random', 11 ); }
function wp_insert_user( $data ) {
    insist( 'subscriber' === $data['role'], 'New user requested excessive role.' );
    $GLOBALS['users'][100] = new WP_User( 100, $data['user_email'], array( $data['role'] ), $data['user_login'] );
    $GLOBALS['meta'][100] = $data['meta_input'];
    return 100;
}
function apply_filters( $hook, $user, ...$args ) {
    if ( 'authenticate' === $hook ) {
        $GLOBALS['policy_hook'] = true;
        return KAAE_MS_Login::enforce_login( $user, ...$args );
    }
    return $user;
}
function wp_set_auth_cookie( $id, $remember, $secure ) {
    insist( $GLOBALS['policy_hook'] && $GLOBALS['state_deleted'] && $secure, 'Login bypassed auth gate, state consumption, or secure cookie.' );
    $GLOBALS['authenticated'] = $id;
}
function do_action( $hook, ...$args ) { if ( 'wp_login' === $hook ) { $GLOBALS['login_hook'] = true; } }
function admin_url( $path = '' ) { return 'https://example.test/wp-admin/' . $path; }
function wp_safe_redirect( $url ) {
    $scenario = $GLOBALS['scenario'];
    insist( $url === $GLOBALS['expected_destination'], 'Wrong final destination or callback query overrode the saved destination.' );
    if ( 'profile-link' === $scenario ) {
        insist( ! $GLOBALS['authenticated'] && $GLOBALS['meta'][7]['_kaae_ms_identity'] === $GLOBALS['identity'], 'Profile linking behavior changed.' );
        echo "Profile-link redirect passed.\n";
        exit;
    }
    insist( in_array( $scenario, array( 'existing', 'new', 'manual', 'redirect-report', 'redirect-relative', 'redirect-external', 'redirect-array', 'redirect-query-only', 'redirect-query-injection' ), true ), 'Invalid identity reached redirect.' );
    $id = $GLOBALS['authenticated'];
    insist( $id && $GLOBALS['login_hook'], 'Missing authenticated user or login hook.' );
    insist( $GLOBALS['meta'][ $id ]['_kaae_ms_identity'] === $GLOBALS['identity'], 'Identity not saved.' );
    insist( ! empty( $GLOBALS['meta'][ $id ]['_kaae_ms_verified_login'] ), 'Microsoft login test not recorded.' );
    insist( ( 'new' === $scenario ? array( 'subscriber' ) : array( 'editor' ) ) === $GLOBALS['users'][ $id ]->roles, 'Incorrect account permissions.' );
    echo 'Callback scenario passed: ' . $scenario . "\n";
    exit;
}
function esc_html( $value ) { return $value; }
function wp_die( $message, ...$args ) {
    insist( in_array( $GLOBALS['scenario'], array( 'guest', 'wrong-tenant', 'wrong-nonce', 'conflicting' ), true ), 'Unexpected callback failure: ' . $message );
    insist( ! $GLOBALS['authenticated'], 'Failed identity was authenticated.' );
    insist( count( $GLOBALS['users'] ) === 1, 'Rejected identity created a user.' );
    insist( false === strpos( $message, 'offline-secret' ) && false === strpos( $message, $GLOBALS['token'] ), 'Secret/token leaked.' );
    echo 'Callback rejection passed: ' . $GLOBALS['scenario'] . "\n";
    exit;
}
require dirname( __DIR__ ) . '/includes/class-kaae-token.php';
require dirname( __DIR__ ) . '/includes/class-kaae-login.php';
KAAE_MS_Login::callback();
insist( false, 'Callback unexpectedly returned.' );
