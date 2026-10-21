<?php
/** Offline authentication-policy tests; no WordPress/database/network access. */
if ( PHP_SAPI !== 'cli' ) {
    http_response_code( 404 );
    exit;
}
define( 'ABSPATH', __DIR__ );
if ( 'recovery' === ( $argv[1] ?? '' ) ) {
    define( 'KAAE_MS_PASSWORD_RECOVERY', true );
}
class WP_User { public function __construct( public int $ID, public string $user_email = 'staff@kaae.org' ) {} }
class WP_Error { public function __construct( public string $code, public string $message ) {} }
class PolicyStop extends RuntimeException {}
$options = array();
$meta = array();
$count = 0;
$ssl = true;
$can_manage = true;
$nonce_valid = true;
$users = array();
function get_option( $name, $default = false ) { return $GLOBALS['options'][ $name ] ?? $default; }
function wp_parse_args( $args, $defaults ) { return array_merge( $defaults, $args ); }
function current_user_can( $cap ) { return $GLOBALS['can_manage']; }
function check_admin_referer( $action ) { if ( ! $GLOBALS['nonce_valid'] ) { throw new PolicyStop( 'nonce rejected' ); } }
function sanitize_text_field( $value ) { return trim( $value ); }
function wp_unslash( $value ) { return $value; }
function get_current_user_id() { return 7; }
function get_user_meta( $uid, $key, $single ) { return $GLOBALS['meta'][ $uid ][ $key ] ?? ''; }
function update_user_meta( $uid, $key, $value ) { $GLOBALS['meta'][ $uid ][ $key ] = $value; }
function get_userdata( $id ) { return $GLOBALS['users'][ $id ] ?? false; }
function get_users( $args ) { return array_values( array_filter( $GLOBALS['users'], static fn( $u ) => strtolower( $u->user_email ) === strtolower( $args['search'] ?? '' ) ) ); }
function is_user_member_of_blog( $id ) { return isset( $GLOBALS['users'][ $id ] ); }
function is_multisite() { return false; }
function is_email( $value ) { return filter_var( $value, FILTER_VALIDATE_EMAIL ); }
function update_option( $key, $value, $autoload ) { $GLOBALS['options'][ $key ] = $value; }
function delete_transient( $key ) {}
function delete_user_meta( $uid, $key ) { unset( $GLOBALS['meta'][ $uid ][ $key ] ); }
function admin_url( $path ) { return 'https://example.test/wp-admin/' . $path; }
function wp_safe_redirect( $url ) { throw new PolicyStop( 'saved' ); }
function esc_html( $value ) { return $value; }
function wp_die( $message, ...$args ) { throw new PolicyStop( $message ); }
function is_ssl() { return $GLOBALS['ssl']; }
function check( $condition, $message ) {
    ++$GLOBALS['count'];
    if ( ! $condition ) { throw new RuntimeException( $message ); }
}
function save(): string {
    try { KAAE_MS_Login::save_settings(); } catch ( PolicyStop $e ) { return $e->getMessage(); }
    throw new RuntimeException( 'Unexpected save return.' );
}
require dirname( __DIR__ ) . '/includes/class-kaae-login.php';
$user = new WP_User( 7 );
$users[7] = $user;
check( ! KAAE_MS_Login::microsoft_only(), 'Enforcement enabled by default.' );
check( KAAE_MS_Login::enforce_login( $user ) === $user, 'Normal password login blocked by default.' );
check( KAAE_MS_Login::application_passwords( true ), 'API passwords blocked by default.' );
$options['kaae_ms_settings'] = array( 'microsoft_only' => true );
if ( defined( 'KAAE_MS_PASSWORD_RECOVERY' ) ) {
    check( ! KAAE_MS_Login::microsoft_only(), 'Recovery did not override enforcement.' );
    check( KAAE_MS_Login::enforce_login( $user ) === $user, 'Recovery password authentication blocked.' );
    check( KAAE_MS_Login::application_passwords( true ), 'Recovery API authentication blocked.' );
    echo $count . " recovery checks passed.\n";
    exit;
}
check( KAAE_MS_Login::enforce_login( $user ) instanceof WP_Error, 'Password-authenticated user bypassed enforcement.' );
check( KAAE_MS_Login::enforce_login( null ) instanceof WP_Error, 'Unauthenticated login bypassed enforcement.' );
check( ! KAAE_MS_Login::application_passwords( true ), 'API passwords allowed under enforcement.' );
check( KAAE_MS_Login::microsoft_only(), 'Missing credentials silently restored passwords.' );
$verified = new ReflectionProperty( KAAE_MS_Login::class, 'verified_user' );
$verified->setValue( null, 7 );
check( KAAE_MS_Login::enforce_login( $user ) === $user, 'Verified Microsoft identity blocked.' );
check( KAAE_MS_Login::enforce_login( new WP_User( 8 ) ) instanceof WP_Error, 'Different identity allowed in verified context.' );
$verified->setValue( null, 0 );
check( KAAE_MS_Login::enforce_login( $user ) instanceof WP_Error, 'Microsoft verification persisted beyond its context.' );
$meta[7]['_kaae_ms_identity'] = 'keep-me';
try { KAAE_MS_Login::disconnect(); } catch ( PolicyStop $e ) {}
check( 'keep-me' === $meta[7]['_kaae_ms_identity'], 'Enforced account was disconnected.' );
$tenant = '11111111-1111-1111-1111-111111111111';
$client = '22222222-2222-2222-2222-222222222222';
$identity = $tenant . ':33333333-3333-3333-3333-333333333333';
$initial = array( 'tenant' => $tenant, 'client' => $client, 'secret' => 'test-secret', 'repository' => '', 'microsoft_only' => false );
$options['kaae_ms_settings'] = $initial;
$_POST = array( 'tenant' => $tenant, 'client' => $client, 'secret' => '', 'repository' => '', 'microsoft_only' => '1' );
check( 'saved' !== save(), 'Unlinked administrator enabled enforcement.' );
check( $options['kaae_ms_settings'] === $initial, 'Rejected save modified settings.' );
$meta[7]['_kaae_ms_identity'] = $identity;
check( 'saved' !== save(), 'Untested administrator enabled enforcement.' );
$meta[7]['_kaae_ms_verified_login'] = hash( 'sha256', $tenant . ':' . $client . ':test-secret:' . $identity );
check( 'saved' === save(), 'Tested connected administrator could not enable enforcement.' );
check( KAAE_MS_Login::microsoft_only(), 'Enforcement was not saved.' );
$options['kaae_ms_settings'] = $initial;
$_POST['secret'] = 'rotated-secret';
check( 'saved' !== save(), 'Changed credentials enabled enforcement without a new test.' );
$_POST['secret'] = '';
$ssl = false;
check( 'saved' !== save(), 'Enforcement enabled without HTTPS.' );
$ssl = true;
$can_manage = false;
check( 'saved' !== save(), 'Non-administrator saved settings.' );
$can_manage = true;
$nonce_valid = false;
check( 'saved' !== save(), 'Invalid settings nonce accepted.' );
$nonce_valid = true;
unset( $_POST['microsoft_only'] );
check( 'saved' === save(), 'Administrator could not turn enforcement off.' );
check( ! KAAE_MS_Login::microsoft_only(), 'Disabled enforcement remained on.' );

// A single selected external account may use passwords; other external users may not.
$users[8] = new WP_User( 8, 'external@example.test' );
$users[9] = new WP_User( 9, 'other@example.test' );
$options['kaae_ms_settings']['microsoft_only'] = true;
$options['kaae_ms_settings']['password_exception_users'] = array( 8 );
check( KAAE_MS_Login::enforce_login( $users[8] ) === $users[8], 'Selected external account could not use password.' );
check( KAAE_MS_Login::enforce_login( $users[9] ) instanceof WP_Error, 'Unselected external account bypassed policy.' );
check( KAAE_MS_Login::enforce_login( $user ) instanceof WP_Error, 'KAAE user bypassed policy.' );
check( ! KAAE_MS_Login::application_passwords( true, $users[8] ), 'External exception enabled API passwords.' );
check( KAAE_MS_Login::allow_password_reset( true, 8 ), 'External exception cannot reset password.' );
check( ! KAAE_MS_Login::allow_password_reset( true, 7 ), 'KAAE user can reset password under enforced policy.' );
$users[8]->user_email = 'renamed@kaae.org';
check( KAAE_MS_Login::enforce_login( $users[8] ) instanceof WP_Error, 'Exception allowed after becoming a KAAE user.' );
$users[8]->user_email = 'external@example.test';

// Personal restriction blocks passwords even when the site policy is off.
$options['kaae_ms_settings']['microsoft_only'] = false;
$meta[7][KAAE_MS_Accounts::PASSWORD_DISABLED] = 1;
check( KAAE_MS_Login::enforce_login( $user ) instanceof WP_Error, 'Personal password preference was ignored.' );
check( ! KAAE_MS_Login::application_passwords( true, $user ), 'Personal restriction allowed API passwords.' );
$verified->setValue( null, 7 );
check( KAAE_MS_Login::enforce_login( $user ) === $user, 'Personal restriction blocked Microsoft callback.' );
$verified->setValue( null, 0 );
try { KAAE_MS_Login::disconnect(); } catch ( PolicyStop $e ) {}
check( isset( $meta[7]['_kaae_ms_identity'] ), 'Personal restriction allowed disconnection.' );
unset( $meta[7][KAAE_MS_Accounts::PASSWORD_DISABLED] );

// Personal preference is authenticated, nonce-protected, and needs a tested link.
$options['kaae_ms_settings'] = $initial;
$_POST = array( 'kaae_ms_policy_present' => '1', 'kaae_ms_disable_password' => '1' );
$meta[7]['_kaae_ms_verified_login'] = '';
try { KAAE_MS_Login::save_personal_policy( 7 ); } catch ( PolicyStop $e ) {}
check( empty( $meta[7][KAAE_MS_Accounts::PASSWORD_DISABLED] ), 'Untested connection could disable password.' );
$meta[7]['_kaae_ms_verified_login'] = hash( 'sha256', $tenant . ':' . $client . ':test-secret:' . $identity );
$nonce_valid = false;
try { KAAE_MS_Login::save_personal_policy( 7 ); } catch ( PolicyStop $e ) {}
check( empty( $meta[7][KAAE_MS_Accounts::PASSWORD_DISABLED] ), 'Bad nonce changed personal preference.' );
$nonce_valid = true;
KAAE_MS_Login::save_personal_policy( 7 );
check( 1 === $meta[7][KAAE_MS_Accounts::PASSWORD_DISABLED], 'Connected user could not disable password.' );
try { KAAE_MS_Login::save_personal_policy( 8 ); } catch ( PolicyStop $e ) {}
check( empty( $meta[8][KAAE_MS_Accounts::PASSWORD_DISABLED] ), 'User changed another account’s preference.' );
unset( $_POST['kaae_ms_disable_password'] );
KAAE_MS_Login::save_personal_policy( 7 );
check( empty( $meta[7][KAAE_MS_Accounts::PASSWORD_DISABLED] ), 'User could not clear personal preference.' );

// Exception selection must resolve to an existing external user, not a domain rule.
$_POST = array( 'tenant' => $tenant, 'client' => $client, 'secret' => '', 'repository' => '', 'password_exception_email' => 'external@example.test', 'automatic_accounts' => '1' );
check( 'saved' === save(), 'Valid external account and automatic setting not saved.' );
check( array( 8 ) === $options['kaae_ms_settings']['password_exception_users'], 'Legacy form was not saved as a user ID list.' );
check( true === $options['kaae_ms_settings']['automatic_accounts'], 'Automatic accounts setting was lost.' );
$_POST['password_exception_email'] = 'staff@kaae.org';
check( 'saved' !== save(), 'KAAE email was accepted as external exception.' );
$_POST['password_exception_email'] = 'missing@example.test';
check( 'saved' !== save(), 'Missing user was accepted as external exception.' );

// Upgrading immediately honors the old saved exception without any write.
$options['kaae_ms_settings'] = array_merge( $initial, array( 'microsoft_only' => true, 'password_exception_user' => 8 ) );
$before = $options;
check( array( 8 ) === KAAE_MS_Login::settings()['password_exception_users'], 'Legacy saved exception was not normalized.' );
check( KAAE_MS_Login::enforce_login( $users[8] ) === $users[8], 'Upgrade revoked existing external access.' );
check( $before === $options, 'Reading legacy settings wrote to the database.' );

// Multiple approved accounts work independently, while staff/unlisted users stay blocked.
$_POST = array( 'tenant' => $tenant, 'client' => $client, 'secret' => '', 'repository' => '', 'microsoft_only' => '1', 'password_exception_emails' => "EXTERNAL@example.test\r\nother@example.test\nexternal@example.test\n" );
check( 'saved' === save(), 'Multiple external exceptions could not be saved.' );
check( array( 8, 9 ) === $options['kaae_ms_settings']['password_exception_users'], 'Emails were not deduplicated and bound to IDs.' );
check( KAAE_MS_Login::enforce_login( $users[8] ) === $users[8] && KAAE_MS_Login::enforce_login( $users[9] ) === $users[9], 'One of the listed external accounts was blocked.' );
$users[10] = new WP_User( 10, 'unlisted@example.test' );
check( KAAE_MS_Login::enforce_login( $users[10] ) instanceof WP_Error && KAAE_MS_Login::enforce_login( $users[7] ) instanceof WP_Error, 'Unlisted external or staff account bypassed restrictions.' );
check( ! KAAE_MS_Login::application_passwords( true, $users[9] ), 'Multiple exceptions enabled application passwords.' );
$meta[9][KAAE_MS_Accounts::PASSWORD_DISABLED] = 1;
check( KAAE_MS_Login::enforce_login( $users[9] ) instanceof WP_Error, 'List exception overrode personal password restriction.' );
unset( $meta[9][KAAE_MS_Accounts::PASSWORD_DISABLED] );
$before = $options;
$_POST['password_exception_emails'] .= "staff@kaae.org\n";
check( 'saved' !== save() && $before === $options, 'Invalid list entry partially changed saved access.' );
$_POST['password_exception_emails'] = "external@example.test\nmissing@example.test";
check( 'saved' !== save() && $before === $options, 'Unknown account partially changed saved access.' );
$_POST['password_exception_emails'] = array( 'external@example.test' );
check( 'saved' !== save() && $before === $options, 'Array form input was accepted.' );
$_POST['password_exception_emails'] = '0';
check( 'saved' !== save() && $before === $options, 'Invalid zero value silently cleared the list.' );

$_POST['password_exception_emails'] = 'external@example.test';
check( 'saved' === save(), 'Removing one exception failed.' );
check( KAAE_MS_Login::enforce_login( $users[8] ) === $users[8] && KAAE_MS_Login::enforce_login( $users[9] ) instanceof WP_Error, 'Removed user retained password access or remaining user lost it.' );
unset( $_POST['password_exception_emails'] );
check( 'saved' === save() && array( 8 ) === $options['kaae_ms_settings']['password_exception_users'], 'Missing field unexpectedly cleared the list.' );
$_POST['password_exception_emails'] = '';
check( 'saved' === save() && array() === $options['kaae_ms_settings']['password_exception_users'], 'Explicit empty list did not remove all exceptions.' );
check( KAAE_MS_Login::enforce_login( $users[8] ) instanceof WP_Error, 'Cleared exception was resurrected.' );
$options['kaae_ms_settings']['password_exception_user'] = 8;
check( KAAE_MS_Login::enforce_login( $users[8] ) instanceof WP_Error, 'Legacy ID overrode the new empty list.' );

// Staff blocking must win even inside a verified Microsoft authentication context.
$options['kaae_ms_settings'] = $initial;
$meta[7]['_kaae_ms_identity'] = $identity;
$meta[7]['_kaae_ms_verified_login'] = hash( 'sha256', $tenant . ':' . $client . ':test-secret:' . $identity );
$meta[7][KAAE_MS_Staff::BLOCKED] = $identity;
$verified->setValue( null, 7 );
check( KAAE_MS_Login::enforce_login( $user ) instanceof WP_Error, 'Microsoft authentication bypassed staff block.' );
check( ! KAAE_MS_Login::application_passwords( true, $user ) && ! KAAE_MS_Login::allow_password_reset( true, 7 ), 'Blocked staff retained password/API/reset access.' );
check( 0 === KAAE_MS_Staff::validate_session( 7 ), 'Blocked existing session was retained.' );
unset( $meta[7][KAAE_MS_Staff::BLOCKED] );
$options['kaae_ms_settings']['approved_staff_only'] = true;
check( KAAE_MS_Login::enforce_login( $user ) instanceof WP_Error, 'Verified but unapproved staff bypassed approval policy.' );
$state_key = 'kaae_ms_access_' . hash( 'sha256', $identity );
$options[$state_key] = array( 'approved' => true );
check( KAAE_MS_Login::enforce_login( $user ) === $user, 'Approved Microsoft identity could not authenticate.' );
$options[$state_key]['blocked'] = true;
check( KAAE_MS_Login::enforce_login( $user ) instanceof WP_Error, 'Saved identity block was ignored without user metadata.' );
$verified->setValue( null, 0 );
unset( $options[$state_key] );
$options['kaae_ms_settings'] = $initial;
$_POST = array( 'tenant' => $tenant, 'client' => $client, 'secret' => '', 'repository' => '', 'kaae_ms_staff_policy_present' => '1', 'approved_staff_only' => '1' );
$before = $options;
check( 'saved' !== save() && $before === $options, 'Administrator enabled approved-only mode before enrolling themself.' );
$options[$state_key] = array( 'approved' => true );
check( 'saved' === save() && $options['kaae_ms_settings']['approved_staff_only'], 'Approved/tested administrator could not enable approved-only mode.' );
unset( $_POST['kaae_ms_staff_policy_present'], $_POST['approved_staff_only'] );
check( 'saved' === save() && $options['kaae_ms_settings']['approved_staff_only'], 'An old settings tab silently disabled approved-only mode.' );
$_POST['kaae_ms_staff_policy_present'] = '1';
check( 'saved' === save() && ! $options['kaae_ms_settings']['approved_staff_only'], 'Administrator could not explicitly disable approved-only mode.' );
echo $count . " policy checks passed.\n";
