<?php
/** Offline update-check UI and permission tests; no WordPress/network/database. */
if ( PHP_SAPI !== 'cli' ) { http_response_code( 404 ); exit; }
define( 'ABSPATH', __DIR__ );
define( 'MINUTE_IN_SECONDS', 60 );
define( 'DAY_IN_SECONDS', 86400 );
class WP_Error {}
class UpdateStop extends RuntimeException {}
class KAAE_MS_Login { public static function settings(): array { return array( 'repository' => '' ); } }
$cache = array();
$allowed = true;
$nonce = true;
$checks = 0;
$count = 0;
$calls = 0;
$response = array( 'status' => 404, 'body' => '{}' );
$data = array( 'UpdateURI' => 'https://github.com/akamomer/kaae-microsoft-login', 'Version' => '0.4.1' );
$file = 'kaae-microsoft-login/kaae-microsoft-login.php';
function check( $condition, $message ) { ++$GLOBALS['count']; if ( ! $condition ) { throw new RuntimeException( $message ); } }
function add_action( ...$args ) {}
function add_filter( ...$args ) {}
function plugin_basename( $path ) { return $GLOBALS['file']; }
function get_transient( $key ) { return $GLOBALS['cache'][ $key ] ?? false; }
function set_transient( $key, $value, $ttl ) { $GLOBALS['cache'][ $key ] = $value; }
function delete_transient( $key ) { unset( $GLOBALS['cache'][ $key ] ); }
function delete_site_transient( $key ) { $GLOBALS['cleared_site_cache'] = $key; }
function current_user_can( $cap ) { return $GLOBALS['allowed']; }
function check_admin_referer( $action ) { if ( ! $GLOBALS['nonce'] ) { throw new UpdateStop( 'nonce' ); } }
function wp_die( ...$args ) { throw new UpdateStop( 'permission' ); }
function wp_safe_redirect( $url ) { throw new UpdateStop( 'redirect' ); }
function wp_update_plugins() {
    ++$GLOBALS['checks'];
    check( false === get_transient( 'kaae_ms_release' ) && false === get_transient( 'kaae_ms_update_status' ), 'Check reused stale GitHub cache.' );
    KAAE_MS_Updates::check( false, $GLOBALS['data'], $GLOBALS['file'], array() );
}
function wp_remote_get( $url, $args ) {
    ++$GLOBALS['calls'];
    check( 'https://api.github.com/repos/akamomer/kaae-microsoft-login/releases/latest' === $url, 'Official default repository was not used.' );
    check( 0 === $args['redirection'], 'Update API followed redirects.' );
    return $GLOBALS['response'];
}
function is_wp_error( $response ) { return $response instanceof WP_Error; }
function wp_remote_retrieve_response_code( $response ) { return $response['status']; }
function wp_remote_retrieve_body( $response ) { return $response['body']; }
function admin_url( $path ) { return 'https://example.test/wp-admin/' . $path; }
function self_admin_url( $path ) { return admin_url( $path ); }
function wp_nonce_url( $url, $action ) { return $url . '&_wpnonce=offline'; }
function wp_nonce_field( $action ) { echo '<input name="_wpnonce" value="offline">'; }
function esc_html( $value ) { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
function esc_attr( $value ) { return esc_html( $value ); }
function esc_url( $value ) { return esc_html( $value ); }
function wp_date( $format, $time ) { return gmdate( $format, $time ); }
function get_file_data( $path, $headers ) { return array( 'Version' => '0.4.1' ); }
function render(): string { ob_start(); KAAE_MS_Updates::render(); return ob_get_clean(); }
require dirname( __DIR__ ) . '/includes/class-kaae-updates.php';
KAAE_MS_Updates::boot( 'offline' );
check( str_contains( render(), 'Check for updates' ), 'Update button missing.' );
check( 0 === $calls, 'Rendering caused a remote request.' );
KAAE_MS_Updates::check( false, $data, $file, array() );
check( 'none' === $cache['kaae_ms_update_status']['code'] && str_contains( render(), 'No published release' ), 'Missing release reported as up to date.' );
$response = new WP_Error();
KAAE_MS_Updates::check( false, $data, $file, array() );
check( 'unavailable' === $cache['kaae_ms_update_status']['code'], 'Network failure hidden.' );
$response = array( 'status' => 403, 'body' => '{}' );
KAAE_MS_Updates::check( false, $data, $file, array() );
check( 'unavailable' === $cache['kaae_ms_update_status']['code'], 'Permission/rate-limit error reported as current.' );
$response = array( 'status' => 200, 'body' => '{malformed' );
KAAE_MS_Updates::check( false, $data, $file, array() );
check( 'invalid' === $cache['kaae_ms_update_status']['code'], 'Malformed release accepted.' );
$cache = array();
$release = array( 'tag_name' => 'v0.4.2', 'assets' => array( array( 'name' => 'kaae-microsoft-login.zip', 'browser_download_url' => 'https://github.com/akamomer/kaae-microsoft-login/releases/download/v0.4.2/kaae-microsoft-login.zip' ) ) );
$response = array( 'status' => 200, 'body' => json_encode( $release ) );
$update = KAAE_MS_Updates::check( false, $data, $file, array() );
check( '0.4.2' === $update['version'], 'Valid published update rejected.' );
check( str_contains( render(), 'Version 0.4.2 is available' ) && str_contains( render(), 'Open WordPress Updates' ), 'Available update has no installation route.' );
$cache['kaae_ms_release']['tag_name'] = 'v0.4.1';
$cache['kaae_ms_release']['assets'][0]['browser_download_url'] = 'https://github.com/akamomer/kaae-microsoft-login/releases/download/v0.4.1/kaae-microsoft-login.zip';
KAAE_MS_Updates::check( false, $data, $file, array() );
check( str_contains( render(), 'Your plugin is up to date.' ), 'Current version was not recognized.' );
try { KAAE_MS_Updates::check_now(); } catch ( UpdateStop $e ) { check( 'redirect' === $e->getMessage(), 'Manual check did not redirect.' ); }
check( 1 === $checks && 'update_plugins' === $GLOBALS['cleared_site_cache'], 'Manual check did not refresh WordPress.' );
$allowed = false;
try { KAAE_MS_Updates::check_now(); } catch ( UpdateStop $e ) { check( 'permission' === $e->getMessage(), 'Update permissions not checked.' ); }
check( 1 === $checks && '' === render(), 'Unauthorized user ran/saw the update control.' );
$allowed = true;
$nonce = false;
try { KAAE_MS_Updates::check_now(); } catch ( UpdateStop $e ) { check( 'nonce' === $e->getMessage(), 'Update nonce not checked.' ); }
check( 1 === $checks, 'Invalid nonce triggered a check.' );
check( str_contains( implode( '', KAAE_MS_Updates::action_links( array() ) ), 'Check for updates' ), 'Installed Plugins link missing.' );
echo $count . " offline update-control checks passed.\n";
