<?php
/** Offline redirect helper/button/start tests; no WordPress bootstrap or requests. */
if ( PHP_SAPI !== 'cli' ) { http_response_code( 404 ); exit; }
define( 'ABSPATH', __DIR__ );
class RedirectCaptured extends RuntimeException {}
$count = 0;
$validator_calls = 0;
$force_empty = false;
$saved = array();
function check( bool $condition, string $message ): void { ++$GLOBALS['count']; if ( ! $condition ) { throw new RuntimeException( $message ); } }
function admin_url( $path = '' ) { return 'https://example.test/wp-admin/' . $path; }
function site_url( $path, $scheme = '' ) { return 'https://example.test/' . $path; }
function get_option( $key, $default = false ) { return array( 'tenant' => '11111111-1111-1111-1111-111111111111', 'client' => '22222222-2222-2222-2222-222222222222', 'secret' => 'offline-secret' ); }
function wp_parse_args( $args, $defaults ) { return array_merge( $defaults, $args ); }
function wp_unslash( $value ) { return $value; }
function is_ssl() { return true; }
function nocache_headers() {}
function esc_url( $value ) { return htmlspecialchars( $value, ENT_QUOTES, 'UTF-8' ); }
function wp_validate_redirect( $requested, $fallback = '' ) {
    ++$GLOBALS['validator_calls'];
    if ( $GLOBALS['force_empty'] ) { return ''; }
    $parts = parse_url( $requested );
    if ( false === $parts || ( isset( $parts['scheme'] ) && ! in_array( $parts['scheme'], array( 'http', 'https' ), true ) ) || ( isset( $parts['host'] ) && 'example.test' !== $parts['host'] ) ) { return $fallback; }
    return $requested;
}
// WordPress add_query_arg preserves newly supplied query values as encoded by callers.
// Do not use http_build_query here: it would hide missing/double URL encoding bugs.
function add_query_arg( ...$args ) {
    if ( is_array( $args[0] ) ) { $query = $args[0]; $url = $args[1]; }
    else { $query = array( $args[0] => $args[1] ); $url = $args[2]; }
    $pairs = array();
    foreach ( $query as $key => $value ) { $pairs[] = $key . '=' . $value; }
    return $url . '?' . implode( '&', $pairs );
}
function set_transient( $key, $value, $ttl ) { $GLOBALS['saved'] = array( 'key' => $key, 'value' => $value, 'ttl' => $ttl ); return true; }
function wp_redirect( $url ) { $GLOBALS['authorization_url'] = $url; throw new RedirectCaptured(); }
require dirname( __DIR__ ) . '/includes/class-kaae-login.php';
$helper = new ReflectionMethod( KAAE_MS_Login::class, 'login_destination' );
foreach ( array( null, '', '  ', array( '/reports/' ), 42 ) as $value ) {
    check( admin_url() === $helper->invoke( null, $value ), 'Missing/empty/non-string destination did not fall back.' );
}
$before = $validator_calls;
check( admin_url() === $helper->invoke( null, 'https://untrusted.test/reports/' ) && $validator_calls === $before + 1, 'Unsafe URL did not delegate to WordPress validation.' );
$reports = 'https://example.test/reports/?status=open&team=Finance%20%26%20Admin&search=A%2BB&page=2#results';
check( $reports === $helper->invoke( null, $reports ), 'Report filters or fragment changed.' );
check( '/reports/?status=open&team=Finance' === $helper->invoke( null, '/reports/?status=open&team=Finance' ), 'Relative destination changed.' );
$force_empty = true;
check( admin_url() === $helper->invoke( null, $reports ), 'An empty WordPress validation result did not fall back.' );
$force_empty = false;
$_REQUEST = array( 'redirect_to' => $reports );
ob_start(); KAAE_MS_Login::login_button(); $html = ob_get_clean();
preg_match( '/href="([^"]+)"/', $html, $match );
$button_url = html_entity_decode( $match[1], ENT_QUOTES, 'UTF-8' );
parse_str( parse_url( $button_url, PHP_URL_QUERY ), $query );
check( 'kaae_ms_start' === $query['action'] && $reports === $query['redirect_to'] && str_contains( $button_url, 'redirect_to=' . rawurlencode( $reports ) ), 'Button dropped or incorrectly encoded the destination/filters.' );
// Simulate the browser following the local start link, decoding its query once.
$_REQUEST = $query;
try { KAAE_MS_Login::start_login(); } catch ( RedirectCaptured $error ) {}
parse_str( parse_url( $authorization_url, PHP_URL_QUERY ), $authorization );
check( $reports === $saved['value']['redirect_to'] && 600 === $saved['ttl']
    && $saved['key'] === 'kaae_ms_' . hash( 'sha256', $authorization['state'] )
    && strlen( $saved['value']['browser'] ) === 64
    && 'https://example.test/wp-login.php?action=kaae_ms_callback' === $authorization['redirect_uri']
    && 'S256' === $authorization['code_challenge_method']
    && rtrim( strtr( base64_encode( hash( 'sha256', $saved['value']['verifier'], true ) ), '+/', '-_' ), '=' ) === $authorization['code_challenge'], 'Start lost the destination, browser binding, TTL, callback URI or PKCE.' );
$_REQUEST = array( 'redirect_to' => 'https://untrusted.test/reports/' );
try { KAAE_MS_Login::start_login(); } catch ( RedirectCaptured $error ) {}
check( admin_url() === $saved['value']['redirect_to'], 'Start stored an unsafe destination.' );
echo $count . " redirect helper/button/start regression cases passed.\n";
