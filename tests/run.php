<?php
/** Standalone offline tests. Never bootstrap the production WordPress installation. */
if ( PHP_SAPI !== 'cli' ) {
    http_response_code( 404 );
    exit;
}
define( 'ABSPATH', __DIR__ );
require dirname( __DIR__ ) . '/includes/class-kaae-token.php';
$count = 0;
function check( bool $condition, string $message ): void {
    global $count;
    if ( ! $condition ) {
        throw new RuntimeException( $message );
    }
    ++$count;
}
function b64( string $value ): string {
    return rtrim( strtr( base64_encode( $value ), '+/', '-_' ), '=' );
}
$private = openssl_pkey_new( array( 'private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA ) );
$details = openssl_pkey_get_details( $private );
$keys = array( array( 'kid' => 'test', 'kty' => 'RSA', 'use' => 'sig', 'n' => b64( $details['rsa']['n'] ), 'e' => b64( $details['rsa']['e'] ) ) );
$tenant = '11111111-1111-1111-1111-111111111111';
$client = '22222222-2222-2222-2222-222222222222';
$claims = array( 'iss' => 'https://login.microsoftonline.com/' . $tenant . '/v2.0', 'tid' => $tenant, 'aud' => $client, 'nonce' => 'nonce', 'exp' => 2000, 'nbf' => 900, 'iat' => 900, 'oid' => '33333333-3333-3333-3333-333333333333', 'sub' => 'subject' );
function token( array $claims, $private, array $header = array( 'alg' => 'RS256', 'kid' => 'test' ) ): string {
    $input = b64( json_encode( $header ) ) . '.' . b64( json_encode( $claims ) );
    openssl_sign( $input, $signature, $private, OPENSSL_ALGO_SHA256 );
    return $input . '.' . b64( $signature );
}
$valid = token( $claims, $private );
check( KAAE_MS_Token::verify( $valid, $keys, $tenant, $client, 'nonce', 1000 ) === $claims, 'Valid RSA token rejected.' );
foreach ( array( 'iss' => 'https://evil.example', 'tid' => $client, 'aud' => 'other', 'nonce' => 'wrong', 'exp' => 1000, 'nbf' => 1061, 'iat' => 1061, 'oid' => '', 'sub' => '', 'exp-string' => '2000' ) as $field => $value ) {
    $bad = $claims;
    $bad[ 'exp-string' === $field ? 'exp' : $field ] = $value;
    $rejected = false;
    try {
        KAAE_MS_Token::verify( token( $bad, $private ), $keys, $tenant, $client, 'nonce', 1000 );
    } catch ( Throwable $e ) {
        $rejected = true;
    }
    check( $rejected, 'Accepted invalid claim: ' . $field );
}
foreach ( array( array( 'alg' => 'none', 'kid' => 'test' ), array( 'alg' => 'HS256', 'kid' => 'test' ), array( 'alg' => 'RS256', 'kid' => 'unknown' ), array( 'alg' => 'RS256', 'kid' => 'test', 'crit' => array( 'unsupported' ) ) ) as $header ) {
    $rejected = false;
    try {
        KAAE_MS_Token::verify( token( $claims, $private, $header ), $keys, $tenant, $client, 'nonce', 1000 );
    } catch ( Throwable $e ) {
        $rejected = true;
    }
    check( $rejected, 'Accepted invalid algorithm/key/header.' );
}
$parts = explode( '.', $valid );
$tampered = $claims;
$tampered['oid'] = $client;
$parts[1] = b64( json_encode( $tampered ) );
foreach ( array( implode( '.', $parts ), 'bad.token', str_repeat( 'a', 32769 ), '!!!.!!!.!!!' ) as $bad ) {
    $rejected = false;
    try {
        KAAE_MS_Token::verify( $bad, $keys, $tenant, $client, 'nonce', 1000 );
    } catch ( Throwable $e ) {
        $rejected = true;
    }
    check( $rejected, 'Accepted tampered or malformed token.' );
}

// Minimal in-memory WordPress doubles test updater decisions without DB/network.
define( 'MINUTE_IN_SECONDS', 60 );
class KAAE_MS_Login {
    public static function settings(): array { return array( 'repository' => 'example/kaae' ); }
}
function plugin_basename( $file ) { return 'kaae-microsoft-login/kaae-microsoft-login.php'; }
function add_filter( ...$args ) {}
function get_transient( $key ) { return $GLOBALS['release']; }
require dirname( __DIR__ ) . '/includes/class-kaae-updates.php';
KAAE_MS_Updates::boot( 'test' );
$file = 'kaae-microsoft-login/kaae-microsoft-login.php';
$data = array( 'UpdateURI' => 'https://github.com/kaae-microsoft-login', 'Version' => '0.1.0' );
$GLOBALS['release'] = array( 'tag_name' => 'v0.2.0', 'assets' => array( array( 'name' => 'kaae-microsoft-login.zip', 'browser_download_url' => 'https://github.com/example/kaae/releases/download/v0.2.0/kaae-microsoft-login.zip' ) ) );
check( '0.2.0' === KAAE_MS_Updates::check( false, $data, $file, array() )['version'], 'Valid release rejected.' );
check( 'unchanged' === KAAE_MS_Updates::check( 'unchanged', $data, 'other/plugin.php', array() ), 'Updater affected another plugin.' );
$saved = $GLOBALS['release'];
foreach ( array( 'draft', 'prerelease' ) as $field ) {
    $GLOBALS['release'] = $saved;
    $GLOBALS['release'][ $field ] = true;
    check( false === KAAE_MS_Updates::check( false, $data, $file, array() ), 'Unstable release accepted.' );
}
$GLOBALS['release'] = $saved;
$GLOBALS['release']['assets'][0]['browser_download_url'] = 'https://evil.example/plugin.zip';
check( false === KAAE_MS_Updates::check( false, $data, $file, array() ), 'Untrusted package accepted.' );
$GLOBALS['release'] = array( 'tag_name' => 'v0.2.0', 'assets' => array() );
check( false === KAAE_MS_Updates::check( false, $data, $file, array() ), 'Missing asset accepted.' );
echo $count . " offline checks passed.\n";
