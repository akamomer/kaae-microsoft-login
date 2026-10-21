<?php
defined( 'ABSPATH' ) || exit;

/** Public GitHub releases integrate with WordPress's normal update controls. */
final class KAAE_MS_Updates {
    private static string $plugin;

    public static function boot( string $file ): void {
        self::$plugin = plugin_basename( $file );
        add_filter( 'update_plugins_github.com', array( self::class, 'check' ), 10, 4 );
    }

    public static function check( $update, array $data, string $file, array $locales ) {
        if ( $file !== self::$plugin ) {
            return $update;
        }
        $repo = KAAE_MS_Login::settings()['repository'];
        if ( ! preg_match( '/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/D', $repo ) ) {
            return false;
        }
        $release = get_transient( 'kaae_ms_release' );
        if ( false === $release ) {
            $response = wp_remote_get( 'https://api.github.com/repos/' . $repo . '/releases/latest', array( 'timeout' => 10, 'redirection' => 0, 'limit_response_size' => 262144, 'headers' => array( 'Accept' => 'application/vnd.github+json' ) ) );
            $release = array();
            if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {
                $decoded = json_decode( wp_remote_retrieve_body( $response ), true );
                if ( is_array( $decoded ) ) {
                    $release = $decoded;
                }
            }
            set_transient( 'kaae_ms_release', $release, 15 * MINUTE_IN_SECONDS );
        }
        $version = ltrim( $release['tag_name'] ?? '', 'v' );
        if ( ! preg_match( '/^\d+\.\d+\.\d+$/D', $version ) || ! empty( $release['draft'] ) || ! empty( $release['prerelease'] ) ) {
            return false;
        }
        $package = '';
        foreach ( $release['assets'] ?? array() as $asset ) {
            $url = $asset['browser_download_url'] ?? '';
            $expected = 'https://github.com/' . $repo . '/releases/download/' . rawurlencode( $release['tag_name'] ) . '/kaae-microsoft-login.zip';
            if ( 'kaae-microsoft-login.zip' === ( $asset['name'] ?? '' ) && $url === $expected ) {
                $package = $url;
                break;
            }
        }
        if ( '' === $package ) {
            return false;
        }
        return array( 'id' => $data['UpdateURI'], 'slug' => 'kaae-microsoft-login', 'version' => $version, 'url' => 'https://github.com/' . $repo, 'package' => $package, 'requires' => '6.0', 'requires_php' => '8.1' );
    }
}
