<?php
defined( 'ABSPATH' ) || exit;

/** Public GitHub releases integrate with WordPress's normal update controls. */
final class KAAE_MS_Updates {
    private static string $plugin;

    public static function boot( string $file ): void {
        self::$plugin = plugin_basename( $file );
        add_filter( 'update_plugins_github.com', array( self::class, 'check' ), 10, 4 );
        add_action( 'admin_post_kaae_ms_check_updates', array( self::class, 'check_now' ) );
        add_filter( 'plugin_action_links_' . self::$plugin, array( self::class, 'action_links' ) );
        // Run before WordPress's priority-10 plugin update check on this screen.
        add_action( 'load-update-core.php', array( self::class, 'refresh_dashboard_check' ), 1 );
    }

    private static function repository(): string {
        return KAAE_MS_Login::settings()['repository'] ?: 'akamomer/kaae-microsoft-login';
    }

    private static function status( string $code, string $version = '' ): void {
        set_transient( 'kaae_ms_update_status', array( 'code' => $code, 'version' => $version, 'checked_at' => time() ), DAY_IN_SECONDS );
    }

    public static function action_links( array $links ): array {
        array_unshift( $links, '<a href="' . esc_url( admin_url( 'options-general.php?page=kaae-ms' ) ) . '">Settings</a>' );
        if ( current_user_can( 'manage_options' ) && current_user_can( 'update_plugins' ) ) {
            $links[] = '<a href="' . esc_url( wp_nonce_url( admin_url( 'admin-post.php?action=kaae_ms_check_updates' ), 'kaae_ms_check_updates' ) ) . '">Check for updates</a>';
        }
        return $links;
    }

    public static function check_now(): void {
        if ( ! current_user_can( 'manage_options' ) || ! current_user_can( 'update_plugins' ) ) {
            wp_die( 'You do not have permission to check plugin updates.', 'KAAE Microsoft Login', array( 'response' => 403 ) );
            return;
        }
        check_admin_referer( 'kaae_ms_check_updates' );
        delete_transient( 'kaae_ms_release' );
        delete_transient( 'kaae_ms_update_status' );
        delete_site_transient( 'update_plugins' );
        wp_update_plugins(); // Checks only; installation uses WordPress's normal UI.
        wp_safe_redirect( admin_url( 'options-general.php?page=kaae-ms#kaae-ms-updates' ) );
        exit;
    }

    public static function refresh_dashboard_check(): void {
        if ( empty( $_GET['force-check'] ) || ! current_user_can( 'update_plugins' ) ) {
            return;
        }
        // Dashboard → Updates → Check again must bypass both independent caches.
        delete_transient( 'kaae_ms_release' );
        delete_transient( 'kaae_ms_update_status' );
        delete_site_transient( 'update_plugins' );
    }

    public static function render(): void {
        if ( ! current_user_can( 'manage_options' ) || ! current_user_can( 'update_plugins' ) ) {
            return;
        }
        $headers = get_file_data( dirname( __DIR__ ) . '/kaae-microsoft-login.php', array( 'Version' => 'Version' ) );
        $installed = $headers['Version'];
        $status = get_transient( 'kaae_ms_update_status' );
        echo '<section id="kaae-ms-updates" class="postbox" style="max-width:960px;padding:16px 24px;margin-top:20px;box-sizing:border-box"><h2 style="margin-top:0">Plugin updates</h2>';
        echo '<p>Installed version: <strong>' . esc_html( $installed ) . '</strong></p>';
        $message = 'Check whether a newer version is available.';
        $available = false;
        if ( is_array( $status ) ) {
            switch ( $status['code'] ?? '' ) {
                case 'ready':
                    $available = version_compare( $status['version'], $installed, '>' );
                    $message = $available ? 'Version ' . $status['version'] . ' is available. Install it through WordPress Updates.' : 'Your plugin is up to date.';
                    break;
                case 'none':
                    $message = 'No published release is available on GitHub yet. There is currently no update for WordPress to install.';
                    break;
                case 'unavailable':
                    $message = 'Could not reach GitHub or GitHub rejected the request. Please try again later.';
                    break;
                case 'invalid':
                    $message = 'The GitHub release does not contain a supported version and installable plugin ZIP. Contact the plugin maintainer.';
                    break;
            }
        }
        echo '<p role="status">' . esc_html( $message ) . '</p>';
        if ( ! empty( $status['checked_at'] ) ) {
            echo '<p class="description">Last checked: ' . esc_html( wp_date( 'M j, Y H:i', $status['checked_at'] ) ) . '</p>';
        }
        echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="kaae_ms_check_updates">';
        wp_nonce_field( 'kaae_ms_check_updates' );
        echo '<p><button type="submit" class="button button-secondary">Check for updates</button> ';
        if ( $available ) {
            echo '<a class="button button-primary" href="' . esc_url( self_admin_url( 'update-core.php' ) ) . '">Open WordPress Updates</a>';
        }
        echo '</p></form><p class="description">For automatic installation, enable auto-updates for KAAE Microsoft Login on the Installed Plugins page.</p></section>';
    }

    public static function check( $update, array $data, string $file, array $locales ) {
        if ( $file !== self::$plugin ) {
            return $update;
        }
        $repo = self::repository();
        if ( ! preg_match( '/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/D', $repo ) ) {
            self::status( 'invalid' );
            return false;
        }
        $release = get_transient( 'kaae_ms_release' );
        if ( false === $release ) {
            $response = wp_remote_get( 'https://api.github.com/repos/' . $repo . '/releases/latest', array( 'timeout' => 10, 'redirection' => 0, 'limit_response_size' => 262144, 'headers' => array( 'Accept' => 'application/vnd.github+json' ) ) );
            $release = array();
            if ( is_wp_error( $response ) ) {
                self::status( 'unavailable' );
                return false;
            }
            $code = wp_remote_retrieve_response_code( $response );
            if ( 200 !== $code ) {
                self::status( 404 === $code ? 'none' : 'unavailable' );
                return false;
            }
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
            self::status( 'invalid' );
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
            self::status( 'invalid' );
            return false;
        }
        self::status( 'ready', $version );
        return array( 'id' => $data['UpdateURI'], 'slug' => 'kaae-microsoft-login', 'version' => $version, 'url' => 'https://github.com/' . $repo, 'package' => $package, 'requires' => '6.0', 'requires_php' => '8.1' );
    }
}
