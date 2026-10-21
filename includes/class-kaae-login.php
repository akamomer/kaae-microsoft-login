<?php
defined( 'ABSPATH' ) || exit;
require_once __DIR__ . '/class-kaae-accounts.php';

final class KAAE_MS_Login {
    private const OPTION = 'kaae_ms_settings';
    private const META = '_kaae_ms_identity';
    private const VERIFIED = '_kaae_ms_verified_login';
    private static int $verified_user = 0;

    public static function boot(): void {
        add_action( 'admin_menu', static function () {
            add_options_page( 'KAAE Microsoft Login', 'KAAE Microsoft Login', 'manage_options', 'kaae-ms', array( self::class, 'settings_page' ) );
        } );
        add_action( 'admin_post_kaae_ms_settings', array( self::class, 'save_settings' ) );
        add_action( 'admin_post_kaae_ms_connect', array( self::class, 'connect' ) );
        add_action( 'admin_post_kaae_ms_disconnect', array( self::class, 'disconnect' ) );
        add_action( 'show_user_profile', array( self::class, 'profile' ) );
        add_action( 'personal_options_update', array( self::class, 'save_personal_policy' ) );
        add_action( 'login_form_kaae_ms_start', array( self::class, 'start_login' ) );
        add_action( 'login_form_kaae_ms_callback', array( self::class, 'callback' ) );
        add_action( 'login_form', array( self::class, 'login_button' ) );
        add_filter( 'authenticate', array( self::class, 'enforce_login' ), PHP_INT_MAX, 3 );
        add_filter( 'wp_is_application_passwords_available_for_user', array( self::class, 'application_passwords' ), PHP_INT_MAX, 2 );
        add_filter( 'allow_password_reset', array( self::class, 'allow_password_reset' ), PHP_INT_MAX, 2 );
        add_action( 'login_form_login', array( self::class, 'exclusive_screen' ) );
        foreach ( array( 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'register' ) as $action ) {
            add_action( 'login_form_' . $action, array( self::class, 'exclusive_account_action' ) );
        }
    }

    public static function settings(): array {
        $settings = (array) get_option( self::OPTION, array() );
        foreach ( array( 'tenant', 'client', 'secret' ) as $name ) {
            $constant = 'KAAE_MS_' . strtoupper( $name );
            if ( defined( $constant ) ) {
                $settings[ $name ] = constant( $constant );
            }
        }
        return wp_parse_args( $settings, array( 'tenant' => '', 'client' => '', 'secret' => '', 'repository' => '', 'microsoft_only' => false, 'automatic_accounts' => false, 'password_exception_user' => 0 ) );
    }

    public static function microsoft_only(): bool {
        // Server access is required for emergency recovery; no URL/password bypass.
        return ! ( defined( 'KAAE_MS_PASSWORD_RECOVERY' ) && true === KAAE_MS_PASSWORD_RECOVERY )
            && ! empty( self::settings()['microsoft_only'] );
    }

    public static function enforce_login( $user, $username = '', $password = '' ) {
        if ( $user instanceof WP_User && self::$verified_user === $user->ID ) {
            return $user;
        }
        if ( ( $user instanceof WP_User && self::password_blocked( $user ) ) || ( ! $user instanceof WP_User && self::microsoft_only() ) ) {
            return new WP_Error( 'kaae_ms_required', 'Sign in with your connected KAAE Microsoft account. WordPress password login is disabled.' );
        }
        return $user;
    }

    public static function password_blocked( WP_User $user ): bool {
        if ( defined( 'KAAE_MS_PASSWORD_RECOVERY' ) && true === KAAE_MS_PASSWORD_RECOVERY ) {
            return false;
        }
        if ( get_user_meta( $user->ID, KAAE_MS_Accounts::PASSWORD_DISABLED, true ) ) {
            return true;
        }
        if ( ! self::microsoft_only() ) {
            return false;
        }
        return (int) self::settings()['password_exception_user'] !== $user->ID || KAAE_MS_Accounts::kaae_email( $user->user_email );
    }

    public static function application_passwords( bool $available, $user = null ): bool {
        // The external exception is for interactive password login, not API passwords.
        return self::microsoft_only() || ( $user instanceof WP_User && self::password_blocked( $user ) ) ? false : $available;
    }

    public static function allow_password_reset( $allowed, int $user_id ) {
        $user = get_userdata( $user_id );
        return $user && self::password_blocked( $user ) ? false : $allowed;
    }

    public static function exclusive_screen(): void {
        if ( ! self::microsoft_only() || self::has_password_exception() ) {
            return;
        }
        nocache_headers();
        login_header( 'KAAE Microsoft sign-in', '<p class="message">Sign in with your connected KAAE Microsoft work account.</p>' );
        if ( self::ready() ) {
            echo '<div style="padding:24px;background:white">';
            self::login_button();
            echo '</div>';
        } else {
            echo '<p class="message">Microsoft sign-in is unavailable. Contact your site administrator.</p>';
        }
        login_footer();
        exit;
    }

    public static function exclusive_account_action(): void {
        if ( self::microsoft_only() && ( ! self::has_password_exception() || 'register' === ( $_REQUEST['action'] ?? '' ) ) ) {
            self::fail( 'This site uses Microsoft sign-in. Manage your password through your organization’s Microsoft account or contact your administrator.' );
        }
    }

    private static function has_password_exception(): bool {
        $user = get_userdata( (int) self::settings()['password_exception_user'] );
        return $user instanceof WP_User && ! self::password_blocked( $user );
    }

    public static function save_personal_policy( int $user_id ): void {
        if ( ! isset( $_POST['kaae_ms_policy_present'] ) ) {
            return;
        }
        if ( get_current_user_id() !== $user_id ) {
            self::fail( 'You can change only your own password sign-in preference.' );
        }
        check_admin_referer( 'kaae_ms_personal_policy', 'kaae_ms_policy_nonce' );
        $disable = isset( $_POST['kaae_ms_disable_password'] );
        if ( $disable && ! self::can_disable_password( $user_id ) ) {
            self::fail( 'Connect Microsoft and complete a Microsoft sign-in with the current configuration before disabling your password login.' );
        }
        if ( $disable ) {
            update_user_meta( $user_id, KAAE_MS_Accounts::PASSWORD_DISABLED, 1 );
        } else {
            delete_user_meta( $user_id, KAAE_MS_Accounts::PASSWORD_DISABLED );
        }
    }

    private static function can_disable_password( int $user_id ): bool {
        $identity = (string) get_user_meta( $user_id, self::META, true );
        $settings = self::settings();
        return '' !== $identity && str_starts_with( $identity, $settings['tenant'] . ':' )
            && (string) get_user_meta( $user_id, self::VERIFIED, true ) === self::verification_stamp( $settings, $identity );
    }

    private static function ready(): bool {
        $s = self::settings();
        return is_ssl() && extension_loaded( 'openssl' ) && self::guid( $s['tenant'] ) && self::guid( $s['client'] ) && '' !== $s['secret'];
    }

    private static function guid( string $value ): bool {
        return 1 === preg_match( '/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/Di', $value );
    }

    public static function callback_url(): string {
        return add_query_arg( 'action', 'kaae_ms_callback', site_url( 'wp-login.php', 'https' ) );
    }

    private static function fail( string $message ): void {
        wp_die( esc_html( $message ), 'KAAE Microsoft Login', array( 'response' => 403, 'back_link' => true ) );
        exit;
    }

    public static function settings_page(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        $s = self::settings();
        echo '<div class="wrap"><h1>KAAE Microsoft Login</h1><p>Manage Microsoft staff sign-in, automatic Subscriber accounts, and the external user’s password exception.</p>';
        require_once __DIR__ . '/class-kaae-setup-guide.php';
        KAAE_MS_Setup_Guide::render( self::callback_url(), admin_url( 'profile.php' ) );
        echo '<h2>Configuration</h2><p>Complete the Microsoft steps above, then enter the three Microsoft values here.</p>';
        echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="kaae_ms_settings">';
        wp_nonce_field( 'kaae_ms_settings' );
        foreach ( array( 'tenant' => 'Microsoft tenant ID', 'client' => 'Application client ID', 'secret' => 'Client secret', 'repository' => 'Public GitHub repository (owner/repository)' ) as $name => $label ) {
            $locked = defined( 'KAAE_MS_' . strtoupper( $name ) );
            if ( 'repository' === $name ) {
                echo '<h3>GitHub updates (optional)</h3><p>You can leave this blank while configuring Microsoft sign-in.</p>';
            }
            echo '<p><label for="kaae-ms-' . esc_attr( $name ) . '">' . esc_html( $label ) . '</label><br><input id="kaae-ms-' . esc_attr( $name ) . '" class="regular-text" name="' . esc_attr( $name ) . '" type="' . ( 'secret' === $name ? 'password' : 'text' ) . '" value="' . esc_attr( 'secret' === $name ? '' : $s[ $name ] ) . '" autocomplete="off" ' . ( $locked ? 'disabled' : '' ) . '></p>';
            if ( $locked ) {
                echo '<p class="description">Managed in server configuration.</p>';
            } elseif ( 'secret' === $name ) {
                echo '<p class="description">' . ( '' !== $s['secret'] ? 'A client secret is saved. Leave blank to keep it, or enter a new secret Value to replace it.' : 'No client secret is saved. Paste the Value from Microsoft, not the Secret ID.' ) . '</p>';
            }
        }
        echo '<p>Leave the secret blank to keep its current value. Secrets defined in server configuration take precedence. Updates use a public repository with a versioned release ZIP named <code>kaae-microsoft-login.zip</code>.</p>';
        echo '<h3>Automatic KAAE staff accounts</h3><p><label><input type="checkbox" name="automatic_accounts" value="1" ' . checked( ! empty( $s['automatic_accounts'] ), true, false ) . '> Automatically connect existing KAAE users and create new staff as Subscribers</label></p>';
        echo '<p>Microsoft directory members with a verified directory sign-in address ending in @kaae.org can sign in directly. An existing WordPress user with that exact email keeps their role. A new user gets Subscriber only and has password sign-in disabled. An existing connection to a different Microsoft identity is never replaced automatically. Your Microsoft tenant administrators must control staff sign-in addresses and address reassignment.</p>';
        echo '<p>Before enabling, add <strong>Microsoft Graph → Delegated permissions → User.Read</strong> under the app’s API permissions and obtain consent according to KAAE policy. This reads only the signed-in user’s directory identity, membership type, and sign-in address. No mail or directory-wide permission is needed. <a href="https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0" target="_blank" rel="noopener noreferrer">Microsoft documentation</a>.</p>';
        $exception = get_userdata( (int) $s['password_exception_user'] );
        echo '<h3>External user password exception</h3><p><label for="kaae-ms-exception">Email of the existing external WordPress user</label><br><input id="kaae-ms-exception" type="email" class="regular-text" name="password_exception_email" value="' . esc_attr( $exception ? $exception->user_email : '' ) . '" placeholder="External user’s email"></p>';
        echo '<p>Only this selected account may keep normal password login when Microsoft-only mode is enabled. The email must belong to an existing non-KAAE WordPress user. This does not create an account or change their role. Leave blank for no exception. Application passwords remain disabled in Microsoft-only mode.</p>';
        echo '<h3>Sign-in policy — enable after testing</h3><p><label><input type="checkbox" name="microsoft_only" value="1" ' . checked( ! empty( $s['microsoft_only'] ), true, false ) . '> Require Microsoft sign-in for all users</label></p>';
        echo '<p>Applies to everyone except the selected external password account. Test your administrator’s Microsoft login first. Connect staff beforehand, or configure automatic KAAE accounts. Existing sessions remain signed in. With an external exception, the normal login form remains visible; password attempts by other users are still rejected. Without an exception, the login screen shows Microsoft only. Disconnecting is blocked while Microsoft-only mode or a personal password restriction applies.</p>';
        echo '<p>Emergency recovery requires server access: temporarily define <code>KAAE_MS_PASSWORD_RECOVERY</code> as <code>true</code> in protected WordPress configuration, or deactivate this plugin. No recovery URL is provided.</p>';
        if ( defined( 'KAAE_MS_PASSWORD_RECOVERY' ) && true === KAAE_MS_PASSWORD_RECOVERY ) {
            echo '<p><strong>Server-side password recovery override is active. Microsoft-only mode is not being enforced.</strong></p>';
        }
        submit_button();
        echo '</form></div>';
    }

    public static function save_settings(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            self::fail( 'Administrator access required.' );
        }
        check_admin_referer( 'kaae_ms_settings' );
        $old = (array) get_option( self::OPTION, array() );
        $s = array();
        foreach ( array( 'tenant', 'client', 'repository' ) as $key ) {
            $s[ $key ] = sanitize_text_field( wp_unslash( $_POST[ $key ] ?? '' ) );
        }
        foreach ( array( 'tenant', 'client' ) as $key ) {
            $s[ $key ] = strtolower( $s[ $key ] );
            if ( ! defined( 'KAAE_MS_' . strtoupper( $key ) ) && '' !== $s[ $key ] && ! self::guid( $s[ $key ] ) ) {
                self::fail( 'Tenant and application IDs must be valid GUIDs.' );
            }
        }
        if ( '' !== $s['repository'] && ! preg_match( '/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/D', $s['repository'] ) ) {
            self::fail( 'Use owner/repository for the GitHub repository.' );
        }
        $secret = trim( (string) wp_unslash( $_POST['secret'] ?? '' ) );
        $s['secret'] = '' !== $secret ? $secret : ( $old['secret'] ?? '' );
        $s['microsoft_only'] = isset( $_POST['microsoft_only'] ) && '1' === $_POST['microsoft_only'];
        $s['automatic_accounts'] = isset( $_POST['automatic_accounts'] ) && '1' === $_POST['automatic_accounts'];
        if ( $s['automatic_accounts'] && is_multisite() ) {
            self::fail( 'Automatic staff accounts currently support separate WordPress installations, not multisite.' );
        }
        $exception_email = trim( (string) wp_unslash( $_POST['password_exception_email'] ?? '' ) );
        $s['password_exception_user'] = 0;
        if ( '' !== $exception_email ) {
            if ( ! is_email( $exception_email ) || KAAE_MS_Accounts::kaae_email( $exception_email ) ) {
                self::fail( 'The password exception must be an existing external user’s email, outside @kaae.org. No settings were saved.' );
            }
            $users = get_users( array( 'search' => $exception_email, 'search_columns' => array( 'user_email' ), 'number' => 2 ) );
            if ( count( $users ) !== 1 || strtolower( $users[0]->user_email ) !== strtolower( $exception_email ) || ! is_user_member_of_blog( $users[0]->ID ) ) {
                self::fail( 'The external email must identify exactly one existing user of this site. No settings were saved.' );
            }
            if ( get_user_meta( $users[0]->ID, KAAE_MS_Accounts::PASSWORD_DISABLED, true ) ) {
                self::fail( 'This user has personally disabled password login. They must remove that preference before being selected as the external password exception.' );
            }
            $s['password_exception_user'] = $users[0]->ID;
        }
        if ( $s['microsoft_only'] ) {
            $effective = $s;
            foreach ( array( 'tenant', 'client', 'secret' ) as $name ) {
                if ( defined( 'KAAE_MS_' . strtoupper( $name ) ) ) {
                    $effective[ $name ] = constant( 'KAAE_MS_' . strtoupper( $name ) );
                }
            }
            $identity = (string) get_user_meta( get_current_user_id(), self::META, true );
            $verified = (string) get_user_meta( get_current_user_id(), self::VERIFIED, true );
            if ( ! is_ssl() || ! extension_loaded( 'openssl' ) || ! self::guid( $effective['tenant'] ) || ! self::guid( $effective['client'] ) || '' === $effective['secret']
                || ! str_starts_with( $identity, $effective['tenant'] . ':' ) || $verified !== self::verification_stamp( $effective, $identity ) ) {
                self::fail( 'Before requiring Microsoft sign-in, save valid configuration, connect your administrator account, then complete a Microsoft sign-in using that configuration. No settings were saved.' );
            }
            // Changing credentials at the same time would make a previous test obsolete.
            $current = self::settings();
            foreach ( array( 'tenant', 'client', 'secret' ) as $name ) {
                if ( $effective[ $name ] !== $current[ $name ] ) {
                    self::fail( 'Save configuration changes with Microsoft-only mode disabled, test Microsoft sign-in, then enable it in a separate step. No settings were saved.' );
                }
            }
        }
        update_option( self::OPTION, $s, false );
        delete_transient( 'kaae_ms_release' );
        wp_safe_redirect( admin_url( 'options-general.php?page=kaae-ms' ) );
        exit;
    }

    public static function profile( WP_User $user ): void {
        if ( get_current_user_id() !== $user->ID ) {
            return;
        }
        self::button_styles();
        $linked = (bool) get_user_meta( $user->ID, self::META, true );
        echo '<section class="kaae-ms-account" aria-labelledby="kaae-ms-account-title"><h2 id="kaae-ms-account-title">' . self::microsoft_logo() . 'KAAE Microsoft account</h2>';
        if ( $linked ) {
            echo '<p><span class="kaae-ms-status"><svg width="14" height="14" viewBox="0 0 16 16" aria-hidden="true" focusable="false"><path d="m3 8 3 3 7-7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>Microsoft account connected</span></p>';
            $personal = (bool) get_user_meta( $user->ID, KAAE_MS_Accounts::PASSWORD_DISABLED, true );
            if ( $personal || self::can_disable_password( $user->ID ) ) {
                wp_nonce_field( 'kaae_ms_personal_policy', 'kaae_ms_policy_nonce' );
                echo '<input type="hidden" name="kaae_ms_policy_present" value="1"><p><label><input type="checkbox" name="kaae_ms_disable_password" value="1" ' . checked( $personal, true, false ) . '> Disable password sign-in for my account</label></p><p>Save with <strong>Update Profile</strong>. This also disables your application passwords. Removing this preference cannot override a site-wide Microsoft-only rule.</p>';
            } else {
                echo '<p>Complete a Microsoft sign-in once to unlock your personal password-disable option.</p>';
            }
        }
        if ( $linked && self::password_blocked( $user ) ) {
            echo '<p>Microsoft sign-in is required for your account. Disconnecting is disabled while your password sign-in is blocked.</p></section>';
            return;
        }
        $action = $linked ? 'kaae_ms_disconnect' : 'kaae_ms_connect';
        // A separate form cannot be nested inside WordPress's profile form.
        $url = wp_nonce_url( add_query_arg( 'action', $action, admin_url( 'admin-post.php' ) ), $action );
        echo '<p>' . ( $linked ? 'Use your connected Microsoft work account to sign in to this site.' : 'Connect your own @kaae.org Microsoft work account to enable Microsoft sign-in.' ) . '</p>';
        if ( $linked || self::ready() ) {
            echo '<p class="kaae-ms-account-actions"><a class="kaae-ms-button' . ( $linked ? ' kaae-ms-button-disconnect' : '' ) . '" href="' . esc_url( $url ) . '">' . self::microsoft_logo() . '<span>' . ( $linked ? 'Disconnect Microsoft account' : 'Connect Microsoft account' ) . '</span></a></p>';
        } else {
            echo '<p>An administrator must configure Microsoft sign-in first.</p>';
        }
        echo '</section>';
    }

    private static function microsoft_logo(): string {
        return '<svg class="kaae-ms-logo" width="21" height="21" viewBox="0 0 21 21" aria-hidden="true" focusable="false"><path fill="#f25022" d="M0 0h10v10H0z"/><path fill="#7fba00" d="M11 0h10v10H11z"/><path fill="#00a4ef" d="M0 11h10v10H0z"/><path fill="#ffb900" d="M11 11h10v10H11z"/></svg>';
    }

    private static function button_styles(): void {
        static $printed = false;
        if ( $printed ) {
            return;
        }
        $printed = true;
        ?>
        <style>
            .kaae-ms-account{box-sizing:border-box;max-width:680px;margin:24px 0;padding:22px 24px;background:#fff;border:1px solid #dcdcde;border-radius:10px;box-shadow:0 2px 5px rgba(0,0,0,.035)}
            .kaae-ms-account h2{display:flex;align-items:center;gap:12px;margin:0 0 14px;padding:0;font-size:18px;line-height:1.4}
            .kaae-ms-account p{margin:12px 0;color:#50575e;line-height:1.65}
            .kaae-ms-logo{display:block;flex:0 0 21px}
            .kaae-ms-account .kaae-ms-status{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border:1px solid #b8d9c6;border-radius:20px;background:#edf7f0;color:#186138;font-size:12px;font-weight:600;line-height:1.5}
            .kaae-ms-account .kaae-ms-account-actions{margin:18px 0 0}
            a.kaae-ms-button{box-sizing:border-box;display:inline-flex;align-items:center;justify-content:center;gap:12px;min-height:42px;max-width:100%;padding:10px 16px;border:1px solid #8c8c8c;border-radius:4px;background:#fff;color:#333;font-family:"Segoe UI",Arial,sans-serif;font-size:14px;font-weight:600;line-height:20px;text-align:center;text-decoration:none;box-shadow:0 1px 2px rgba(0,0,0,.04);transition:background-color .15s,border-color .15s,box-shadow .15s}
            a.kaae-ms-button:hover{background:#f3f3f3;border-color:#505050;color:#111;box-shadow:0 2px 4px rgba(0,0,0,.08)}
            a.kaae-ms-button:focus{outline:2px solid #2271b1;outline-offset:3px;color:#111}
            a.kaae-ms-button-disconnect:hover{background:#fff5f5;border-color:#b32d2e;color:#8a2424}
            @media(max-width:480px){.kaae-ms-account{padding:18px}.kaae-ms-account a.kaae-ms-button{width:100%}}
            @media(prefers-reduced-motion:reduce){a.kaae-ms-button{transition:none}}
        </style>
        <?php
    }

    public static function disconnect(): void {
        check_admin_referer( 'kaae_ms_disconnect' );
        if ( self::microsoft_only() || get_user_meta( get_current_user_id(), KAAE_MS_Accounts::PASSWORD_DISABLED, true ) ) {
            self::fail( 'An administrator must disable Microsoft-only sign-in before you can disconnect your account.' );
        }
        delete_user_meta( get_current_user_id(), self::META );
        delete_user_meta( get_current_user_id(), self::VERIFIED );
        wp_safe_redirect( admin_url( 'profile.php' ) );
        exit;
    }

    public static function connect(): void {
        check_admin_referer( 'kaae_ms_connect' );
        self::begin( get_current_user_id() );
    }

    public static function login_button(): void {
        if ( self::ready() ) {
            self::button_styles();
            echo '<p style="margin:16px 0"><a class="kaae-ms-button" href="' . esc_url( add_query_arg( 'action', 'kaae_ms_start', site_url( 'wp-login.php', 'https' ) ) ) . '">' . self::microsoft_logo() . '<span>Sign in with Microsoft</span></a></p>';
            if ( self::microsoft_only() && self::has_password_exception() ) {
                echo '<p style="margin:12px 0">KAAE staff: use Microsoft sign-in. Password login is reserved for the approved external account.</p>';
            }
        }
    }

    public static function start_login(): void {
        self::begin( 0 );
    }

    private static function verification_stamp( array $settings, string $identity ): string {
        return hash( 'sha256', $settings['tenant'] . ':' . $settings['client'] . ':' . $settings['secret'] . ':' . $identity );
    }

    private static function cookie( string $value, int $expires ): void {
        setcookie( '__Host-kaae_ms', $value, array( 'expires' => $expires, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax' ) );
    }

    private static function begin( int $user_id ): void {
        if ( ! self::ready() || headers_sent() ) {
            self::fail( 'Microsoft sign-in is not configured or HTTPS is unavailable.' );
        }
        nocache_headers();
        $s = self::settings();
        $state = bin2hex( random_bytes( 32 ) );
        $browser = bin2hex( random_bytes( 32 ) );
        $nonce = bin2hex( random_bytes( 32 ) );
        $verifier = bin2hex( random_bytes( 32 ) );
        $session = $user_id ? hash( 'sha256', wp_get_session_token() ) : '';
        set_transient( 'kaae_ms_' . hash( 'sha256', $state ), array( 'browser' => hash( 'sha256', $browser ), 'nonce' => $nonce, 'verifier' => $verifier, 'uid' => $user_id, 'session' => $session, 'tenant' => $s['tenant'], 'client' => $s['client'], 'automatic_accounts' => (bool) $s['automatic_accounts'] ), 600 );
        self::cookie( $browser, time() + 600 );
        $url = 'https://login.microsoftonline.com/' . $s['tenant'] . '/oauth2/v2.0/authorize';
        $scope = 'openid profile email' . ( $s['automatic_accounts'] ? ' https://graph.microsoft.com/User.Read' : '' );
        $url = add_query_arg( array( 'client_id' => $s['client'], 'response_type' => 'code', 'redirect_uri' => self::callback_url(), 'response_mode' => 'query', 'scope' => $scope, 'state' => $state, 'nonce' => $nonce, 'code_challenge' => rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' ), 'code_challenge_method' => 'S256', 'prompt' => 'select_account' ), $url );
        wp_redirect( $url ); // Fixed Microsoft host; no user-controlled redirect destination.
        exit;
    }

    private static function keys( string $tenant, bool $refresh = false ): array {
        $cache_key = 'kaae_ms_keys_' . $tenant;
        $keys = $refresh ? false : get_transient( $cache_key );
        if ( is_array( $keys ) ) {
            return $keys;
        }
        $response = wp_remote_get( 'https://login.microsoftonline.com/' . $tenant . '/discovery/v2.0/keys', array( 'timeout' => 15, 'redirection' => 0, 'limit_response_size' => 262144 ) );
        if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
            throw new RuntimeException( 'Signing keys unavailable.' );
        }
        $body = json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $body['keys'] ) || ! is_array( $body['keys'] ) ) {
            throw new RuntimeException( 'Invalid signing keys.' );
        }
        set_transient( $cache_key, $body['keys'], HOUR_IN_SECONDS );
        return $body['keys'];
    }

    public static function callback(): void {
        nocache_headers();
        header( 'Referrer-Policy: no-referrer' );
        if ( ! self::ready() ) {
            self::fail( 'Microsoft sign-in is unavailable.' );
        }
        $state = (string) wp_unslash( $_GET['state'] ?? '' );
        if ( ! preg_match( '/^[a-f0-9]{64}$/D', $state ) ) {
            self::fail( 'Invalid sign-in request.' );
        }
        $key = 'kaae_ms_' . hash( 'sha256', $state );
        $flow = get_transient( $key );
        $browser = (string) wp_unslash( $_COOKIE['__Host-kaae_ms'] ?? '' );
        if ( ! is_array( $flow ) || ! hash_equals( $flow['browser'], hash( 'sha256', $browser ) ) ) {
            self::fail( 'Sign-in expired or browser verification failed. Please start again.' );
        }
        delete_transient( $key );
        self::cookie( '', time() - 3600 );
        $s = self::settings();
        if ( $flow['tenant'] !== $s['tenant'] || $flow['client'] !== $s['client'] || (bool) ( $flow['automatic_accounts'] ?? false ) !== (bool) $s['automatic_accounts'] ) {
            self::fail( 'Configuration changed. Please start again.' );
        }
        if ( isset( $_GET['error'] ) || empty( $_GET['code'] ) ) {
            self::fail( 'Microsoft sign-in was cancelled or declined.' );
        }
        try {
            $response = wp_remote_post( 'https://login.microsoftonline.com/' . $s['tenant'] . '/oauth2/v2.0/token', array( 'timeout' => 20, 'redirection' => 0, 'limit_response_size' => 65536, 'body' => array( 'client_id' => $s['client'], 'client_secret' => $s['secret'], 'grant_type' => 'authorization_code', 'code' => (string) wp_unslash( $_GET['code'] ), 'redirect_uri' => self::callback_url(), 'code_verifier' => $flow['verifier'] ) ) );
            if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
                throw new RuntimeException( 'Token exchange failed.' );
            }
            $body = json_decode( wp_remote_retrieve_body( $response ), true );
            $jwt = $body['id_token'] ?? '';
            $keys = self::keys( $s['tenant'] );
            $parts = explode( '.', $jwt );
            $header = json_decode( KAAE_MS_Token::decode( $parts[0] ?? '' ), true );
            if ( ! in_array( $header['kid'] ?? null, array_column( $keys, 'kid' ), true ) ) {
                $keys = self::keys( $s['tenant'], true );
            }
            $claims = KAAE_MS_Token::verify( $jwt, $keys, $s['tenant'], $s['client'], $flow['nonce'] );
            $email = $s['automatic_accounts'] ? KAAE_MS_Accounts::directory_email( $claims, (string) ( $body['access_token'] ?? '' ) ) : strtolower( $claims['preferred_username'] ?? '' );
            if ( ! KAAE_MS_Accounts::kaae_email( $email ) ) {
                self::fail( 'Use your KAAE Microsoft work account.' );
            }
            $identity = $claims['tid'] . ':' . strtolower( $claims['oid'] );
            $matches = KAAE_MS_Accounts::identity_users( $identity );
            if ( $flow['uid'] ) {
                if ( get_current_user_id() !== $flow['uid'] || ! hash_equals( $flow['session'], hash( 'sha256', wp_get_session_token() ) ) ) {
                    self::fail( 'Sign in to your WordPress account again before connecting Microsoft.' );
                }
                $user = get_userdata( $flow['uid'] );
                if ( strtolower( $user->user_email ) !== $email || ( $matches && ( count( $matches ) !== 1 || (int) $matches[0] !== $user->ID ) ) ) {
                    self::fail( 'Your Microsoft sign-in address must match your WordPress email and cannot already be connected to another user.' );
                }
                if ( get_user_meta( $user->ID, self::META, true ) ) {
                    self::fail( 'Disconnect the existing Microsoft account before connecting another.' );
                }
                update_user_meta( $user->ID, self::META, $identity );
                wp_safe_redirect( admin_url( 'profile.php' ) );
                exit;
            }
            if ( ! $matches && $s['automatic_accounts'] ) {
                $user = KAAE_MS_Accounts::resolve( $identity, $email, (string) ( $claims['name'] ?? '' ) );
            } elseif ( count( $matches ) !== 1 ) {
                self::fail( self::microsoft_only() ? 'This Microsoft account is not connected. Contact your site administrator.' : 'This Microsoft account is not connected. Sign in with your WordPress password and connect it from your profile first.' );
            } else {
                $user = get_userdata( (int) $matches[0] );
            }
            if ( ! $user || ! is_user_member_of_blog( $user->ID ) || ( is_multisite() && ( $user->spam || $user->deleted ) ) ) {
                self::fail( 'This account does not have access to this site.' );
            }
            self::$verified_user = $user->ID;
            try {
                $checked = apply_filters( 'wp_authenticate_user', $user, '' );
                if ( ! is_wp_error( $checked ) && $checked instanceof WP_User ) {
                    // Core password authenticators preserve an authenticated WP_User.
                    $checked = apply_filters( 'authenticate', $checked, $user->user_login, '' );
                }
            } finally {
                self::$verified_user = 0;
            }
            if ( is_wp_error( $checked ) || ! $checked instanceof WP_User || $checked->ID !== $user->ID ) {
                self::fail( 'Sign-in was blocked by this site’s authentication policy.' );
            }
            wp_set_auth_cookie( $user->ID, false, true );
            update_user_meta( $user->ID, self::VERIFIED, self::verification_stamp( $s, $identity ) );
            do_action( 'wp_login', $user->user_login, $user );
            wp_safe_redirect( admin_url() );
            exit;
        } catch ( KAAE_MS_Account_Error $error ) {
            self::fail( $error->getMessage() );
        } catch ( Throwable $error ) {
            // Never expose tokens, secrets, authorization codes, or provider error bodies.
            self::fail( 'Microsoft authentication could not be verified. Please retry or contact your administrator.' );
        }
    }
}
