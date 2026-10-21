<?php
defined( 'ABSPATH' ) || exit;

/** Directory browsing is administrator-delegated; all access decisions stay local. */
final class KAAE_MS_Staff {
    public const BLOCKED = '_kaae_ms_staff_blocked';

    public static function boot(): void {
        add_action( 'admin_menu', static function () {
            add_users_page( 'KAAE Staff', 'KAAE Staff', 'manage_options', 'kaae-ms-staff', array( self::class, 'render' ) );
        } );
        add_action( 'admin_post_kaae_ms_staff_action', array( self::class, 'handle_action' ) );
        add_filter( 'determine_current_user', array( self::class, 'validate_session' ), PHP_INT_MAX );
    }

    public static function can_manage(): bool {
        return current_user_can( 'manage_options' ) && current_user_can( 'list_users' ) && current_user_can( 'create_users' ) && current_user_can( 'edit_users' ) && ! is_multisite();
    }

    private static function recovery(): bool {
        return defined( 'KAAE_MS_PASSWORD_RECOVERY' ) && true === KAAE_MS_PASSWORD_RECOVERY;
    }

    private static function state_key( string $identity ): string {
        return 'kaae_ms_access_' . hash( 'sha256', $identity );
    }

    public static function state( string $identity ): array {
        $state = get_option( self::state_key( $identity ), array() );
        return is_array( $state ) ? $state : array();
    }

    public static function approved( string $identity ): bool {
        $state = self::state( $identity );
        return ! empty( $state['approved'] ) && empty( $state['blocked'] );
    }

    public static function assert_identity_access( string $identity ): void {
        if ( self::recovery() ) { return; }
        $state = self::state( $identity );
        if ( ! empty( $state['blocked'] ) ) {
            throw new KAAE_MS_Account_Error( 'Your access to this WordPress site is blocked. Contact the site administrator.' );
        }
        if ( KAAE_MS_Login::settings()['approved_staff_only'] && ! self::approved( $identity ) ) {
            throw new KAAE_MS_Account_Error( 'Your account has not been approved for this WordPress site. Contact the site administrator.' );
        }
    }

    public static function user_allowed( WP_User $user ): bool {
        if ( self::recovery() ) { return true; }
        if ( get_user_meta( $user->ID, self::BLOCKED, true ) ) { return false; }
        $identity = (string) get_user_meta( $user->ID, KAAE_MS_Accounts::IDENTITY, true );
        if ( '' !== $identity && ! empty( self::state( $identity )['blocked'] ) ) { return false; }
        $settings = KAAE_MS_Login::settings();
        if ( ! $settings['approved_staff_only'] ) { return true; }
        // External password exceptions keep their independent existing policy.
        if ( '' === $identity && ! KAAE_MS_Accounts::kaae_email( $user->user_email ) ) { return true; }
        return str_starts_with( $identity, $settings['tenant'] . ':' ) && self::approved( $identity );
    }

    public static function validate_session( $user_id ) {
        if ( ! $user_id ) { return $user_id; }
        $user = get_userdata( (int) $user_id );
        return $user instanceof WP_User && ! self::user_allowed( $user ) ? 0 : $user_id;
    }

    private static function cache_key(): string {
        $s = KAAE_MS_Login::settings();
        return 'kaae_ms_dir_' . hash( 'sha256', get_current_user_id() . ':' . wp_get_session_token() . ':' . $s['tenant'] . ':' . $s['client'] . ':' . $s['secret'] );
    }

    public static function directory(): array {
        $rows = get_transient( self::cache_key() );
        return is_array( $rows ) ? $rows : array();
    }

    /** No bearer tokens are persisted. Cache only sanitized directory rows for 15m. */
    public static function load_directory( string $access_token ): void {
        if ( ! self::can_manage() || '' === $access_token ) {
            throw new KAAE_MS_Account_Error( 'Administrator directory access is required.' );
        }
        $url = 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,mail,userPrincipalName&$top=100';
        $rows = array(); $seen = array();
        for ( $page = 0; $page < 50; ++$page ) {
            $parts = wp_parse_url( $url );
            if ( ! is_array( $parts ) || ( $parts['scheme'] ?? '' ) !== 'https' || ( $parts['host'] ?? '' ) !== 'graph.microsoft.com'
                || ( $parts['path'] ?? '' ) !== '/v1.0/users' || isset( $parts['user'] ) || isset( $parts['pass'] ) || isset( $parts['port'] ) || isset( $parts['fragment'] ) || isset( $seen[$url] ) ) {
                throw new KAAE_MS_Account_Error( 'Microsoft returned an unsupported directory paging link. No directory data was saved.' );
            }
            $seen[$url] = true;
            $response = wp_remote_get( $url, array( 'timeout' => 15, 'redirection' => 0, 'limit_response_size' => 262144, 'headers' => array( 'Authorization' => 'Bearer ' . $access_token, 'Accept' => 'application/json' ) ) );
            if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
                throw new KAAE_MS_Account_Error( 'Could not load the Microsoft directory. Check delegated User.ReadBasic.All consent and try Load directory again.' );
            }
            $body = json_decode( wp_remote_retrieve_body( $response ), true );
            if ( ! is_array( $body ) || ! is_array( $body['value'] ?? null ) ) {
                throw new KAAE_MS_Account_Error( 'Microsoft returned an invalid directory response. No directory data was saved.' );
            }
            foreach ( $body['value'] as $profile ) {
                if ( ! is_array( $profile ) || ! is_string( $profile['id'] ?? null ) || ! preg_match( '/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/Di', $profile['id'] ) || ! is_string( $profile['userPrincipalName'] ?? null ) ) { continue; }
                $email = strtolower( $profile['userPrincipalName'] );
                if ( ! KAAE_MS_Accounts::kaae_email( $email ) ) { continue; }
                $id = strtolower( $profile['id'] );
                $row = array( 'id' => $id, 'email' => $email, 'name' => sanitize_text_field( is_string( $profile['displayName'] ?? null ) ? $profile['displayName'] : $email ), 'mail' => is_string( $profile['mail'] ?? null ) && is_email( $profile['mail'] ) ? $profile['mail'] : '' );
                if ( isset( $rows[$id] ) && $rows[$id] !== $row ) { throw new KAAE_MS_Account_Error( 'The directory changed during loading. Please load it again.' ); }
                $rows[$id] = $row;
                if ( count( $rows ) > 5000 ) { throw new KAAE_MS_Account_Error( 'The directory exceeds this version’s 5,000-person limit.' ); }
            }
            if ( empty( $body['@odata.nextLink'] ) ) {
                uasort( $rows, static fn( $a, $b ) => strcasecmp( $a['name'], $b['name'] ) );
                set_transient( self::cache_key(), $rows, 15 * MINUTE_IN_SECONDS );
                return;
            }
            if ( ! is_string( $body['@odata.nextLink'] ) ) { throw new KAAE_MS_Account_Error( 'Invalid directory paging response.' ); }
            $url = $body['@odata.nextLink'];
        }
        throw new KAAE_MS_Account_Error( 'The directory could not be loaded completely. Please contact your administrator.' );
    }

    public static function matching_user( array $row ): ?WP_User {
        $identity = KAAE_MS_Login::settings()['tenant'] . ':' . $row['id'];
        $ids = KAAE_MS_Accounts::identity_users( $identity );
        if ( ! $ids ) { $ids = get_users( array( 'meta_key' => self::BLOCKED, 'meta_value' => $identity, 'number' => 2, 'fields' => 'ID' ) ); }
        if ( count( $ids ) > 1 ) { throw new KAAE_MS_Account_Error( 'Conflicting WordPress identity connections require administrator review.' ); }
        if ( $ids ) {
            $user = get_userdata( (int) $ids[0] );
        } else {
            $matches = get_users( array( 'search' => $row['email'], 'search_columns' => array( 'user_email' ), 'number' => 2 ) );
            $matches = array_values( array_filter( $matches, static fn( $u ) => strtolower( $u->user_email ) === $row['email'] ) );
            if ( count( $matches ) > 1 ) { throw new KAAE_MS_Account_Error( 'Duplicate WordPress emails require administrator review.' ); }
            $user = $matches[0] ?? null;
        }
        if ( $user ) {
            $connected = get_user_meta( $user->ID, KAAE_MS_Accounts::IDENTITY, true );
            $blocked = get_user_meta( $user->ID, self::BLOCKED, true );
            if ( ! is_user_member_of_blog( $user->ID ) || ( $connected && $connected !== $identity ) || ( $blocked && $blocked !== $identity ) ) {
                throw new KAAE_MS_Account_Error( 'This WordPress account belongs to a different identity or has no site access.' );
            }
        }
        return $user ?: null;
    }

    /** Per-identity locks prevent enrollment overwriting a concurrent block. */
    public static function apply_action( string $action, array $row ): void {
        if ( ! self::can_manage() || ! in_array( $action, array( 'enroll', 'block', 'unblock' ), true ) ) { throw new KAAE_MS_Account_Error( 'Administrator staff-management access is required.' ); }
        $identity = KAAE_MS_Login::settings()['tenant'] . ':' . $row['id'];
        global $wpdb;
        $lock = 'kaae_ms_staff_' . substr( hash( 'sha256', $wpdb->users . ':' . $identity ), 0, 45 );
        if ( '1' !== (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 5)', $lock ) ) ) { throw new KAAE_MS_Account_Error( 'Another action is updating this staff member. Please retry.' ); }
        try {
            $state = self::state( $identity );
            $user = self::matching_user( $row );
            if ( $user && ! current_user_can( 'edit_user', $user->ID ) ) { throw new KAAE_MS_Account_Error( 'You cannot manage this WordPress account.' ); }
            if ( 'block' === $action && ( ( $user && $user->ID === get_current_user_id() ) || get_user_meta( get_current_user_id(), KAAE_MS_Accounts::IDENTITY, true ) === $identity ) ) { throw new KAAE_MS_Account_Error( 'You cannot block your own administrator account.' ); }
            if ( 'enroll' === $action ) {
                if ( ! empty( $state['blocked'] ) || ( $user && get_user_meta( $user->ID, self::BLOCKED, true ) ) ) { throw new KAAE_MS_Account_Error( 'Unblock this person before enrolling them.' ); }
                $user = KAAE_MS_Accounts::resolve( $identity, $row['email'], $row['name'] );
                $state['approved'] = true;
            } elseif ( 'block' === $action ) {
                $state['blocked'] = true;
            } else {
                $state['blocked'] = false; // Approval is retained, never granted by Unblock.
            }
            $state['updated_at'] = time();
            $state['updated_by'] = get_current_user_id();
            update_option( self::state_key( $identity ), $state, false );
            if ( self::state( $identity ) !== $state ) { throw new KAAE_MS_Account_Error( 'WordPress could not save this access decision. Please retry.' ); }
            if ( $user && 'block' === $action ) {
                update_user_meta( $user->ID, self::BLOCKED, $identity );
                if ( get_user_meta( $user->ID, self::BLOCKED, true ) !== $identity ) { throw new KAAE_MS_Account_Error( 'The account block could not be saved completely. Please retry.' ); }
                WP_Session_Tokens::get_instance( $user->ID )->destroy_all();
            } elseif ( $user && 'unblock' === $action ) {
                delete_user_meta( $user->ID, self::BLOCKED );
                if ( get_user_meta( $user->ID, self::BLOCKED, true ) ) { throw new KAAE_MS_Account_Error( 'The account block could not be removed. Please retry.' ); }
            }
        } finally {
            $wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) );
        }
    }

    public static function handle_action(): void {
        if ( ! self::can_manage() || 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) { wp_die( 'Administrator access is required.', '', array( 'response' => 403 ) ); return; }
        check_admin_referer( 'kaae_ms_staff_action' );
        $action = $_POST['staff_action'] ?? '';
        $ids = $_POST['staff_ids'] ?? array();
        $directory = self::directory();
        if ( ! is_string( $action ) || ! in_array( $action, array( 'enroll', 'block', 'unblock' ), true ) || ! is_array( $ids ) || ! $ids || count( $ids ) > 50 ) { wp_die( 'Select between one and fifty staff members and choose an action.' ); return; }
        foreach ( $ids as $id ) { if ( ! is_string( $id ) || ! isset( $directory[$id] ) ) { wp_die( 'The directory selection expired or is invalid. Load the directory again. No actions were performed.' ); return; } }
        $messages = array(); $done = 0;
        foreach ( array_unique( $ids ) as $id ) {
            try { self::apply_action( $action, $directory[$id] ); ++$done; }
            catch ( KAAE_MS_Account_Error $error ) { $messages[] = $directory[$id]['email'] . ': ' . $error->getMessage(); }
            catch ( Throwable $error ) { $messages[] = $directory[$id]['email'] . ': The action could not be completed. Retry or contact your administrator.'; }
        }
        set_transient( self::cache_key() . '_notice', array( 'done' => $done, 'errors' => $messages ), 300 );
        wp_safe_redirect( admin_url( 'users.php?page=kaae-ms-staff' ) );
        exit;
    }

    public static function render(): void {
        if ( ! self::can_manage() ) { wp_die( 'Administrator staff-management access is required.', '', array( 'response' => 403 ) ); return; }
        $directory = self::directory();
        $s = KAAE_MS_Login::settings();
        echo '<div class="wrap"><h1>KAAE Staff</h1><p>Select Microsoft directory staff to enroll, block or unblock on this WordPress site. Microsoft accounts are never modified.</p>';
        $notice = get_transient( self::cache_key() . '_notice' );
        if ( is_array( $notice ) ) {
            delete_transient( self::cache_key() . '_notice' );
            echo '<div class="notice notice-' . ( $notice['errors'] ? 'warning' : 'success' ) . '"><p>' . esc_html( (string) $notice['done'] ) . ' staff action(s) completed.</p>';
            foreach ( $notice['errors'] as $error ) { echo '<p>' . esc_html( $error ) . '</p>'; }
            echo '</div>';
        }
        echo '<p><strong>Access policy:</strong> ' . ( $s['approved_staff_only'] ? 'Approved staff only' : 'All eligible KAAE staff (unless blocked)' ) . ' · <a href="' . esc_url( admin_url( 'options-general.php?page=kaae-ms' ) ) . '">Manage sign-in settings</a></p>';
        echo '<p>To restrict access to your selection: enroll your own administrator account and the required staff first, then enable <strong>Approved staff only</strong> in settings. New WordPress accounts receive Subscriber; existing roles are preserved. Blocking ends existing WordPress sessions. Unblocking restores the previous approval status.</p>';
        echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="kaae_ms_directory_connect">';
        wp_nonce_field( 'kaae_ms_directory_connect' );
        echo '<p><button class="button button-primary" type="submit">Load directory from Microsoft</button></p></form><p class="description">Uses your connected administrator Microsoft account and delegated User.ReadBasic.All. The directory snapshot lasts 15 minutes in this browser session. Microsoft tokens are not stored.</p>';
        if ( ! $directory ) { echo '<p>No staff snapshot is loaded. Select Load directory from Microsoft to continue.</p></div>'; return; }
        $search = isset( $_GET['staff_search'] ) && is_string( $_GET['staff_search'] ) ? sanitize_text_field( wp_unslash( $_GET['staff_search'] ) ) : '';
        $rows = array_values( array_filter( $directory, static fn( $r ) => '' === $search || false !== stripos( $r['name'] . ' ' . $r['email'] . ' ' . $r['mail'], $search ) ) );
        $pages = max( 1, (int) ceil( count( $rows ) / 50 ) );
        $page = max( 1, min( $pages, isset( $_GET['staff_page'] ) && is_scalar( $_GET['staff_page'] ) ? (int) $_GET['staff_page'] : 1 ) );
        echo '<form method="get" action="' . esc_url( admin_url( 'users.php' ) ) . '"><input type="hidden" name="page" value="kaae-ms-staff"><p><label for="kaae-staff-search">Search staff</label> <input id="kaae-staff-search" name="staff_search" value="' . esc_attr( $search ) . '"> <button class="button" type="submit">Search</button></p></form>';
        echo '<form method="post" action="' . esc_url( admin_url( 'admin-post.php' ) ) . '"><input type="hidden" name="action" value="kaae_ms_staff_action">';
        wp_nonce_field( 'kaae_ms_staff_action' );
        echo '<p><label for="kaae-staff-action">Selected staff:</label> <select id="kaae-staff-action" name="staff_action"><option value="enroll">Enroll / approve</option><option value="block">Block access and end sessions</option><option value="unblock">Unblock access</option></select> <button class="button" type="submit">Apply</button></p>';
        echo '<table class="widefat striped"><thead><tr><td><input id="kaae-staff-all" type="checkbox" aria-label="Select all staff on this page"></td><th>Name</th><th>Microsoft sign-in email</th><th>Mailbox email</th><th>WordPress role</th><th>Access</th></tr></thead><tbody>';
        foreach ( array_slice( $rows, ( $page - 1 ) * 50, 50 ) as $row ) {
            $identity = $s['tenant'] . ':' . $row['id'];
            $state = self::state( $identity ); $conflict = false;
            try { $user = self::matching_user( $row ); } catch ( KAAE_MS_Account_Error $error ) { $user = null; $conflict = true; }
            $blocked = ! empty( $state['blocked'] ) || ( $user && get_user_meta( $user->ID, self::BLOCKED, true ) );
            $status = $conflict ? 'Account conflict — review required' : ( $blocked ? 'Blocked' : ( ! empty( $state['approved'] ) ? 'Approved' : 'Not approved' ) );
            echo '<tr><td><input type="checkbox" name="staff_ids[]" value="' . esc_attr( $row['id'] ) . '" aria-label="' . esc_attr( 'Select ' . $row['email'] ) . '" ' . ( $conflict ? 'disabled' : '' ) . '></td><td>' . esc_html( $row['name'] ) . '</td><td>' . esc_html( $row['email'] ) . '</td><td>' . esc_html( $row['mail'] ) . '</td><td>' . esc_html( $user ? implode( ', ', $user->roles ) : 'No WordPress account' ) . '</td><td>' . esc_html( $status ) . '</td></tr>';
        }
        echo '</tbody></table></form><p>' . esc_html( (string) count( $rows ) ) . ' staff found. Page ' . esc_html( (string) $page ) . ' of ' . esc_html( (string) $pages ) . '.</p>';
        foreach ( array( $page - 1 => 'Previous page', $page + 1 => 'Next page' ) as $number => $label ) {
            if ( $number >= 1 && $number <= $pages ) { echo '<a class="button" style="margin-inline-end:8px" href="' . esc_url( add_query_arg( array( 'page' => 'kaae-ms-staff', 'staff_page' => $number, 'staff_search' => rawurlencode( $search ) ), admin_url( 'users.php' ) ) ) . '">' . esc_html( $label ) . '</a>'; }
        }
        echo '</div><script>(()=>{const all=document.getElementById("kaae-staff-all");if(all){all.addEventListener("change",()=>{all.closest("table").querySelectorAll("input[name=\"staff_ids[]\"]:not(:disabled)").forEach(box=>{box.checked=all.checked;});});}})();</script>';
    }
}
