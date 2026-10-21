<?php
defined( 'ABSPATH' ) || exit;

/** Messages from this exception are fixed plugin text, never provider responses. */
final class KAAE_MS_Account_Error extends RuntimeException {}

final class KAAE_MS_Accounts {
    public const IDENTITY = '_kaae_ms_identity';
    public const PASSWORD_DISABLED = '_kaae_ms_password_disabled';

    public static function kaae_email( string $email ): bool {
        return (bool) is_email( $email ) && 'kaae.org' === strtolower( substr( $email, strrpos( $email, '@' ) + 1 ) );
    }

    /** Only /me on Microsoft's fixed host receives the short-lived delegated token. */
    public static function directory_email( array $claims, string $access_token ): string {
        if ( '' === $access_token ) {
            throw new KAAE_MS_Account_Error( 'Automatic staff sign-in requires Microsoft Graph User.Read consent. Ask your Microsoft administrator to approve it and try again.' );
        }
        $response = wp_remote_get( 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName,userType', array( 'timeout' => 15, 'redirection' => 0, 'limit_response_size' => 16384, 'headers' => array( 'Authorization' => 'Bearer ' . $access_token, 'Accept' => 'application/json' ) ) );
        if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
            throw new KAAE_MS_Account_Error( 'Microsoft directory verification failed. Check delegated User.Read permission, consent, and connectivity to Microsoft Graph. No automatic account link was made.' );
        }
        $profile = json_decode( wp_remote_retrieve_body( $response ), true );
        $email = strtolower( $profile['userPrincipalName'] ?? '' );
        if ( ! is_array( $profile ) || ! is_string( $profile['id'] ?? null ) || strtolower( $profile['id'] ) !== strtolower( $claims['oid'] )
            || 'Member' !== ( $profile['userType'] ?? '' ) || ! self::kaae_email( $email ) ) {
            throw new KAAE_MS_Account_Error( 'Automatic staff sign-in is limited to directory members whose Microsoft user principal name ends in @kaae.org. Guest accounts and mailbox aliases do not qualify.' );
        }
        return $email;
    }

    public static function identity_users( string $identity ): array {
        return get_users( array( 'meta_key' => self::IDENTITY, 'meta_value' => $identity, 'number' => 2, 'fields' => 'ID' ) );
    }

    /** Match once by canonical directory UPN, then permanently use tenant:object ID. */
    public static function resolve( string $identity, string $email, string $display_name ): WP_User {
        if ( is_multisite() || ! self::kaae_email( $email ) ) {
            throw new KAAE_MS_Account_Error( 'Automatic accounts require a standalone WordPress installation and a verified KAAE directory address.' );
        }
        global $wpdb;
        // MySQL advisory locks serialize enrollment without changing schema. A crashed
        // connection releases the lock automatically. Never enroll without the lock.
        $lock = 'kaae_ms_' . substr( hash( 'sha256', $wpdb->users . ':' . strtolower( $email ) ), 0, 48 );
        if ( '1' !== (string) $wpdb->get_var( $wpdb->prepare( 'SELECT GET_LOCK(%s, 5)', $lock ) ) ) {
            throw new KAAE_MS_Account_Error( 'Another sign-in is updating this account, or the database cannot lock enrollment. Please retry or contact your administrator.' );
        }
        try {
            $linked = self::identity_users( $identity );
            if ( count( $linked ) > 1 ) {
                throw new KAAE_MS_Account_Error( 'This Microsoft identity has conflicting WordPress connections. Contact your administrator.' );
            }
            if ( $linked ) {
                $user = get_userdata( (int) $linked[0] );
                if ( ! $user || ! is_user_member_of_blog( $user->ID ) ) {
                    throw new KAAE_MS_Account_Error( 'This account does not have access to this site.' );
                }
                return $user;
            }
            $matches = get_users( array( 'search' => $email, 'search_columns' => array( 'user_email' ), 'number' => 2 ) );
            // Search results must be exact even if database collation is permissive.
            $matches = array_values( array_filter( $matches, static fn( $user ) => strtolower( $user->user_email ) === strtolower( $email ) ) );
            if ( count( $matches ) > 1 ) {
                throw new KAAE_MS_Account_Error( 'More than one WordPress user has this email. Contact your administrator.' );
            }
            if ( $matches ) {
                $user = $matches[0];
                if ( ! is_user_member_of_blog( $user->ID ) || get_user_meta( $user->ID, self::IDENTITY, true ) ) {
                    throw new KAAE_MS_Account_Error( 'This WordPress account is already connected to a different identity or has no site access. Contact your administrator.' );
                }
                if ( ! add_user_meta( $user->ID, self::IDENTITY, $identity, true ) ) {
                    throw new KAAE_MS_Account_Error( 'The account connection changed during sign-in. Please retry or contact your administrator.' );
                }
                return $user; // Existing roles, passwords, content and profile stay intact.
            }
            $id = wp_insert_user( array(
                'user_login' => 'kaae_' . substr( hash( 'sha256', $identity ), 0, 40 ),
                'user_pass' => wp_generate_password( 64, true, true ),
                'user_email' => $email,
                'display_name' => sanitize_text_field( $display_name ?: $email ),
                'role' => 'subscriber', // Never inherit WordPress's configurable default role.
                'meta_input' => array( self::IDENTITY => $identity, self::PASSWORD_DISABLED => 1 ),
            ) );
            if ( is_wp_error( $id ) ) {
                throw new KAAE_MS_Account_Error( 'WordPress could not create the staff Subscriber account. Contact your administrator.' );
            }
            $user = get_userdata( $id );
            if ( ! $user || get_user_meta( $id, self::IDENTITY, true ) !== $identity ) {
                throw new KAAE_MS_Account_Error( 'The new account connection could not be confirmed. Contact your administrator.' );
            }
            return $user;
        } finally {
            $wpdb->get_var( $wpdb->prepare( 'SELECT RELEASE_LOCK(%s)', $lock ) );
        }
    }
}
