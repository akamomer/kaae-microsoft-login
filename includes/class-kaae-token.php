<?php
defined( 'ABSPATH' ) || exit;

/** Strict RS256 ID-token validation; keys come only from Microsoft's fixed endpoint. */
final class KAAE_MS_Token {
    public static function decode( string $value ): string {
        if ( ! preg_match( '/^[A-Za-z0-9_-]+$/D', $value ) ) {
            throw new RuntimeException( 'Invalid token encoding.' );
        }
        $raw = base64_decode( strtr( $value, '-_', '+/' ) . str_repeat( '=', ( 4 - strlen( $value ) % 4 ) % 4 ), true );
        if ( false === $raw ) {
            throw new RuntimeException( 'Invalid token encoding.' );
        }
        return $raw;
    }

    private static function der( int $tag, string $value ): string {
        $length = strlen( $value );
        $encoded = '';
        if ( $length < 128 ) {
            $encoded = chr( $length );
        } else {
            while ( $length > 0 ) {
                $encoded = chr( $length & 255 ) . $encoded;
                $length >>= 8;
            }
            $encoded = chr( 128 | strlen( $encoded ) ) . $encoded;
        }
        return chr( $tag ) . $encoded . $value;
    }

    private static function integer( string $value ): string {
        $value = ltrim( $value, "\0" );
        if ( '' === $value ) {
            throw new RuntimeException( 'Invalid signing key.' );
        }
        if ( ord( $value[0] ) & 128 ) {
            $value = "\0" . $value;
        }
        return self::der( 2, $value );
    }

    public static function verify( string $jwt, array $keys, string $tenant, string $client, string $nonce, ?int $now = null ): array {
        if ( strlen( $jwt ) > 32768 ) {
            throw new RuntimeException( 'Invalid token size.' );
        }
        $parts = explode( '.', $jwt );
        if ( 3 !== count( $parts ) ) {
            throw new RuntimeException( 'Invalid token.' );
        }
        $header = json_decode( self::decode( $parts[0] ), true, 16, JSON_THROW_ON_ERROR );
        $claims = json_decode( self::decode( $parts[1] ), true, 32, JSON_THROW_ON_ERROR );
        if ( ! is_array( $header ) || ! is_array( $claims ) || 'RS256' !== ( $header['alg'] ?? '' ) || ! is_string( $header['kid'] ?? null ) || isset( $header['crit'] ) ) {
            throw new RuntimeException( 'Unsupported token.' );
        }
        $valid = false;
        foreach ( $keys as $key ) {
            if ( ( $key['kid'] ?? '' ) !== $header['kid'] || 'RSA' !== ( $key['kty'] ?? '' ) || 'sig' !== ( $key['use'] ?? 'sig' ) ) {
                continue;
            }
            $rsa = self::der( 48, self::integer( self::decode( $key['n'] ) ) . self::integer( self::decode( $key['e'] ) ) );
            $spki = self::der( 48, hex2bin( '300d06092a864886f70d0101010500' ) . self::der( 3, "\0" . $rsa ) );
            $pem = "-----BEGIN PUBLIC KEY-----\n" . chunk_split( base64_encode( $spki ), 64, "\n" ) . "-----END PUBLIC KEY-----\n";
            $valid = 1 === openssl_verify( $parts[0] . '.' . $parts[1], self::decode( $parts[2] ), $pem, OPENSSL_ALGO_SHA256 );
            if ( $valid ) {
                break;
            }
        }
        $now = $now ?? time();
        if ( ! $valid || ( $claims['iss'] ?? '' ) !== 'https://login.microsoftonline.com/' . $tenant . '/v2.0'
            || ( $claims['tid'] ?? '' ) !== $tenant || ( $claims['aud'] ?? '' ) !== $client
            || ! is_string( $claims['nonce'] ?? null ) || ! hash_equals( $nonce, $claims['nonce'] )
            || ! is_int( $claims['exp'] ?? null ) || $claims['exp'] <= $now
            || ! is_int( $claims['nbf'] ?? null ) || $claims['nbf'] > $now + 60
            || ! is_int( $claims['iat'] ?? null ) || $claims['iat'] > $now + 60
            || ! is_string( $claims['oid'] ?? null ) || ! preg_match( '/^[a-f0-9-]{36}$/Di', $claims['oid'] )
            || ! is_string( $claims['sub'] ?? null ) || '' === $claims['sub'] ) {
            throw new RuntimeException( 'Token validation failed.' );
        }
        return $claims;
    }
}
