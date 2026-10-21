<?php
/**
 * Plugin Name: KAAE Microsoft Login
 * Description: KAAE Microsoft staff sign-in, automatic Subscriber accounts, and individual password policies.
 * Version: 0.4.2
 * Requires at least: 6.0
 * Requires PHP: 8.1
 * Plugin URI: https://github.com/akamomer/kaae-microsoft-login
 * Update URI: https://github.com/akamomer/kaae-microsoft-login
 * License: GPL-2.0-or-later
 */

defined( 'ABSPATH' ) || exit;
require_once __DIR__ . '/includes/class-kaae-token.php';
require_once __DIR__ . '/includes/class-kaae-login.php';
require_once __DIR__ . '/includes/class-kaae-updates.php';
KAAE_MS_Login::boot();
KAAE_MS_Updates::boot( __FILE__ );
