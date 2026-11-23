<?php

/**
 * -------------------------------------------------------------------------
 * DMARC plugin for GLPI
 * -------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of DMARC.
 *
 * DMARC is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * DMARC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DMARC. If not, see <https://www.gnu.org/licenses/>.
 * -------------------------------------------------------------------------
 * @copyright Copyright (C) 2026 by Yaco Melian.
 * @license   GPLv2+ https://www.gnu.org/licenses/gpl-2.0.html
 * @link      https://github.com/__REPO__
 * -------------------------------------------------------------------------
 */

use Glpi\Plugin\Hooks;
use GlpiPlugin\Dmarc\Alert;
use GlpiPlugin\Dmarc\Menu;
use GlpiPlugin\Dmarc\Profile;
use GlpiPlugin\Dmarc\Settings;

define('PLUGIN_DMARC_VERSION', '1.0.0');

// Minimal GLPI version, inclusive
define('PLUGIN_DMARC_MIN_GLPI_VERSION', '11.0.0');

// Maximum GLPI version, exclusive
define('PLUGIN_DMARC_MAX_GLPI_VERSION', '12.0.99');

/**
 * Boot: runs before GLPI starts the session (plugin_init runs after).
 *
 * Google sends the browser back to front/oauth.php (the redirect URI). With
 * session.cookie_samesite=Strict the browser does not send GLPI's session
 * cookie on that cross-site navigation: GLPI would start a new session, send
 * a new cookie and the user would be logged out. That page is therefore
 * stateless (no session, no cookie) and unauthenticated, and only bounces
 * (same-site) to front/oauth.callback.php, which uses the session.
 */
function plugin_dmarc_boot(): void
{
    \Glpi\Http\SessionManager::registerPluginStatelessPath('dmarc', '#^/front/oauth\.php$#');
    \Glpi\Http\Firewall::addPluginStrategyForLegacyScripts('dmarc', '#^/front/oauth\.php$#', \Glpi\Http\Firewall::STRATEGY_NO_CHECK);
}

/**
 * Init hooks of the plugin.
 */
function plugin_init_dmarc(): void
{
    /** @var array $PLUGIN_HOOKS */
    global $PLUGIN_HOOKS;

    Plugin::registerClass(Profile::class, ['addtabon' => ['Profile']]);
    Plugin::registerClass(Alert::class, ['notificationtemplates_types' => true]);

    $PLUGIN_HOOKS[Hooks::CONFIG_PAGE]['dmarc'] = 'front/config.form.php';

    // IMAP password, OAuth client secret and refresh token are stored encrypted by GLPI.
    $PLUGIN_HOOKS[Hooks::SECURED_CONFIGS]['dmarc'] = Settings::SECRET_KEYS;

    if (Session::getLoginUserID() && Menu::canView()) {
        $PLUGIN_HOOKS[Hooks::MENU_TOADD]['dmarc'] = ['tools' => Menu::class];
    }
}

/**
 * Get the name and the version of the plugin
 */
function plugin_version_dmarc(): array
{
    return [
        'name'         => 'DMARC',
        'version'      => PLUGIN_DMARC_VERSION,
        'author'       => 'Yaco Melian',
        'license'      => 'GPLv2+',
        'homepage'     => 'https://github.com/__REPO__',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_DMARC_MIN_GLPI_VERSION,
                'max' => PLUGIN_DMARC_MAX_GLPI_VERSION,
            ],
            'php' => [
                'min' => '8.2',
            ],
        ],
    ];
}

function plugin_dmarc_check_prerequisites(): bool
{
    $missing = array_filter(['openssl', 'zlib', 'zip', 'curl', 'mbstring', 'simplexml'], static fn($e) => !extension_loaded($e));
    if ($missing !== []) {
        echo htmlspecialchars(sprintf(__('Missing PHP extensions: %s', 'dmarc'), implode(', ', $missing)));

        return false;
    }

    return true;
}

function plugin_dmarc_check_config($verbose = false): bool
{
    return true;
}
