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
 * @link      https://github.com/yacomelian/glpi-plugin-dmarc
 * -------------------------------------------------------------------------
 */

namespace GlpiPlugin\Dmarc;

use Config;
use GLPIKey;

/**
 * Plugin configuration, stored in glpi_configs under the "plugin:dmarc"
 * context. Secrets are encrypted by GLPI itself (secured_configs hook): they
 * are saved in clear and decrypted here when read.
 */
final class Settings
{
    public const CONTEXT = 'plugin:dmarc';

    /** Configuration keys holding encrypted secrets. */
    public const SECRET_KEYS = ['password', 'oauth_client_secret', 'oauth_refresh_token', 'abuseipdb_key'];

    /** Keys of the removed service-account method (deleted on upgrade). */
    public const OBSOLETE_KEYS = ['sa_json'];

    /** Collector state, not shown in the configuration form. */
    public const STATE_KEYS = [
        'state_uidvalidity', 'state_last_uid', 'state_last_run', 'state_last_ok',
        'state_last_error', 'state_error_count', 'state_last_summary', 'state_last_alert_record',
        'state_abuseipdb_count', 'state_abuseipdb_blocked_until',
    ];

    public const MAX_RETENTION_MONTHS = 36;

    private static ?array $cache = null;

    public static function defaults(): array
    {
        return [
            // Entity where the plugin works: Tools > DMARC is shown only when the
            // active entity is this one (or a tree that includes it), and the
            // alerts belong to it (entity administrators, notification targets).
            'entities_id'      => 0,
            'entity_recursive' => 0, // also visible from its child entities

            // Mailbox
            'host'          => 'imap.gmail.com',
            'port'          => 993,
            'encryption'    => 'ssl',      // ssl | starttls | none
            'validate_cert' => 1,
            'auth'          => 'oauth_google', // oauth_google | password
            'username'      => '',
            'password'      => '',
            // OAuth of Google with the consent of the mailbox owner
            'oauth_client_id'     => '',
            'oauth_client_secret' => '',
            'oauth_refresh_token' => '',
            'oauth_email'         => '', // account that authorized
            'folder'        => 'DMARC',
            'since_date'    => '',         // Y-m-d: first load starts here ('' = everything)

            // readonly: EXAMINE + BODY.PEEK, the mailbox is never changed.
            // write: after processing, post_action is applied.
            'mode'          => 'readonly',
            'post_action'   => 'seen',     // seen | move | delete
            'move_folder'   => 'DMARC/Processed',

            // Processing
            'batch_size'       => 200,
            'max_message_mb'   => 20,
            'keep_raw'         => 1,
            'imap_idle_check'  => 60, // seconds idle before checking the IMAP connection (no form field)
            'retention_months' => self::MAX_RETENTION_MONTHS,
            'rdns'             => 1,
            'own_networks'     => '',     // CIDR list of our own mail servers

            // Reputation of the sending IPs in AbuseIPDB (background, cached per IP)
            'abuseipdb_enabled'   => 1,
            'abuseipdb_key'       => '',
            'abuseipdb_days'      => 30,  // ask again after this many days
            'abuseipdb_daily_max' => 500, // queries per day (the free plan allows 1,000)

            // Recommendations
            'compliance_target' => 98,   // % for "ready to tighten the policy"
            'none_days'         => 30,   // p=none for longer than this → recommendation

            // Notifications (GLPI notifications; this is the global switch)
            'notify_enabled'           => 0,
            'notify_min_messages'      => 5,
            'notify_failing_threshold' => 90,
            'notify_no_reports_days'   => 3,
            'notify_collect_errors'    => 3,
            'notify_summary_day'       => 1, // ISO day of the week (1 = Monday), 0 = no summary

            // State
            'state_uidvalidity'       => 0,
            'state_last_uid'          => 0,
            'state_last_run'          => '',
            'state_last_ok'           => '',
            'state_last_error'        => '',
            'state_error_count'       => 0,
            'state_last_summary'      => '',
            'state_last_alert_record' => 0,
            'state_abuseipdb_count'         => '', // "Y-m-d|n" queries made today
            'state_abuseipdb_blocked_until' => '', // after a 429
        ];
    }

    /** Called on install: adds missing keys, never overwrites existing values. */
    public static function installDefaults(): void
    {
        $current = Config::getConfigurationValues(self::CONTEXT);

        // 0.1.0 had a service-account method: it is gone (it could impersonate
        // any user of the domain). The stored key is deleted and the mailbox
        // must be connected again with OAuth (or a password).
        $obsolete = array_intersect(self::OBSOLETE_KEYS, array_keys($current));
        if ($obsolete !== []) {
            (new Config())->deleteConfigurationValues(self::CONTEXT, array_values($obsolete));
            $current = array_diff_key($current, array_flip($obsolete));
        }
        if (($current['auth'] ?? '') === 'google_sa') {
            Config::setConfigurationValues(self::CONTEXT, ['auth' => 'oauth_google']);
            $current['auth'] = 'oauth_google';
        }
        $missing = array_diff_key(self::defaults(), $current);
        if ($missing !== []) {
            Config::setConfigurationValues(self::CONTEXT, $missing);
        }
        self::$cache = null;
    }

    public static function uninstall(): void
    {
        $keys = array_keys(Config::getConfigurationValues(self::CONTEXT));
        if ($keys !== []) {
            (new Config())->deleteConfigurationValues(self::CONTEXT, $keys);
        }
        self::$cache = null;
    }

    /** Raw values (secrets still encrypted). */
    public static function all(): array
    {
        if (self::$cache === null) {
            self::$cache = array_replace(self::defaults(), Config::getConfigurationValues(self::CONTEXT));
        }

        return self::$cache;
    }

    public static function get(string $key): mixed
    {
        $value = self::all()[$key] ?? null;
        if (in_array($key, self::SECRET_KEYS, true) && is_string($value) && $value !== '') {
            set_error_handler(static fn() => true);
            try {
                $value = (string) (new GLPIKey())->decrypt($value);
            } catch (\Throwable) {
                $value = '';
            } finally {
                restore_error_handler();
            }
        }

        return $value;
    }

    public static function int(string $key): int
    {
        return (int) self::get($key);
    }

    /** All values with secrets decrypted: what the collector needs. */
    public static function decrypted(): array
    {
        $values = self::all();
        foreach (self::SECRET_KEYS as $key) {
            $values[$key] = (string) self::get($key);
        }

        return $values;
    }

    public static function hasSecret(string $key): bool
    {
        return (string) (self::all()[$key] ?? '') !== '';
    }

    /**
     * Secrets are passed in clear: GLPI encrypts them itself because they are
     * declared in the "secured_configs" hook (see setup.php).
     */
    public static function set(array $values): void
    {
        Config::setConfigurationValues(self::CONTEXT, $values);
        self::$cache = null;
    }

    public static function refresh(): void
    {
        self::$cache = null;
    }

    public static function retentionMonths(): int
    {
        return max(1, min(self::MAX_RETENTION_MONTHS, self::int('retention_months')));
    }

    public static function isMailboxConfigured(): bool
    {
        if (trim((string) self::get('host')) === '' || trim((string) self::get('username')) === '') {
            return false;
        }

        return self::get('auth') === 'oauth_google'
            ? self::hasSecret('oauth_refresh_token') && trim((string) self::get('oauth_client_id')) !== ''
            : self::hasSecret('password');
    }

    /** Directory where the original reports are kept (gzip). */
    public static function rawDir(): string
    {
        return GLPI_PLUGIN_DOC_DIR . '/dmarc/raw';
    }
}
