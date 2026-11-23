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

/*
 * Configuration: mailbox, processing, recommendations and notifications.
 */

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Dmarc\Collector;
use GlpiPlugin\Dmarc\GoogleAuth;
use GlpiPlugin\Dmarc\Menu;
use GlpiPlugin\Dmarc\Settings;
use GlpiPlugin\Dmarc\Ui;

/** @var array $CFG_GLPI */
global $CFG_GLPI;

Session::checkRight('config', UPDATE);

$self = Ui::root() . '/plugins/dmarc/front/config.form.php';
$test = null;

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST') {
    $in     = $_POST;
    $values = [];
    $errors = [];

    $entity = (int) ($in['entities_id'] ?? 0);
    if ($entity === 0 || countElementsInTable('glpi_entities', ['id' => $entity]) > 0) {
        $values['entities_id'] = $entity;
    }
    $values['entity_recursive'] = empty($in['entity_recursive']) ? 0 : 1;

    $values['host']          = trim((string) ($in['host'] ?? ''));
    $values['port']          = max(1, min(65535, (int) ($in['port'] ?? 993)));
    $values['encryption']    = in_array($in['encryption'] ?? '', ['ssl', 'starttls', 'none'], true) ? $in['encryption'] : 'ssl';
    $values['validate_cert'] = empty($in['validate_cert']) ? 0 : 1;
    $values['auth']          = ($in['auth'] ?? '') === 'password' ? 'password' : 'oauth_google';
    $values['username']      = trim((string) ($in['username'] ?? ''));
    $values['folder']        = trim((string) ($in['folder'] ?? '')) ?: 'DMARC';
    $since                   = trim((string) ($in['since_date'] ?? ''));
    if ($since === '' || (preg_match('/^\d{4}-\d{2}-\d{2}$/', $since) === 1 && strtotime($since) !== false)) {
        $values['since_date'] = $since;
    } else {
        $errors[] = __('The start date is not valid; it was not changed.', 'dmarc');
    }
    $values['mode']        = ($in['mode'] ?? '') === 'write' ? 'write' : 'readonly';
    $values['post_action'] = in_array($in['post_action'] ?? '', ['seen', 'move', 'delete'], true) ? $in['post_action'] : 'seen';
    $values['move_folder'] = trim((string) ($in['move_folder'] ?? '')) ?: 'DMARC/Processed';
    if ($values['mode'] === 'write' && $values['post_action'] === 'move' && $values['move_folder'] === $values['folder']) {
        $errors[] = __('The destination folder cannot be the reports folder: read-only mode is kept.', 'dmarc');
        $values['mode'] = 'readonly';
    }

    $values['batch_size']       = max(1, min(5000, (int) ($in['batch_size'] ?? 200)));
    $values['max_message_mb']   = max(1, min(100, (int) ($in['max_message_mb'] ?? 20)));
    $values['keep_raw']         = empty($in['keep_raw']) ? 0 : 1;
    $values['retention_months'] = max(1, min(Settings::MAX_RETENTION_MONTHS, (int) ($in['retention_months'] ?? 36)));
    $values['rdns']             = empty($in['rdns']) ? 0 : 1;
    $values['own_networks']     = trim(preg_replace('/[^0-9a-fA-F:.\/,\s]/', '', (string) ($in['own_networks'] ?? '')) ?? '');

    // AbuseIPDB
    $values['abuseipdb_enabled']   = empty($in['abuseipdb_enabled']) ? 0 : 1;
    $values['abuseipdb_days']      = max(1, min(365, (int) ($in['abuseipdb_days'] ?? 30)));
    $values['abuseipdb_daily_max'] = max(1, min(100000, (int) ($in['abuseipdb_daily_max'] ?? 500)));
    if (!empty($in['clear_abuseipdb_key'])) {
        $values['abuseipdb_key'] = '';
    } elseif (trim((string) ($in['abuseipdb_key'] ?? '')) !== '') {
        $values['abuseipdb_key'] = trim((string) $in['abuseipdb_key']);
    }

    $values['compliance_target'] = max(50, min(100, (int) ($in['compliance_target'] ?? 98)));
    $values['none_days']         = max(1, min(365, (int) ($in['none_days'] ?? 30)));

    $values['notify_enabled']           = empty($in['notify_enabled']) ? 0 : 1;
    $values['notify_min_messages']      = max(1, (int) ($in['notify_min_messages'] ?? 5));
    $values['notify_failing_threshold'] = max(1, min(100, (int) ($in['notify_failing_threshold'] ?? 90)));
    $values['notify_no_reports_days']   = max(1, min(60, (int) ($in['notify_no_reports_days'] ?? 3)));
    $values['notify_collect_errors']    = max(1, min(100, (int) ($in['notify_collect_errors'] ?? 3)));
    $values['notify_summary_day']       = max(0, min(7, (int) ($in['notify_summary_day'] ?? 1)));

    // Secrets: only replaced when something new is given
    $password = (string) ($in['password'] ?? '');
    if (!empty($in['clear_password'])) {
        $values['password'] = '';
    } elseif ($password !== '') {
        $values['password'] = $password;
    }
    // OAuth client of Google (the secret is only replaced when a new one is given)
    $values['oauth_client_id'] = trim((string) ($in['oauth_client_id'] ?? ''));
    if ($values['oauth_client_id'] !== '' && preg_match('/^[\w.-]+\.apps\.googleusercontent\.com$/', $values['oauth_client_id']) !== 1) {
        $errors[] = __('The OAuth client ID should end with ".apps.googleusercontent.com"; it was saved as given.', 'dmarc');
    }
    $secret = trim((string) ($in['oauth_client_secret'] ?? ''));
    if (!empty($in['clear_oauth_secret'])) {
        $values['oauth_client_secret'] = '';
    } elseif ($secret !== '') {
        $values['oauth_client_secret'] = $secret;
    }

    // Folder or account changed: progress starts over (reports are deduplicated)
    $old = Settings::all();
    if ($old['host'] !== $values['host'] || $old['username'] !== $values['username'] || $old['folder'] !== $values['folder']) {
        $values['state_uidvalidity'] = 0;
        $values['state_last_uid']    = 0;
    }

    // The authorization belongs to one account: with another mailbox it is no longer valid
    if (Settings::hasSecret('oauth_refresh_token') && strtolower($values['username']) !== strtolower((string) $old['oauth_email'])) {
        $values['oauth_refresh_token'] = '';
        $values['oauth_email']         = '';
        $errors[] = __('The mailbox account changed: the previous Google connection was discarded. Press "Connect with Google" again.', 'dmarc');
    }
    if (isset($in['disconnect'])) {
        $values['oauth_refresh_token'] = '';
        $values['oauth_email']         = '';
        $errors[] = __('Disconnected from Google. To remove the permission in Google too: myaccount.google.com › Security › Third-party connections.', 'dmarc');
    }

    Settings::set($values);
    foreach ($errors as $e) {
        Session::addMessageAfterRedirect(htmlspecialchars($e), false, WARNING);
    }

    if (isset($in['connect'])) {
        Html::redirect(Ui::root() . '/plugins/dmarc/front/oauth.callback.php?action=start');
    }
    if (isset($in['test'])) {
        try {
            @set_time_limit(120);
            $test = ['ok' => true] + (new Collector())->test();
        } catch (\Throwable $e) {
            $test = ['ok' => false, 'error' => $e->getMessage()];
        }
    } else {
        Session::addMessageAfterRedirect(__s('Configuration saved.', 'dmarc'));
        Html::redirect($self);
    }
}

$s   = Settings::all();

Html::header('DMARC', '', 'config', 'plugin');

TemplateRenderer::getInstance()->display('@dmarc/config.html.twig', [
    'action'       => $self,
    'dashboard'    => Menu::url(),
    'csrf'         => Ui::csrf(),
    's'            => $s,
    'has_password' => Settings::hasSecret('password'),
    'has_oauth_secret'  => Settings::hasSecret('oauth_client_secret'),
    'oauth_connected'   => Settings::hasSecret('oauth_refresh_token'),
    'redirect_uri'      => GoogleAuth::redirectUri(),
    'scope'        => GoogleAuth::SCOPE,
    'max_months'   => Settings::MAX_RETENTION_MONTHS,
    'test'         => $test,
    'notifications_url' => Ui::root() . '/front/notification.php',
    'abuseipdb'    => [
        'own_key'         => Settings::hasSecret('abuseipdb_key'),
        'used_today'      => (static function (): int {
            [$d, $n] = array_pad(explode('|', (string) Settings::get('state_abuseipdb_count')), 2, '0');

            return $d === date('Y-m-d') ? (int) $n : 0;
        })(),
        'blocked_until'   => (string) Settings::get('state_abuseipdb_blocked_until'),
        'known'           => countElementsInTable('glpi_plugin_dmarc_sources', ['NOT' => ['abuse_score' => null]]),
        'sources'         => countElementsInTable('glpi_plugin_dmarc_sources'),
    ],
    'entities'     => Ui::entities(),
]);

Html::footer();
