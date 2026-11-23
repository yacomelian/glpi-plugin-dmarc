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

use GlpiPlugin\Dmarc\Alert;
use GlpiPlugin\Dmarc\Cron;
use GlpiPlugin\Dmarc\Menu;
use GlpiPlugin\Dmarc\Notifications;
use GlpiPlugin\Dmarc\Settings;

/** Tables of the plugin, in drop order. */
const PLUGIN_DMARC_TABLES = [
    'glpi_plugin_dmarc_authresults',
    'glpi_plugin_dmarc_records',
    'glpi_plugin_dmarc_reports',
    'glpi_plugin_dmarc_messages',
    'glpi_plugin_dmarc_sources',
    'glpi_plugin_dmarc_domains',
    'glpi_plugin_dmarc_alerts',
];

/**
 * Install / upgrade. Idempotent: every step checks what already exists.
 * The plugin only writes its own tables; in the core it registers what every
 * plugin registers (right, automatic actions, notifications and templates).
 */
function plugin_dmarc_install(): bool
{
    /** @var DBmysql $DB */
    global $DB;

    $migration = new Migration(PLUGIN_DMARC_VERSION);
    $charset   = DBConnection::getDefaultCharset();
    $collation = DBConnection::getDefaultCollation();
    $sign      = DBConnection::getDefaultPrimaryKeySignOption();
    $tail      = "ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC";

    // One mail read from the mailbox (or a file imported by hand / demo data).
    if (!$DB->tableExists('glpi_plugin_dmarc_messages')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_dmarc_messages` (
            `id`            int {$sign} NOT NULL AUTO_INCREMENT,
            `source`        varchar(16) NOT NULL DEFAULT 'imap',
            `uidvalidity`   int unsigned DEFAULT NULL,
            `uid`           int unsigned DEFAULT NULL,
            `message_id`    varchar(255) DEFAULT NULL,
            `filename`      varchar(255) DEFAULT NULL,
            `date_mail`     timestamp NULL DEFAULT NULL,
            `sender`        varchar(255) DEFAULT NULL,
            `subject`       varchar(255) DEFAULT NULL,
            `size`          int NOT NULL DEFAULT 0,
            `status`        tinyint NOT NULL DEFAULT 0,
            `error`         text,
            `reports`       int NOT NULL DEFAULT 0,
            `post_action`   varchar(16) DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            `date_mod`      timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `imap_uid` (`uidvalidity`, `uid`),
            KEY `status` (`status`),
            KEY `source` (`source`),
            KEY `date_mail` (`date_mail`)
        ) {$tail}");
    }

    // One aggregate report (RUA). Unique per reporting organisation + report id.
    if (!$DB->tableExists('glpi_plugin_dmarc_reports')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_dmarc_reports` (
            `id`            int {$sign} NOT NULL AUTO_INCREMENT,
            `messages_id`   int {$sign} NOT NULL DEFAULT 0,
            `org_name`      varchar(255) NOT NULL DEFAULT '',
            `org_email`     varchar(255) DEFAULT NULL,
            `extra_contact` varchar(255) DEFAULT NULL,
            `report_id`     varchar(255) NOT NULL DEFAULT '',
            `version`       varchar(16) DEFAULT NULL,
            `date_begin`    timestamp NULL DEFAULT NULL,
            `date_end`      timestamp NULL DEFAULT NULL,
            `day`           date DEFAULT NULL,
            `domain`        varchar(255) NOT NULL DEFAULT '',
            `adkim`         varchar(8) DEFAULT NULL,
            `aspf`          varchar(8) DEFAULT NULL,
            `p`             varchar(16) DEFAULT NULL,
            `sp`            varchar(16) DEFAULT NULL,
            `np`            varchar(16) DEFAULT NULL,
            `pct`           int DEFAULT NULL,
            `fo`            varchar(16) DEFAULT NULL,
            `testing`       varchar(8) DEFAULT NULL,
            `errors`        text,
            `total`         int NOT NULL DEFAULT 0,
            `pass`          int NOT NULL DEFAULT 0,
            `records`       int NOT NULL DEFAULT 0,
            `raw_file`      varchar(255) DEFAULT NULL,
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `unicity` (`org_name`, `report_id`),
            KEY `messages_id` (`messages_id`),
            KEY `domain_day` (`domain`, `day`),
            KEY `day` (`day`)
        ) {$tail}");
    }

    // One row of a report: a source IP, a count and how it was evaluated.
    // `day` and `domain` are copied from the report for fast aggregation.
    if (!$DB->tableExists('glpi_plugin_dmarc_records')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_dmarc_records` (
            `id`              int {$sign} NOT NULL AUTO_INCREMENT,
            `reports_id`      int {$sign} NOT NULL DEFAULT 0,
            `sources_id`      int {$sign} NOT NULL DEFAULT 0,
            `day`             date DEFAULT NULL,
            `domain`          varchar(255) NOT NULL DEFAULT '',
            `ip`              varchar(45) NOT NULL DEFAULT '',
            `count`           int NOT NULL DEFAULT 0,
            `disposition`     varchar(16) DEFAULT NULL,
            `dkim_eval`       varchar(16) DEFAULT NULL,
            `spf_eval`        varchar(16) DEFAULT NULL,
            `dmarc_pass`      tinyint NOT NULL DEFAULT 0,
            `cause`           tinyint NOT NULL DEFAULT 0,
            `reasons`         varchar(255) DEFAULT NULL,
            `header_from`     varchar(255) DEFAULT NULL,
            `envelope_from`   varchar(255) DEFAULT NULL,
            `envelope_to`     varchar(255) DEFAULT NULL,
            `dkim_domains`    varchar(255) DEFAULT NULL,
            `spf_domain`      varchar(255) DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `reports_id` (`reports_id`),
            KEY `sources_id` (`sources_id`, `day`),
            KEY `domain_day` (`domain`, `day`),
            KEY `day` (`day`)
        ) {$tail}");
    }

    // Raw SPF / DKIM results of each record.
    if (!$DB->tableExists('glpi_plugin_dmarc_authresults')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_dmarc_authresults` (
            `id`           int {$sign} NOT NULL AUTO_INCREMENT,
            `records_id`   int {$sign} NOT NULL DEFAULT 0,
            `type`         varchar(8) NOT NULL DEFAULT '',
            `domain`       varchar(255) DEFAULT NULL,
            `selector`     varchar(255) DEFAULT NULL,
            `scope`        varchar(16) DEFAULT NULL,
            `result`       varchar(16) DEFAULT NULL,
            `human_result` varchar(255) DEFAULT NULL,
            PRIMARY KEY (`id`),
            KEY `records_id` (`records_id`),
            KEY `type_domain` (`type`, `domain`)
        ) {$tail}");
    }

    // One sending IP, its reverse name, sender label and the technician's classification.
    if (!$DB->tableExists('glpi_plugin_dmarc_sources')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_dmarc_sources` (
            `id`              int {$sign} NOT NULL AUTO_INCREMENT,
            `ip`              varchar(45) NOT NULL DEFAULT '',
            `ptr`             varchar(255) DEFAULT NULL,
            `ptr_date`        timestamp NULL DEFAULT NULL,
            `sender`          varchar(64) DEFAULT NULL,
            `status`          tinyint NOT NULL DEFAULT 0,
            `comment`         text,
            `users_id`        int {$sign} NOT NULL DEFAULT 0,
            `date_classified` timestamp NULL DEFAULT NULL,
            `first_seen`      date DEFAULT NULL,
            `last_seen`       date DEFAULT NULL,
            `date_creation`   timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `ip` (`ip`),
            KEY `status` (`status`),
            KEY `sender` (`sender`)
        ) {$tail}");
    }

    // AbuseIPDB reputation cached on each source (added in 0.3.0)
    foreach (\GlpiPlugin\Dmarc\AbuseIpdb::FIELDS as $field => $definition) {
        $migration->addField('glpi_plugin_dmarc_sources', $field, $definition);
    }
    $migration->addKey('glpi_plugin_dmarc_sources', 'abuse_date');
    $migration->migrationOneTable('glpi_plugin_dmarc_sources');

    // Domains seen in the reports, optionally linked to Management > Domains.
    if (!$DB->tableExists('glpi_plugin_dmarc_domains')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_dmarc_domains` (
            `id`            int {$sign} NOT NULL AUTO_INCREMENT,
            `name`          varchar(255) NOT NULL DEFAULT '',
            `domains_id`    int {$sign} NOT NULL DEFAULT 0,
            `target_policy` varchar(16) DEFAULT NULL,
            `last_policy`   varchar(16) DEFAULT NULL,
            `first_day`     date DEFAULT NULL,
            `last_day`      date DEFAULT NULL,
            `comment`       text,
            `date_creation` timestamp NULL DEFAULT NULL,
            PRIMARY KEY (`id`),
            UNIQUE KEY `name` (`name`),
            KEY `domains_id` (`domains_id`)
        ) {$tail}");
    }

    // Alerts (the item of the GLPI notifications).
    if (!$DB->tableExists('glpi_plugin_dmarc_alerts')) {
        $DB->doQuery("CREATE TABLE `glpi_plugin_dmarc_alerts` (
            `id`             int {$sign} NOT NULL AUTO_INCREMENT,
            `entities_id`    int {$sign} NOT NULL DEFAULT 0,
            `is_recursive`   tinyint NOT NULL DEFAULT 1,
            `event`          varchar(32) NOT NULL DEFAULT '',
            `keyname`        varchar(255) NOT NULL DEFAULT '',
            `domain`         varchar(255) DEFAULT NULL,
            `ip`             varchar(45) DEFAULT NULL,
            `message`        text,
            `payload`        mediumtext,
            `status`         tinyint NOT NULL DEFAULT 1,
            `count`          int NOT NULL DEFAULT 1,
            `date_creation`  timestamp NULL DEFAULT NULL,
            `date_mod`       timestamp NULL DEFAULT NULL,
            `date_notified`  timestamp NULL DEFAULT NULL,
            `date_close`     timestamp NULL DEFAULT NULL,
            `users_id_close` int {$sign} NOT NULL DEFAULT 0,
            PRIMARY KEY (`id`),
            KEY `event_key` (`event`, `keyname`, `status`),
            KEY `status` (`status`),
            KEY `date_creation` (`date_creation`)
        ) {$tail}");
    }

    // Right: READ = dashboard, UPDATE = actions. Given to who can change the configuration.
    $migration->addRight(Menu::RIGHT, READ | UPDATE, ['config' => UPDATE]);

    CronTask::register(Cron::class, 'collect', HOUR_TIMESTAMP, [
        'state'   => CronTask::STATE_WAITING,
        'mode'    => CronTask::MODE_EXTERNAL,
        'comment' => 'Collects the new DMARC reports from the mailbox',
    ]);
    CronTask::register(Cron::class, 'resolve', HOUR_TIMESTAMP, [
        'state'   => CronTask::STATE_WAITING,
        'mode'    => CronTask::MODE_EXTERNAL,
        'comment' => 'Reverse name, sender and reputation of the new IPs',
    ]);
    CronTask::register(Cron::class, 'check', DAY_TIMESTAMP, [
        'state'   => CronTask::STATE_WAITING,
        'mode'    => CronTask::MODE_EXTERNAL,
        'hourmin' => 6,
        'hourmax' => 9,
        'comment' => 'Daily alerts, periodic summary and cleanup of old data',
    ]);

    Settings::installDefaults();
    Notifications::install();

    $dir = Settings::rawDir();
    if (!is_dir($dir)) {
        @mkdir($dir, 0o770, true);
    }

    $migration->executeMigration();

    return true;
}

/**
 * Uninstall: drop tables, rights, automatic actions, notifications,
 * configuration and stored originals.
 */
function plugin_dmarc_uninstall(): bool
{
    /** @var DBmysql $DB */
    global $DB;

    foreach (PLUGIN_DMARC_TABLES as $table) {
        if ($DB->tableExists($table)) {
            $DB->dropTable($table);
        }
    }

    ProfileRight::deleteProfileRights([Menu::RIGHT]);
    CronTask::unregister('dmarc');
    Notifications::uninstall();
    Settings::uninstall();

    $DB->delete('glpi_displaypreferences', ['itemtype' => ['LIKE', 'GlpiPlugin\\\\Dmarc\\\\%']]);

    plugin_dmarc_rmdir(GLPI_PLUGIN_DOC_DIR . '/dmarc');

    return true;
}

function plugin_dmarc_rmdir(string $dir): void
{
    if (!is_dir($dir) || is_link($dir)) {
        return;
    }
    foreach (new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    ) as $file) {
        $file->isDir() && !$file->isLink() ? @rmdir($file->getPathname()) : @unlink($file->getPathname());
    }
    @rmdir($dir);
}
