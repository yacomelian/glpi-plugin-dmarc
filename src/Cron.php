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

namespace GlpiPlugin\Dmarc;

use CommonGLPI;
use CronTask;
use DBmysql;

/**
 * Automatic actions of the plugin (Setup > Automatic actions).
 */
final class Cron extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return 'DMARC';
    }

    public static function cronInfo($name)
    {
        return match ($name) {
            'collect' => ['description' => __('Collect the DMARC reports from the mailbox', 'dmarc'), 'parameter' => __('Mails per run (0 = the configured one)', 'dmarc')],
            'resolve' => ['description' => __('Reverse name, sender and reputation of the new IPs', 'dmarc'), 'parameter' => __('IPs per run', 'dmarc')],
            'check'   => ['description' => __('DMARC daily alerts, summary and cleanup', 'dmarc')],
            default   => [],
        };
    }

    public static function cronCollect(CronTask $task): int
    {
        if (!Settings::isMailboxConfigured()) {
            $task->log(__('The mailbox is not configured', 'dmarc'));

            return 0;
        }
        $limit = (int) $task->fields['param'] > 0 ? (int) $task->fields['param'] : max(1, Settings::int('batch_size'));

        // GLPI runs its automatic actions one after another: a long DMARC load must
        // not delay the others. The work goes to a background process.
        if (Worker::isRunning()) {
            $task->log(__('A DMARC collection is already running in the background', 'dmarc'));

            return 0;
        }
        if (Worker::spawn(['--worker', '--collect', '--limit=' . $limit])) {
            $task->log(sprintf(__('Collection started in the background (up to %d mails)', 'dmarc'), $limit));

            return 1;
        }

        // exec() not available: do a short run here (at most 2 minutes)
        $stats = (new Collector())->run($limit, null, null, 120);
        $task->addVolume($stats['reports']);
        $task->log(self::summaryLine($stats));
        if ($stats['reports'] > 0) {
            Watcher::afterImport();
        }
        if ($stats['failure'] !== '') {
            return -1;
        }

        return $stats['checked'] > 0 ? 1 : 0;
    }

    public static function cronResolve(CronTask $task): int
    {
        // reverse names and AbuseIPDB lookups take time: background, like the collection
        if (Worker::isRunning('resolve')) {
            $task->log(__('An IP lookup is already running in the background', 'dmarc'));

            return 0;
        }
        if (Worker::spawn(['--worker-resolve'], 'resolve')) {
            $task->log(__('Reverse names and AbuseIPDB started in the background', 'dmarc'));

            return 1;
        }
        $limit = (int) $task->fields['param'] > 0 ? (int) $task->fields['param'] : 100;
        $done  = self::resolveSources($limit);
        $task->addVolume($done);

        return $done > 0 ? 1 : 0;
    }

    /**
     * Background job "resolve": reverse names of the new IPs, then AbuseIPDB.
     * Writes its own run in the history of the "resolve" automatic action.
     * Returns false if another one is running.
     */
    public static function resolveJob(int $maxSeconds = 900): bool
    {
        if (!Worker::acquire('resolve')) {
            return false;
        }
        $started = microtime(true);
        $log     = Worker::cronLogStart(__('DMARC in the background: reverse names and AbuseIPDB', 'dmarc'), 'resolve');
        $text    = '';
        $volume  = 0;
        $state   = \CronTaskLog::STATE_STOP;
        try {
            $ptr  = self::resolveSources(500);
            $text = sprintf(_n('%d reverse name', '%d reverse names', $ptr, 'dmarc'), $ptr);
            if (AbuseIpdb::isEnabled()) {
                $abuse = AbuseIpdb::refresh(max(60, $maxSeconds - (int) (microtime(true) - $started)), static function (array $o) use ($log, $started): void {
                    Worker::cronLog($log, sprintf(__('AbuseIPDB: %d IPs checked', 'dmarc'), $o['done']), $o['done'], microtime(true) - $started, \CronTaskLog::STATE_RUN);
                });
                $volume = $abuse['done'];
                $text  .= '; ' . sprintf(__('AbuseIPDB: %d IPs checked', 'dmarc'), $abuse['done']) . sprintf('%s%s', $abuse['errors'] > 0 ? ', ' . sprintf(__('%d with errors', 'dmarc'), $abuse['errors']) : '', $abuse['stopped'] !== '' ? ' (' . $abuse['stopped'] . ')' : '');
            } else {
                $text .= '; ' . __('AbuseIPDB is disabled or has no API key', 'dmarc');
            }
        } catch (\Throwable $e) {
            $text  = __('Error', 'dmarc') . ': ' . $e->getMessage() . ($text !== '' ? ' · ' . $text : '');
            $state = \CronTaskLog::STATE_ERROR;
        } finally {
            Worker::cronLog($log, __('Background', 'dmarc') . ': ' . $text, $volume, microtime(true) - $started, $state);
            Worker::release('resolve');
        }

        return true;
    }

    public static function cronCheck(CronTask $task): int
    {
        $opened = Watcher::daily();
        $task->log(sprintf(__('New alerts: %d', 'dmarc'), $opened));
        if (Watcher::summary()) {
            $task->log(__('Periodic summary generated', 'dmarc'));
        }
        $deleted = self::cleanup();
        if ($deleted > 0) {
            $task->log(sprintf(__('Old reports deleted: %d', 'dmarc'), $deleted));
        }
        $task->addVolume($opened + $deleted);

        return 1;
    }

    public static function summaryLine(array $stats): string
    {
        $line = sprintf(
            __('%1$d mails checked: %2$d imported (%3$d reports), %4$d duplicates, %5$d not reports, %6$d with errors, %7$d skipped, %8$d mailbox actions; %9$d left', 'dmarc'),
            $stats['checked'],
            $stats['imported'],
            $stats['reports'],
            $stats['duplicate'],
            $stats['not_report'],
            $stats['error'],
            $stats['skipped'],
            $stats['actions'],
            $stats['remaining']
        );

        return $stats['failure'] !== '' ? $line . '. ' . __('Error', 'dmarc') . ': ' . $stats['failure'] : $line;
    }

    /** PTR + sender label of the sources not resolved yet. */
    public static function resolveSources(int $limit = 100): int
    {
        /** @var DBmysql $DB */
        global $DB;

        $own  = (string) Settings::get('own_networks');
        $rdns = (bool) Settings::int('rdns');
        $done = 0;
        foreach ($DB->request([
            'FROM'  => 'glpi_plugin_dmarc_sources',
            'WHERE' => ['ptr_date' => null],
            'ORDER' => 'last_seen DESC',
            'LIMIT' => $limit,
        ]) as $row) {
            $ptr = $rdns ? Rdns::lookup((string) $row['ip']) : '';
            if ($ptr === null) {
                continue; // no answer: try again next time
            }
            $domains = array_column(iterator_to_array($DB->request([
                'SELECT'   => ['a.domain'],
                'DISTINCT' => true,
                'FROM'     => 'glpi_plugin_dmarc_authresults AS a',
                'INNER JOIN' => ['glpi_plugin_dmarc_records AS r' => ['ON' => ['a' => 'records_id', 'r' => 'id']]],
                'WHERE'    => ['r.sources_id' => $row['id'], 'a.result' => 'pass'],
                'LIMIT'    => 20,
            ]), false), 'domain');
            $DB->update('glpi_plugin_dmarc_sources', [
                'ptr'      => mb_substr($ptr, 0, 255) ?: null,
                'ptr_date' => date('Y-m-d H:i:s'),
                'sender'   => mb_substr(Diagnosis::sender((string) $row['ip'], $ptr, array_filter($domains), $own), 0, 64) ?: null,
            ], ['id' => $row['id']]);
            $done++;
        }

        return $done;
    }

    /** Retention: reports, mails, alerts and sources older than the limit. */
    public static function cleanup(): int
    {
        /** @var DBmysql $DB */
        global $DB;

        $limit = date('Y-m-d', strtotime('-' . Settings::retentionMonths() . ' months'));
        $total = 0;
        do {
            $ids = array_column(iterator_to_array($DB->request([
                'SELECT' => ['id'],
                'FROM'   => 'glpi_plugin_dmarc_reports',
                'WHERE'  => ['day' => ['<', $limit]],
                'LIMIT'  => 500,
            ]), false), 'id');
            if ($ids !== []) {
                Importer::deleteReports($ids);
                $total += count($ids);
            }
        } while (count($ids) === 500);

        $DB->delete('glpi_plugin_dmarc_messages', ['date_creation' => ['<', $limit . ' 00:00:00']]);
        $DB->delete('glpi_plugin_dmarc_alerts', ['status' => Alert::CLOSED, 'date_creation' => ['<', $limit . ' 00:00:00']]);
        $DB->delete('glpi_plugin_dmarc_sources', [
            'last_seen' => ['<', $limit],
            'status'    => Diagnosis::SOURCE_UNKNOWN,
        ]);

        return $total;
    }
}
