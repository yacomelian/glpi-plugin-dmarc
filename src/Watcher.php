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

use Glpi\DBAL\QueryExpression;

/**
 * Turns the figures into alerts (Alert::raise → GLPI notifications).
 * Alerts are always recorded; mails are sent only with the global switch on.
 */
final class Watcher
{
    /** Only recent traffic raises source alerts (the first load brings a year of history). */
    private const RECENT_DAYS = 7;

    private const ABUSE_FIELDS = [
        's.abuse_score', 's.abuse_reports', 's.abuse_country', 's.abuse_isp',
        's.abuse_usage', 's.abuse_domain', 's.abuse_tor',
    ];

    /**
     * New records since the last evaluation: unknown sources failing with
     * enough messages (once per source and domain) and sources classified as
     * unauthorized (again whenever the previous alert was closed).
     *
     * @return int alerts opened
     */
    public static function afterImport(): int
    {
        $lastId = Settings::int('state_last_alert_record');
        $max    = Stats::first(['SELECT' => [Stats::agg('MAX', 'id', 'm')], 'FROM' => Importer::T_RECORDS]);
        $maxId  = (int) ($max['m'] ?? 0);
        if ($maxId <= $lastId) {
            return 0;
        }
        $min    = max(1, Settings::int('notify_min_messages'));
        $recent = date('Y-m-d', strtotime('-' . self::RECENT_DAYS . ' days'));
        $opened = 0;

        foreach (Stats::rows([
            'SELECT'     => array_merge(
                ['r.domain', 's.id AS sources_id', 's.ip', 's.ptr', 's.sender', 's.status'],
                self::ABUSE_FIELDS,
                [Stats::agg('SUM', 'r.count', 'fail'), Stats::agg('MAX', 'r.cause', 'cause')]
            ),
            'FROM'       => Importer::T_RECORDS . ' AS r',
            'INNER JOIN' => [Importer::T_SOURCES . ' AS s' => ['ON' => ['s' => 'id', 'r' => 'sources_id']]],
            'WHERE'      => [
                ['r.id' => ['>', $lastId]],
                ['r.id' => ['<=', $maxId]],
                ['r.dmarc_pass' => 0],
                ['r.day' => ['>=', $recent]],
                ['s.status' => [Diagnosis::SOURCE_UNKNOWN, Diagnosis::SOURCE_UNAUTHORIZED]],
            ],
            'GROUPBY'    => ['r.domain', 's.id'],
        ]) as $row) {
            $status = (int) $row['status'];
            $fail   = (int) $row['fail'];
            if ($status === Diagnosis::SOURCE_UNKNOWN && $fail < $min) {
                continue;
            }
            $cause = (int) $row['cause'];
            if ($cause === Diagnosis::FAIL_FORWARDED) {
                continue;
            }
            $sender = (string) ($row['sender'] ?: $row['ptr'] ?: '');
            $message = sprintf(
                $status === Diagnosis::SOURCE_UNAUTHORIZED
                    ? __('The source %1$s (%2$s), classified as unauthorized, sent %3$d messages as %4$s that fail DMARC.', 'dmarc')
                    : __('An unclassified source, %1$s (%2$s), sent %3$d messages as %4$s that fail DMARC.', 'dmarc'),
                $row['ip'],
                $sender ?: __('no reverse name', 'dmarc'),
                $fail,
                $row['domain']
            );
            $opened += (int) Alert::raise('unauthorized_source', 'src:' . $row['ip'] . ':' . $row['domain'], $message, [
                'domain'     => $row['domain'],
                'ip'         => $row['ip'],
                'ptr'        => (string) $row['ptr'],
                'sender'     => $sender,
                'messages'   => $fail,
                'compliance' => 0,
                'diagnosis'  => Diagnosis::label($cause) . '. ' . Diagnosis::explain($cause, $status)
                    . (($abuse = AbuseIpdb::describe($row)) !== '' ? ' ' . $abuse . ' (' . AbuseIpdb::link((string) $row['ip']) . ')' : ''),
            ], $status === Diagnosis::SOURCE_UNKNOWN);
        }

        Settings::set(['state_last_alert_record' => $maxId]);

        return $opened;
    }

    /**
     * Daily checks: authorized sources failing, domains without reports.
     *
     * @return int alerts opened
     */
    public static function daily(): int
    {
        $opened = 0;
        $min    = max(1, Settings::int('notify_min_messages'));
        $limit  = (float) max(1, min(100, Settings::int('notify_failing_threshold')));
        $from   = date('Y-m-d', strtotime('-' . self::RECENT_DAYS . ' days'));

        // authorized sources under the threshold
        $open = Alert::openKeys('failing_source');
        $seen = [];
        $pass = Stats::q('r.dmarc_pass');
        foreach (Stats::rows([
            'SELECT'     => array_merge(
                ['r.domain', 's.ip', 's.ptr', 's.sender'],
                self::ABUSE_FIELDS,
                [
                    Stats::agg('SUM', 'r.count', 'total'),
                    new QueryExpression("SUM(CASE WHEN {$pass} = 1 THEN " . Stats::q('r.count') . ' ELSE 0 END) AS ' . Stats::q('pass')),
                    new QueryExpression("MAX(CASE WHEN {$pass} = 0 THEN " . Stats::q('r.cause') . ' ELSE 0 END) AS ' . Stats::q('cause')),
                ]
            ),
            'FROM'       => Importer::T_RECORDS . ' AS r',
            'INNER JOIN' => [Importer::T_SOURCES . ' AS s' => ['ON' => ['s' => 'id', 'r' => 'sources_id']]],
            'WHERE'      => [['r.day' => ['>=', $from]], ['s.status' => Diagnosis::SOURCE_AUTHORIZED]],
            'GROUPBY'    => ['r.domain', 's.id'],
        ]) as $row) {
            $key   = 'fail:' . $row['ip'] . ':' . $row['domain'];
            $total = (int) $row['total'];
            $pct   = Format::ratio((int) $row['pass'], $total);
            if ($total - (int) $row['pass'] >= $min && $pct < $limit) {
                $seen[$key] = true;
                $sender = (string) ($row['sender'] ?: $row['ptr'] ?: $row['ip']);
                $cause  = (int) $row['cause'];
                $opened += (int) Alert::raise('failing_source', $key, sprintf(
                    __('The authorized source %1$s (%2$s) passes DMARC in only %3$s of its %4$d messages of the last %5$d days for %6$s.', 'dmarc'),
                    $sender,
                    $row['ip'],
                    Format::pct($pct),
                    $total,
                    self::RECENT_DAYS,
                    $row['domain']
                ), [
                    'domain'     => $row['domain'],
                    'ip'         => $row['ip'],
                    'ptr'        => (string) $row['ptr'],
                    'sender'     => $sender,
                    'messages'   => $total,
                    'compliance' => $pct,
                    'diagnosis'  => ($cause > 0 ? Diagnosis::label($cause) . '. ' . Diagnosis::explain($cause, Diagnosis::SOURCE_AUTHORIZED) : '')
                        . (($abuse = AbuseIpdb::describe($row)) !== '' ? ' ' . $abuse : ''),
                ]);
            }
        }
        foreach (array_keys($open) as $key) {
            if (!isset($seen[$key])) {
                Alert::resolve('failing_source', $key);
            }
        }

        // domains that stopped receiving reports (but had them in the last 60 days)
        $days = max(1, Settings::int('notify_no_reports_days'));
        $open = Alert::openKeys('no_reports');
        foreach (Stats::rows([
            'SELECT' => ['name', 'last_day'],
            'FROM'   => Importer::T_DOMAINS,
            'WHERE'  => [['NOT' => ['last_day' => null]], ['last_day' => ['>=', date('Y-m-d', strtotime('-60 days'))]]],
        ]) as $row) {
            $key    = 'noreports:' . $row['name'];
            $silent = (int) floor((strtotime(date('Y-m-d')) - strtotime((string) $row['last_day'])) / 86400);
            if ($silent > $days) {
                $opened += (int) Alert::raise('no_reports', $key, sprintf(
                    __('No DMARC reports received for %1$s since %2$s (%3$d days). Check the _dmarc record (rua=), the mailbox folder and the collection.', 'dmarc'),
                    $row['name'],
                    $row['last_day'],
                    $silent
                ), ['domain' => $row['name'], 'messages' => 0]);
            } elseif (isset($open[$key])) {
                Alert::resolve('no_reports', $key);
            }
        }

        return $opened;
    }

    /** Weekly summary on the configured day (once). */
    public static function summary(bool $force = false): bool
    {
        $day = Settings::int('notify_summary_day');
        if (!$force && ($day < 1 || (int) date('N') !== $day || Settings::get('state_last_summary') === date('Y-m-d'))) {
            return false;
        }
        $stats   = new Stats(date('Y-m-d', strtotime('-7 days')), date('Y-m-d', strtotime('-1 day')));
        $totals  = $stats->totals();
        $domains = $stats->domains();
        $recs    = array_map(static fn($r) => $r['domain'] . ': ' . $r['title'] . '. ' . $r['text'], Advisor::recommendations($stats, $domains));

        Alert::raise('summary', 'summary:' . date('Y-m-d'), sprintf(
            __('DMARC summary from %1$s to %2$s: %3$s messages, %4$s pass DMARC.', 'dmarc'),
            $stats->from,
            $stats->to,
            Format::int($totals['total']),
            Format::pct($totals['pass_pct'])
        ), [
            'period'   => $stats->from . ' – ' . $stats->to,
            'total'    => $totals['total'],
            'pass_pct' => $totals['pass_pct'],
            'domains'  => array_map(static fn($d) => [
                'domain'      => $d['domain'],
                'policy'      => trim(($d['policy']['p'] ?? '') . (($d['policy']['pct'] ?? 100) < 100 ? ' pct=' . $d['policy']['pct'] : '')),
                'total'       => $d['total'],
                'pass_pct'    => $d['pass_pct'],
                'state_label' => $d['state']['label'] . ($d['state']['reasons'] !== [] ? ': ' . implode(', ', $d['state']['reasons']) : ''),
            ], $domains),
            'recommendations' => array_slice($recs, 0, 20),
        ]);
        Settings::set(['state_last_summary' => date('Y-m-d')]);

        return true;
    }
}
