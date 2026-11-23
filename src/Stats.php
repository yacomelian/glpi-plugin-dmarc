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

use DBmysql;
use Glpi\DBAL\QueryExpression;
use Glpi\DBAL\QueryFunction;
use Glpi\DBAL\QuerySubQuery;

/**
 * Aggregated figures for the dashboard. Read-only queries on the plugin
 * tables, built with GLPI's query builder (values are always escaped; the
 * only expressions are aggregates over quoted column names and constants).
 */
final class Stats
{
    private const R = 'glpi_plugin_dmarc_records';

    private const SOURCE_FIELDS = [
        's.abuse_score', 's.abuse_reports', 's.abuse_country', 's.abuse_isp', 's.abuse_usage',
        's.abuse_domain', 's.abuse_tor', 's.abuse_date', 's.abuse_error',
    ];

    public function __construct(
        public readonly string $from,
        public readonly string $to,
        public readonly string $domain = '',
        public readonly string $org = '',
    ) {}

    /** Period of N days ending today (0 = everything). */
    public static function forDays(int $days, string $domain = '', string $org = ''): self
    {
        $to = date('Y-m-d');
        if ($days <= 0) {
            $row  = self::first(['SELECT' => [self::agg('MIN', 'day', 'd')], 'FROM' => self::R]);
            $from = (string) ($row['d'] ?? '') ?: date('Y-m-d', strtotime('-1 year'));
        } else {
            $from = date('Y-m-d', strtotime('-' . ($days - 1) . ' days'));
        }

        return new self($from, $to, $domain, $org);
    }

    /** Same length, just before. */
    public function previous(): self
    {
        $days = $this->days();

        return new self(
            date('Y-m-d', strtotime($this->from . ' -' . $days . ' days')),
            date('Y-m-d', strtotime($this->from . ' -1 day')),
            $this->domain,
            $this->org
        );
    }

    /**
     * Domains of the filter: "a.example,b.example" (comma or space separated) or a list.
     *
     * @return list<string>
     */
    public static function parseDomains(string|array $value): array
    {
        $parts = is_array($value) ? $value : preg_split('/[\s,;]+/', $value);
        $out   = [];
        foreach ($parts ?: [] as $d) {
            $d = strtolower(trim((string) $d, ' .'));
            if ($d !== '' && preg_match('/^[a-z0-9._-]{1,253}$/', $d) === 1) {
                $out[$d] = $d;
            }
        }

        return array_values($out);
    }

    /** @return list<string> */
    public function domainList(): array
    {
        return self::parseDomains($this->domain);
    }

    public function days(): int
    {
        return max(1, (int) round((strtotime($this->to) - strtotime($this->from)) / 86400) + 1);
    }

    /** WHERE on the records (alias r): period, domains and reporting organisation. */
    private function where(): array
    {
        $w = [
            ['r.day' => ['>=', $this->from]],
            ['r.day' => ['<=', $this->to]],
        ];
        if (($list = $this->domainList()) !== []) {
            $w[] = ['r.domain' => $list];
        }
        if ($this->org !== '') {
            $w[] = ['r.reports_id' => new QuerySubQuery([
                'SELECT' => 'id',
                'FROM'   => Importer::T_REPORTS,
                'WHERE'  => ['org_name' => $this->org],
            ])];
        }

        return $w;
    }

    /** Message counters of a group of records. */
    private static function sums(): array
    {
        $count = self::q('r.count');
        $pass  = self::q('r.dmarc_pass');
        $disp  = self::q('r.disposition');
        $case  = static fn(string $cond, string $alias) => new QueryExpression(
            "SUM(CASE WHEN {$cond} THEN {$count} ELSE 0 END) AS " . self::q($alias)
        );

        return [
            self::agg('SUM', 'r.count', 'total'),
            $case("{$pass} = 1", 'pass'),
            $case(self::q('r.dkim_eval') . " = 'pass'", 'dkim'),
            $case(self::q('r.spf_eval') . " = 'pass'", 'spf'),
            $case("{$pass} = 0 AND {$disp} = 'quarantine'", 'quarantine'),
            $case("{$pass} = 0 AND {$disp} = 'reject'", 'reject'),
            $case("{$pass} = 0 AND {$disp} NOT IN ('quarantine', 'reject')", 'fail_none'),
        ];
    }

    private static function suspiciousStatuses(): array
    {
        return [Diagnosis::SOURCE_UNKNOWN, Diagnosis::SOURCE_UNAUTHORIZED];
    }

    public function totals(): array
    {
        $row = self::first([
            'SELECT' => array_merge(self::sums(), [
                QueryFunction::count('r.reports_id', true, 'reports'),
                QueryFunction::count('r.sources_id', true, 'sources'),
                QueryFunction::count('r.domain', true, 'domains'),
            ]),
            'FROM'   => self::R . ' AS r',
            'WHERE'  => $this->where(),
        ]);
        $row = self::numbers($row ?? []);

        $unknown = self::first([
            'SELECT'     => [QueryFunction::count('r.sources_id', true, 'n'), self::agg('SUM', 'r.count', 'm')],
            'FROM'       => self::R . ' AS r',
            'INNER JOIN' => [Importer::T_SOURCES . ' AS s' => ['ON' => ['s' => 'id', 'r' => 'sources_id']]],
            'WHERE'      => array_merge($this->where(), [['r.dmarc_pass' => 0], ['s.status' => self::suspiciousStatuses()]]),
        ]);
        $row['suspicious_sources']  = (int) ($unknown['n'] ?? 0);
        $row['suspicious_messages'] = (int) ($unknown['m'] ?? 0);

        $where = [['s.status' => Diagnosis::SOURCE_UNKNOWN], ['s.first_seen' => ['>=', $this->from]]];
        if ($this->domainList() !== []) {
            $where[] = ['s.id' => new QuerySubQuery([
                'SELECT' => 'r.sources_id',
                'FROM'   => self::R . ' AS r',
                'WHERE'  => $this->where(),
            ])];
        }
        $new = self::first(['SELECT' => [QueryFunction::count('s.id', false, 'n')], 'FROM' => Importer::T_SOURCES . ' AS s', 'WHERE' => $where]);
        $row['new_unclassified'] = (int) ($new['n'] ?? 0);

        $last = self::first([
            'SELECT' => [self::agg('MAX', 'date_creation', 'last_import'), self::agg('MAX', 'day', 'last_day')],
            'FROM'   => Importer::T_REPORTS,
            'WHERE'  => $this->domainList() !== [] ? ['domain' => $this->domainList()] : [],
        ]);
        $row['last_import'] = (string) ($last['last_import'] ?? '');
        $row['last_day']    = (string) ($last['last_day'] ?? '');

        return self::withPct($row);
    }

    /** One row per domain with its state. */
    public function domains(): array
    {
        $rows = [];
        foreach (self::rows([
            'SELECT'  => array_merge(['r.domain'], self::sums(), [self::agg('MAX', 'r.day', 'last_day')]),
            'FROM'    => self::R . ' AS r',
            'WHERE'   => $this->where(),
            'GROUPBY' => ['r.domain'],
            'ORDER'   => ['total DESC'],
        ]) as $row) {
            $rows[$row['domain']] = self::withPct(self::numbers($row));
        }

        // failing messages by source classification
        foreach (self::rows([
            'SELECT'     => ['r.domain', 's.status', self::agg('SUM', 'r.count', 'm'), QueryFunction::count('r.sources_id', true, 'n')],
            'FROM'       => self::R . ' AS r',
            'INNER JOIN' => [Importer::T_SOURCES . ' AS s' => ['ON' => ['s' => 'id', 'r' => 'sources_id']]],
            'WHERE'      => array_merge($this->where(), [['r.dmarc_pass' => 0]]),
            'GROUPBY'    => ['r.domain', 's.status'],
        ]) as $row) {
            if (!isset($rows[$row['domain']])) {
                continue;
            }
            $keys = match ((int) $row['status']) {
                Diagnosis::SOURCE_AUTHORIZED   => ['auth_fail'],
                Diagnosis::SOURCE_FORWARDER    => ['fwd_fail'],
                Diagnosis::SOURCE_UNAUTHORIZED => ['bad_fail', 'susp_fail'],
                default                        => ['unk_fail', 'susp_fail'],
            };
            foreach ($keys as $k) {
                $rows[$row['domain']][$k]          = ($rows[$row['domain']][$k] ?? 0) + (int) $row['m'];
                $rows[$row['domain']][$k . '_src'] = ($rows[$row['domain']][$k . '_src'] ?? 0) + (int) $row['n'];
            }
        }

        // policy published in the latest report, and since when
        $policies = self::currentPolicies();
        $domains  = [];
        foreach (self::rows(['SELECT' => ['name', 'domains_id', 'target_policy', 'last_day'], 'FROM' => Importer::T_DOMAINS]) as $d) {
            $domains[$d['name']] = $d;
        }
        foreach ($rows as $name => &$row) {
            $row['domain']        = $name;
            $row['policy']        = $policies[$name] ?? ['p' => '', 'sp' => '', 'pct' => null, 'since' => ''];
            $row['domains_id']    = (int) ($domains[$name]['domains_id'] ?? 0);
            $row['target_policy'] = (string) ($domains[$name]['target_policy'] ?? '');
            $row['last_report']   = (string) ($domains[$name]['last_day'] ?? $row['last_day']);
            $row['days_silent']   = $row['last_report'] !== '' ? (int) floor((strtotime(date('Y-m-d')) - strtotime($row['last_report'])) / 86400) : null;
            foreach (['auth_fail', 'fwd_fail', 'susp_fail', 'unk_fail', 'bad_fail', 'auth_fail_src', 'fwd_fail_src', 'susp_fail_src', 'unk_fail_src', 'bad_fail_src'] as $k) {
                $row[$k] ??= 0;
            }
            // compliance of the traffic that may be ours: everything except
            // sources classified as unauthorized or forwarders
            $legit = $row['total'] - $row['bad_fail'] - $row['fwd_fail'];
            $row['legit_pct'] = Format::ratio($row['pass'], max(1, $legit));
            $row['state'] = self::state($row);
        }
        unset($row);

        return array_values($rows);
    }

    /**
     * Traffic light of a domain: ok | warning | danger, with a short reason.
     *
     * @return array{level:string, label:string, reasons:string[]}
     */
    public static function state(array $d): array
    {
        $reasons = [];
        $level   = 'ok';
        $silentDays = max(1, Settings::int('notify_no_reports_days'));
        if ($d['days_silent'] !== null && $d['days_silent'] > $silentDays) {
            $reasons[] = sprintf(_n('%d day without reports', '%d days without reports', (int) $d['days_silent'], 'dmarc'), $d['days_silent']);
            $level = 'warning';
        }
        if ($d['auth_fail'] > 0 && Format::ratio($d['auth_fail'], $d['total']) >= 1) {
            $reasons[] = __('authorized sources failing', 'dmarc');
            $level = 'danger';
        } elseif ($d['auth_fail'] > 0) {
            $reasons[] = __('occasional failures of authorized sources', 'dmarc');
            $level = $level === 'ok' ? 'warning' : $level;
        }
        if ($d['susp_fail'] > 0) {
            $p = $d['policy']['p'] ?? '';
            if ($p === 'none' || $p === '') {
                $reasons[] = __('possible spoofing and the policy does not stop it (p=none)', 'dmarc');
                $level = 'danger';
            } else {
                $reasons[] = sprintf(__('unknown sources (stopped by p=%s)', 'dmarc'), $p);
                $level = $level === 'ok' ? 'warning' : $level;
            }
        }
        if (($d['policy']['p'] ?? '') === 'none' && $level === 'ok') {
            $reasons[] = __('policy in monitoring mode (p=none)', 'dmarc');
            $level = 'warning';
        }
        $labels = ['ok' => __('Good', 'dmarc'), 'warning' => __('Review', 'dmarc'), 'danger' => __('Attention', 'dmarc')];

        return ['level' => $level, 'label' => $labels[$level], 'reasons' => $reasons];
    }

    /** name => [p, sp, pct, adkim, aspf, np, day, since] from the most recent report of each domain. */
    public static function currentPolicies(): array
    {
        $latest = self::rows([
            'SELECT'  => ['domain', self::agg('MAX', 'day', 'd')],
            'FROM'    => Importer::T_REPORTS,
            'GROUPBY' => ['domain'],
        ]);
        $out = [];
        foreach (array_chunk($latest, 200) as $chunk) {
            $or = [];
            foreach ($chunk as $l) {
                $or[] = ['domain' => $l['domain'], 'day' => $l['d']];
            }
            foreach (self::rows([
                'SELECT' => ['domain', 'p', 'sp', 'pct', 'adkim', 'aspf', 'np', 'day'],
                'FROM'   => Importer::T_REPORTS,
                'WHERE'  => ['OR' => $or],
                'ORDER'  => ['id DESC'],
            ]) as $row) {
                $out[$row['domain']] ??= $row;
            }
        }
        foreach (self::policyChanges() as $domain => $changes) {
            if (isset($out[$domain]) && $changes !== []) {
                $out[$domain]['since'] = end($changes)['day'];
            }
        }

        return $out;
    }

    /**
     * Changes of the published policy, as seen in the reports.
     *
     * @return array<string, list<array{day:string, p:string, sp:string, pct:?int, adkim:string, aspf:string}>>
     */
    public static function policyChanges(string $domain = ''): array
    {
        $list = self::parseDomains($domain);
        // one policy per domain and day (the most common one that day)
        $rows = self::rows([
            'SELECT'  => ['domain', 'day', 'p', 'sp', 'pct', 'adkim', 'aspf', QueryFunction::count('id', false, 'n')],
            'FROM'    => Importer::T_REPORTS,
            'WHERE'   => $list !== [] ? ['domain' => $list] : [],
            'GROUPBY' => ['domain', 'day', 'p', 'sp', 'pct', 'adkim', 'aspf'],
            'ORDER'   => ['domain', 'day', 'n DESC'],
        ]);
        $out  = [];
        $seen = [];
        foreach ($rows as $row) {
            $key = $row['domain'] . '|' . $row['day'];
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $sig  = implode('|', [$row['p'], $row['sp'], $row['pct'], $row['adkim'], $row['aspf']]);
            $list = $out[$row['domain']] ?? [];
            $last = $list === [] ? null : $list[count($list) - 1];
            if ($last === null || $last['sig'] !== $sig) {
                $list[] = [
                    'day' => $row['day'], 'p' => (string) $row['p'], 'sp' => (string) $row['sp'],
                    'pct' => $row['pct'] === null ? null : (int) $row['pct'],
                    'adkim' => (string) $row['adkim'], 'aspf' => (string) $row['aspf'], 'sig' => $sig,
                ];
            }
            $out[$row['domain']] = $list;
        }

        return $out;
    }

    /**
     * Volume by day / week / month.
     *
     * @return list<array>
     */
    public function timeline(string $group = 'day'): array
    {
        $day    = self::q('r.day');
        $bucket = new QueryExpression(match ($group) {
            'week'  => "DATE_SUB({$day}, INTERVAL WEEKDAY({$day}) DAY)",
            'month' => "DATE_FORMAT({$day}, '%Y-%m-01')",
            default => $day,
        } . ' AS ' . self::q('bucket'));
        $rows = [];
        foreach (self::rows([
            'SELECT'  => array_merge([$bucket], self::sums()),
            'FROM'    => self::R . ' AS r',
            'WHERE'   => $this->where(),
            'GROUPBY' => ['bucket'],
            'ORDER'   => ['bucket'],
        ]) as $row) {
            $rows[(string) $row['bucket']] = self::withPct(self::numbers($row)) + ['bucket' => (string) $row['bucket']];
        }

        // fill the gaps so that the charts show the silences
        $filled = [];
        $step   = match ($group) {
            'week'  => '+1 week',
            'month' => '+1 month',
            default => '+1 day',
        };
        $start = match ($group) {
            'week'  => date('Y-m-d', strtotime($this->from . ' -' . ((int) date('N', strtotime($this->from)) - 1) . ' days')),
            'month' => date('Y-m-01', strtotime($this->from)),
            default => $this->from,
        };
        $empty = self::withPct(self::numbers([]));
        for ($t = strtotime($start), $end = strtotime($this->to); $t <= $end; $t = strtotime($step, $t)) {
            $b = date('Y-m-d', $t);
            $filled[] = $rows[$b] ?? ($empty + ['bucket' => $b]);
        }

        return $filled;
    }

    /** Volume and compliance by reporting organisation. */
    public function reporters(): array
    {
        $out = [];
        foreach (self::rows([
            'SELECT'     => array_merge(['p.org_name', QueryFunction::count('p.id', true, 'reports')], self::sums(), [self::agg('MAX', 'p.day', 'last_day')]),
            'FROM'       => self::R . ' AS r',
            'INNER JOIN' => [Importer::T_REPORTS . ' AS p' => ['ON' => ['p' => 'id', 'r' => 'reports_id']]],
            'WHERE'      => $this->where(),
            'GROUPBY'    => ['p.org_name'],
            'ORDER'      => ['total DESC'],
        ]) as $row) {
            $out[] = self::withPct(self::numbers($row)) + ['org_name' => $row['org_name'], 'last_day' => $row['last_day']];
        }

        return $out;
    }

    /** Sending sources (one row per IP). */
    public function sources(int $status = -1, bool $onlyNew = false, string $search = ''): array
    {
        $where = $this->where();
        if ($status >= 0) {
            $where[] = ['s.status' => $status];
        }
        if ($onlyNew) {
            $where[] = ['s.first_seen' => ['>=', $this->from]];
        }
        if ($search !== '') {
            $like    = '%' . str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $search) . '%';
            $where[] = ['OR' => [['s.ip' => ['LIKE', $like]], ['s.ptr' => ['LIKE', $like]], ['s.sender' => ['LIKE', $like]]]];
        }
        $failCause = new QueryExpression('CASE WHEN ' . self::q('r.dmarc_pass') . ' = 0 THEN ' . self::q('r.cause') . ' END');
        $out = [];
        foreach (self::rows([
            'SELECT'     => array_merge(
                ['s.id', 's.ip', 's.ptr', 's.sender', 's.status', 's.comment', 's.first_seen', 's.last_seen'],
                self::SOURCE_FIELDS,
                self::sums(),
                [
                    QueryFunction::groupConcat('r.domain', ', ', true, ['r.domain'], 'domains'),
                    QueryFunction::groupConcat($failCause, ',', true, null, 'causes'),
                ]
            ),
            'FROM'       => self::R . ' AS r',
            'INNER JOIN' => [Importer::T_SOURCES . ' AS s' => ['ON' => ['s' => 'id', 'r' => 'sources_id']]],
            'WHERE'      => $where,
            'GROUPBY'    => ['s.id'],
            'ORDER'      => ['total DESC'],
            'LIMIT'      => 1000,
        ]) as $row) {
            $item = self::withPct(self::numbers($row));
            foreach (['id', 'ip', 'ptr', 'sender', 'status', 'comment', 'first_seen', 'last_seen', 'domains',
                'abuse_score', 'abuse_reports', 'abuse_country', 'abuse_isp', 'abuse_usage', 'abuse_domain', 'abuse_tor', 'abuse_date', 'abuse_error'] as $k) {
                $item[$k] = $row[$k];
            }
            $item['status'] = (int) $row['status'];
            $item['abuse_public'] = AbuseIpdb::isPublic((string) $row['ip']);
            $item['causes'] = array_values(array_filter(array_map('intval', explode(',', (string) $row['causes']))));
            $out[] = $item;
        }

        return $out;
    }

    /** Sources grouped by sender label (for the chart and the grouped view). */
    public function senders(): array
    {
        $groups = [];
        foreach ($this->sources() as $s) {
            $label = (string) ($s['sender'] ?: ($s['ptr'] ?: __('Unknown', 'dmarc')));
            $g = $groups[$label] ?? ['sender' => $label, 'total' => 0, 'pass' => 0, 'dkim' => 0, 'spf' => 0, 'ips' => 0, 'statuses' => []];
            foreach (['total', 'pass', 'dkim', 'spf'] as $k) {
                $g[$k] += $s[$k];
            }
            $g['ips']++;
            $g['statuses'][$s['status']] = true;
            $groups[$label] = $g;
        }
        $out = [];
        foreach ($groups as $g) {
            $g['statuses'] = array_keys($g['statuses']);
            $out[] = self::withPct($g);
        }
        usort($out, static fn($a, $b) => $b['total'] <=> $a['total']);

        return $out;
    }

    /** Failing messages grouped by cause. */
    public function causes(): array
    {
        $out = [];
        foreach (self::rows([
            'SELECT'  => ['r.cause', self::agg('SUM', 'r.count', 'total'), QueryFunction::count('r.sources_id', true, 'sources')],
            'FROM'    => self::R . ' AS r',
            'WHERE'   => $this->where(),
            'GROUPBY' => ['r.cause'],
            'ORDER'   => ['total DESC'],
        ]) as $row) {
            $out[] = ['cause' => (int) $row['cause'], 'total' => (int) $row['total'], 'sources' => (int) $row['sources']];
        }

        return $out;
    }

    /** Failing records grouped by cause + source + domain. */
    public function failures(int $cause = 0, string $ip = ''): array
    {
        $where = array_merge($this->where(), [['r.dmarc_pass' => 0]]);
        if ($cause > 0) {
            $where[] = ['r.cause' => $cause];
        }
        if ($ip !== '') {
            $where[] = ['r.ip' => $ip];
        }
        $out = [];
        foreach (self::rows([
            'SELECT'     => array_merge(
                ['r.cause', 'r.domain', 'r.sources_id', 's.ip', 's.ptr', 's.sender', 's.status'],
                self::SOURCE_FIELDS,
                [
                    self::agg('SUM', 'r.count', 'total'),
                    self::agg('MIN', 'r.day', 'first_day'),
                    self::agg('MAX', 'r.day', 'last_day'),
                    QueryFunction::groupConcat('r.header_from', ', ', true, null, 'header_from'),
                    QueryFunction::groupConcat('r.envelope_from', ', ', true, null, 'envelope_from'),
                    QueryFunction::groupConcat('r.dkim_domains', ' | ', true, null, 'dkim'),
                    QueryFunction::groupConcat('r.spf_domain', ' | ', true, null, 'spf'),
                    QueryFunction::groupConcat('r.disposition', ',', true, null, 'dispositions'),
                    QueryFunction::groupConcat('r.reasons', '; ', true, null, 'reasons'),
                ]
            ),
            'FROM'       => self::R . ' AS r',
            'INNER JOIN' => [Importer::T_SOURCES . ' AS s' => ['ON' => ['s' => 'id', 'r' => 'sources_id']]],
            'WHERE'      => $where,
            'GROUPBY'    => ['r.cause', 'r.domain', 'r.sources_id'],
            'ORDER'      => ['total DESC'],
            'LIMIT'      => 500,
        ]) as $row) {
            $row['cause']        = (int) $row['cause'];
            $row['status']       = (int) $row['status'];
            $row['abuse_public'] = AbuseIpdb::isPublic((string) $row['ip']);
            $row['total']        = (int) $row['total'];
            $out[] = $row;
        }

        return $out;
    }

    /** DKIM selectors / signing domains seen for our domains. */
    public function dkimSelectors(): array
    {
        return self::rows([
            'SELECT'     => [
                'r.domain', 'a.domain AS d', 'a.selector',
                self::agg('SUM', 'r.count', 'total'),
                new QueryExpression('SUM(CASE WHEN ' . self::q('a.result') . " = 'pass' THEN " . self::q('r.count') . ' ELSE 0 END) AS ' . self::q('pass')),
                self::agg('MAX', 'r.day', 'last_day'),
            ],
            'FROM'       => Importer::T_AUTH . ' AS a',
            'INNER JOIN' => [self::R . ' AS r' => ['ON' => ['r' => 'id', 'a' => 'records_id']]],
            'WHERE'      => array_merge($this->where(), [['a.type' => 'dkim']]),
            'GROUPBY'    => ['r.domain', 'a.domain', 'a.selector'],
            'ORDER'      => ['r.domain', 'total DESC'],
            'LIMIT'      => 300,
        ]);
    }

    /** Reports of the period (most recent first). */
    public function reports(int $limit = 200, int $offset = 0): array
    {
        $where = [['day' => ['>=', $this->from]], ['day' => ['<=', $this->to]]];
        if (($list = $this->domainList()) !== []) {
            $where[] = ['domain' => $list];
        }
        if ($this->org !== '') {
            $where[] = ['org_name' => $this->org];
        }
        $count = self::first(['SELECT' => [QueryFunction::count('id', false, 'n')], 'FROM' => Importer::T_REPORTS, 'WHERE' => $where]);

        return [
            'count' => (int) ($count['n'] ?? 0),
            'rows'  => self::rows([
                'SELECT' => ['id', 'org_name', 'report_id', 'domain', 'day', 'date_begin', 'date_end', 'p', 'sp', 'pct',
                    'total', 'pass', 'records', 'raw_file', 'errors'],
                'FROM'   => Importer::T_REPORTS,
                'WHERE'  => $where,
                'ORDER'  => ['day DESC', 'id DESC'],
                'LIMIT'  => max(1, $limit),
                'START'  => max(0, $offset),
            ]),
        ];
    }

    /** Domains and organisations available for the filters. */
    public static function filterOptions(): array
    {
        return [
            'domains' => array_column(self::rows(['SELECT' => 'name', 'FROM' => Importer::T_DOMAINS, 'ORDER' => 'name']), 'name'),
            'orgs'    => array_column(self::rows(['SELECT' => 'org_name', 'DISTINCT' => true, 'FROM' => Importer::T_REPORTS, 'ORDER' => 'org_name']), 'org_name'),
        ];
    }

    // --- helpers -----------------------------------------------------------

    public static function withPct(array $row): array
    {
        $t = (int) ($row['total'] ?? 0);
        foreach (['pass', 'dkim', 'spf'] as $k) {
            $row[$k . '_pct'] = Format::ratio((int) ($row[$k] ?? 0), $t);
        }

        return $row;
    }

    private static function numbers(array $row): array
    {
        foreach (['total', 'pass', 'dkim', 'spf', 'quarantine', 'reject', 'fail_none', 'reports', 'sources', 'domains'] as $k) {
            $row[$k] = (int) ($row[$k] ?? 0);
        }

        return $row;
    }

    /** Quoted column name ("r.day" → `r`.`day`). */
    public static function q(string $name): string
    {
        /** @var DBmysql $DB */
        global $DB;

        return $DB->quoteName($name);
    }

    /** FN(column) AS alias, with quoted names. */
    public static function agg(string $fn, string $column, string $alias): QueryExpression
    {
        return new QueryExpression($fn . '(' . self::q($column) . ') AS ' . self::q($alias));
    }

    /** All rows of a query-builder request. */
    public static function rows(array $criteria): array
    {
        /** @var DBmysql $DB */
        global $DB;

        return iterator_to_array($DB->request($criteria), false);
    }

    public static function first(array $criteria): ?array
    {
        /** @var DBmysql $DB */
        global $DB;

        $criteria['LIMIT'] ??= 1;

        return $DB->request($criteria)->current();
    }
}
