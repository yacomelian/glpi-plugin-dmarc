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

use Session;

/**
 * Variables of the dashboard template for a request (filters + tab).
 * Used by front/dashboard.php and by the "demo --render" command.
 */
final class Dashboard
{
    public static function build(array $get): array
    {
        // query parameters are scalars only (an array would break the casts)
        $get = array_filter($get, static fn($v, $k) => is_scalar($v) || $k === 'domain', ARRAY_FILTER_USE_BOTH);
        /** @var \DBmysql $DB */
        global $DB;

        $tabs = [
            'summary'         => [__('Summary', 'dmarc'), 'ti ti-layout-dashboard'],
            'evolution'       => [__('Evolution', 'dmarc'), 'ti ti-chart-line'],
            'sources'         => [__('Sending sources', 'dmarc'), 'ti ti-server'],
            'failures'        => [__('Failures', 'dmarc'), 'ti ti-alert-triangle'],
            'recommendations' => [__('Recommendations', 'dmarc'), 'ti ti-bulb'],
            'reports'         => [__('Reports', 'dmarc'), 'ti ti-file-text'],
            'alerts'          => [__('Alerts', 'dmarc'), 'ti ti-bell'],
            'collection'      => [__('Collection', 'dmarc'), 'ti ti-mail-down'],
        ];

        $tab = (string) ($get['tab'] ?? 'summary');
        if (!isset($tabs[$tab])) {
            $tab = 'summary';
        }

        // --- filters -----------------------------------------------------------------
        $period = (string) ($get['period'] ?? '30');
        // one or several domains ("a.es,b.es"); all of them selected = no filter
        $selected = Stats::parseDomains($get['domain'] ?? '');
        $known    = Stats::filterOptions()['domains'];
        if ($known !== [] && array_diff($known, $selected) === []) {
            $selected = [];
        }
        $domain = implode(',', $selected);
        $org    = trim((string) ($get['org'] ?? ''));
        $from   = (string) ($get['from'] ?? '');
        $to     = (string) ($get['to'] ?? '');
        $valid  = static fn(string $d): bool => preg_match('/^\d{4}-\d{2}-\d{2}$/', $d) === 1 && strtotime($d) !== false;
        if ($period === 'custom' && $valid($from) && $valid($to)) {
            if ($from > $to) {
                [$from, $to] = [$to, $from];
            }
            $stats = new Stats($from, $to, $domain, $org);
        } else {
            $period = in_array($period, ['7', '30', '90', '365', '730', '0'], true) ? $period : '30';
            $stats  = Stats::forDays((int) $period, $domain, $org);
        }
        $days  = $stats->days();
        $group = (string) ($get['group'] ?? '');
        if (!in_array($group, ['day', 'week', 'month'], true)) {
            $group = $days <= 92 ? 'day' : ($days <= 400 ? 'week' : 'month');
        }
        $filters = ['period' => $period, 'domain' => $domain, 'org' => $org, 'from' => $stats->from, 'to' => $stats->to, 'group' => $group];

        // --- data of the tab ---------------------------------------------------------
        $data   = [];
        $charts = [];

        switch ($tab) {
            case 'summary':
                $totals   = $stats->totals();
                $prev     = $stats->previous()->totals();
                $domains  = $stats->domains();
                $timeline = $stats->timeline($group);
                $causes   = $stats->causes();
                $data = [
                    'totals'  => $totals,
                    'prev'    => $prev,
                    'domains' => $domains,
                    'recs'    => array_slice(Advisor::recommendations($stats, $domains), 0, 6),
                    'alerts'  => countElementsInTable(Alert::getTable(), ['status' => Alert::OPEN, 'NOT' => ['event' => 'summary']]),
                    'configured' => Settings::isMailboxConfigured(),
                    'empty'   => (int) countElementsInTable('glpi_plugin_dmarc_reports') === 0,
                ];
                $charts['volume'] = ['type' => 'volume', 'rows' => $timeline];
                $charts['causes'] = ['type' => 'causes', 'rows' => array_map(static fn($c) => ['name' => Diagnosis::label($c['cause']), 'value' => $c['total'], 'pass' => Diagnosis::isPass($c['cause'])], $causes)];
                break;

            case 'evolution':
                $timeline = $stats->timeline($group);
                $data = [
                    'policies'  => Stats::policyChanges($domain),
                    'reporters' => $stats->reporters(),
                ];
                $charts['volume']     = ['type' => 'volume', 'rows' => $timeline];
                $charts['compliance'] = ['type' => 'compliance', 'rows' => $timeline];
                $charts['reporters']  = ['type' => 'bars', 'rows' => array_map(static fn($r) => ['name' => $r['org_name'], 'value' => $r['total']], array_slice($data['reporters'], 0, 12))];
                break;

            case 'sources':
                $status  = isset($get['status']) && $get['status'] !== '' ? (int) $get['status'] : -1;
                $onlyNew = !empty($get['new']);
                $search  = trim((string) ($get['q'] ?? ''));
                $view    = ($get['view'] ?? '') === 'senders' ? 'senders' : 'ips';
                $data = [
                    'status'  => $status,
                    'new'     => $onlyNew,
                    'q'       => $search,
                    'view'    => $view,
                    'sources' => $view === 'ips' ? $stats->sources($status, $onlyNew, $search) : [],
                    'senders' => $stats->senders(),
                ];
                $charts['senders'] = ['type' => 'senders', 'rows' => array_slice($data['senders'], 0, 12)];
                break;

            case 'failures':
                $cause = (int) ($get['cause'] ?? 0);
                $ip    = trim((string) ($get['q'] ?? ''));
                $ip    = filter_var($ip, FILTER_VALIDATE_IP) !== false ? $ip : '';
                $data = [
                    'cause'     => $cause,
                    'ip'        => $ip,
                    'causes'    => $stats->causes(),
                    'failures'  => $stats->failures($cause, $ip),
                    'selectors' => $stats->dkimSelectors(),
                ];
                foreach ($data['failures'] as &$f) {
                    $f['explain'] = Diagnosis::explain($f['cause'], $f['status']);
                }
                unset($f);
                break;

            case 'recommendations':
                $domains = $stats->domains();
                $data = ['recs' => Advisor::recommendations($stats, $domains), 'domains' => $domains];
                break;

            case 'reports':
                $page = max(0, (int) ($get['page'] ?? 0));
                $data = $stats->reports(100, $page * 100) + ['page' => $page];
                break;

            case 'alerts':
                $closed = !empty($get['closed']);
                $alerts = [];
                foreach ($DB->request([
                    'FROM'  => Alert::getTable(),
                    'WHERE' => $closed ? [] : ['status' => Alert::OPEN],
                    'ORDER' => 'date_mod DESC',
                    'LIMIT' => 300,
                ]) as $row) {
                    $row['event_label'] = Alert::eventLabel((string) $row['event']);
                    $alerts[] = $row;
                }
                $data = ['alerts' => $alerts, 'closed' => $closed, 'notify' => (bool) Settings::int('notify_enabled')];
                break;

            case 'collection':
                $mstatus  = isset($get['mstatus']) && $get['mstatus'] !== '' ? (int) $get['mstatus'] : -1;
                $messages = [];
                foreach ($DB->request([
                    'FROM'  => Importer::T_MESSAGES,
                    'WHERE' => $mstatus >= 0 ? ['status' => $mstatus] : [],
                    'ORDER' => 'id DESC',
                    'LIMIT' => 200,
                ]) as $row) {
                    $messages[] = $row;
                }
                $counts = [];
                foreach ($DB->request(['SELECT' => ['status', 'COUNT' => 'id AS n'], 'FROM' => Importer::T_MESSAGES, 'GROUPBY' => 'status']) as $row) {
                    $counts[(int) $row['status']] = (int) $row['n'];
                }
                $s = Settings::all();
                $data = [
                    'messages'   => $messages,
                    'counts'     => $counts,
                    'mstatus'    => $mstatus,
                    'configured' => Settings::isMailboxConfigured(),
                    'mailbox'    => [
                        'host' => $s['host'], 'port' => $s['port'], 'username' => $s['username'], 'folder' => $s['folder'],
                        'auth' => $s['auth'], 'mode' => $s['mode'], 'post_action' => $s['post_action'], 'move_folder' => $s['move_folder'],
                    ],
                    'state'      => [
                        'last_run' => $s['state_last_run'], 'last_ok' => $s['state_last_ok'], 'last_error' => $s['state_last_error'],
                        'errors' => (int) $s['state_error_count'], 'uidvalidity' => (int) $s['state_uidvalidity'], 'last_uid' => (int) $s['state_last_uid'],
                    ],
                    'worker'     => Worker::status(),
                ];
                break;
        }

        return [
            'root'       => Ui::root(),
            'self'       => Ui::root() . '/plugins/dmarc/front/dashboard.php',
            'action_url' => Ui::root() . '/plugins/dmarc/front/action.php',
            'report_url' => Ui::root() . '/plugins/dmarc/front/report.php',
            'config_url' => Session::haveRight('config', UPDATE) ? Ui::root() . '/plugins/dmarc/front/config.form.php' : '',
            'asset_ver'  => Ui::assetVersion(),
            'csrf'       => Ui::csrf(),
            'can_update' => Menu::canUpdate(),
            'tabs'       => $tabs,
            'tab'        => $tab,
            'filters'    => $filters,
            'options'    => Stats::filterOptions(),
            'selected_domains' => $selected,
            'data'       => $data,
            'charts'     => $charts,
            'cause_labels'    => Ui::causeLabels(),
            'source_statuses' => Ui::sourceStatuses(),
            'message_statuses' => Ui::messageStatuses(),
        ];
    }
}
