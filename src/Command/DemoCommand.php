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

/*
 * DMARC plugin for GLPI — DEVELOPMENT ONLY (not deployed to production)
 */

namespace GlpiPlugin\Dmarc\Command;

use Glpi\Console\AbstractCommand;
use Glpi\DBAL\QuerySubQuery;
use GlpiPlugin\Dmarc\Collector;
use GlpiPlugin\Dmarc\Diagnosis;
use GlpiPlugin\Dmarc\GoogleAuth;
use GlpiPlugin\Dmarc\Imap;
use GlpiPlugin\Dmarc\Importer;
use GlpiPlugin\Dmarc\Mime;
use GlpiPlugin\Dmarc\ReportParser;
use GlpiPlugin\Dmarc\Settings;
use GlpiPlugin\Dmarc\Stats;
use GlpiPlugin\Dmarc\Watcher;
use RuntimeException;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Synthetic data and self-test. Only plugin tables are written.
 *
 *   php bin/console plugins:dmarc:demo --create [--days=365]
 *   php bin/console plugins:dmarc:demo --purge
 *   php bin/console plugins:dmarc:demo --selftest
 *   php bin/console plugins:dmarc:demo --eml=/tmp/dmarc [--days=30]   (only write the mails)
 *
 * The demo domains are fictitious (*.example) and every demo mail is stored
 * with source "demo", so --purge removes exactly that.
 */
final class DemoCommand extends AbstractCommand
{
    private const DOMAINS = ['corp-demo.example', 'news-demo.example', 'portal-demo.example'];

    private const REPORTERS = [
        ['google.com', 'noreply-dmarc-support@google.com', 'google', 0.55],
        ['Outlook.com', 'dmarcreport@microsoft.com', 'microsoft', 0.33],
        ['Yahoo', 'dmarchelp@yahooinc.com', 'yahoo', 0.12],
    ];

    protected function configure(): void
    {
        $this->setName('plugins:dmarc:demo');
        $this->setDescription('DMARC: synthetic data and self-test (development only)');
        $this->addOption('create', null, InputOption::VALUE_NONE, 'Create a year of synthetic reports');
        $this->addOption('purge', null, InputOption::VALUE_NONE, 'Delete the synthetic data');
        $this->addOption('selftest', null, InputOption::VALUE_NONE, 'Self-test (parser, simulated IMAP, Google and AbuseIPDB)');
        $this->addOption('days', null, InputOption::VALUE_REQUIRED, 'Days of data', '365');
        $this->addOption('eml', null, InputOption::VALUE_REQUIRED, 'Write the .eml mails to this folder instead of importing them');
        $this->addOption('render', null, InputOption::VALUE_REQUIRED, 'Render the tabs to HTML files in this folder (to review them without the web)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if ($input->getOption('render')) {
            return $this->render((string) $input->getOption('render'), $output);
        }
        if ($input->getOption('purge')) {
            $n = self::purge();
            $output->writeln("<info>Deleted {$n} demo reports.</info>");
        }
        if ($input->getOption('create') || $input->getOption('eml')) {
            $this->create(max(7, (int) $input->getOption('days')), $output, (string) $input->getOption('eml'));
        }
        if ($input->getOption('selftest')) {
            return $this->selftest($output);
        }
        if (!$input->getOption('purge') && !$input->getOption('create') && !$input->getOption('eml')) {
            $output->writeln('Use --create, --purge, --selftest, --render=DIR or --eml=DIR');
        }

        return 0;
    }

    // --- render ------------------------------------------------------------

    private function render(string $dir, OutputInterface $output): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        if (!is_dir($dir) && !mkdir($dir, 0o777, true)) {
            throw new RuntimeException("Cannot create {$dir}");
        }
        $tpl   = \Glpi\Application\View\TemplateRenderer::getInstance();
        $wrap  = static fn(string $title, string $body) => '<!doctype html><html lang="es"><head><meta charset="utf-8"><title>' . htmlspecialchars($title) . '</title>'
            . '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0/dist/css/tabler.min.css">'
            . '<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">'
            . '<script src="https://cdnjs.cloudflare.com/ajax/libs/echarts/5.5.1/echarts.min.js"></script>'
            . '<script src="https://cdn.jsdelivr.net/npm/@tabler/core@1.0.0/dist/js/tabler.min.js"></script>'
            . '</head><body class="p-3">' . $body . '</body></html>';
        $fix = static function (string $html): string {
            $html = str_replace('/plugins/dmarc/js/dmarc.js', 'dmarc.js', $html);
            // links between tabs → the rendered files
            return (string) preg_replace_callback('#/plugins/dmarc/front/dashboard\.php\?([^"\']*)#', static function ($m) {
                parse_str(html_entity_decode($m[1]), $q);

                return 'dashboard-' . preg_replace('/\W/', '', (string) ($q['tab'] ?? 'summary')) . '.html';
            }, $html);
        };
        $pages = [
            'summary'         => ['tab' => 'summary', 'period' => '90'],
            'evolution'       => ['tab' => 'evolution', 'period' => '365'],
            'sources'         => ['tab' => 'sources', 'period' => '90'],
            'failures'        => ['tab' => 'failures', 'period' => '365'],
            'recommendations' => ['tab' => 'recommendations', 'period' => '90'],
            'reports'         => ['tab' => 'reports', 'period' => '30'],
            'alerts'          => ['tab' => 'alerts', 'closed' => 1],
            'collection'      => ['tab' => 'collection'],
        ];
        // several domains selected (when there are at least three)
        $doms = Stats::filterOptions()['domains'];
        if (count($doms) > 2) {
            $pages['summary-multi'] = ['tab' => 'summary', 'period' => '90', 'domain' => $doms[0] . ',' . $doms[1]];
        }
        foreach ($pages as $name => $get) {
            $html = $tpl->render('@dmarc/dashboard.html.twig', \GlpiPlugin\Dmarc\Dashboard::build($get));
            file_put_contents("{$dir}/dashboard-{$name}.html", $wrap('DMARC ' . $name, $fix($html)));
            $output->writeln("  dashboard-{$name}.html");
        }
        copy(dirname(__DIR__, 2) . '/public/js/dmarc.js', $dir . '/dmarc.js');

        $report = $DB->request(['FROM' => Importer::T_REPORTS, 'ORDER' => ['records DESC'], 'LIMIT' => 1])->current();
        if ($report !== null) {
            $records = [];
            foreach ($DB->request([
                'SELECT' => ['r.*', 's.ptr', 's.sender', 's.status AS source_status', 's.abuse_score', 's.abuse_reports', 's.abuse_country', 's.abuse_isp', 's.abuse_usage', 's.abuse_domain', 's.abuse_tor', 's.abuse_date', 's.abuse_error'],
                'FROM' => Importer::T_RECORDS . ' AS r',
                'LEFT JOIN' => [Importer::T_SOURCES . ' AS s' => ['ON' => ['r' => 'sources_id', 's' => 'id']]],
                'WHERE' => ['r.reports_id' => $report['id']],
            ]) as $row) {
                $row['auth'] = iterator_to_array($DB->request(['FROM' => Importer::T_AUTH, 'WHERE' => ['records_id' => $row['id']]]), false);
                $row['abuse_public'] = \GlpiPlugin\Dmarc\AbuseIpdb::isPublic((string) $row['ip']);
    $row['explain'] = Diagnosis::isPass((int) $row['cause']) ? '' : Diagnosis::explain((int) $row['cause'], (int) $row['source_status']);
                $records[] = $row;
            }
            $html = $tpl->render('@dmarc/report.html.twig', [
                'report' => $report, 'records' => $records, 'message' => null, 'has_raw' => Importer::readRaw($report) !== null,
                'self' => 'report.php', 'dashboard' => 'dashboard-reports.html',
                'cause_labels' => \GlpiPlugin\Dmarc\Ui::causeLabels(), 'source_statuses' => \GlpiPlugin\Dmarc\Ui::sourceStatuses(),
            ]);
            file_put_contents("{$dir}/report.html", $wrap('Informe', $html));
            $output->writeln('  report.html');
        }

        $html = $tpl->render('@dmarc/config.html.twig', [
            'action' => 'config.form.php', 'dashboard' => 'dashboard-summary.html', 'csrf' => '', 's' => Settings::all(),
            'has_password' => false, 'has_oauth_secret' => true, 'oauth_connected' => true,
            'redirect_uri' => 'https://glpi.corp.example/plugins/dmarc/front/oauth.php',
            'scope' => GoogleAuth::SCOPE, 'max_months' => Settings::MAX_RETENTION_MONTHS,
            'test' => ['ok' => true, 'folders' => ['INBOX', 'DMARC', 'DMARC/Procesados', '[Gmail]/Enviados'], 'folder_exists' => true,
                'exists' => 2530, 'uidvalidity' => 1, 'pending' => 12, 'move_folder_exists' => null],
            'notifications_url' => '#',
            'abuseipdb' => ['own_key' => true, 'used_today' => 37, 'blocked_until' => '', 'known' => 180, 'sources' => 190],
            'entities' => \GlpiPlugin\Dmarc\Ui::entities(),
        ]);
        file_put_contents("{$dir}/config.html", $wrap('Configuration', $html));
        $output->writeln('  config.html');

        return 0;
    }

    // --- demo data ---------------------------------------------------------

    /** Sending sources of the scenario. */
    private static function sources(): array
    {
        return [
            // key => [ip, ptr-like label, status after creation, comment]
            'google1' => ['209.85.220.41', Diagnosis::SOURCE_AUTHORIZED, 'Google Workspace'],
            'google2' => ['209.85.220.69', Diagnosis::SOURCE_AUTHORIZED, 'Google Workspace'],
            'google6' => ['2a00:1450:4864:20::62a', Diagnosis::SOURCE_AUTHORIZED, 'Google Workspace'],
            'relay'   => ['203.0.113.10', Diagnosis::SOURCE_AUTHORIZED, 'SMTP relay of internal applications'],
            'news'    => ['198.51.100.25', Diagnosis::SOURCE_AUTHORIZED, 'Newsletter (SendGrid)'],
            'ses'     => ['198.51.100.77', Diagnosis::SOURCE_UNKNOWN, ''],
            'list'    => ['192.0.2.50', Diagnosis::SOURCE_FORWARDER, 'Partner mailing list'],
            'bad'     => ['203.0.113.200', Diagnosis::SOURCE_UNAUTHORIZED, 'Recurring spoofing'],
        ];
    }

    private function create(int $days, OutputInterface $output, string $emlDir): void
    {
        if ($emlDir !== '' && !is_dir($emlDir) && !mkdir($emlDir, 0o777, true)) {
            throw new RuntimeException("Cannot create {$emlDir}");
        }
        mt_srand(20261113);
        $importer = Importer::fromSettings();
        $today    = strtotime(date('Y-m-d') . ' 00:00:00 UTC');
        $count    = 0;
        $reports  = 0;
        $src      = self::sources();

        for ($d = $days; $d >= 1; $d--) {
            $begin = $today - $d * 86400;
            $end   = $begin + 86399;
            $dow   = (int) gmdate('N', $begin);

            foreach (self::DOMAINS as $domain) {
                // portal-demo stopped receiving reports 6 days ago (alert "no reports")
                if ($domain === 'portal-demo.example' && $d < 6) {
                    continue;
                }
                [$p, $sp, $pct] = self::policy($domain, $d);
                $disp = static fn(bool $pass) => $pass ? 'none' : ($p === 'none' ? 'none' : (mt_rand(1, 100) <= ($pct ?? 100) ? $p : 'none'));

                // traffic of the day for this domain, split later among reporters
                $traffic = [];
                $weekday = $dow <= 5 ? 1.0 : 0.35;
                $g = (int) round(mt_rand(150, 320) * $weekday * ($domain === 'corp-demo.example' ? 1.6 : 0.6));
                $traffic[] = ['google1', (int) ($g * 0.6), true, true, [[$domain, 'google', 'pass']], [[$domain, 'pass']], $domain];
                $traffic[] = ['google2', (int) ($g * 0.3), true, true, [[$domain, 'google', 'pass']], [[$domain, 'pass']], $domain];
                $traffic[] = ['google6', (int) ($g * 0.1), true, true, [[$domain, 'google', 'pass']], [[$domain, 'pass']], $domain];
                if ($domain === 'corp-demo.example') {
                    $traffic[] = ['relay', (int) round(mt_rand(20, 60) * $weekday), false, true, [], [[$domain, 'pass']], $domain];
                }
                if ($domain === 'news-demo.example' && $dow === 2) {
                    // weekly newsletter: DKIM with the provider's domain until it was fixed 120 days ago
                    $fixed = $d < 120;
                    $traffic[] = ['news', mt_rand(700, 900), $fixed, false,
                        $fixed ? [[$domain, 's1', 'pass'], ['sendgrid.net', 'smtpapi', 'pass']] : [['sendgrid.net', 'smtpapi', 'pass']],
                        [['em1234.sendgrid.net', 'pass']], 'em1234.sendgrid.net'];
                }
                if ($domain === 'portal-demo.example') {
                    // appointments app on Amazon SES, not classified, DKIM aligned only in the last 60 days
                    $ok = $d < 60;
                    $traffic[] = ['ses', (int) round(mt_rand(15, 45) * $weekday), $ok, false,
                        $ok ? [[$domain, 'ses2026', 'pass'], ['amazonses.com', 'ug7nbtf4', 'pass']] : [['amazonses.com', 'ug7nbtf4', 'pass']],
                        [['eu-west-1.amazonses.com', 'pass']], 'eu-west-1.amazonses.com'];
                }
                if (mt_rand(1, 3) === 1) {
                    $traffic[] = ['list', mt_rand(1, 8), false, false, [[$domain, 'google', 'fail']], [['lists.femp-demo.example', 'pass']], 'lists.femp-demo.example', ['mailing_list']];
                }
                // spoofing: background noise and some bursts
                $burst = mt_rand(1, 40) === 1 ? mt_rand(200, 900) : 0;
                $noise = mt_rand(0, 3) === 0 ? mt_rand(1, 25) : 0;
                if ($noise + $burst > 0) {
                    $ip = mt_rand(0, 1) ? '203.0.113.' . mt_rand(129, 250) : '198.51.100.' . mt_rand(129, 250);
                    $traffic[] = ['@' . $ip, $noise + $burst, false, false, [], [['mail.' . ['bulk-demo.example', 'mx-demo.test', 'spam-demo.example'][mt_rand(0, 2)], mt_rand(0, 1) ? 'fail' : 'softfail']], ''];
                }
                if ($d % 9 === 0) {
                    $traffic[] = ['bad', mt_rand(5, 60), false, false, [], [[$domain, 'fail']], $domain];
                }

                foreach (self::REPORTERS as [$org, $email, $style, $share]) {
                    if ($org === 'Yahoo' && mt_rand(1, 3) > 1) {
                        continue;
                    }
                    $records = [];
                    foreach ($traffic as $tr) {
                        [$key, $n, $dkimOk, $spfOk, $adkim, $aspf, $envFrom] = $tr;
                        $reasons = $tr[7] ?? [];
                        $n = (int) round($n * $share * (mt_rand(80, 120) / 100));
                        if ($n <= 0) {
                            continue;
                        }
                        $pass = $dkimOk || $spfOk;
                        $records[] = [
                            'ip'            => str_starts_with($key, '@') ? substr($key, 1) : $src[$key][0],
                            'count'         => $n,
                            'disposition'   => $disp($pass),
                            'dkim'          => $dkimOk ? 'pass' : 'fail',
                            'spf'           => $spfOk ? 'pass' : 'fail',
                            'header_from'   => $domain,
                            'envelope_from' => $envFrom,
                            'reasons'       => $reasons,
                            'auth_dkim'     => $adkim,
                            'auth_spf'      => $aspf,
                        ];
                    }
                    if ($records === []) {
                        continue;
                    }
                    $report = [
                        'org' => $org, 'email' => $email, 'domain' => $domain,
                        'id' => 'demo-' . strtolower(preg_replace('/\W/', '', $org)) . '-' . $domain . '-' . gmdate('Ymd', $begin),
                        'begin' => $begin, 'end' => $end, 'p' => $p, 'sp' => $sp, 'pct' => $pct, 'adkim' => 'r', 'aspf' => 'r',
                        'records' => $records,
                    ];
                    $xml  = Samples::xml($report, $org === 'Yahoo');
                    $mail = Samples::mail($report, $xml, $style);
                    if ($emlDir !== '') {
                        file_put_contents(sprintf('%s/%s-%s-%s.eml', $emlDir, gmdate('Ymd', $begin), $style, $domain), $mail);
                    } else {
                        $res = $importer->importMail($mail, ['source' => 'demo']);
                        $reports += $res['reports'];
                    }
                    $count++;
                }
            }
            if ($d % 30 === 0) {
                $output->writeln(sprintf('  … %s: %d mails', gmdate('Y-m-d', $begin), $count));
            }
        }

        if ($emlDir !== '') {
            $output->writeln("<info>{$count} mails written to {$emlDir}</info>");

            return;
        }

        // classification of the scenario's sources and PTR/sender as the resolver would leave them
        /** @var \DBmysql $DB */
        global $DB;
        $ptrs = [
            '209.85.220.41' => 'mail-sor-f41.google.com', '209.85.220.69' => 'mail-sor-f69.google.com',
            '2a00:1450:4864:20::62a' => 'mail-ej1-x62a.google.com', '203.0.113.10' => 'smtp.corp-demo.example',
            '198.51.100.25' => 'o1.ptr1234.sendgrid.net', '198.51.100.77' => 'a77-12.smtp-out.eu-west-1.amazonses.com',
            '192.0.2.50' => 'lists.femp-demo.example',
        ];
        foreach (self::sources() as [$ip, $status, $comment]) {
            $ptr = $ptrs[$ip] ?? '';
            $DB->update('glpi_plugin_dmarc_sources', [
                'status'   => $status,
                'comment'  => $comment ?: null,
                'ptr'      => $ptr ?: null,
                'ptr_date' => date('Y-m-d H:i:s'),
                'sender'   => mb_substr(Diagnosis::sender($ip, $ptr, [], ''), 0, 64) ?: null,
            ], ['ip' => $ip]);
        }
        $DB->update('glpi_plugin_dmarc_sources', ['ptr_date' => date('Y-m-d H:i:s')], ['ptr_date' => null, 'ip' => ['LIKE', '203.0.113.%']]);
        $DB->update('glpi_plugin_dmarc_sources', ['ptr_date' => date('Y-m-d H:i:s')], ['ptr_date' => null, 'ip' => ['LIKE', '198.51.100.%']]);
        $DB->update('glpi_plugin_dmarc_domains', ['target_policy' => 'reject'], ['name' => 'corp-demo.example']);

        // AbuseIPDB as the background job would leave it (no network in development)
        $known = [
            '209.85.220.41' => [0, 'US', 'Google LLC', 'Search Engine Spider', 'google.com'],
            '209.85.220.69' => [0, 'US', 'Google LLC', 'Search Engine Spider', 'google.com'],
            '2a00:1450:4864:20::62a' => [0, 'IE', 'Google LLC', 'Search Engine Spider', 'google.com'],
            '198.51.100.25' => [0, 'US', 'SendGrid Inc.', 'Data Center/Web Hosting/Transit', 'sendgrid.com'],
            '198.51.100.77' => [2, 'IE', 'Amazon.com, Inc.', 'Data Center/Web Hosting/Transit', 'amazon.com'],
            '192.0.2.50'    => [0, 'ES', 'RedIRIS', 'University/College/School', 'rediris.es'],
            '203.0.113.200' => [100, 'RU', 'Hosting Demo LLC', 'Data Center/Web Hosting/Transit', 'hosting-demo.example'],
        ];
        $isps = [['CN', 'China Telecom', 'cn-telecom-demo.example'], ['BR', 'Vivo', 'vivo-demo.example'], ['VN', 'VNPT', 'vnpt-demo.example'],
            ['US', 'DigitalOcean, LLC', 'digitalocean.com'], ['NL', 'Hosting Holanda BV', 'nl-hosting-demo.example']];
        foreach ($DB->request(['SELECT' => ['id', 'ip', 'sender'], 'FROM' => 'glpi_plugin_dmarc_sources']) as $row) {
            $ip = (string) $row['ip'];
            if (isset($known[$ip])) {
                [$score, $cc, $isp, $usage, $dom] = $known[$ip];
            } elseif (str_starts_with($ip, '203.0.113.') || str_starts_with($ip, '198.51.100.')) {
                [$cc, $isp, $dom] = $isps[crc32($ip) % count($isps)];
                $score = [0, 12, 35, 68, 100][crc32($ip . 'x') % 5];
                $usage = 'Data Center/Web Hosting/Transit';
            } else {
                continue;
            }
            $update = \GlpiPlugin\Dmarc\AbuseIpdb::toFields([
                'abuseConfidenceScore' => $score, 'totalReports' => $score * 4, 'numDistinctUsers' => intdiv($score, 2),
                'countryCode' => $cc, 'isp' => $isp, 'usageType' => $usage, 'domain' => $dom,
                'lastReportedAt' => $score > 0 ? date('c', strtotime('-3 days')) : null,
            ]) + ['abuse_date' => date('Y-m-d H:i:s')];
            if ((string) $row['sender'] === '') {
                $update['sender'] = mb_substr($isp, 0, 64);
            }
            $DB->update('glpi_plugin_dmarc_sources', $update, ['id' => $row['id']]);
        }

        $alerts = Watcher::afterImport() + Watcher::daily();
        $output->writeln("<info>{$count} demo mails, {$reports} new reports, {$alerts} alerts.</info>");
    }

    /** Policy timeline of each demo domain (days ago → p, sp, pct). */
    private static function policy(string $domain, int $daysAgo): array
    {
        return match ($domain) {
            'corp-demo.example' => match (true) {
                $daysAgo > 170 => ['none', '', null],
                $daysAgo > 120 => ['quarantine', '', 25],
                $daysAgo > 40  => ['quarantine', '', null],
                default        => ['reject', '', null],
            },
            'news-demo.example' => ['none', '', null],
            default => ['quarantine', 'none', null],
        };
    }

    public static function purge(): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $msgIds = array_column(iterator_to_array($DB->request(['SELECT' => ['id'], 'FROM' => Importer::T_MESSAGES, 'WHERE' => ['source' => ['demo', 'selftest']]]), false), 'id');
        $repIds = [];
        foreach (array_chunk($msgIds, 1000) as $chunk) {
            foreach ($DB->request(['SELECT' => ['id'], 'FROM' => Importer::T_REPORTS, 'WHERE' => ['messages_id' => $chunk]]) as $row) {
                $repIds[] = (int) $row['id'];
            }
        }
        // demo domains imported some other way (.eml written with --eml and imported by hand)
        foreach ($DB->request(['SELECT' => ['id', 'messages_id'], 'FROM' => Importer::T_REPORTS, 'WHERE' => ['domain' => ['LIKE', '%-demo.example']]]) as $row) {
            $repIds[] = (int) $row['id'];
            $msgIds[] = (int) $row['messages_id'];
        }
        foreach ($DB->request(['SELECT' => ['id'], 'FROM' => Importer::T_MESSAGES, 'WHERE' => ['filename' => ['LIKE', '%-demo.example.eml']]]) as $row) {
            $msgIds[] = (int) $row['id'];
        }
        $repIds = array_values(array_unique($repIds));
        $msgIds = array_values(array_unique($msgIds));
        Importer::deleteReports($repIds);
        foreach (array_chunk($msgIds, 1000) as $chunk) {
            $DB->delete(Importer::T_MESSAGES, ['id' => $chunk]);
        }
        self::deleteOrphanSources();
        $DB->delete(Importer::T_DOMAINS, ['NOT' => ['name' => new QuerySubQuery(['SELECT' => 'domain', 'DISTINCT' => true, 'FROM' => Importer::T_REPORTS])]]);
        $DB->delete('glpi_plugin_dmarc_alerts', ['OR' => [
            ['domain' => ['LIKE', '%-demo.example']],
            ['domain' => ['LIKE', '%.selftest.example']],
            ['event' => 'summary', 'payload' => ['LIKE', '%-demo.example%']],
        ]]);

        return count($repIds);
    }

    // --- self-test ---------------------------------------------------------

    private function selftest(OutputInterface $output): int
    {
        $ok = 0;
        $fail = 0;
        $check = function (string $name, callable $fn) use ($output, &$ok, &$fail): void {
            try {
                $fn();
                $output->writeln("  <info>OK</info>   {$name}");
                $ok++;
            } catch (\Throwable $e) {
                $output->writeln("  <error>FAIL</error> {$name}: " . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ')');
                $fail++;
            }
        };
        $assert = static function (bool $c, string $msg): void {
            if (!$c) {
                throw new RuntimeException($msg);
            }
        };

        $domain = 'corp.selftest.example';
        $mk = static fn(string $id, int $daysAgo = 2) => [
            'org' => 'Selftest Org', 'email' => 'dmarc@selftest.example', 'id' => $id . '-' . bin2hex(random_bytes(4)),
            'begin' => strtotime('-' . $daysAgo . ' days 00:00:00 UTC'), 'end' => strtotime('-' . $daysAgo . ' days 23:59:59 UTC'),
            'domain' => $domain, 'p' => 'quarantine', 'sp' => '', 'pct' => 50, 'adkim' => 'r', 'aspf' => 's',
            'records' => [
                ['ip' => '192.0.2.1', 'count' => 10, 'disposition' => 'none', 'dkim' => 'pass', 'spf' => 'pass', 'header_from' => $domain,
                    'envelope_from' => $domain, 'auth_dkim' => [[$domain, 'sel1', 'pass']], 'auth_spf' => [[$domain, 'pass']]],
                ['ip' => '192.0.2.2', 'count' => 3, 'disposition' => 'quarantine', 'dkim' => 'fail', 'spf' => 'fail', 'header_from' => $domain,
                    'envelope_from' => 'bounce.provider.example', 'auth_dkim' => [['provider.example', 'k1', 'pass']], 'auth_spf' => [['bounce.provider.example', 'pass']]],
                ['ip' => '2001:DB8::0001', 'count' => 1, 'disposition' => 'quarantine', 'dkim' => 'fail', 'spf' => 'fail', 'header_from' => $domain,
                    'auth_spf' => [['spoof.example', 'fail']]],
            ],
        ];

        $output->writeln('<comment>Parser</comment>');
        $check('Complete XML 1.0', function () use ($mk, $assert) {
            $p = ReportParser::parse(Samples::xml($mk('a')));
            $assert($p['meta']['org_name'] === 'Selftest Org', 'org_name');
            $assert($p['policy']['pct'] === 50 && $p['policy']['aspf'] === 's', 'policy');
            $assert(count($p['records']) === 3, 'filas');
            $assert($p['records'][2]['ip'] === '2001:db8::1', 'IPv6 normalizada: ' . $p['records'][2]['ip']);
            $assert($p['records'][1]['dkim'][0]['domain'] === 'provider.example', 'dkim');
        });
        $check('DMARCbis XML with namespace', function () use ($mk, $assert) {
            $p = ReportParser::parse(Samples::xml($mk('b'), true));
            $assert($p['meta']['version'] === '2.0' && count($p['records']) === 3, 'namespace');
        });
        $check('Rejects DOCTYPE / entities', function () use ($assert) {
            try {
                ReportParser::parse('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><feedback>&e;</feedback>');
            } catch (RuntimeException) {
                return;
            }
            $assert(false, 'accepted a DOCTYPE');
        });
        $check('Rejects a root other than feedback', function () use ($assert) {
            try {
                ReportParser::parse('<html/>');
            } catch (RuntimeException) {
                return;
            }
            $assert(false, 'accepted <html>');
        });
        $check('Decompression limit (gzip)', function () use ($assert) {
            // built in pieces so that the test itself does not need the memory
            $ctx   = deflate_init(ZLIB_ENCODING_GZIP, ['level' => 9]);
            $chunk = str_repeat('<', 1024 * 1024);
            $bomb  = '';
            for ($i = 0; $i <= ReportParser::MAX_XML_BYTES / strlen($chunk); $i++) {
                $bomb .= deflate_add($ctx, $chunk, ZLIB_NO_FLUSH);
            }
            $bomb .= deflate_add($ctx, '', ZLIB_FINISH);
            try {
                ReportParser::extract($bomb, 'x.xml.gz');
            } catch (RuntimeException) {
                return;
            }
            $assert(false, 'the limit did not trigger');
        });
        foreach (['google' => 'attached zip', 'microsoft' => 'attached gzip', 'plain' => 'attached xml', 'body' => 'zip as body'] as $style => $label) {
            $check("Mail with {$label}", function () use ($mk, $style, $assert) {
                $r    = $mk('m-' . $style);
                $mime = Mime::parse(Samples::mail($r, Samples::xml($r), $style));
                $docs = [];
                foreach ($mime['parts'] as $part) {
                    if (ReportParser::isCandidate($part)) {
                        $docs = array_merge($docs, ReportParser::extract($part['data'], $part['filename'], $part['type']));
                    }
                }
                $assert(count($docs) === 1, 'reports found: ' . count($docs));
                $assert(str_contains(Mime::header($mime['headers'], 'subject'), 'Report domain'), 'subject');
                $assert(ReportParser::parse($docs[0]['xml'])['meta']['report_id'] === $r['id'], 'report_id');
            });
        }
        $check('RFC 2231 attachment name and encoded header', function () use ($assert) {
            $m = Mime::parse("Subject: =?UTF-8?B?SW5mb3JtZSDDsQ==?=\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n"
                . "Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=utf-8''informe%20a%C3%B1o.xml\r\n\r\n<feedback/>\r\n--b--\r\n");
            $assert($m['parts'][0]['filename'] === 'informe año.xml', 'filename: ' . $m['parts'][0]['filename']);
            $assert(Mime::header($m['headers'], 'subject') === 'Informe ñ', 'subject');
        });

        $output->writeln('<comment>Diagnosis</comment>');
        $check('Failure causes', function () use ($mk, $assert, $domain) {
            $p = ReportParser::parse(Samples::xml($mk('c')));
            $assert(Diagnosis::cause($p['records'][0], $domain) === Diagnosis::PASS_BOTH, 'pass both');
            $assert(Diagnosis::cause($p['records'][1], $domain) === Diagnosis::FAIL_DKIM_OTHER, 'dkim other');
            $assert(Diagnosis::cause($p['records'][2], $domain) === Diagnosis::FAIL_NO_AUTH, 'no auth');
            $fwd = $p['records'][2];
            $fwd['reasons'] = ['forwarded'];
            $assert(Diagnosis::cause($fwd, $domain) === Diagnosis::FAIL_FORWARDED, 'forwarded');
            $spf = $p['records'][1];
            $spf['dkim'] = [];
            $assert(Diagnosis::cause($spf, $domain) === Diagnosis::FAIL_SPF_UNALIGN, 'spf unaligned');
        });
        $check('Organizational domain, own networks and senders', function () use ($assert) {
            $assert(Diagnosis::orgDomain('mail.corp.com.es') === 'corp.com.es', 'com.es');
            $assert(Diagnosis::orgDomain('a.b.example.es') === 'example.es', 'es');
            $assert(Diagnosis::inNetworks('10.1.2.3', '10.0.0.0/8, 192.168.1.0/24'), 'v4');
            $assert(!Diagnosis::inNetworks('11.1.2.3', '10.0.0.0/8'), 'v4 fuera');
            $assert(Diagnosis::inNetworks('2001:db8::5', '2001:db8::/32'), 'v6');
            $assert(Diagnosis::sender('1.2.3.4', 'mail-sor-f41.google.com', []) === 'Google', 'google');
            $assert(Diagnosis::sender('1.2.3.4', '', ['amazonses.com']) === 'Amazon SES', 'ses');
            $assert(Diagnosis::sender('10.0.0.1', 'x.google.com', [], '10.0.0.0/8') === 'Own server', 'own server');
        });
        $check('Folders with non-ASCII characters (modified UTF-7)', function () use ($assert) {
            $enc = Imap::encodeFolder('DMARC/Año');
            $assert($enc === 'DMARC/A&APE-o', 'codificado: ' . $enc);
            $assert(Imap::decodeFolder($enc) === 'DMARC/Año', 'decoded');
        });

        $output->writeln('<comment>Google OAuth (simulated Google, tools/fake-google.php)</comment>');
        $check('Authorization URL', function () use ($assert) {
            $url = GoogleAuth::authUrl('cid', 'https://glpi.example/plugins/dmarc/front/oauth.php', 'state123', 'dmarc@corp.example');
            $q   = [];
            parse_str((string) parse_url($url, PHP_URL_QUERY), $q);
            $assert(str_starts_with($url, GoogleAuth::AUTH_URI . '?'), 'url');
            $assert($q['response_type'] === 'code' && $q['access_type'] === 'offline' && $q['prompt'] === 'consent', 'parameters');
            $assert($q['client_id'] === 'cid' && $q['state'] === 'state123' && $q['login_hint'] === 'dmarc@corp.example', 'cliente/estado');
            $assert($q['scope'] === 'openid email https://mail.google.com/', 'scope: ' . $q['scope']);
            $assert($q['redirect_uri'] === 'https://glpi.example/plugins/dmarc/front/oauth.php', 'redirect_uri');
        });
        $gport  = random_int(41000, 45000);
        $google = null;
        try {
            $google = $this->startFakeGoogle($gport);
            GoogleAuth::$tokenUri = "http://127.0.0.1:{$gport}/token";
            $redirect = 'https://glpi.example/plugins/dmarc/front/oauth.php';

            $check('Code → refresh token and authorized account', function () use ($assert, $redirect) {
                $t = GoogleAuth::exchangeCode('cid', 'csec', $redirect, 'good-code');
                $assert($t['refresh_token'] === 'rt-1' && $t['access_token'] === 'at-1', 'tokens');
                $assert($t['email'] === 'dmarc@corp.example', 'lower-case address: ' . $t['email']);
            });
            $check('Refresh token → access token', function () use ($assert) {
                $assert(GoogleAuth::accessToken('cid', 'csec', 'rt-1') === 'at-2', 'access token');
            });
            $check('Google errors with an explanation', function () use ($assert, $redirect) {
                $cases = [
                    [fn() => GoogleAuth::exchangeCode('cid', 'bad', $redirect, 'good-code'), 'invalid_client', 'secret'],
                    [fn() => GoogleAuth::exchangeCode('cid', 'csec', $redirect, 'expired'), 'invalid_grant', 'Connect with Google'],
                    [fn() => GoogleAuth::accessToken('cid', 'csec', 'rt-revoked'), 'invalid_grant', 'revoked'],
                    [fn() => GoogleAuth::exchangeCode('cid', 'csec', $redirect, 'no-refresh'), 'refresh token', 'myaccount.google.com'],
                    [fn() => GoogleAuth::accessToken('', '', ''), 'Connect with Google in the plugin configuration first', ''],
                ];
                foreach ($cases as [$fn, $a, $b]) {
                    try {
                        $fn();
                        $assert(false, "did not fail ($a)");
                    } catch (RuntimeException $e) {
                        $assert(str_contains($e->getMessage(), $a) && str_contains($e->getMessage(), $b), "message: {$e->getMessage()}");
                    }
                }
            });
            $check('An id_token without account is not trusted', function () use ($assert) {
                $assert(GoogleAuth::idTokenEmail('') === '' && GoogleAuth::idTokenEmail('a.b') === '' && GoogleAuth::idTokenEmail('x.%%%.y') === '', 'empty');
            });

            // OAuth + IMAP: the IMAP server only accepts the renewed access token
            $itmp  = (defined('GLPI_TMP_DIR') ? GLPI_TMP_DIR : sys_get_temp_dir()) . '/dmarc-oauth-' . $gport;
            $iproc = null;
            try {
                @mkdir($itmp . '/DMARC', 0o777, true);
                $r1 = $mk('oauth1', 2);
                file_put_contents($itmp . '/DMARC/1.eml', Samples::mail($r1, Samples::xml($r1), 'google'));
                $iport = $gport + 1;
                $iproc = $this->startFakeImap($iport, $itmp, 4321, 'dmarc@corp.example', '', 'at-2');
                $conf  = array_replace(Settings::defaults(), [
                    'host' => '127.0.0.1', 'port' => $iport, 'encryption' => 'none', 'validate_cert' => 0,
                    'auth' => 'oauth_google', 'username' => 'dmarc@corp.example', 'folder' => 'DMARC', 'keep_raw' => 0,
                    'oauth_client_id' => 'cid', 'oauth_client_secret' => 'csec', 'oauth_refresh_token' => 'rt-1',
                ]);
                $check('IMAP with OAuth: logs in with the renewed token and imports', function () use ($conf, $assert) {
                    $s = (new Collector($conf, false))->run();
                    $assert($s['failure'] === '' && $s['imported'] === 1, json_encode($s));
                });
                $check('IMAP with OAuth: a revoked authorization gives a clear error', function () use ($conf, $assert) {
                    $s = (new Collector(array_replace($conf, ['oauth_refresh_token' => 'rt-revocado', 'state_last_uid' => 0, 'state_uidvalidity' => 0]), false))->run();
                    $assert(str_contains($s['failure'], 'invalid_grant') && str_contains($s['failure'], 'Connect with Google'), $s['failure']);
                });
                $check('IMAP with OAuth: without connection nothing is attempted', function () use ($conf, $assert) {
                    $s = (new Collector(array_replace($conf, ['oauth_refresh_token' => '']), false))->run();
                    $assert(str_contains($s['failure'], 'Connect with Google in the plugin configuration first'), $s['failure']);
                });
            } finally {
                if (is_resource($iproc)) {
                    proc_terminate($iproc);
                }
                foreach (glob($itmp . '/*/*.eml') ?: [] as $f) {
                    @unlink($f);
                }
                foreach (glob($itmp . '/*', GLOB_ONLYDIR) ?: [] as $d) {
                    @rmdir($d);
                }
                @rmdir($itmp);
            }
        } finally {
            GoogleAuth::$tokenUri = null;
            if (is_resource($google)) {
                proc_terminate($google);
            }
            $this->cleanSelftest(0);
        }

        $output->writeln('<comment>Notifications</comment>');
        $check('Summary data and template', function () use ($assert) {
            $alert = new \GlpiPlugin\Dmarc\Alert();
            $alert->fields = ['id' => 0, 'entities_id' => 0, 'event' => 'summary', 'message' => 'm', 'date_creation' => date('Y-m-d H:i:s'),
                'payload' => json_encode(['period' => 'p', 'total' => 1234, 'pass_pct' => 98.5,
                    'domains' => [['domain' => 'a.example', 'policy' => 'reject', 'total' => 1000, 'pass_pct' => 99.1, 'state_label' => 'Good']],
                    'recommendations' => ['Move to reject']])];
            $target = new \GlpiPlugin\Dmarc\NotificationTargetAlert(0, 'summary', $alert);
            $data   = $target->getForTemplate('summary', []);
            // numbers in the user's format (whatever it is)
            $total = \GlpiPlugin\Dmarc\Format::int(1234);
            $assert(($data['##dmarc.total##'] ?? '') === $total && ($data['##dmarc.pass##'] ?? '') === \GlpiPlugin\Dmarc\Format::pct(98.5), 'data: ' . json_encode(array_slice($data, 0, 6)));
            $assert(($data['domains'][0]['##domain.name##'] ?? '') === 'a.example', 'foreach domains');
            $assert(($data['##lang.dmarc.open_dashboard##'] ?? '') !== '', 'lang tags');
            if (method_exists(\NotificationTemplate::class, 'process')) {
                $text = \NotificationTemplate::process('##FOREACHdomains##[##domain.name## ##domain.compliance##]##ENDFOREACHdomains## ##dmarc.total##', $data);
                $assert(str_contains($text, '[a.example ' . \GlpiPlugin\Dmarc\Format::pct(99.1) . ']') && str_contains($text, $total), 'template: ' . $text);
            }
        });

        $output->writeln('<comment>Simulated IMAP (tools/fake-imap.php)</comment>');
        $validity = random_int(100000, 999999);
        $tmp      = (defined('GLPI_TMP_DIR') ? GLPI_TMP_DIR : sys_get_temp_dir()) . '/dmarc-selftest-' . $validity;
        $proc     = null;
        try {
            @mkdir($tmp . '/DMARC', 0o777, true);
            $r1 = $mk('imap1', 3);
            $r2 = $mk('imap2', 2);
            file_put_contents($tmp . '/DMARC/1.eml', Samples::mail($r1, Samples::xml($r1), 'google'));
            file_put_contents($tmp . '/DMARC/2.eml', Samples::mail($r2, Samples::xml($r2), 'microsoft'));
            file_put_contents($tmp . '/DMARC/3.eml', Samples::notAReport('dmarc@' . $domain));
            file_put_contents($tmp . '/DMARC/4.eml', Samples::mail($r1, Samples::xml($r1), 'plain')); // same report again

            $port  = random_int(20000, 40000);
            $proc  = $this->startFakeImap($port, $tmp, $validity);
            $base  = Settings::defaults();
            $conf  = array_replace($base, [
                'host' => '127.0.0.1', 'port' => $port, 'encryption' => 'none', 'validate_cert' => 0,
                'auth' => 'password', 'username' => 'dmarc@' . $domain, 'password' => 'x', 'folder' => 'DMARC',
                'keep_raw' => 0, 'batch_size' => 2,
            ]);

            $check('Test the connection', function () use ($conf, $assert) {
                $t = (new Collector($conf, false))->test();
                $assert($t['folder_exists'] && $t['exists'] === 4 && $t['pending'] === 4, json_encode($t));
            });
            $check('XOAUTH2', function () use ($port, $domain, $assert) {
                $imap = new Imap('127.0.0.1', $port, 'none', false, 5);
                $imap->connect();
                $imap->authenticateXoauth2('dmarc@' . $domain, 'ya29.token-de-prueba');
                $assert(in_array('DMARC', $imap->listFolders(), true), 'carpetas');
                $imap->logout();
            });
            $check('Read-only: batches, duplicates and nothing changes', function () use (&$conf, $assert, $port) {
                $c = new Collector($conf, false);
                $s1 = $c->run();
                $assert($s1['checked'] === 2 && $s1['imported'] === 2 && $s1['remaining'] === 2 && $s1['actions'] === 0, 'lote 1: ' . json_encode($s1));
                $conf = (fn() => $this->config)->call($c);
                $s2 = (new Collector($conf, false))->run();
                $assert($s2['checked'] === 2 && $s2['not_report'] === 1 && $s2['duplicate'] === 1, 'lote 2: ' . json_encode($s2));
                $conf = array_replace($conf, ['state_last_uid' => 4]);
                $s3 = (new Collector($conf, false))->run();
                $assert($s3['checked'] === 0, 'nada nuevo: ' . json_encode($s3));
                $imap = new Imap('127.0.0.1', $port, 'none', false, 5);
                $imap->connect();
                $imap->login('u', 'p');
                $assert($imap->open('DMARC')['exists'] === 4, 'the mailbox changed');
                $imap->logout();
            });
            $check('Read-write: move to another folder', function () use ($conf, $assert, $port) {
                $conf = array_replace($conf, ['mode' => 'write', 'post_action' => 'move', 'move_folder' => 'DMARC/Procesados',
                    'state_uidvalidity' => 0, 'state_last_uid' => 0, 'batch_size' => 10]);
                $s = (new Collector($conf, false))->run();
                // 1 and 4 are duplicates now, 2 duplicate, 3 not a report: 3 moved, 1 stays
                $assert($s['checked'] === 4 && $s['actions'] === 3, json_encode($s));
                $imap = new Imap('127.0.0.1', $port, 'none', false, 5);
                $imap->connect();
                $imap->login('u', 'p');
                $assert($imap->open('DMARC')['exists'] === 1, 'quedan en DMARC');
                $assert($imap->open('DMARC/Procesados')['exists'] === 3, 'movidos');
                $imap->logout();
            });
            $check('Read-write: delete', function () use ($conf, $assert, $port) {
                $conf = array_replace($conf, ['mode' => 'write', 'post_action' => 'delete', 'folder' => 'DMARC/Procesados',
                    'state_uidvalidity' => 0, 'state_last_uid' => 0, 'batch_size' => 10]);
                $s = (new Collector($conf, false))->run();
                $assert($s['actions'] === 3, json_encode($s));
                $imap = new Imap('127.0.0.1', $port, 'none', false, 5);
                $imap->connect();
                $imap->login('u', 'p');
                $assert($imap->open('DMARC/Procesados')['exists'] === 0, 'borrados');
                $imap->logout();
            });
            $check('Reconnects when the connection drops during a long pause', function () use ($conf, $assert, $port, $tmp, $validity) {
                // a server that drops clients silent for 2 s, like a firewall;
                // the collector checks the connection after 1 s idle
                $p3   = $port + 2;
                $proc = $this->startFakeImap($p3, $tmp, $validity, '', '', '', 2);
                try {
                    $collector = new Collector(array_replace($conf, ['port' => $p3, 'folder' => 'DMARC', 'imap_idle_check' => 1,
                        'state_uidvalidity' => 0, 'state_last_uid' => 0, 'batch_size' => 10, 'mode' => 'readonly']), false);
                    $slow = 0;
                    $s = $collector->run(0, function () use (&$slow): void {
                        if ($slow++ === 0) {
                            sleep(3); // "saving a big report": longer than the server waits
                        }
                    });
                    $assert($s['failure'] === '', 'error: ' . $s['failure']);
                    $assert($collector->reconnections >= 1, 'did not reconnect');
                    $assert($s['checked'] === 4, 'mails: ' . json_encode($s));
                } finally {
                    proc_terminate($proc);
                }
            });
            $check('Wrong authentication gives a clear error', function () use ($conf, $assert, $port, $tmp) {
                // second server that requires a password
                $p2   = $port + 1;
                $proc = $this->startFakeImap($p2, $tmp, 1, 'dmarc@x', 'buena');
                try {
                    $s = (new Collector(array_replace($conf, ['port' => $p2, 'username' => 'dmarc@x', 'password' => 'mala']), false))->run();
                    $assert(str_contains($s['failure'], 'AUTHENTICATIONFAILED') && !str_contains($s['failure'], 'mala'), 'error: ' . $s['failure']);
                } finally {
                    proc_terminate($proc);
                }
            });
            $check('AbuseIPDB: query, cache per IP and limit (simulated server)', function () use ($assert, $port) {
                /** @var \DBmysql $DB */
                global $DB;
                $hp     = $port + 3;
                $router = dirname(__DIR__, 2) . '/tools/fake-abuseipdb.php';
                $proc   = proc_open([PHP_BINARY, '-S', "127.0.0.1:{$hp}", $router], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
                $keys   = ['abuseipdb_enabled', 'abuseipdb_key', 'abuseipdb_days', 'abuseipdb_daily_max', 'state_abuseipdb_count', 'state_abuseipdb_blocked_until'];
                $before = array_intersect_key(Settings::all(), array_flip($keys));
                $before['abuseipdb_key'] = (string) Settings::get('abuseipdb_key'); // in clear: set() encrypts it again
                $oldUrl = \GlpiPlugin\Dmarc\AbuseIpdb::$baseUrl;
                try {
                    for ($i = 0; $i < 50 && @fsockopen('127.0.0.1', $hp) === false; $i++) {
                        usleep(100000);
                    }
                    \GlpiPlugin\Dmarc\AbuseIpdb::$baseUrl = "http://127.0.0.1:{$hp}";
                    Settings::set(['abuseipdb_enabled' => 1, 'abuseipdb_key' => 'test-key', 'abuseipdb_days' => 30,
                        'abuseipdb_daily_max' => 1000, 'state_abuseipdb_count' => '', 'state_abuseipdb_blocked_until' => '']);
                    $DB->update('glpi_plugin_dmarc_sources', ['abuse_date' => null, 'abuse_score' => null], ['ip' => ['192.0.2.1', '192.0.2.2']]);

                    $r1 = \GlpiPlugin\Dmarc\AbuseIpdb::refresh(30);
                    $row = $DB->request(['FROM' => 'glpi_plugin_dmarc_sources', 'WHERE' => ['ip' => '192.0.2.2']])->current();
                    $assert($r1['done'] >= 2 && (int) $row['abuse_score'] === 2 && $row['abuse_country'] === 'ES' && $row['abuse_isp'] !== null, 'primera consulta: ' . json_encode($r1));
                    $r2 = \GlpiPlugin\Dmarc\AbuseIpdb::refresh(30);
                    $assert($r2['done'] === 0, 'queried again IPs already saved: ' . json_encode($r2));
                    $assert(str_starts_with((string) Settings::get('state_abuseipdb_count'), date('Y-m-d') . '|'), 'contador diario');

                    try {
                        \GlpiPlugin\Dmarc\AbuseIpdb::check('203.0.113.99', 'key');
                        $assert(false, 'did not detect the 429');
                    } catch (\GlpiPlugin\Dmarc\AbuseIpdbRateLimit $e) {
                        $assert($e->retryAfter === 120, 'Retry-After');
                    }
                    $assert(!\GlpiPlugin\Dmarc\AbuseIpdb::isPublic('10.1.2.3') && !\GlpiPlugin\Dmarc\AbuseIpdb::isPublic('127.0.0.1')
                        && \GlpiPlugin\Dmarc\AbuseIpdb::isPublic('209.85.220.41'), 'public IPs');
                } finally {
                    \GlpiPlugin\Dmarc\AbuseIpdb::$baseUrl = $oldUrl;
                    Settings::set($before);
                    proc_terminate($proc);
                }
            });
            $check('Statistics of the imported data', function () use ($assert, $domain) {
                $st = new Stats(date('Y-m-d', strtotime('-5 days')), date('Y-m-d'), $domain);
                $t  = $st->totals();
                $assert($t['total'] === 28 && $t['pass'] === 20, 'totales: ' . json_encode([$t['total'], $t['pass']]));
                $d = $st->domains();
                $assert(count($d) === 1 && $d[0]['policy']['p'] === 'quarantine', 'domain');
                $assert(count($st->timeline('day')) === 6, 'serie');
                $assert(count($st->failures()) === 2, 'fallos');
            });
            $check('Filter by several domains', function () use ($assert, $domain) {
                $assert(Stats::parseDomains(' A.example, b.example;;a.example. x y%') === ['a.example', 'b.example', 'x'], 'lista');
                $from = date('Y-m-d', strtotime('-5 days'));
                $one  = (new Stats($from, date('Y-m-d'), $domain))->totals();
                $two  = (new Stats($from, date('Y-m-d'), $domain . ',other.selftest.example'))->totals();
                $none = (new Stats($from, date('Y-m-d'), 'other.selftest.example'))->totals();
                $assert($two['total'] === $one['total'] && $none['total'] === 0, 'totals with two domains');
                $assert(count((new Stats($from, date('Y-m-d'), $domain . ',other.selftest.example'))->domains()) === 1, 'domains');
                $assert(isset(Stats::policyChanges($domain . ',other.selftest.example')[$domain]), 'policies');
            });
        } finally {
            if (is_resource($proc)) {
                proc_terminate($proc);
            }
            foreach (glob($tmp . '/*/*.eml') ?: [] as $f) {
                @unlink($f);
            }
            foreach (glob($tmp . '/*', GLOB_ONLYDIR) ?: [] as $d) {
                @rmdir($d);
            }
            @rmdir($tmp);
            $this->cleanSelftest($validity);
        }

        $output->writeln(sprintf('%s: %d passed, %d failed', $fail === 0 ? '<info>Self-test passed</info>' : '<error>Self-test failed</error>', $ok, $fail));

        return $fail === 0 ? 0 : 1;
    }

    /** @return resource */
    private function startFakeImap(int $port, string $dir, int $validity, string $user = '', string $pass = '', string $token = '', int $idleDrop = 0)
    {
        $script = dirname(__DIR__, 2) . '/tools/fake-imap.php';
        $cmd    = [PHP_BINARY, $script, (string) $port, $dir, (string) $validity, $user, $pass, $token, (string) $idleDrop];
        $proc   = proc_open($cmd, [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) {
            throw new RuntimeException('Could not start the simulated IMAP');
        }
        stream_set_timeout($pipes[1], 5);
        $line = (string) fgets($pipes[1]);
        if (!str_starts_with($line, 'ready')) {
            throw new RuntimeException('The simulated IMAP did not start: ' . trim($line . stream_get_contents($pipes[2])));
        }

        return $proc;
    }

    /** @return resource */
    private function startFakeGoogle(int $port)
    {
        $script = dirname(__DIR__, 2) . '/tools/fake-google.php';
        $proc   = proc_open([PHP_BINARY, '-S', "127.0.0.1:{$port}", $script], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        if (!is_resource($proc)) {
            throw new RuntimeException('Could not start the simulated Google');
        }
        for ($i = 0; $i < 50; $i++) {
            $sock = @fsockopen('127.0.0.1', $port, $errno, $errstr, 0.2);
            if ($sock !== false) {
                fclose($sock);

                return $proc;
            }
            usleep(100000);
        }
        throw new RuntimeException('The simulated Google did not start');
    }

    private function cleanSelftest(int $validity): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(Importer::T_MESSAGES, ['source' => 'selftest'], ['uidvalidity' => $validity]);
        $ids = array_column(iterator_to_array($DB->request(['SELECT' => ['id'], 'FROM' => Importer::T_REPORTS, 'WHERE' => ['org_name' => 'Selftest Org']]), false), 'id');
        Importer::deleteReports($ids);
        $DB->delete(Importer::T_MESSAGES, ['source' => 'selftest']);
        self::deleteOrphanSources();
        $DB->delete('glpi_plugin_dmarc_domains', ['name' => ['LIKE', '%.selftest.example']]);
    }

    /** Sources without any record left. */
    private static function deleteOrphanSources(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->delete(Importer::T_SOURCES, ['NOT' => ['id' => new QuerySubQuery(['SELECT' => 'sources_id', 'DISTINCT' => true, 'FROM' => Importer::T_RECORDS])]]);
    }
}
