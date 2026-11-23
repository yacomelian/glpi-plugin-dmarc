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

namespace GlpiPlugin\Dmarc\Command;

use Glpi\Console\AbstractCommand;
use GlpiPlugin\Dmarc\Collector;
use GlpiPlugin\Dmarc\Cron;
use GlpiPlugin\Dmarc\Importer;
use GlpiPlugin\Dmarc\Settings;
use GlpiPlugin\Dmarc\Watcher;
use GlpiPlugin\Dmarc\Worker;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 *   php bin/console plugins:dmarc:collect            one batch (like the automatic action)
 *   php bin/console plugins:dmarc:collect --all      everything pending (first load)
 *   php bin/console plugins:dmarc:collect --test     test the connection only
 *   php bin/console plugins:dmarc:collect --resolve  reverse names of the new IPs
 *   php bin/console plugins:dmarc:collect --check    daily alerts (and --summary to force the summary)
 *
 * Background worker (started by the web pages and the automatic action, see
 * Worker; not meant to be typed):
 *   plugins:dmarc:collect --worker [--collect [--all|--limit=N] | --uids=1,2,3]
 * imports the files waiting in the inbox folder and then collects, writing
 * its progress for the "Recogida" tab.
 */
final class CollectCommand extends AbstractCommand
{
    protected function configure(): void
    {
        $this->setName('plugins:dmarc:collect');
        $this->setDescription('DMARC: collect the reports from the mailbox');
        $this->addOption('all', null, InputOption::VALUE_NONE, 'All pending mails, no batch limit');
        $this->addOption('limit', null, InputOption::VALUE_REQUIRED, 'Maximum number of mails');
        $this->addOption('test', null, InputOption::VALUE_NONE, 'Only test the connection');
        $this->addOption('resolve', null, InputOption::VALUE_NONE, 'Resolve the reverse name of the new IPs (and AbuseIPDB)');
        $this->addOption('check', null, InputOption::VALUE_NONE, 'Daily alert checks');
        $this->addOption('summary', null, InputOption::VALUE_NONE, 'Generate the periodic summary now');
        $this->addOption('worker', null, InputOption::VALUE_NONE, 'Background job (started by the plugin itself)');
        $this->addOption('worker-resolve', null, InputOption::VALUE_NONE, 'Reverse names and AbuseIPDB in the background (started by the plugin itself)');
        $this->addOption('collect', null, InputOption::VALUE_NONE, 'With --worker: collect from the mailbox besides importing the pending files');
        $this->addOption('uids', null, InputOption::VALUE_REQUIRED, 'With --worker: read these mailbox UIDs again (comma separated)');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        if ($input->getOption('worker')) {
            return $this->worker($input, $output);
        }
        if ($input->getOption('worker-resolve')) {
            $output->writeln(Cron::resolveJob() ? 'Done' : 'An IP lookup is already running.');

            return 0;
        }
        if ($input->getOption('test')) {
            $t = (new Collector())->test();
            $output->writeln('Folders: ' . implode(' · ', $t['folders']));
            $output->writeln(sprintf(
                'Folder "%s": %s; %d mails, %d pending, UIDVALIDITY %d',
                Settings::get('folder'),
                $t['folder_exists'] ? 'exists' : 'DOES NOT EXIST',
                $t['exists'],
                $t['pending'],
                $t['uidvalidity']
            ));

            return $t['folder_exists'] ? 0 : 1;
        }
        if ($input->getOption('resolve')) {
            $output->writeln('IPs resolved: ' . Cron::resolveSources(100000));
            if (\GlpiPlugin\Dmarc\AbuseIpdb::isEnabled()) {
                $r = \GlpiPlugin\Dmarc\AbuseIpdb::refresh(3600);
                $output->writeln(sprintf('AbuseIPDB: %d IPs checked, %d with errors%s', $r['done'], $r['errors'], $r['stopped'] !== '' ? ' (' . $r['stopped'] . ')' : ''));
            }

            return 0;
        }
        if ($input->getOption('check') || $input->getOption('summary')) {
            if ($input->getOption('check')) {
                $output->writeln('New alerts: ' . Watcher::daily());
            }
            if ($input->getOption('summary')) {
                $output->writeln(Watcher::summary(true) ? 'Summary generated' : 'No summary');
            }

            return 0;
        }

        if (!Settings::isMailboxConfigured()) {
            $output->writeln('<error>The mailbox is not configured.</error>');

            return 1;
        }
        $limit = $input->getOption('all') ? 0 : ($input->getOption('limit') !== null ? max(1, (int) $input->getOption('limit')) : null);
        $progress = function (int $done, int $total, array $result) use ($output): void {
            if ($done % 50 === 0 || $done === $total || $result['status'] === Importer::ERROR) {
                $output->writeln(sprintf('  %d/%d %s%s', $done, $total, Importer::statusLabel($result['status']), $result['error'] !== '' ? ': ' . $result['error'] : ''));
            }
        };
        $stats = (new Collector())->run($limit, $progress);
        if ($stats['reports'] > 0) {
            $output->writeln('New alerts: ' . Watcher::afterImport());
        }
        $output->writeln(Cron::summaryLine($stats));

        return $stats['failure'] === '' ? 0 : 1;
    }

    /** Background job: pending files, then the mailbox. Writes its progress for the page. */
    private function worker(InputInterface $input, OutputInterface $output): int
    {
        if (!Worker::acquire()) {
            $output->writeln('A DMARC job is already running.');

            return 0;
        }
        $started = time();
        $status  = ['state' => 'running', 'started' => $started, 'step' => '', 'done' => 0, 'total' => 0, 'reports' => 0];
        $last    = 0;
        $save    = static function (array $status, bool $force = false) use (&$last): void {
            if ($force || time() - $last >= 2) {
                Worker::writeStatus($status);
                $last = time();
            }
        };
        $save($status, true);
        $lines = [];

        // Entry in the history of the "collect" automatic action: start, progress, result
        $uidsOpt = $input->getOption('uids');
        $what    = match (true) {
            $uidsOpt !== null              => sprintf(_n('read %d mail again', 'read %d mails again', count(explode(',', (string) $uidsOpt)), 'dmarc'), count(explode(',', (string) $uidsOpt))),
            !$input->getOption('collect') => __('import uploaded files', 'dmarc'),
            (bool) $input->getOption('all') => __('collect everything pending', 'dmarc'),
            default                        => sprintf(__('collect up to %d mails', 'dmarc'), max(1, (int) ($input->getOption('limit') ?? Settings::int('batch_size')))),
        };
        $cronLog = Worker::cronLogStart(sprintf(__('DMARC in the background: start (%s)', 'dmarc'), $what));
        $short   = '';
        try {
            // 1) files uploaded from the page
            $this->importInbox($status, $save, $lines);

            // 2) the mailbox
            $uids = $input->getOption('uids') !== null
                ? array_values(array_filter(array_map('intval', explode(',', (string) $input->getOption('uids')))))
                : null;
            if (($input->getOption('collect') || $uids !== null) && Settings::isMailboxConfigured()) {
                $limit = $uids !== null ? 0 : ($input->getOption('all') ? 0 : ($input->getOption('limit') !== null ? max(1, (int) $input->getOption('limit')) : null));
                $status = array_replace($status, ['step' => $uids !== null ? 'reprocess' : 'collect', 'done' => 0, 'total' => 0]);
                $save($status, true);
                $reportsBefore = $status['reports'];
                $collector = new Collector();
                $stats = $collector->run($limit, function (int $done, int $total, array $result) use (&$status, $save, $reportsBefore, $cronLog, $started): void {
                    $status['done']    = $done;
                    $status['total']   = $total;
                    $status['reports'] = $reportsBefore + ($status['collect_reports'] = ($status['collect_reports'] ?? 0) + $result['reports']);
                    $save($status);
                    if (($result['fetch_s'] ?? 0) + ($result['import_s'] ?? 0) > 30) {
                        Worker::cronLog($cronLog, sprintf(
                            __('Slow mail (UID %1$d, %2$.1f MB): download %3$d s, saving %4$d s, %5$d report(s)', 'dmarc'),
                            $result['uid'],
                            $result['size'] / 1048576,
                            $result['fetch_s'],
                            $result['import_s'],
                            $result['reports']
                        ), $status['reports'], microtime(true) - $started, \CronTaskLog::STATE_RUN);
                    }
                    if ($done % 100 === 0) {
                        Worker::cronLog($cronLog, sprintf(__('%1$d of %2$d mails, %3$d new reports', 'dmarc'), $done, $total, $status['reports']), $status['reports'], microtime(true) - $started, \CronTaskLog::STATE_RUN);
                    }
                }, $uids, max(60, Worker::MAX_RUNTIME - (time() - $started)));
                $lines[] = Cron::summaryLine($stats);
                $short   = sprintf(
                    __('Background (%1$s): %2$d mails, %3$d new reports, %4$d duplicates, %5$d without report, %6$d with errors, %7$d skipped; %8$d left', 'dmarc'),
                    $what,
                    $stats['checked'],
                    $stats['reports'],
                    $stats['duplicate'],
                    $stats['not_report'],
                    $stats['error'],
                    $stats['skipped'],
                    $stats['remaining']
                ) . ($collector->reconnections > 0 ? '; ' . sprintf(_n('%d reconnection to the server', '%d reconnections to the server', $collector->reconnections, 'dmarc'), $collector->reconnections) : '');
                if ($stats['failure'] !== '') {
                    $status['failure'] = $stats['failure'];
                }
                if ($stats['remaining'] > 0) {
                    $lines[] = __('The automatic action will go on with the rest (or press "Collect now" again).', 'dmarc');
                }
            }

            // 3) files uploaded while this job was running
            $this->importInbox($status, $save, $lines);

            if (Watcher::afterImport() > 0) {
                $lines[] = __('There are new alerts.', 'dmarc');
            }
            $status = array_replace($status, [
                'state'    => isset($status['failure']) ? 'error' : 'done',
                'finished' => time(),
                'summary'  => implode(' ', $lines) ?: __('Nothing to do.', 'dmarc'),
            ]);
        } catch (\Throwable $e) {
            $status = array_replace($status, ['state' => 'error', 'finished' => time(), 'summary' => implode(' ', $lines), 'failure' => $e->getMessage()]);
        } finally {
            $save($status, true);
            $text = $short !== '' ? $short : ($status['summary'] ?? '');
            if (isset($status['failure'])) {
                $text = __('Error', 'dmarc') . ': ' . $status['failure'] . ($text !== '' ? ' · ' . $text : ' · ' . sprintf(__('background (%s)', 'dmarc'), $what));
            }
            Worker::cronLog(
                $cronLog,
                $text !== '' ? $text : __('Nothing to do.', 'dmarc'),
                (int) $status['reports'],
                microtime(true) - $started,
                $status['state'] === 'done' ? \CronTaskLog::STATE_STOP : \CronTaskLog::STATE_ERROR
            );
            Worker::release();
        }
        $output->writeln(($status['summary'] ?? '') . (isset($status['failure']) ? ' Error: ' . $status['failure'] : ''));

        // new sources: their names and AbuseIPDB now, in this same background process
        if ((int) ($status['reports'] ?? 0) > 0 && !Worker::isRunning('resolve')) {
            Cron::resolveJob();
        }

        return $status['state'] === 'done' ? 0 : 1;
    }

    /** Imports (and removes) the files waiting in the inbox folder. */
    private function importInbox(array &$status, callable $save, array &$lines): void
    {
        $files = glob(Worker::inboxDir() . '/*') ?: [];
        sort($files);
        if ($files === []) {
            return;
        }
        $importer = Importer::fromSettings();
        $status   = array_replace($status, ['step' => 'import', 'done' => 0, 'total' => count($files)]);
        $new      = 0;
        $errors   = 0;
        foreach ($files as $i => $file) {
            $res = null;
            if (is_file($file)) {
                $name = preg_replace('/^\d+-[0-9a-f]+-/', '', basename($file)) ?: basename($file);
                $res  = $importer->importFile($name, (string) file_get_contents($file));
                $new += $res['reports'];
                $errors += in_array($res['status'], [Importer::ERROR, Importer::NOT_REPORT], true) ? 1 : 0;
                @unlink($file);
            }
            $status['done'] = $i + 1;
            $status['reports'] += $res['reports'] ?? 0;
            $save($status);
        }
        $lines[] = sprintf(__('%1$d file(s) imported: %2$d new report(s)', 'dmarc'), count($files), $new)
            . ($errors > 0 ? ', ' . sprintf(__('%d with errors or without a report (see the list of processed mails)', 'dmarc'), $errors) : '') . '.';
    }
}
