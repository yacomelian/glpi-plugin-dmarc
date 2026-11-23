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

/**
 * Background work, so that nothing heavy runs inside a web request (which
 * would keep the user's PHP session locked: GLPI stops answering that user)
 * nor inside GLPI's automatic actions (which run one after another: a long
 * DMARC load would delay the mail collector, notifications, etc.).
 *
 * The web side and the automatic action only call spawn(), which starts
 *   nice php bin/console plugins:dmarc:collect --worker …
 * as a detached process with low CPU priority. One lock file guarantees a
 * single worker at a time (collection, reprocessing and file imports share
 * it). The worker writes its progress to a small JSON file for the page.
 */
final class Worker
{
    /** Longest a background collection keeps going, in seconds. */
    public const MAX_RUNTIME = 3000;

    /** @var array<string, resource> one lock per kind of job ("collect", "resolve") */
    private static array $locks = [];

    public static function canSpawn(): bool
    {
        $disabled = array_map('trim', explode(',', (string) ini_get('disable_functions')));

        return function_exists('exec') && !in_array('exec', $disabled, true) && DIRECTORY_SEPARATOR === '/';
    }

    /** Is a job of this kind running (in any process)? */
    public static function isRunning(string $job = 'collect'): bool
    {
        if (isset(self::$locks[$job]) && is_resource(self::$locks[$job])) {
            return true;
        }
        $fp = @fopen(self::lockFile($job), 'c');
        if ($fp === false) {
            return false;
        }
        $free = flock($fp, LOCK_EX | LOCK_NB);
        if ($free) {
            flock($fp, LOCK_UN);
        }
        fclose($fp);

        return !$free;
    }

    /**
     * Starts a detached worker with these console arguments (already safe:
     * only built by the plugin). Returns false when it cannot (exec disabled)
     * or another worker is running.
     *
     * @param string[] $args e.g. ['--worker', '--limit=200']
     * @param string   $job  kind of job (its lock): "collect" or "resolve"
     */
    public static function spawn(array $args, string $job = 'collect'): bool
    {
        if (self::isRunning($job) || !self::canSpawn()) {
            return false;
        }
        $php = is_executable(PHP_BINDIR . '/php') ? PHP_BINDIR . '/php' : 'php';

        // Docker images locate config/files through environment variables; pass the
        // directories GLPI is using right now (paths only, never credentials).
        $env = [];
        foreach (['GLPI_CONFIG_DIR', 'GLPI_VAR_DIR', 'GLPI_LOG_DIR', 'GLPI_MARKETPLACE_DIR'] as $constant) {
            if (defined($constant)) {
                $env[] = $constant . '=' . escapeshellarg((string) constant($constant));
            }
        }
        if (($mode = getenv('GLPI_INSTALL_MODE')) !== false) {
            $env[] = 'GLPI_INSTALL_MODE=' . escapeshellarg($mode);
        }
        $nice = is_executable('/usr/bin/nice') ? '/usr/bin/nice -n 15 ' : (is_executable('/bin/nice') ? '/bin/nice -n 15 ' : '');

        if ($job === 'collect') {
            self::writeStatus(['state' => 'starting', 'args' => $args]);
        }
        $command = sprintf(
            'cd %s && %s nohup %s%s bin/console %s > %s 2>&1 &',
            escapeshellarg(GLPI_ROOT),
            $env !== [] ? 'env ' . implode(' ', $env) : '',
            $nice,
            escapeshellarg($php),
            implode(' ', array_map('escapeshellarg', array_merge(['plugins:dmarc:collect'], $args))),
            escapeshellarg($job === 'collect' ? self::logFile() : self::logFile($job))
        );
        @exec($command);

        return true;
    }

    /** Does this process hold the lock? */
    public static function holds(string $job = 'collect'): bool
    {
        return isset(self::$locks[$job]) && is_resource(self::$locks[$job]);
    }

    /** Takes the lock of a kind of job (non blocking). */
    public static function acquire(string $job = 'collect'): bool
    {
        if (self::holds($job)) {
            return true;
        }
        $fp = @fopen(self::lockFile($job), 'c');
        if ($fp === false) {
            return true; // cannot lock (read-only dir?): go on
        }
        if (!flock($fp, LOCK_EX | LOCK_NB)) {
            fclose($fp);

            return false;
        }
        self::$locks[$job] = $fp;

        return true;
    }

    public static function release(string $job = 'collect'): void
    {
        if (self::holds($job)) {
            flock(self::$locks[$job], LOCK_UN);
            fclose(self::$locks[$job]);
        }
        unset(self::$locks[$job]);
    }

    /** Progress of the current / last background job. */
    public static function status(): array
    {
        $data = @file_get_contents(self::statusFile());
        $status = is_string($data) ? json_decode($data, true) : null;
        $status = is_array($status) ? $status : [];
        $status['running'] = self::isRunning();
        // "starting" for long and nothing running: the process did not start
        if (!$status['running'] && ($status['state'] ?? '') === 'starting' && time() - (int) ($status['time'] ?? 0) > 60) {
            $status['state'] = 'failed_start';
            $status['log']   = self::lastLog();
        }

        return $status;
    }

    public static function writeStatus(array $status): void
    {
        $status['time'] = time();
        $dir = dirname(self::statusFile());
        if (!is_dir($dir)) {
            @mkdir($dir, 0o770, true);
        }
        @file_put_contents(self::statusFile(), json_encode($status, JSON_UNESCAPED_UNICODE), LOCK_EX);
    }

    public static function lastLog(int $lines = 10): string
    {
        $all = @file(self::logFile(), FILE_IGNORE_NEW_LINES) ?: [];

        return implode("\n", array_slice($all, -$lines));
    }

    /**
     * Opens an entry in the history of the "collect" automatic action
     * (Setup > Automatic actions > collect), like GLPI does for its own runs,
     * so that the background work appears there with its duration and volume.
     *
     * @return int id of the start entry (0 if the task is not found)
     */
    public static function cronLogStart(string $content, string $taskName = 'collect'): int
    {
        $task = new \CronTask();
        if (!$task->getFromDBbyName(Cron::class, $taskName)) {
            return 0;
        }
        $id = (new \CronTaskLog())->add([
            'crontasks_id'    => $task->getID(),
            'date'            => date('Y-m-d H:i:s'),
            'content'         => mb_substr($content, 0, 200),
            'crontasklogs_id' => 0,
            'state'           => \CronTaskLog::STATE_START,
            'volume'          => 0,
            'elapsed'         => 0,
        ]);

        return (int) $id;
    }

    /**
     * Adds a line (or the final line) to the entry opened by cronLogStart().
     *
     * @param int $state \CronTaskLog::STATE_RUN, STATE_STOP or STATE_ERROR
     */
    public static function cronLog(int $startId, string $content, int $volume, float $elapsed, int $state): void
    {
        if ($startId <= 0) {
            return;
        }
        $start = new \CronTaskLog();
        if (!$start->getFromDB($startId)) {
            return;
        }
        (new \CronTaskLog())->add([
            'crontasks_id'    => $start->fields['crontasks_id'],
            'date'            => date('Y-m-d H:i:s'),
            'content'         => mb_substr($content, 0, 200),
            'crontasklogs_id' => $startId,
            'state'           => $state,
            'volume'          => $volume,
            'elapsed'         => $elapsed,
        ]);
    }

    /** Folder for files waiting to be imported by the worker. */
    public static function inboxDir(): string
    {
        return GLPI_PLUGIN_DOC_DIR . '/dmarc/inbox';
    }

    private static function lockFile(string $job = 'collect'): string
    {
        return (defined('GLPI_LOCK_DIR') ? GLPI_LOCK_DIR : sys_get_temp_dir()) . '/dmarc-' . preg_replace('/\W/', '', $job) . '.lock';
    }

    private static function statusFile(): string
    {
        return GLPI_PLUGIN_DOC_DIR . '/dmarc/worker.json';
    }

    private static function logFile(string $job = 'collect'): string
    {
        return GLPI_PLUGIN_DOC_DIR . '/dmarc/' . ($job === 'collect' ? 'worker' : 'worker-' . preg_replace('/\W/', '', $job)) . '.log';
    }
}
