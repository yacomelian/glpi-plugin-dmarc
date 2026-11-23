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

use RuntimeException;

/**
 * Reads the DMARC folder of the mailbox and imports the new mails.
 *
 * Read-only mode (default): EXAMINE + BODY.PEEK, nothing changes in the
 * mailbox. Write mode: after a mail is imported (or found duplicate) it is
 * marked as read, moved to another folder or deleted.
 *
 * Progress is kept by UIDVALIDITY + last UID; reports are also deduplicated
 * by organisation + report id, so reading a mail twice is harmless.
 */
final class Collector
{
    private array $config;
    private ?Imap $imap = null;
    /** Did this collector take the worker lock (and must release it)? */
    private bool $ownsLock = false;
    /** Google access token, reused on reconnection (valid for an hour). */
    private string $accessToken = '';
    private int $accessTokenUntil = 0;
    /** Reconnections done in this run (the connection may be cut during long pauses). */
    public int $reconnections = 0;

    /** After this long without talking to the server, check the connection first (seconds, setting imap_idle_check). */
    private int $idleCheck = 60;
    private const MAX_RECONNECTIONS = 20;

    /**
     * @param array|null $config decrypted settings (Settings::decrypted() by default)
     * @param bool       $persist save the progress and the alerts (false in the self-test)
     */
    public function __construct(?array $config = null, private readonly bool $persist = true)
    {
        $this->config = $config ?? Settings::decrypted();
        $this->idleCheck = max(1, (int) ($this->config['imap_idle_check'] ?? 60));
    }

    public function __destruct()
    {
        $this->disconnect();
        $this->unlock();
    }

    /** Connects and authenticates. */
    public function connect(): Imap
    {
        $c = $this->config;
        if (trim((string) $c['host']) === '' || trim((string) $c['username']) === '') {
            throw new RuntimeException(__('The mailbox server or user is missing in the configuration', 'dmarc'));
        }
        $imap = new Imap(
            trim((string) $c['host']),
            (int) $c['port'] ?: 993,
            (string) $c['encryption'],
            (bool) $c['validate_cert'],
        );
        $imap->connect();
        if ($c['auth'] === 'oauth_google') {
            if ($this->accessToken === '' || time() >= $this->accessTokenUntil) {
                $this->accessToken = GoogleAuth::accessToken(
                    trim((string) $c['oauth_client_id']),
                    (string) $c['oauth_client_secret'],
                    (string) $c['oauth_refresh_token']
                );
                $this->accessTokenUntil = time() + 45 * 60;
            }
            $imap->authenticateXoauth2((string) $c['username'], $this->accessToken);
        } else {
            $imap->login((string) $c['username'], (string) $c['password']);
        }

        return $this->imap = $imap;
    }

    /**
     * "Test the connection".
     *
     * @return array{folders: string[], folder_exists: bool, exists: int, uidvalidity: int, pending: int, move_folder_exists: bool|null}
     */
    public function test(): array
    {
        $imap    = $this->imap ?? $this->connect();
        $folders = $imap->listFolders();
        $folder  = (string) $this->config['folder'];
        $result  = [
            'folders'            => $folders,
            'folder_exists'      => in_array($folder, $folders, true),
            'exists'             => 0,
            'uidvalidity'        => 0,
            'pending'            => 0,
            'move_folder_exists' => null,
        ];
        if ($result['folder_exists']) {
            $info = $imap->open($folder, false);
            $result['exists']      = $info['exists'];
            $result['uidvalidity'] = $info['uidvalidity'];
            $last = (int) $this->config['state_uidvalidity'] === $info['uidvalidity'] ? (int) $this->config['state_last_uid'] : 0;
            $result['pending'] = count($imap->searchUids($last, (string) $this->config['since_date']));
        }
        if ($this->config['mode'] === 'write' && $this->config['post_action'] === 'move') {
            $result['move_folder_exists'] = in_array((string) $this->config['move_folder'], $folders, true);
        }
        $this->disconnect();

        return $result;
    }

    /**
     * Imports new mails.
     *
     * @param int|null      $limit    max mails this run (null = batch_size; 0 = no limit)
     * @param callable|null $progress fn(int $done, int $total, array $result)
     * @param int[]|null    $onlyUids reprocess these UIDs only (progress is not moved)
     * @param int           $maxSeconds stop after this long (0 = no limit); the rest stays for the next run
     *
     * @return array{checked:int, imported:int, duplicate:int, not_report:int, error:int, skipped:int, reports:int, actions:int, remaining:int, failure:string}
     */
    public function run(?int $limit = null, ?callable $progress = null, ?array $onlyUids = null, int $maxSeconds = 0): array
    {
        $stats = ['checked' => 0, 'imported' => 0, 'duplicate' => 0, 'not_report' => 0, 'error' => 0,
            'skipped' => 0, 'reports' => 0, 'actions' => 0, 'remaining' => 0, 'failure' => ''];

        if (!$this->lock()) {
            $stats['failure'] = __('A collection is already running', 'dmarc');

            return $stats;
        }

        $started  = time();
        $c        = $this->config;
        $writable = $c['mode'] === 'write';
        $action   = $writable ? (string) $c['post_action'] : '';
        $limit    = $limit ?? max(1, (int) $c['batch_size']);
        $maxBytes = max(1, (int) $c['max_message_mb']) * 1024 * 1024;
        $importer = new Importer((bool) $c['keep_raw'], (string) $c['own_networks']);
        $state    = [
            'state_uidvalidity' => (int) $c['state_uidvalidity'],
            'state_last_uid'    => (int) $c['state_last_uid'],
        ];

        try {
            $imap = $this->imap ?? $this->connect();
            if ($action === 'move') {
                $target = trim((string) $c['move_folder']);
                if ($target === '' || $target === $c['folder']) {
                    throw new RuntimeException(__('The destination folder to move to is not valid', 'dmarc'));
                }
                if (!in_array($target, $imap->listFolders(), true)) {
                    $imap->createFolder($target);
                }
            }
            $info = $imap->open((string) $c['folder'], $writable);
            if ($info['uidvalidity'] !== $state['state_uidvalidity']) {
                // new folder or rebuilt by the server: start over (reports are deduplicated)
                $state = ['state_uidvalidity' => $info['uidvalidity'], 'state_last_uid' => 0];
            }

            $uids = $onlyUids ?? $imap->searchUids($state['state_last_uid'], (string) $c['since_date']);
            $todo = $limit > 0 ? array_slice($uids, 0, $limit) : $uids;
            $stats['remaining'] = count($uids) - count($todo);

            foreach ($todo as $i => $uid) {
                if ($maxSeconds > 0 && time() - $started >= $maxSeconds) {
                    $stats['remaining'] += count($todo) - $i;
                    break;
                }
                $msgInfo = ['source' => 'imap', 'uidvalidity' => $info['uidvalidity'], 'uid' => $uid];

                // Saving a big report can take minutes; meanwhile the server or a
                // firewall may drop the idle connection. Check it, and reconnect
                // (once per message) if it was cut.
                $raw  = null;
                $size = 0;
                $t0   = microtime(true);
                for ($attempt = 0; ; $attempt++) {
                    try {
                        if ($imap->idleSeconds() > $this->idleCheck) {
                            $imap->noop();
                        }
                        $size = $imap->size($uid);
                        if ($size > 0 && $size <= $maxBytes) {
                            $raw = $imap->fetch($uid);
                        }
                        break;
                    } catch (ImapConnectionException $e) {
                        if ($attempt >= 1 || $this->reconnections >= self::MAX_RECONNECTIONS) {
                            throw $e;
                        }
                        $imap = $this->reconnect((string) $c['folder'], $writable, $info['uidvalidity']);
                    }
                }
                if ($size === 0) {
                    continue; // gone meanwhile
                }
                $stats['checked']++;
                if ($size > $maxBytes) {
                    $importer->skipMessage($msgInfo + ['size' => $size], sprintf(__('Message of %.1f MB: larger than the configured maximum', 'dmarc'), $size / 1048576));
                    $stats['skipped']++;
                } else {
                    if ($raw === null) {
                        continue;
                    }
                    $t1     = microtime(true);
                    $result = $importer->importMail($raw, $msgInfo);
                    unset($raw);
                    $result += ['uid' => $uid, 'size' => $size, 'fetch_s' => $t1 - $t0, 'import_s' => microtime(true) - $t1];
                    $stats['reports'] += $result['reports'];
                    $key = match ($result['status']) {
                        Importer::IMPORTED   => 'imported',
                        Importer::DUPLICATE  => 'duplicate',
                        Importer::NOT_REPORT => 'not_report',
                        default              => 'error',
                    };
                    $stats[$key]++;

                    if ($writable && in_array($result['status'], [Importer::IMPORTED, Importer::DUPLICATE], true)) {
                        if ($imap->idleSeconds() > $this->idleCheck) {
                            try {
                                $imap->noop();
                            } catch (ImapConnectionException) {
                                $imap = $this->reconnect((string) $c['folder'], $writable, $info['uidvalidity']);
                            }
                        }
                        match ($action) {
                            'move'   => $imap->move($uid, (string) $c['move_folder']),
                            'delete' => $imap->delete($uid),
                            default  => $imap->markSeen($uid),
                        };
                        $importer->setPostAction($result['id'], $action ?: 'seen');
                        $stats['actions']++;
                    }
                    if ($progress !== null) {
                        $progress($i + 1, count($todo), $result);
                    }
                }
                if ($onlyUids === null && $uid > $state['state_last_uid']) {
                    $state['state_last_uid'] = $uid;
                    if ($this->persist && $stats['checked'] % 20 === 0) {
                        Settings::set($state);
                    }
                }
            }

            $this->saveOutcome($state, '');
        } catch (\Throwable $e) {
            $stats['failure'] = $e->getMessage();
            $this->saveOutcome($state, $e->getMessage());
        } finally {
            $this->disconnect();
            $this->unlock();
        }

        return $stats;
    }

    /** New connection to the same folder; the folder must be the same one (UIDVALIDITY). */
    private function reconnect(string $folder, bool $writable, int $uidvalidity): Imap
    {
        $this->disconnect();
        $this->reconnections++;
        $imap = $this->connect();
        $info = $imap->open($folder, $writable);
        if ($info['uidvalidity'] !== $uidvalidity) {
            throw new RuntimeException(__('The folder changed on the server during the collection (different UIDVALIDITY); it will go on in the next run', 'dmarc'));
        }

        return $imap;
    }

    public function disconnect(): void
    {
        try {
            $this->imap?->logout();
        } catch (\Throwable) {
            // already gone
        }
        $this->imap = null;
    }

    private function saveOutcome(array $state, string $error): void
    {
        $now = date('Y-m-d H:i:s');
        $state['state_last_run'] = $now;
        if ($error === '') {
            $state['state_last_ok']      = $now;
            $state['state_last_error']   = '';
            $state['state_error_count']  = 0;
        } else {
            $state['state_last_error']  = mb_substr($now . ' ' . $error, 0, 1000);
            $state['state_error_count'] = (int) $this->config['state_error_count'] + 1;
        }
        $this->config = array_replace($this->config, $state);
        if (!$this->persist) {
            return;
        }
        Settings::set($state);

        if ($error === '') {
            Alert::resolve('collect_error', 'collect');
        } elseif ($state['state_error_count'] >= max(1, (int) $this->config['notify_collect_errors'])) {
            Alert::raise('collect_error', 'collect', sprintf(
                __('The collection of DMARC reports failed %1$d times in a row. Last error: %2$s', 'dmarc'),
                $state['state_error_count'],
                $error
            ), ['errors' => $state['state_error_count']]);
        }
    }

    /** The single-worker lock (shared with the background worker, see Worker). */
    private function lock(): bool
    {
        if (Worker::holds()) {
            return true; // taken by the worker process we run in
        }
        if (!Worker::acquire()) {
            return false;
        }
        $this->ownsLock = true;

        return true;
    }

    private function unlock(): void
    {
        if ($this->ownsLock) {
            Worker::release();
            $this->ownsLock = false;
        }
    }
}
