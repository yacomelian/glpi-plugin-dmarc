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

use RuntimeException;

/**
 * Minimal IMAP4rev1 client over a PHP stream: no "imap" extension needed (it
 * is gone from PHP 8.4). Only what the plugin uses, always by UID:
 * LOGIN / AUTHENTICATE XOAUTH2, LIST, CREATE, EXAMINE / SELECT, UID SEARCH,
 * UID FETCH BODY.PEEK[], UID STORE, UID MOVE (or COPY + \Deleted + EXPUNGE).
 */
final class Imap
{
    /** @var resource|null */
    private $stream = null;
    private int $tag = 0;
    /** Last time something was sent to or received from the server. */
    private float $lastActivity = 0.0;
    private array $capabilities = [];
    private bool $writable = false;
    private string $selected = '';

    public function __construct(
        private readonly string $host,
        private readonly int $port = 993,
        private readonly string $encryption = 'ssl',
        private readonly bool $validateCert = true,
        private readonly int $timeout = 30,
    ) {}

    public function __destruct()
    {
        $this->close();
    }

    public function connect(): void
    {
        $context = stream_context_create(['ssl' => [
            'verify_peer'       => $this->validateCert,
            'verify_peer_name'  => $this->validateCert,
            'allow_self_signed' => !$this->validateCert,
            'peer_name'         => $this->host,
            'SNI_enabled'       => true,
        ]]);
        $scheme = $this->encryption === 'ssl' ? 'ssl' : 'tcp';
        $errno  = 0;
        $errstr = '';
        set_error_handler(static fn() => true);
        try {
            $stream = stream_socket_client("{$scheme}://{$this->host}:{$this->port}", $errno, $errstr, $this->timeout, STREAM_CLIENT_CONNECT, $context);
        } finally {
            restore_error_handler();
        }
        if ($stream === false) {
            throw new RuntimeException(sprintf(__('Cannot connect to %1$s:%2$d (%3$s)', 'dmarc'), $this->host, $this->port, trim($errstr) ?: 'error ' . $errno));
        }
        stream_set_timeout($stream, $this->timeout);
        $this->stream = $stream;

        $greeting = $this->readLine();
        if (!str_starts_with($greeting, '* OK') && !str_starts_with($greeting, '* PREAUTH')) {
            throw new RuntimeException(sprintf(__('Unexpected answer from the server: %s', 'dmarc'), self::short($greeting)));
        }

        if ($this->encryption === 'starttls') {
            $this->command('STARTTLS');
            set_error_handler(static fn() => true);
            try {
                $ok = stream_socket_enable_crypto($this->stream, true, STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT);
            } finally {
                restore_error_handler();
            }
            if ($ok !== true) {
                throw new RuntimeException(__('TLS negotiation failed (STARTTLS)', 'dmarc'));
            }
        }
        $this->loadCapabilities();
    }

    public function login(string $user, string $password): void
    {
        if (in_array('LOGINDISABLED', $this->capabilities, true)) {
            throw new RuntimeException(__('The server does not allow LOGIN without encryption', 'dmarc'));
        }
        $this->command('LOGIN ' . self::quote($user) . ' ' . self::quote($password), true);
        $this->loadCapabilities();
    }

    /** SASL XOAUTH2 (Google, Microsoft 365). */
    public function authenticateXoauth2(string $user, string $accessToken): void
    {
        $sasl = base64_encode("user={$user}\x01auth=Bearer {$accessToken}\x01\x01");
        if ($this->hasCapability('SASL-IR')) {
            $this->command('AUTHENTICATE XOAUTH2 ' . $sasl, true);
        } else {
            $this->command('AUTHENTICATE XOAUTH2', true, $sasl);
        }
        $this->loadCapabilities();
    }

    public function hasCapability(string $cap): bool
    {
        return in_array(strtoupper($cap), $this->capabilities, true);
    }

    /** @return string[] folder names (UTF-8) */
    public function listFolders(): array
    {
        $folders = [];
        foreach ($this->command('LIST "" "*"')['untagged'] as $resp) {
            if (preg_match('/^\* LIST \(([^)]*)\) (NIL|"(?:[^"\\\\]|\\\\.)*") (.*)$/s', $resp['line'], $m) !== 1) {
                continue;
            }
            if (stripos($m[1], '\\Noselect') !== false || stripos($m[1], '\\NonExistent') !== false) {
                continue;
            }
            $name = $resp['literals'][0] ?? self::unquote(trim($m[3]));
            $folders[] = self::decodeFolder($name);
        }
        sort($folders, SORT_NATURAL | SORT_FLAG_CASE);

        return $folders;
    }

    public function createFolder(string $folder): void
    {
        $this->command('CREATE ' . self::quote(self::encodeFolder($folder)));
    }

    /**
     * Opens a folder. Read-only (EXAMINE) unless $writable.
     *
     * @return array{uidvalidity:int, exists:int, uidnext:int}
     */
    public function open(string $folder, bool $writable = false): array
    {
        $resp = $this->command(($writable ? 'SELECT ' : 'EXAMINE ') . self::quote(self::encodeFolder($folder)));
        $info = ['uidvalidity' => 0, 'exists' => 0, 'uidnext' => 0];
        foreach ($resp['untagged'] as $u) {
            if (preg_match('/^\* (\d+) EXISTS/i', $u['line'], $m) === 1) {
                $info['exists'] = (int) $m[1];
            } elseif (preg_match('/\[UIDVALIDITY (\d+)\]/i', $u['line'], $m) === 1) {
                $info['uidvalidity'] = (int) $m[1];
            } elseif (preg_match('/\[UIDNEXT (\d+)\]/i', $u['line'], $m) === 1) {
                $info['uidnext'] = (int) $m[1];
            }
        }
        $this->writable = $writable;
        $this->selected = $folder;

        return $info;
    }

    /**
     * UIDs greater than $after, optionally received since a date (Y-m-d).
     *
     * @return int[] ascending
     */
    public function searchUids(int $after = 0, string $since = ''): array
    {
        $criteria = 'UID ' . ($after + 1) . ':*';
        if ($since !== '' && ($ts = strtotime($since)) !== false) {
            $criteria .= ' SINCE ' . date('j-M-Y', $ts);
        }
        $uids = [];
        foreach ($this->command('UID SEARCH ' . $criteria)['untagged'] as $u) {
            if (preg_match('/^\* SEARCH ?(.*)$/i', $u['line'], $m) === 1) {
                foreach (preg_split('/\s+/', trim($m[1])) ?: [] as $n) {
                    // "n:*" always includes the last message, even when its UID is lower
                    if (ctype_digit($n) && (int) $n > $after) {
                        $uids[] = (int) $n;
                    }
                }
            }
        }
        sort($uids);

        return array_values(array_unique($uids));
    }

    /** Size in bytes of a message (0 if it does not exist any more). */
    public function size(int $uid): int
    {
        foreach ($this->command("UID FETCH {$uid} (UID RFC822.SIZE)")['untagged'] as $u) {
            if (preg_match('/RFC822\.SIZE (\d+)/i', $u['line'], $m) === 1) {
                return (int) $m[1];
            }
        }

        return 0;
    }

    /** Whole message, without setting \Seen. Null if the UID does not exist. */
    public function fetch(int $uid): ?string
    {
        foreach ($this->command("UID FETCH {$uid} (UID BODY.PEEK[])")['untagged'] as $u) {
            if (stripos($u['line'], 'FETCH') !== false && isset($u['literals'][0])) {
                return $u['literals'][0];
            }
        }

        return null;
    }

    public function markSeen(int $uid): void
    {
        $this->requireWritable();
        $this->command("UID STORE {$uid} +FLAGS.SILENT (\\Seen)");
    }

    public function move(int $uid, string $folder): void
    {
        $this->requireWritable();
        $target = self::quote(self::encodeFolder($folder));
        if ($this->hasCapability('MOVE')) {
            $this->command("UID MOVE {$uid} {$target}");

            return;
        }
        $this->command("UID COPY {$uid} {$target}");
        $this->delete($uid);
    }

    /**
     * Flags \Deleted and expunges. In Gmail what happens then depends on the
     * account's IMAP settings (remove the label, move to the bin, delete).
     */
    public function delete(int $uid): void
    {
        $this->requireWritable();
        $this->command("UID STORE {$uid} +FLAGS.SILENT (\\Deleted)");
        $this->command($this->hasCapability('UIDPLUS') ? "UID EXPUNGE {$uid}" : 'EXPUNGE');
    }

    /** Seconds since the last exchange with the server. */
    public function idleSeconds(): float
    {
        return $this->lastActivity > 0 ? microtime(true) - $this->lastActivity : 0.0;
    }

    /**
     * Checks that the connection is still alive (it may have been closed by
     * the server or a firewall during a long pause). Short timeout.
     */
    public function noop(int $timeout = 10): void
    {
        if ($this->stream === null) {
            throw new ImapConnectionException(__('No IMAP connection', 'dmarc'));
        }
        stream_set_timeout($this->stream, $timeout);
        try {
            $this->command('NOOP');
        } finally {
            if (is_resource($this->stream)) {
                stream_set_timeout($this->stream, $this->timeout);
            }
        }
    }

    public function logout(): void
    {
        if ($this->stream !== null) {
            try {
                $this->command('LOGOUT');
            } catch (\Throwable) {
                // server closed already
            }
        }
        $this->close();
    }

    private function close(): void
    {
        if (is_resource($this->stream)) {
            @fclose($this->stream);
        }
        $this->stream = null;
    }

    private function requireWritable(): void
    {
        if (!$this->writable) {
            throw new RuntimeException(__('The folder is open read-only', 'dmarc'));
        }
    }

    private function loadCapabilities(): void
    {
        $caps = [];
        foreach ($this->command('CAPABILITY')['untagged'] as $u) {
            if (preg_match('/^\* CAPABILITY (.*)$/i', $u['line'], $m) === 1) {
                $caps = array_merge($caps, preg_split('/\s+/', strtoupper(trim($m[1]))) ?: []);
            }
        }
        $this->capabilities = $caps;
    }

    /**
     * Sends a command and reads until its tagged answer.
     *
     * @return array{untagged: list<array{line:string, literals:list<string>}>, text:string}
     */
    private function command(string $command, bool $sensitive = false, ?string $continuation = null): array
    {
        if ($this->stream === null) {
            throw new ImapConnectionException(__('No IMAP connection', 'dmarc'));
        }
        $this->lastActivity = microtime(true);
        $tag = sprintf('A%04d', ++$this->tag);
        $this->write("{$tag} {$command}\r\n");

        $untagged = [];
        while (true) {
            [$line, $literals] = $this->readResponse();
            if (str_starts_with($line, '+')) {
                // Continuation: the SASL data when the server asks for it, then
                // empty (a failed AUTHENTICATE sends the error as a challenge).
                $this->write(($continuation ?? '') . "\r\n");
                $continuation = null;
                continue;
            }
            if (str_starts_with($line, $tag . ' ')) {
                $rest = substr($line, strlen($tag) + 1);
                if (stripos($rest, 'OK') !== 0) {
                    $shown = $sensitive ? preg_replace('/^(\S+).*/', '$1 …', $command) : $command;
                    throw new RuntimeException(sprintf('%s → %s', self::short((string) $shown, 60), self::short($rest)));
                }

                $this->lastActivity = microtime(true);

                return ['untagged' => $untagged, 'text' => $rest];
            }
            $untagged[] = ['line' => $line, 'literals' => $literals];
        }
    }

    /**
     * One response "line", with its literals ({n}\r\n<n bytes>) taken out.
     *
     * @return array{0:string, 1:list<string>}
     */
    private function readResponse(): array
    {
        $line     = '';
        $literals = [];
        while (true) {
            $part = $this->readLine();
            if (preg_match('/\{(\d+)\+?\}$/', $part, $m) === 1) {
                $line .= substr($part, 0, -strlen($m[0])) . '{' . count($literals) . '}';
                $literals[] = $this->readBytes((int) $m[1]);
                continue;
            }
            $line .= $part;

            return [$line, $literals];
        }
    }

    private function readLine(): string
    {
        $line = fgets($this->stream);
        if ($line === false) {
            $meta = stream_get_meta_data($this->stream);
            throw new ImapConnectionException(!empty($meta['timed_out']) ? __('Timed out talking to the IMAP server', 'dmarc') : __('The IMAP server closed the connection', 'dmarc'));
        }
        // very long lines come in pieces
        while (!str_ends_with($line, "\n")) {
            $more = fgets($this->stream);
            if ($more === false) {
                break;
            }
            $line .= $more;
        }

        return rtrim($line, "\r\n");
    }

    private function readBytes(int $length): string
    {
        $data = '';
        while (strlen($data) < $length) {
            $chunk = fread($this->stream, min(65536, $length - strlen($data)));
            if ($chunk === false || $chunk === '') {
                $meta = stream_get_meta_data($this->stream);
                if (!empty($meta['timed_out']) || feof($this->stream)) {
                    throw new ImapConnectionException(__('IMAP connection interrupted while reading a message', 'dmarc'));
                }
                continue;
            }
            $data .= $chunk;
        }

        return $data;
    }

    private function write(string $data): void
    {
        $written = 0;
        while ($written < strlen($data)) {
            $n = fwrite($this->stream, substr($data, $written));
            if ($n === false || $n === 0) {
                throw new ImapConnectionException(__('Cannot write to the IMAP connection', 'dmarc'));
            }
            $written += $n;
        }
    }

    public static function quote(string $s): string
    {
        // a quoted string cannot carry line breaks: they would start a new IMAP command
        if (strpbrk($s, "\r\n\0") !== false) {
            throw new RuntimeException(__('Invalid characters (line break) in an IMAP value', 'dmarc'));
        }

        return '"' . str_replace(['\\', '"'], ['\\\\', '\\"'], $s) . '"';
    }

    private static function unquote(string $s): string
    {
        if (strlen($s) >= 2 && $s[0] === '"' && str_ends_with($s, '"')) {
            return stripcslashes(substr($s, 1, -1));
        }

        return $s;
    }

    /** Folder names travel in "modified UTF-7" (RFC 3501). */
    public static function encodeFolder(string $name): string
    {
        return preg_match('/[^\x20-\x7e]|&/', $name) === 1 ? (string) mb_convert_encoding($name, 'UTF7-IMAP', 'UTF-8') : $name;
    }

    public static function decodeFolder(string $name): string
    {
        return str_contains($name, '&') ? (string) mb_convert_encoding($name, 'UTF-8', 'UTF7-IMAP') : $name;
    }

    private static function short(string $s, int $max = 200): string
    {
        $s = trim(preg_replace('/\s+/', ' ', $s) ?? $s);

        return mb_strlen($s) > $max ? mb_substr($s, 0, $max) . '…' : $s;
    }
}
