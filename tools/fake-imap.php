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

/*
 * DMARC plugin for GLPI — DEVELOPMENT ONLY
 * Tiny IMAP server for tests without a real mailbox. Plain TCP, in memory,
 * one client at a time. Only the commands the plugin's client uses.
 *
 *   php fake-imap.php <port> <dir> [uidvalidity] [user] [password] [oauth-token] [idle-drop-seconds]
 *
 * <dir>/<Folder>/*.eml are loaded at start (folder names with "__" for "/").
 * Any password is accepted when none is given; XOAUTH2 accepts any token
 * unless [oauth-token] is given.
 */

if (PHP_SAPI !== 'cli') {
    exit(1);
}

$port     = (int) ($argv[1] ?? 1143);
$dir      = (string) ($argv[2] ?? '.');
$validity = (int) ($argv[3] ?? 1234);
$user     = (string) ($argv[4] ?? '');
$pass     = (string) ($argv[5] ?? '');
$token    = (string) ($argv[6] ?? '');
// like a firewall: drop the connection when the client is silent this long (0 = never)
$idleDrop = (int) ($argv[7] ?? 0);

/** folder => [uid => ['data' => string, 'flags' => [], 'date' => int]] */
$folders = ['INBOX' => []];
$nextUid = ['INBOX' => 1];
foreach (glob(rtrim($dir, '/') . '/*', GLOB_ONLYDIR) ?: [] as $fdir) {
    $name = str_replace('__', '/', basename($fdir));
    $folders[$name] = [];
    $nextUid[$name] = 1;
    $files = glob($fdir . '/*.eml') ?: [];
    sort($files);
    foreach ($files as $f) {
        $folders[$name][$nextUid[$name]++] = ['data' => (string) file_get_contents($f), 'flags' => [], 'date' => filemtime($f) ?: time()];
    }
}

$server = @stream_socket_server("tcp://127.0.0.1:{$port}", $errno, $errstr);
if ($server === false) {
    fwrite(STDERR, "cannot listen on {$port}: {$errstr}\n");
    exit(2);
}
fwrite(STDOUT, "ready {$port}\n");

function tokens(string $s): array
{
    $out = [];
    $len = strlen($s);
    $i   = 0;
    while ($i < $len) {
        if ($s[$i] === ' ') {
            $i++;
            continue;
        }
        if ($s[$i] === '"') {
            $j = $i + 1;
            $v = '';
            while ($j < $len && $s[$j] !== '"') {
                if ($s[$j] === '\\' && $j + 1 < $len) {
                    $j++;
                }
                $v .= $s[$j++];
            }
            $out[] = $v;
            $i = $j + 1;
            continue;
        }
        if ($s[$i] === '(') {
            $j = strpos($s, ')', $i);
            $j = $j === false ? $len : $j;
            $out[] = substr($s, $i, $j - $i + 1);
            $i = $j + 1;
            continue;
        }
        $j = strpos($s, ' ', $i);
        $j = $j === false ? $len : $j;
        $out[] = substr($s, $i, $j - $i);
        $i = $j;
    }

    return $out;
}

function uidSet(string $set, array $msgs): array
{
    $uids = [];
    $max  = $msgs === [] ? 0 : max(array_keys($msgs));
    foreach (explode(',', $set) as $part) {
        [$a, $b] = array_pad(explode(':', $part, 2), 2, null);
        $a = $a === '*' ? $max : (int) $a;
        $b = $b === null ? $a : ($b === '*' ? $max : (int) $b);
        if ($a > $b) {
            [$a, $b] = [$b, $a];
        }
        foreach (array_keys($msgs) as $u) {
            if ($u >= $a && $u <= $b) {
                $uids[] = $u;
            }
        }
        if ($b === $max && $msgs !== [] && !in_array($max, $uids, true) && str_ends_with($part, '*')) {
            $uids[] = $max; // RFC 3501: "n:*" includes the last message
        }
    }
    sort($uids);

    return array_values(array_unique($uids));
}

while (true) {
    $c = @stream_socket_accept($server, -1);
    if ($c === false) {
        continue;
    }
    $selected = null;
    $writable = false;
    $authed   = false;
    fwrite($c, "* OK fake-imap ready\r\n");
    while (true) {
        if ($idleDrop > 0) {
            $r = [$c]; $w = null; $x = null;
            if (stream_select($r, $w, $x, $idleDrop) === 0) {
                break; // silent too long: drop
            }
        }
        $line = fgets($c);
        if ($line === false) {
            break;
        }
        $line = rtrim($line, "\r\n");
        if ($line === '') {
            continue;
        }
        [$tag, $rest] = array_pad(explode(' ', $line, 2), 2, '');
        $t   = tokens($rest);
        $cmd = strtoupper($t[0] ?? '');
        $ok  = "{$tag} OK done\r\n";
        if ($cmd === 'UID') {
            $cmd = 'UID ' . strtoupper($t[1] ?? '');
            array_shift($t);
        }
        switch ($cmd) {
            case 'CAPABILITY':
                fwrite($c, "* CAPABILITY IMAP4rev1 MOVE UIDPLUS SASL-IR AUTH=XOAUTH2\r\n" . $ok);
                break;
            case 'NOOP':
                fwrite($c, $ok);
                break;
            case 'LOGIN':
                if (($user === '' || $t[1] === $user) && ($pass === '' || ($t[2] ?? '') === $pass)) {
                    $authed = true;
                    fwrite($c, $ok);
                } else {
                    fwrite($c, "{$tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n");
                }
                break;
            case 'AUTHENTICATE':
                $data = base64_decode((string) ($t[2] ?? ''), true);
                if (is_string($data) && preg_match('/^user=([^\x01]+)\x01auth=Bearer (\S+)\x01\x01$/', $data, $m) === 1 && ($user === '' || $m[1] === $user) && ($token === '' || $m[2] === $token)) {
                    $authed = true;
                    fwrite($c, $ok);
                } else {
                    fwrite($c, '+ ' . base64_encode('{"status":"400"}') . "\r\n");
                    fgets($c);
                    fwrite($c, "{$tag} NO [AUTHENTICATIONFAILED] Invalid credentials\r\n");
                }
                break;
            case 'LIST':
                foreach (array_keys($folders) as $f) {
                    fwrite($c, '* LIST (\\HasNoChildren) "/" "' . addcslashes($f, '"\\') . "\"\r\n");
                }
                fwrite($c, $ok);
                break;
            case 'CREATE':
                $name = mb_convert_encoding((string) $t[1], 'UTF-8', 'UTF7-IMAP');
                $folders[$name] ??= [];
                $nextUid[$name] ??= 1;
                fwrite($c, $ok);
                break;
            case 'EXAMINE':
            case 'SELECT':
                $name = mb_convert_encoding((string) $t[1], 'UTF-8', 'UTF7-IMAP');
                if (!$authed || !isset($folders[$name])) {
                    fwrite($c, "{$tag} NO no such folder\r\n");
                    break;
                }
                $selected = $name;
                $writable = $cmd === 'SELECT';
                fwrite($c, '* ' . count($folders[$name]) . " EXISTS\r\n* OK [UIDVALIDITY {$validity}] ok\r\n* OK [UIDNEXT {$nextUid[$name]}] ok\r\n"
                    . "{$tag} OK [" . ($writable ? 'READ-WRITE' : 'READ-ONLY') . "] done\r\n");
                break;
            case 'UID SEARCH':
                $set  = '1:*';
                $args = array_slice($t, 1);
                for ($i = 0; $i < count($args); $i++) {
                    if (strtoupper($args[$i]) === 'UID') {
                        $set = $args[++$i];
                    } elseif (strtoupper($args[$i]) === 'SINCE') {
                        $since = strtotime($args[++$i]);
                    }
                }
                $msgs = $folders[$selected] ?? [];
                $uids = array_filter(uidSet($set, $msgs), static fn($u) => !isset($since) || $msgs[$u]['date'] >= $since);
                unset($since);
                fwrite($c, '* SEARCH' . ($uids ? ' ' . implode(' ', $uids) : '') . "\r\n" . $ok);
                break;
            case 'UID FETCH':
                $msgs  = $folders[$selected] ?? [];
                $items = strtoupper(implode(' ', array_slice($t, 2)));
                $seq   = 0;
                foreach (array_keys($msgs) as $u) {
                    $seq++;
                    if (!in_array($u, uidSet($t[1], $msgs), true)) {
                        continue;
                    }
                    $data = $msgs[$u]['data'];
                    if (str_contains($items, 'BODY')) {
                        fwrite($c, "* {$seq} FETCH (UID {$u} BODY[] {" . strlen($data) . "}\r\n" . $data . ")\r\n");
                        if ($writable && !str_contains($items, 'PEEK')) {
                            $folders[$selected][$u]['flags']['\\Seen'] = true;
                        }
                    } else {
                        fwrite($c, "* {$seq} FETCH (UID {$u} RFC822.SIZE " . strlen($data) . ")\r\n");
                    }
                }
                fwrite($c, $ok);
                break;
            case 'UID STORE':
                if (!$writable) {
                    fwrite($c, "{$tag} NO read-only\r\n");
                    break;
                }
                preg_match_all('/\\\\\w+/', implode(' ', array_slice($t, 3)), $fm);
                foreach (uidSet($t[1], $folders[$selected]) as $u) {
                    foreach ($fm[0] as $flag) {
                        $folders[$selected][$u]['flags'][$flag] = true;
                    }
                }
                fwrite($c, $ok);
                break;
            case 'UID COPY':
            case 'UID MOVE':
                if (!$writable) {
                    fwrite($c, "{$tag} NO read-only\r\n");
                    break;
                }
                $dest = mb_convert_encoding((string) $t[2], 'UTF-8', 'UTF7-IMAP');
                if (!isset($folders[$dest])) {
                    fwrite($c, "{$tag} NO [TRYCREATE] no such folder\r\n");
                    break;
                }
                foreach (uidSet($t[1], $folders[$selected]) as $u) {
                    $folders[$dest][$nextUid[$dest]++] = ['data' => $folders[$selected][$u]['data'], 'flags' => [], 'date' => $folders[$selected][$u]['date']];
                    if ($cmd === 'UID MOVE') {
                        unset($folders[$selected][$u]);
                    }
                }
                fwrite($c, $ok);
                break;
            case 'UID EXPUNGE':
            case 'EXPUNGE':
                foreach ($folders[$selected] ?? [] as $u => $msg) {
                    if (isset($msg['flags']['\\Deleted']) && ($cmd === 'EXPUNGE' || in_array($u, uidSet($t[1], $folders[$selected]), true))) {
                        unset($folders[$selected][$u]);
                    }
                }
                fwrite($c, $ok);
                break;
            case 'LOGOUT':
                fwrite($c, "* BYE\r\n" . $ok);
                break 2;
            default:
                fwrite($c, "{$tag} BAD unknown command\r\n");
        }
    }
    fclose($c);
}
