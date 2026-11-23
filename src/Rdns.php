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
 * Reverse DNS (PTR) with a short timeout: gethostbyaddr() can block for
 * many seconds per IP when the resolver gets no answer (servers without
 * Internet). Uses the nameservers of /etc/resolv.conf over UDP.
 */
final class Rdns
{
    private static ?array $servers = null;

    /** PTR name, '' when there is none, null when no server answered. */
    public static function lookup(string $ip, float $timeout = 2.0): ?string
    {
        $name = self::arpa($ip);
        if ($name === null) {
            return '';
        }
        foreach (self::servers() as $server) {
            $answer = self::query($server, $name, $timeout);
            if ($answer !== null) {
                return $answer;
            }
        }

        return null;
    }

    private static function servers(): array
    {
        if (self::$servers !== null) {
            return self::$servers;
        }
        $servers = [];
        $conf    = @file_get_contents('/etc/resolv.conf');
        if (is_string($conf) && preg_match_all('/^\s*nameserver\s+(\S+)/m', $conf, $m)) {
            foreach ($m[1] as $ip) {
                if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
                    $servers[] = $ip;
                }
            }
        }

        return self::$servers = array_slice($servers ?: ['127.0.0.1'], 0, 3);
    }

    private static function arpa(string $ip): ?string
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 4) {
            return implode('.', array_reverse(explode('.', $ip))) . '.in-addr.arpa';
        }
        $hex = bin2hex($bin);

        return implode('.', array_reverse(str_split($hex))) . '.ip6.arpa';
    }

    private static function query(string $server, string $name, float $timeout): ?string
    {
        $id     = random_int(0, 0xFFFF);
        $packet = pack('nnnnnn', $id, 0x0100, 1, 0, 0, 0);
        foreach (explode('.', $name) as $label) {
            $packet .= chr(strlen($label)) . $label;
        }
        $packet .= "\0" . pack('nn', 12, 1); // PTR, IN

        $addr = str_contains($server, ':') ? "udp://[{$server}]:53" : "udp://{$server}:53";
        $sock = @stream_socket_client($addr, $errno, $errstr, $timeout);
        if ($sock === false) {
            return null;
        }
        stream_set_timeout($sock, (int) $timeout, (int) (($timeout - floor($timeout)) * 1e6));
        @fwrite($sock, $packet);
        $resp = @fread($sock, 4096);
        fclose($sock);
        if (!is_string($resp) || strlen($resp) < 12) {
            return null;
        }
        $h = unpack('nid/nflags/nqd/nan', substr($resp, 0, 8));
        if ($h === false || $h['id'] !== $id) {
            return null;
        }
        $rcode = $h['flags'] & 0x0F;
        if ($rcode === 3) {
            return ''; // NXDOMAIN
        }
        if ($rcode !== 0) {
            return null; // SERVFAIL, REFUSED… try the next server
        }
        $pos = 12;
        for ($i = 0; $i < $h['qd']; $i++) {
            self::name($resp, $pos);
            $pos += 4;
        }
        for ($i = 0; $i < $h['an']; $i++) {
            self::name($resp, $pos);
            if ($pos + 10 > strlen($resp)) {
                break;
            }
            $rr = unpack('ntype/nclass/Nttl/nlen', substr($resp, $pos, 10));
            $pos += 10;
            if ($rr['type'] === 12) {
                $p = $pos;

                // a host name only (the answer comes over UDP and could be forged)
                return substr((string) preg_replace('/[^a-z0-9._-]/', '', strtolower(rtrim(self::name($resp, $p), '.'))), 0, 253);
            }
            $pos += $rr['len'];
        }

        return '';
    }

    private static function name(string $data, int &$pos, int $depth = 0): string
    {
        $labels = [];
        while ($pos < strlen($data)) {
            $len = ord($data[$pos]);
            if ($len === 0) {
                $pos++;
                break;
            }
            if (($len & 0xC0) === 0xC0) {
                if ($depth > 10 || $pos + 1 >= strlen($data)) {
                    $pos += 2;
                    break;
                }
                $ptr = (($len & 0x3F) << 8) | ord($data[$pos + 1]);
                $pos += 2;
                $labels[] = self::name($data, $ptr, $depth + 1);
                break;
            }
            $labels[] = substr($data, $pos + 1, $len);
            $pos += $len + 1;
        }

        return implode('.', array_filter($labels, static fn($l) => $l !== ''));
    }
}
