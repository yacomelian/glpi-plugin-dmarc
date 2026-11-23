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
 * Small MIME reader: headers of the message and its leaf parts, decoded.
 * Enough for DMARC report mails (a zip/gzip/xml attachment, sometimes the
 * whole body).
 */
final class Mime
{
    private const MAX_DEPTH = 8;

    /**
     * @return array{headers: array<string,string>, parts: list<array{type:string, filename:string, data:string}>}
     */
    public static function parse(string $raw): array
    {
        [$headers, $body] = self::split($raw);
        $parts = [];
        self::walk($headers, $body, $parts, 0);

        return ['headers' => $headers, 'parts' => $parts];
    }

    /** Decoded header value (RFC 2047 encoded words). */
    public static function header(array $headers, string $name): string
    {
        $value = $headers[strtolower($name)] ?? '';
        if ($value === '') {
            return '';
        }
        if (str_contains($value, '=?')) {
            $decoded = @iconv_mime_decode($value, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
            if (is_string($decoded)) {
                $value = $decoded;
            }
        }

        return trim(mb_convert_encoding($value, 'UTF-8', 'UTF-8'));
    }

    /** @return array{0: array<string,string>, 1: string} */
    private static function split(string $raw): array
    {
        $pos = strpos($raw, "\r\n\r\n");
        $sep = 4;
        $alt = strpos($raw, "\n\n");
        if ($pos === false || ($alt !== false && $alt < $pos)) {
            $pos = $alt;
            $sep = 2;
        }
        if ($pos === false) {
            return [self::headers($raw), ''];
        }

        return [self::headers(substr($raw, 0, $pos)), substr($raw, $pos + $sep)];
    }

    /** @return array<string,string> lower-case name => unfolded value (first occurrence) */
    private static function headers(string $block): array
    {
        $block   = preg_replace("/\r?\n[ \t]+/", ' ', $block) ?? $block;
        $headers = [];
        foreach (preg_split("/\r?\n/", $block) ?: [] as $line) {
            $colon = strpos($line, ':');
            if ($colon === false || $colon === 0) {
                continue;
            }
            $name = strtolower(trim(substr($line, 0, $colon)));
            if (!isset($headers[$name])) {
                $headers[$name] = trim(substr($line, $colon + 1));
            }
        }

        return $headers;
    }

    private static function walk(array $headers, string $body, array &$parts, int $depth): void
    {
        [$type, $params] = self::contentType($headers['content-type'] ?? 'text/plain');

        if (str_starts_with($type, 'multipart/') && isset($params['boundary']) && $depth < self::MAX_DEPTH) {
            $boundary = '--' . $params['boundary'];
            $chunks   = explode($boundary, $body);
            array_shift($chunks); // preamble
            foreach ($chunks as $chunk) {
                if (str_starts_with($chunk, '--')) {
                    break; // closing boundary
                }
                $chunk = preg_replace('/^[ \t]*\r?\n/', '', $chunk) ?? $chunk;
                $chunk = preg_replace('/\r?\n$/', '', $chunk) ?? $chunk;
                [$h, $b] = self::split($chunk);
                self::walk($h, $b, $parts, $depth + 1);
            }

            return;
        }

        if ($type === 'message/rfc822' && $depth < self::MAX_DEPTH) {
            [$h, $b] = self::split(self::decode($body, $headers['content-transfer-encoding'] ?? ''));
            self::walk($h, $b, $parts, $depth + 1);

            return;
        }

        $parts[] = [
            'type'     => $type,
            'filename' => self::filename($headers, $params),
            'data'     => self::decode($body, $headers['content-transfer-encoding'] ?? ''),
        ];
    }

    /** @return array{0:string, 1:array<string,string>} */
    private static function contentType(string $value): array
    {
        $pieces = explode(';', $value);
        $type   = strtolower(trim((string) array_shift($pieces)));

        return [$type ?: 'text/plain', self::params(implode(';', $pieces))];
    }

    /** Parameters, with RFC 2231 (name*=utf-8''..., name*0=...) support. */
    private static function params(string $s): array
    {
        $params = [];
        $ext    = [];
        preg_match_all('/([\w*.-]+)\s*=\s*("(?:[^"\\\\]|\\\\.)*"|[^;]*)/', $s, $m, PREG_SET_ORDER);
        foreach ($m as [, $name, $value]) {
            $name  = strtolower($name);
            $value = trim($value);
            if (strlen($value) >= 2 && $value[0] === '"') {
                $value = stripcslashes(substr($value, 1, -1));
            }
            if (preg_match('/^(.+?)\*(\d+)?(\*)?$/', $name, $mm) === 1) {
                $ext[$mm[1]][(int) ($mm[2] ?? 0)] = [$value, isset($mm[3]) || (!isset($mm[2]) || $mm[2] === '')];
                continue;
            }
            $params[$name] = $value;
        }
        foreach ($ext as $name => $sections) {
            ksort($sections);
            $value   = '';
            $charset = 'UTF-8';
            foreach ($sections as $i => [$v, $encoded]) {
                if ($encoded) {
                    if ($i === 0 && preg_match("/^([^']*)'[^']*'(.*)$/", $v, $mm) === 1) {
                        $charset = $mm[1] ?: 'UTF-8';
                        $v       = $mm[2];
                    }
                    $v = rawurldecode($v);
                }
                $value .= $v;
            }
            $params[$name] = (string) @mb_convert_encoding($value, 'UTF-8', $charset);
        }

        return $params;
    }

    private static function filename(array $headers, array $typeParams): string
    {
        $disposition = self::params((string) strstr(($headers['content-disposition'] ?? '') . ';', ';'));
        $name        = $disposition['filename'] ?? $typeParams['name'] ?? '';
        if (str_contains($name, '=?')) {
            $decoded = @iconv_mime_decode($name, ICONV_MIME_DECODE_CONTINUE_ON_ERROR, 'UTF-8');
            $name    = is_string($decoded) ? $decoded : $name;
        }

        return basename(str_replace('\\', '/', trim($name)));
    }

    private static function decode(string $body, string $encoding): string
    {
        return match (strtolower(trim($encoding))) {
            'base64'           => (string) base64_decode(preg_replace('/[^A-Za-z0-9+\/=]/', '', $body) ?? '', false),
            'quoted-printable' => quoted_printable_decode($body),
            default            => $body,
        };
    }
}
