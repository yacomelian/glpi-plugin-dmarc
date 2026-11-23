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
use ZipArchive;

/**
 * DMARC aggregate reports (RFC 7489 appendix C, and the DMARCbis fields):
 * finds them in a mail or a file (zip, gzip or plain XML), decompresses with
 * a size limit and parses the XML without network or external entities.
 */
final class ReportParser
{
    /** Uncompressed size limit of one report. */
    public const MAX_XML_BYTES = 20 * 1024 * 1024;
    private const MAX_ZIP_ENTRIES = 20;

    /**
     * XML documents found in a MIME part or a file.
     *
     * @return list<array{name:string, xml:string}>
     */
    public static function extract(string $data, string $filename = '', string $type = ''): array
    {
        $lname = strtolower($filename);
        if (str_starts_with($data, "PK\x03\x04")) {
            return self::unzip($data);
        }
        if (str_starts_with($data, "\x1f\x8b")) {
            return [['name' => preg_replace('/\.gz$/i', '', $filename) ?: 'report.xml', 'xml' => self::gunzip($data)]];
        }
        $trim = ltrim($data, "\xEF\xBB\xBF \t\r\n");
        if (str_starts_with($trim, '<') && (str_ends_with($lname, '.xml') || str_contains($type, 'xml') || stripos(substr($trim, 0, 2048), '<feedback') !== false)) {
            if (strlen($data) > self::MAX_XML_BYTES) {
                throw new RuntimeException(__('Report too large', 'dmarc'));
            }

            return [['name' => $filename ?: 'report.xml', 'xml' => $trim]];
        }

        return [];
    }

    /** Is this MIME part worth looking at? */
    public static function isCandidate(array $part): bool
    {
        $type = $part['type'];
        $name = strtolower($part['filename']);
        if (preg_match('/\.(zip|gz|gzip|xml)$/', $name) === 1) {
            return true;
        }
        if (in_array($type, ['application/zip', 'application/x-zip-compressed', 'application/x-zip', 'application/gzip',
            'application/x-gzip', 'application/x-gunzip', 'application/xml', 'text/xml', 'application/octet-stream'], true)) {
            return true;
        }

        return str_starts_with($part['data'], "PK\x03\x04") || str_starts_with($part['data'], "\x1f\x8b");
    }

    /**
     * Parses one report.
     *
     * @return array{meta: array, policy: array, records: list<array>}
     */
    public static function parse(string $xml): array
    {
        // Namespaced documents (DMARCbis: xmlns="urn:ietf:params:xml:ns:dmarc-2.0"):
        // drop the namespace declarations so the element names are plain.
        $xml = preg_replace('/\sxmlns(?::\w+)?\s*=\s*("[^"]*"|\'[^\']*\')/', '', $xml, 5) ?? $xml;
        // No DTD at all: no entities (internal or external) can be expanded.
        if (stripos($xml, '<!DOCTYPE') !== false || stripos($xml, '<!ENTITY') !== false) {
            throw new RuntimeException(__('The XML declares a DOCTYPE: it is not processed', 'dmarc'));
        }

        $previous = libxml_use_internal_errors(true);
        try {
            $doc = simplexml_load_string($xml, \SimpleXMLElement::class, LIBXML_NONET | LIBXML_COMPACT);
            if ($doc === false) {
                $err = libxml_get_last_error();
                throw new RuntimeException(__('Invalid XML', 'dmarc') . ($err ? ': ' . trim($err->message) . ' (' . sprintf(__('line %d', 'dmarc'), $err->line) . ')' : ''));
            }
        } finally {
            libxml_clear_errors();
            libxml_use_internal_errors($previous);
        }
        if ($doc->getName() !== 'feedback') {
            throw new RuntimeException(sprintf(__('Not a DMARC aggregate report (root <%s>)', 'dmarc'), $doc->getName()));
        }

        $md = $doc->report_metadata;
        $pp = $doc->policy_published;
        $errors = [];
        foreach ($md->error ?? [] as $e) {
            $errors[] = self::s($e);
        }
        $meta = [
            'version'       => self::s($doc->version),
            'org_name'      => self::s($md->org_name),
            'org_email'     => self::s($md->email),
            'extra_contact' => self::s($md->extra_contact_info),
            'report_id'     => self::s($md->report_id),
            'begin'         => (int) self::s($md->date_range->begin),
            'end'           => (int) self::s($md->date_range->end),
            'errors'        => $errors,
        ];
        if ($meta['org_name'] === '' || $meta['report_id'] === '') {
            throw new RuntimeException(__('The report has no org_name or report_id', 'dmarc'));
        }
        if ($meta['begin'] <= 0 || $meta['end'] <= 0) {
            throw new RuntimeException(__('The report has no period (date_range)', 'dmarc'));
        }
        $pctRaw = self::s($pp->pct);
        $policy = [
            'domain'  => strtolower(rtrim(self::s($pp->domain), '.')),
            'adkim'   => strtolower(self::s($pp->adkim)) ?: 'r',
            'aspf'    => strtolower(self::s($pp->aspf)) ?: 'r',
            'p'       => strtolower(self::s($pp->p)),
            'sp'      => strtolower(self::s($pp->sp)),
            'np'      => strtolower(self::s($pp->np)),
            'pct'     => $pctRaw === '' ? null : max(0, min(100, (int) $pctRaw)),
            'fo'      => self::s($pp->fo),
            'testing' => strtolower(self::s($pp->testing)),
        ];
        if ($policy['domain'] === '') {
            throw new RuntimeException(__('The report has no policy_published/domain', 'dmarc'));
        }

        $records = [];
        foreach ($doc->record ?? [] as $rec) {
            $row     = $rec->row;
            $pe      = $row->policy_evaluated;
            $reasons = [];
            foreach ($pe->reason ?? [] as $r) {
                $reasons[] = trim(self::s($r->type) . (self::s($r->comment) !== '' ? ': ' . self::s($r->comment) : ''));
            }
            $dkim = [];
            foreach ($rec->auth_results->dkim ?? [] as $d) {
                $dkim[] = [
                    'domain'       => strtolower(rtrim(self::s($d->domain), '.')),
                    'selector'     => self::s($d->selector),
                    'result'       => strtolower(self::s($d->result)),
                    'human_result' => self::s($d->human_result),
                ];
            }
            $spf = [];
            foreach ($rec->auth_results->spf ?? [] as $s) {
                $spf[] = [
                    'domain' => strtolower(rtrim(self::s($s->domain), '.')),
                    'scope'  => strtolower(self::s($s->scope)) ?: 'mfrom',
                    'result' => strtolower(self::s($s->result)),
                ];
            }
            $ip = self::s($row->source_ip);
            if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
                continue; // malformed row
            }
            $records[] = [
                'ip'            => inet_ntop((string) inet_pton($ip)) ?: $ip,
                'count'         => max(0, (int) self::s($row->count)),
                'disposition'   => strtolower(self::s($pe->disposition)) ?: 'none',
                'dkim_eval'     => strtolower(self::s($pe->dkim)),
                'spf_eval'      => strtolower(self::s($pe->spf)),
                'reasons'       => $reasons,
                'header_from'   => strtolower(rtrim(self::s($rec->identifiers->header_from), '.')),
                'envelope_from' => strtolower(rtrim(self::s($rec->identifiers->envelope_from), '.')),
                'envelope_to'   => strtolower(rtrim(self::s($rec->identifiers->envelope_to), '.')),
                'dkim'          => $dkim,
                'spf'           => $spf,
            ];
        }

        return ['meta' => $meta, 'policy' => $policy, 'records' => $records];
    }

    private static function s(mixed $node): string
    {
        if ($node === null) {
            return '';
        }

        return trim((string) $node);
    }

    private static function gunzip(string $data): string
    {
        $ctx = inflate_init(ZLIB_ENCODING_GZIP);
        if ($ctx === false) {
            throw new RuntimeException(__('zlib is not available', 'dmarc'));
        }
        $out = '';
        $len = strlen($data);
        // small input steps: one step cannot inflate to much more than the limit
        for ($pos = 0; $pos < $len; $pos += 4096) {
            $chunk = @inflate_add($ctx, substr($data, $pos, 4096), $pos + 4096 >= $len ? ZLIB_FINISH : ZLIB_SYNC_FLUSH);
            if ($chunk === false) {
                throw new RuntimeException(__('Damaged gzip file', 'dmarc'));
            }
            $out .= $chunk;
            if (strlen($out) > self::MAX_XML_BYTES) {
                throw new RuntimeException(__('The uncompressed report exceeds the size limit', 'dmarc'));
            }
        }

        return $out;
    }

    /** @return list<array{name:string, xml:string}> */
    private static function unzip(string $data): array
    {
        $tmp = tempnam(defined('GLPI_TMP_DIR') ? GLPI_TMP_DIR : sys_get_temp_dir(), 'dmarc');
        if ($tmp === false) {
            throw new RuntimeException(__('Cannot create a temporary file', 'dmarc'));
        }
        try {
            file_put_contents($tmp, $data);
            $zip = new ZipArchive();
            if ($zip->open($tmp, ZipArchive::RDONLY) !== true) {
                throw new RuntimeException(__('Damaged zip file', 'dmarc'));
            }
            $out = [];
            try {
                for ($i = 0; $i < min($zip->numFiles, self::MAX_ZIP_ENTRIES); $i++) {
                    $stat = $zip->statIndex($i);
                    $name = (string) ($stat['name'] ?? '');
                    if ($stat === false || str_ends_with($name, '/')) {
                        continue;
                    }
                    if ((int) $stat['size'] > self::MAX_XML_BYTES) {
                        throw new RuntimeException(__('The uncompressed report exceeds the size limit', 'dmarc'));
                    }
                    $stream = $zip->getStreamIndex($i);
                    if ($stream === false) {
                        continue;
                    }
                    $content = '';
                    while (!feof($stream)) {
                        $content .= (string) fread($stream, 8192);
                        if (strlen($content) > self::MAX_XML_BYTES) {
                            fclose($stream);
                            throw new RuntimeException(__('The uncompressed report exceeds the size limit', 'dmarc'));
                        }
                    }
                    fclose($stream);
                    if (str_starts_with($content, "\x1f\x8b")) {
                        $content = self::gunzip($content);
                    }
                    $content = ltrim($content, "\xEF\xBB\xBF \t\r\n");
                    if (str_starts_with($content, '<')) {
                        $out[] = ['name' => basename($name), 'xml' => $content];
                    }
                }
            } finally {
                $zip->close();
            }

            return $out;
        } finally {
            @unlink($tmp);
        }
    }
}
