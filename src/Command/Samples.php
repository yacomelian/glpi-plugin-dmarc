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

use ZipArchive;

/**
 * Builds synthetic DMARC aggregate reports and the mails that carry them,
 * the way the big reporters send them (Google: zip, Microsoft: gzip).
 */
final class Samples
{
    /**
     * @param array $report ['org', 'email', 'id', 'begin', 'end', 'domain', 'p', 'sp', 'pct', 'adkim', 'aspf', 'records' => [...]]
     *                      record: ['ip', 'count', 'disposition', 'dkim', 'spf', 'header_from', 'envelope_from', 'reasons' => [],
     *                               'auth_dkim' => [[domain, selector, result]], 'auth_spf' => [[domain, result]]]
     */
    public static function xml(array $report, bool $bis = false): string
    {
        $e = static fn($s) => htmlspecialchars((string) $s, ENT_XML1 | ENT_QUOTES, 'UTF-8');
        $x = '<?xml version="1.0" encoding="UTF-8" ?>' . "\n";
        $x .= $bis ? '<feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0">' : '<feedback>';
        $x .= "\n  <version>" . ($bis ? '2.0' : '1.0') . "</version>\n  <report_metadata>\n"
            . '    <org_name>' . $e($report['org']) . "</org_name>\n"
            . '    <email>' . $e($report['email']) . "</email>\n"
            . '    <report_id>' . $e($report['id']) . "</report_id>\n"
            . '    <date_range><begin>' . (int) $report['begin'] . '</begin><end>' . (int) $report['end'] . "</end></date_range>\n"
            . "  </report_metadata>\n  <policy_published>\n"
            . '    <domain>' . $e($report['domain']) . "</domain>\n"
            . '    <adkim>' . $e($report['adkim'] ?? 'r') . '</adkim><aspf>' . $e($report['aspf'] ?? 'r') . "</aspf>\n"
            . '    <p>' . $e($report['p']) . '</p>'
            . (($report['sp'] ?? '') !== '' ? '<sp>' . $e($report['sp']) . '</sp>' : '')
            . (isset($report['pct']) ? '<pct>' . (int) $report['pct'] . '</pct>' : '')
            . "<fo>0</fo>\n  </policy_published>\n";
        foreach ($report['records'] as $r) {
            $x .= "  <record>\n    <row>\n"
                . '      <source_ip>' . $e($r['ip']) . "</source_ip>\n"
                . '      <count>' . (int) $r['count'] . "</count>\n"
                . '      <policy_evaluated><disposition>' . $e($r['disposition']) . '</disposition>'
                . '<dkim>' . $e($r['dkim']) . '</dkim><spf>' . $e($r['spf']) . '</spf>';
            foreach ($r['reasons'] ?? [] as $reason) {
                $x .= '<reason><type>' . $e($reason) . '</type></reason>';
            }
            $x .= "</policy_evaluated>\n    </row>\n    <identifiers>"
                . '<header_from>' . $e($r['header_from']) . '</header_from>'
                . (($r['envelope_from'] ?? '') !== '' ? '<envelope_from>' . $e($r['envelope_from']) . '</envelope_from>' : '')
                . "</identifiers>\n    <auth_results>";
            foreach ($r['auth_dkim'] ?? [] as [$d, $s, $res]) {
                $x .= '<dkim><domain>' . $e($d) . '</domain><selector>' . $e($s) . '</selector><result>' . $e($res) . '</result></dkim>';
            }
            foreach ($r['auth_spf'] ?? [] as [$d, $res]) {
                $x .= '<spf><domain>' . $e($d) . '</domain><scope>mfrom</scope><result>' . $e($res) . '</result></spf>';
            }
            $x .= "</auth_results>\n  </record>\n";
        }

        return $x . "</feedback>\n";
    }

    public static function zip(string $name, string $xml): string
    {
        $tmp = tempnam(defined('GLPI_TMP_DIR') ? GLPI_TMP_DIR : sys_get_temp_dir(), 'dmz');
        $zip = new ZipArchive();
        $zip->open($tmp, ZipArchive::OVERWRITE);
        $zip->addFromString($name, $xml);
        $zip->close();
        $data = (string) file_get_contents($tmp);
        @unlink($tmp);

        return $data;
    }

    /**
     * Mail carrying a report as the reporters send it.
     *
     * @param string $style google (zip attachment) | microsoft (gzip attachment) | yahoo (gzip) | plain (xml) | body (zip as the whole body)
     */
    public static function mail(array $report, string $xml, string $style = 'google'): string
    {
        $base = $report['org'] . '!' . $report['domain'] . '!' . $report['begin'] . '!' . $report['end'];
        [$name, $type, $data] = match ($style) {
            'microsoft', 'yahoo' => [$base . '.xml.gz', 'application/gzip', gzencode($xml, 6)],
            'plain'              => [$base . '.xml', 'text/xml', $xml],
            default              => [$base . '.zip', 'application/zip', self::zip($base . '.xml', $xml)],
        };
        $date     = date('r', (int) $report['end'] + 3600 * 3);
        $boundary = '----=_dmarc_' . substr(sha1($report['id']), 0, 16);
        $subject  = 'Report domain: ' . $report['domain'] . ' Submitter: ' . $report['org'] . ' Report-ID: <' . $report['id'] . '>';
        $headers  = "Return-Path: <{$report['email']}>\r\n"
            . "From: {$report['org']} <{$report['email']}>\r\n"
            . "To: dmarc@{$report['domain']}\r\n"
            . "Subject: {$subject}\r\n"
            . "Date: {$date}\r\n"
            . 'Message-ID: <' . sha1($report['id']) . '@' . preg_replace('/[^a-z0-9.-]/i', '', $report['org']) . ".example>\r\n"
            . "MIME-Version: 1.0\r\n";
        $b64 = chunk_split(base64_encode($data), 76, "\r\n");

        if ($style === 'body') {
            return $headers . "Content-Type: application/zip; name=\"{$name}\"\r\n"
                . "Content-Disposition: attachment; filename=\"{$name}\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" . $b64;
        }

        return $headers . "Content-Type: multipart/mixed; boundary=\"{$boundary}\"\r\n\r\n"
            . "This is a multi-part message in MIME format.\r\n\r\n"
            . "--{$boundary}\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"
            . quoted_printable_encode("This is an aggregate report from {$report['org']}.\r\nInforme agregado DMARC — no responda.") . "\r\n"
            . "--{$boundary}\r\nContent-Type: {$type}; name=\"{$name}\"\r\n"
            . "Content-Disposition: attachment; filename*=utf-8''" . rawurlencode($name) . "\r\n"
            . "Content-Transfer-Encoding: base64\r\n\r\n" . $b64
            . "--{$boundary}--\r\n";
    }

    /** A mail that is not a report (it happens in the folder). */
    public static function notAReport(string $to): string
    {
        return "From: Alguien <alguien@example.net>\r\nTo: {$to}\r\nSubject: =?UTF-8?Q?Consulta_sobre_el_correo?=\r\n"
            . 'Date: ' . date('r') . "\r\nMessage-ID: <" . bin2hex(random_bytes(8)) . "@example.net>\r\nMIME-Version: 1.0\r\n"
            . "Content-Type: text/plain; charset=UTF-8\r\n\r\nHello, this is not a report.\r\n";
    }
}
