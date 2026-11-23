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
 * Saves mails / files with DMARC reports in the plugin tables.
 */
final class Importer
{
    // messages.status
    public const IMPORTED   = 1;
    public const DUPLICATE  = 2;
    public const NOT_REPORT = 3;
    public const ERROR      = 4;
    public const SKIPPED    = 5;

    public const STATUSES = [self::IMPORTED, self::DUPLICATE, self::NOT_REPORT, self::ERROR, self::SKIPPED];

    public const T_MESSAGES = 'glpi_plugin_dmarc_messages';
    public const T_REPORTS  = 'glpi_plugin_dmarc_reports';
    public const T_RECORDS  = 'glpi_plugin_dmarc_records';
    public const T_AUTH     = 'glpi_plugin_dmarc_authresults';
    public const T_SOURCES  = 'glpi_plugin_dmarc_sources';
    public const T_DOMAINS  = 'glpi_plugin_dmarc_domains';

    /** ip => [id, first_seen, last_seen] */
    private array $sources = [];
    /** name => [id, first_day, last_day] */
    private array $domains = [];

    public function __construct(
        private readonly bool $keepRaw = true,
        private readonly string $ownNetworks = '',
    ) {}

    public static function fromSettings(): self
    {
        return new self((bool) Settings::int('keep_raw'), (string) Settings::get('own_networks'));
    }

    public static function statusLabel(int $status): string
    {
        return match ($status) {
            self::IMPORTED   => __('Imported', 'dmarc'),
            self::DUPLICATE  => __('Duplicate', 'dmarc'),
            self::NOT_REPORT => __('Not a report', 'dmarc'),
            self::ERROR      => __('Error', 'dmarc'),
            self::SKIPPED    => __('Skipped', 'dmarc'),
            default          => '?',
        };
    }

    /**
     * Imports one mail.
     *
     * @param array{source?:string, uidvalidity?:int|null, uid?:int|null, filename?:string|null, size?:int} $info
     *
     * @return array{id:int, status:int, reports:int, error:string}
     */
    public function importMail(string $raw, array $info = []): array
    {
        $headers = [];
        $new     = 0;
        $dups    = 0;
        $errors  = [];
        $found   = 0;
        $reports = [];
        try {
            $mime    = Mime::parse($raw);
            $headers = $mime['headers'];
            foreach ($mime['parts'] as $part) {
                if (!ReportParser::isCandidate($part)) {
                    continue;
                }
                try {
                    foreach (ReportParser::extract($part['data'], $part['filename'], $part['type']) as $doc) {
                        $found++;
                        $reports[] = $doc;
                    }
                } catch (\Throwable $e) {
                    $errors[] = ($part['filename'] !== '' ? $part['filename'] . ': ' : '') . $e->getMessage();
                }
            }
        } catch (\Throwable $e) {
            $errors[] = $e->getMessage();
        }

        $messageId = $this->saveMessage($info, $headers, strlen($raw));
        foreach ($reports as $doc) {
            try {
                $this->saveReport(ReportParser::parse($doc['xml']), $messageId, $doc['xml']) ? $new++ : $dups++;
            } catch (\Throwable $e) {
                $errors[] = $doc['name'] . ': ' . $e->getMessage();
            }
        }

        $status = match (true) {
            $new > 0              => self::IMPORTED,
            $dups > 0             => self::DUPLICATE,
            $errors !== []        => self::ERROR,
            default               => self::NOT_REPORT,
        };
        $error = implode("\n", $errors);
        $this->finishMessage($messageId, $status, $new + $dups, $error);

        return ['id' => $messageId, 'status' => $status, 'reports' => $new, 'error' => $error];
    }

    /**
     * Imports a file given by hand: a mail (.eml) or a report (.zip, .gz, .xml).
     *
     * @return array{id:int, status:int, reports:int, error:string}
     */
    public function importFile(string $filename, string $data, string $source = 'file'): array
    {
        $head = substr($data, 0, 4096);
        $isMail = str_ends_with(strtolower($filename), '.eml')
            || (preg_match('/^(Received|Return-Path|From|Delivered-To|Message-ID|MIME-Version|X-[\w-]+):/mi', $head) === 1
                && !str_starts_with($data, "PK\x03\x04") && !str_starts_with($data, "\x1f\x8b") && !str_starts_with(ltrim($head), '<'));
        if ($isMail) {
            return $this->importMail($data, ['source' => $source, 'filename' => $filename]);
        }

        $messageId = $this->saveMessage(['source' => $source, 'filename' => $filename], [], strlen($data));
        $new = 0;
        $dups = 0;
        $errors = [];
        try {
            $docs = ReportParser::extract($data, $filename);
            foreach ($docs as $doc) {
                try {
                    $this->saveReport(ReportParser::parse($doc['xml']), $messageId, $doc['xml']) ? $new++ : $dups++;
                } catch (\Throwable $e) {
                    $errors[] = $doc['name'] . ': ' . $e->getMessage();
                }
            }
        } catch (\Throwable $e) {
            $errors[] = $e->getMessage();
        }
        $status = match (true) {
            $new > 0       => self::IMPORTED,
            $dups > 0      => self::DUPLICATE,
            $errors !== [] => self::ERROR,
            default        => self::NOT_REPORT,
        };
        $error = implode("\n", $errors);
        $this->finishMessage($messageId, $status, $new + $dups, $error);

        return ['id' => $messageId, 'status' => $status, 'reports' => $new, 'error' => $error];
    }

    /** Row for a message that could not be fetched (too big…). */
    public function skipMessage(array $info, string $reason): int
    {
        $id = $this->saveMessage($info, [], (int) ($info['size'] ?? 0));
        $this->finishMessage($id, self::SKIPPED, 0, $reason);

        return $id;
    }

    public function setPostAction(int $messageId, string $action): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::T_MESSAGES, ['post_action' => $action], ['id' => $messageId]);
    }

    private function saveMessage(array $info, array $headers, int $size): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        $date = '';
        if (($h = Mime::header($headers, 'date')) !== '' && ($ts = strtotime($h)) !== false) {
            $date = date('Y-m-d H:i:s', $ts);
        }
        $row = [
            'source'      => (string) ($info['source'] ?? 'imap'),
            'uidvalidity' => isset($info['uidvalidity']) ? (int) $info['uidvalidity'] : null,
            'uid'         => isset($info['uid']) ? (int) $info['uid'] : null,
            'message_id'  => mb_substr(trim(Mime::header($headers, 'message-id'), '<> '), 0, 255) ?: null,
            'filename'    => isset($info['filename']) ? mb_substr((string) $info['filename'], 0, 255) : null,
            'date_mail'   => $date ?: null,
            'sender'      => mb_substr(Mime::header($headers, 'from'), 0, 255) ?: null,
            'subject'     => mb_substr(Mime::header($headers, 'subject'), 0, 255) ?: null,
            'size'        => $size,
            'status'      => 0,
            'date_mod'    => date('Y-m-d H:i:s'),
        ];
        if ($row['uidvalidity'] !== null && $row['uid'] !== null) {
            $existing = $DB->request([
                'SELECT' => ['id'],
                'FROM'   => self::T_MESSAGES,
                'WHERE'  => ['uidvalidity' => $row['uidvalidity'], 'uid' => $row['uid']],
            ])->current();
            if ($existing !== null) {
                $DB->update(self::T_MESSAGES, $row, ['id' => $existing['id']]);

                return (int) $existing['id'];
            }
        }
        $row['date_creation'] = $row['date_mod'];
        $DB->insert(self::T_MESSAGES, $row);

        return (int) $DB->insertId();
    }

    private function finishMessage(int $id, int $status, int $reports, string $error): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::T_MESSAGES, [
            'status'  => $status,
            'reports' => $reports,
            'error'   => $error !== '' ? mb_substr($error, 0, 4000) : null,
        ], ['id' => $id]);
    }

    /**
     * Saves one parsed report.
     *
     * @return bool false when the report was already there (duplicate)
     */
    public function saveReport(array $report, int $messageId, string $xml = ''): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $meta   = $report['meta'];
        $policy = $report['policy'];
        $org    = mb_substr($meta['org_name'], 0, 255);
        $rid    = mb_substr($meta['report_id'], 0, 255);

        $exists = $DB->request([
            'SELECT' => ['id'],
            'FROM'   => self::T_REPORTS,
            'WHERE'  => ['org_name' => $org, 'report_id' => $rid],
        ])->current();
        if ($exists !== null) {
            return false;
        }

        $day   = date('Y-m-d', intdiv($meta['begin'] + $meta['end'], 2));
        $total = 0;
        $pass  = 0;
        foreach ($report['records'] as $r) {
            $total += $r['count'];
            if ($r['dkim_eval'] === 'pass' || $r['spf_eval'] === 'pass') {
                $pass += $r['count'];
            }
        }

        $DB->beginTransaction();
        try {
            $DB->insert(self::T_REPORTS, [
                'messages_id'   => $messageId,
                'org_name'      => $org,
                'org_email'     => mb_substr($meta['org_email'], 0, 255) ?: null,
                'extra_contact' => mb_substr($meta['extra_contact'], 0, 255) ?: null,
                'report_id'     => $rid,
                'version'       => mb_substr($meta['version'], 0, 16) ?: null,
                'date_begin'    => date('Y-m-d H:i:s', $meta['begin']),
                'date_end'      => date('Y-m-d H:i:s', $meta['end']),
                'day'           => $day,
                'domain'        => mb_substr($policy['domain'], 0, 255),
                'adkim'         => mb_substr($policy['adkim'], 0, 8) ?: null,
                'aspf'          => mb_substr($policy['aspf'], 0, 8) ?: null,
                'p'             => mb_substr($policy['p'], 0, 16) ?: null,
                'sp'            => mb_substr($policy['sp'], 0, 16) ?: null,
                'np'            => mb_substr($policy['np'], 0, 16) ?: null,
                'pct'           => $policy['pct'],
                'fo'            => mb_substr($policy['fo'], 0, 16) ?: null,
                'testing'       => mb_substr($policy['testing'], 0, 8) ?: null,
                'errors'        => $meta['errors'] !== [] ? mb_substr(implode("\n", $meta['errors']), 0, 4000) : null,
                'total'         => $total,
                'pass'          => $pass,
                'records'       => count($report['records']),
                'date_creation' => date('Y-m-d H:i:s'),
            ]);
            $reportId = (int) $DB->insertId();

            $this->touchDomain($policy['domain'], $day, $policy['p']);

            foreach ($report['records'] as $r) {
                $headerFrom = $r['header_from'] ?: $policy['domain'];
                $authDomains = array_values(array_unique(array_filter(array_merge(
                    array_column($r['dkim'], 'domain'),
                    array_column($r['spf'], 'domain')
                ))));
                $sourceId = $this->touchSource($r['ip'], $day, $authDomains);
                $cause    = Diagnosis::cause($r, $headerFrom);
                $dkimList = [];
                foreach ($r['dkim'] as $d) {
                    $dkimList[] = $d['domain'] . ($d['selector'] !== '' ? '/' . $d['selector'] : '') . '=' . $d['result'];
                }

                $DB->insert(self::T_RECORDS, [
                    'reports_id'    => $reportId,
                    'sources_id'    => $sourceId,
                    'day'           => $day,
                    'domain'        => mb_substr($policy['domain'], 0, 255),
                    'ip'            => $r['ip'],
                    'count'         => $r['count'],
                    'disposition'   => mb_substr($r['disposition'], 0, 16),
                    'dkim_eval'     => mb_substr($r['dkim_eval'], 0, 16) ?: null,
                    'spf_eval'      => mb_substr($r['spf_eval'], 0, 16) ?: null,
                    'dmarc_pass'    => Diagnosis::isPass($cause) ? 1 : 0,
                    'cause'         => $cause,
                    'reasons'       => $r['reasons'] !== [] ? mb_substr(implode('; ', $r['reasons']), 0, 255) : null,
                    'header_from'   => mb_substr($headerFrom, 0, 255) ?: null,
                    'envelope_from' => mb_substr($r['envelope_from'], 0, 255) ?: null,
                    'envelope_to'   => mb_substr($r['envelope_to'], 0, 255) ?: null,
                    'dkim_domains'  => $dkimList !== [] ? mb_substr(implode(', ', $dkimList), 0, 255) : null,
                    'spf_domain'    => mb_substr(implode(', ', array_map(static fn($s) => $s['domain'] . '=' . $s['result'], $r['spf'])), 0, 255) ?: null,
                ]);
                $recordId = (int) $DB->insertId();

                foreach ($r['dkim'] as $d) {
                    $DB->insert(self::T_AUTH, [
                        'records_id'   => $recordId,
                        'type'         => 'dkim',
                        'domain'       => mb_substr($d['domain'], 0, 255) ?: null,
                        'selector'     => mb_substr($d['selector'], 0, 255) ?: null,
                        'result'       => mb_substr($d['result'], 0, 16) ?: null,
                        'human_result' => mb_substr($d['human_result'], 0, 255) ?: null,
                    ]);
                }
                foreach ($r['spf'] as $s) {
                    $DB->insert(self::T_AUTH, [
                        'records_id' => $recordId,
                        'type'       => 'spf',
                        'domain'     => mb_substr($s['domain'], 0, 255) ?: null,
                        'scope'      => mb_substr($s['scope'], 0, 16) ?: null,
                        'result'     => mb_substr($s['result'], 0, 16) ?: null,
                    ]);
                }
            }
            $DB->commit();
        } catch (\Throwable $e) {
            $DB->rollBack();
            // the cached ids may belong to rows that were rolled back
            $this->sources = [];
            $this->domains = [];
            throw $e;
        }

        if ($this->keepRaw && $xml !== '') {
            $this->storeRaw($reportId, $day, $xml);
        }

        return true;
    }

    private function storeRaw(int $reportId, string $day, string $xml): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $rel  = substr($day, 0, 4) . '/' . substr($day, 5, 2) . '/' . $reportId . '.xml.gz';
        $path = Settings::rawDir() . '/' . $rel;
        if (!is_dir(dirname($path)) && !@mkdir(dirname($path), 0o770, true) && !is_dir(dirname($path))) {
            return;
        }
        if (@file_put_contents($path, gzencode($xml, 6)) !== false) {
            $DB->update(self::T_REPORTS, ['raw_file' => $rel], ['id' => $reportId]);
        }
    }

    private function touchDomain(string $name, string $day, string $policy): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        if ($name === '') {
            return;
        }
        if (!isset($this->domains[$name])) {
            $row = $DB->request(['FROM' => self::T_DOMAINS, 'WHERE' => ['name' => $name]])->current();
            if ($row === null) {
                $glpi = 0;
                if ($DB->tableExists('glpi_domains')) {
                    $g = $DB->request(['SELECT' => ['id'], 'FROM' => 'glpi_domains', 'WHERE' => ['name' => $name, 'is_deleted' => 0], 'LIMIT' => 1])->current();
                    $glpi = (int) ($g['id'] ?? 0);
                }
                $DB->insert(self::T_DOMAINS, [
                    'name'          => $name,
                    'domains_id'    => $glpi,
                    'last_policy'   => $policy ?: null,
                    'first_day'     => $day,
                    'last_day'      => $day,
                    'date_creation' => date('Y-m-d H:i:s'),
                ]);
                $this->domains[$name] = [(int) $DB->insertId(), $day, $day];

                return;
            }
            $this->domains[$name] = [(int) $row['id'], (string) $row['first_day'], (string) $row['last_day']];
        }
        [$id, $first, $last] = $this->domains[$name];
        $update = [];
        if ($first === '' || $day < $first) {
            $update['first_day'] = $first = $day;
        }
        if ($last === '' || $day >= $last) {
            $update['last_day'] = $last = $day;
            if ($policy !== '') {
                $update['last_policy'] = $policy;
            }
        }
        if ($update !== []) {
            $DB->update(self::T_DOMAINS, $update, ['id' => $id]);
        }
        $this->domains[$name] = [$id, $first, $last];
    }

    /** @param string[] $authDomains */
    private function touchSource(string $ip, string $day, array $authDomains): int
    {
        /** @var \DBmysql $DB */
        global $DB;

        if (!isset($this->sources[$ip])) {
            $row = $DB->request(['FROM' => self::T_SOURCES, 'WHERE' => ['ip' => $ip]])->current();
            if ($row === null) {
                $DB->insert(self::T_SOURCES, [
                    'ip'            => $ip,
                    'sender'        => mb_substr(Diagnosis::sender($ip, '', $authDomains, $this->ownNetworks), 0, 64) ?: null,
                    'status'        => Diagnosis::SOURCE_UNKNOWN,
                    'first_seen'    => $day,
                    'last_seen'     => $day,
                    'date_creation' => date('Y-m-d H:i:s'),
                ]);
                $this->sources[$ip] = [(int) $DB->insertId(), $day, $day];

                return $this->sources[$ip][0];
            }
            $this->sources[$ip] = [(int) $row['id'], (string) $row['first_seen'], (string) $row['last_seen']];
            if ((string) $row['sender'] === '' && $authDomains !== []) {
                $label = Diagnosis::sender($ip, (string) $row['ptr'], $authDomains, $this->ownNetworks);
                if ($label !== '') {
                    $DB->update(self::T_SOURCES, ['sender' => mb_substr($label, 0, 64)], ['id' => $row['id']]);
                }
            }
        }
        [$id, $first, $last] = $this->sources[$ip];
        $update = [];
        if ($first === '' || $day < $first) {
            $update['first_seen'] = $first = $day;
        }
        if ($last === '' || $day > $last) {
            $update['last_seen'] = $last = $day;
        }
        if ($update !== []) {
            $DB->update(self::T_SOURCES, $update, ['id' => $id]);
        }
        $this->sources[$ip] = [$id, $first, $last];

        return $id;
    }

    /** Deletes reports (and their rows and originals) by id. */
    public static function deleteReports(array $ids): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (array_chunk(array_map('intval', $ids), 500) as $chunk) {
            foreach ($DB->request(['SELECT' => ['raw_file'], 'FROM' => self::T_REPORTS, 'WHERE' => ['id' => $chunk]]) as $row) {
                if (self::isRawPath((string) $row['raw_file'])) {
                    @unlink(Settings::rawDir() . '/' . $row['raw_file']);
                }
            }
            $records = array_column(iterator_to_array($DB->request(['SELECT' => ['id'], 'FROM' => self::T_RECORDS, 'WHERE' => ['reports_id' => $chunk]]), false), 'id');
            foreach (array_chunk($records, 1000) as $rchunk) {
                $DB->delete(self::T_AUTH, ['records_id' => $rchunk]);
            }
            $DB->delete(self::T_RECORDS, ['reports_id' => $chunk]);
            $DB->delete(self::T_REPORTS, ['id' => $chunk]);
        }
    }

    public static function readRaw(array $report): ?string
    {
        $rel = (string) ($report['raw_file'] ?? '');
        if (!self::isRawPath($rel)) {
            return null;
        }
        $path = Settings::rawDir() . '/' . $rel;
        if (!is_file($path) || is_link($path)) {
            return null;
        }
        $data = @file_get_contents($path, false, null, 0, ReportParser::MAX_XML_BYTES);
        $xml  = $data === false ? false : @gzdecode($data, ReportParser::MAX_XML_BYTES);

        return $xml === false ? null : $xml;
    }

    /** Only paths written by storeRaw(): YYYY/MM/<id>.xml.gz */
    private static function isRawPath(string $rel): bool
    {
        return preg_match('#^\d{4}/\d{2}/\d+\.xml\.gz$#', $rel) === 1;
    }

    /** Re-parse helper used by the self-test. */
    public static function assert(bool $condition, string $message): void
    {
        if (!$condition) {
            throw new RuntimeException($message);
        }
    }
}
