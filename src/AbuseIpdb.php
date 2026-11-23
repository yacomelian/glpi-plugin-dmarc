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

use DBmysql;
use Glpi\DBAL\QueryExpression;
use GLPIKey;
use RuntimeException;

/**
 * Reputation of the sending IPs in AbuseIPDB (abuse confidence %, reports,
 * country, provider, usage, domain). The answer is kept on the source
 * (glpi_plugin_dmarc_sources.abuse_*) and asked again only when it is older
 * than "abuseipdb_days" days, so the same IP is never queried twice in a row.
 *
 * Only public IPs. Queries run in the background (Worker), never in a page,
 * with a daily cap and a pause when AbuseIPDB answers 429.
 */
final class AbuseIpdb
{
    /** Overridable for the self-test (fake server). */
    public static string $baseUrl = 'https://api.abuseipdb.com/api/v2';

    public const FIELDS = [
        'abuse_score'         => 'smallint DEFAULT NULL',
        'abuse_reports'       => 'int DEFAULT NULL',
        'abuse_users'         => 'int DEFAULT NULL',
        'abuse_country'       => 'varchar(8) DEFAULT NULL',
        'abuse_isp'           => 'varchar(255) DEFAULT NULL',
        'abuse_usage'         => 'varchar(128) DEFAULT NULL',
        'abuse_domain'        => 'varchar(255) DEFAULT NULL',
        'abuse_tor'           => 'tinyint DEFAULT NULL',
        'abuse_whitelisted'   => 'tinyint DEFAULT NULL',
        'abuse_last_reported' => 'timestamp NULL DEFAULT NULL',
        'abuse_date'          => 'timestamp NULL DEFAULT NULL',
        'abuse_error'         => 'varchar(255) DEFAULT NULL',
    ];

    public static function link(string $ip): string
    {
        return 'https://www.abuseipdb.com/check/' . rawurlencode($ip);
    }

    public static function isPublic(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false;
    }

    public static function key(): string
    {
        return trim((string) Settings::get('abuseipdb_key'));
    }

    public static function isEnabled(): bool
    {
        return (bool) Settings::int('abuseipdb_enabled') && self::key() !== '';
    }

    /**
     * Queries the IPs that need it (never asked, or older than the validity),
     * those failing DMARC first. Stops at the daily cap, at the time limit or
     * when AbuseIPDB says "too many requests".
     *
     * @return array{done:int, errors:int, stopped:string}
     */
    public static function refresh(int $maxSeconds = 600, ?callable $log = null): array
    {
        /** @var DBmysql $DB */
        global $DB;

        $out = ['done' => 0, 'errors' => 0, 'stopped' => ''];
        if (!self::isEnabled()) {
            $out['stopped'] = __('AbuseIPDB is disabled or has no API key', 'dmarc');

            return $out;
        }
        $blocked = (string) Settings::get('state_abuseipdb_blocked_until');
        if ($blocked !== '' && strtotime($blocked) > time()) {
            $out['stopped'] = sprintf(__('AbuseIPDB asked to wait until %s', 'dmarc'), $blocked);

            return $out;
        }

        $key      = self::key();
        $days     = max(1, Settings::int('abuseipdb_days'));
        $cap      = max(1, Settings::int('abuseipdb_daily_max'));
        [$day, $used] = array_pad(explode('|', (string) Settings::get('state_abuseipdb_count')), 2, '0');
        $used     = $day === date('Y-m-d') ? (int) $used : 0;
        $started  = time();
        $limit    = date('Y-m-d H:i:s', strtotime("-{$days} days"));

        // failing sources first, then unclassified / unauthorized, then the most recent
        $rows = $DB->request([
            'SELECT'    => [
                's.id', 's.ip', 's.sender', 's.ptr',
                new QueryExpression('MAX(CASE WHEN ' . $DB->quoteName('r.dmarc_pass') . ' = 0 THEN 1 ELSE 0 END) AS ' . $DB->quoteName('fails')),
                new QueryExpression('CASE ' . $DB->quoteName('s.status')
                    . ' WHEN ' . Diagnosis::SOURCE_UNAUTHORIZED . ' THEN 2 WHEN ' . Diagnosis::SOURCE_UNKNOWN . ' THEN 1 ELSE 0 END AS ' . $DB->quoteName('suspicious')),
            ],
            'FROM'      => Importer::T_SOURCES . ' AS s',
            'LEFT JOIN' => [Importer::T_RECORDS . ' AS r' => ['ON' => ['r' => 'sources_id', 's' => 'id']]],
            'WHERE'     => ['OR' => [['s.abuse_date' => null], ['s.abuse_date' => ['<', $limit]]]],
            'GROUPBY'   => ['s.id'],
            'ORDER'     => ['fails DESC', 'suspicious DESC', 's.last_seen DESC'],
            'LIMIT'     => 2000,
        ]);

        foreach ($rows as $row) {
            if (!self::isPublic((string) $row['ip'])) {
                continue;
            }
            if ($used >= $cap) {
                $out['stopped'] = sprintf(__('daily limit of %d queries reached', 'dmarc'), $cap);
                break;
            }
            if (time() - $started >= $maxSeconds) {
                $out['stopped'] = __('maximum run time reached', 'dmarc');
                break;
            }
            try {
                $data = self::check((string) $row['ip'], $key);
                $used++;
                $update = self::toFields($data) + ['abuse_date' => date('Y-m-d H:i:s'), 'abuse_error' => null];
                // no name for the source: use what AbuseIPDB knows (domain or provider)
                if ((string) $row['sender'] === '' && (string) $row['ptr'] === '') {
                    $label = Diagnosis::sender((string) $row['ip'], '', array_filter([(string) ($update['abuse_domain'] ?? '')]), (string) Settings::get('own_networks'));
                    $label = $label !== '' ? $label : (string) ($update['abuse_isp'] ?? '');
                    if ($label !== '') {
                        $update['sender'] = mb_substr($label, 0, 64);
                    }
                }
                $DB->update('glpi_plugin_dmarc_sources', $update, ['id' => $row['id']]);
                $out['done']++;
            } catch (AbuseIpdbRateLimit $e) {
                Settings::set(['state_abuseipdb_blocked_until' => date('Y-m-d H:i:s', time() + $e->retryAfter)]);
                $out['stopped'] = __('AbuseIPDB: too many requests, it will go on later', 'dmarc');
                break;
            } catch (\Throwable $e) {
                $used++;
                $out['errors']++;
                $DB->update('glpi_plugin_dmarc_sources', [
                    'abuse_error' => mb_substr($e->getMessage(), 0, 255),
                    // try again tomorrow, not in every run
                    'abuse_date'  => date('Y-m-d H:i:s', strtotime("-{$days} days +1 day")),
                ], ['id' => $row['id']]);
                if ($out['errors'] >= 5 && $out['done'] === 0) {
                    $out['stopped'] = sprintf(__('repeated errors: %s', 'dmarc'), $e->getMessage());
                    break;
                }
            }
            if ($log !== null && $out['done'] > 0 && $out['done'] % 50 === 0) {
                $log($out);
            }
        }
        Settings::set(['state_abuseipdb_count' => date('Y-m-d') . '|' . $used]);

        return $out;
    }

    /** One query (no cache: see refresh()). */
    public static function check(string $ip, string $key): array
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        $ch = curl_init(self::$baseUrl . '/check?ipAddress=' . rawurlencode($ip) . '&maxAgeInDays=90');
        $headers = [];
        $opts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 8,
            CURLOPT_HTTPHEADER     => ['Key: ' . $key, 'Accept: application/json'],
            CURLOPT_HEADERFUNCTION => static function ($ch, string $line) use (&$headers): int {
                if (str_contains($line, ':')) {
                    [$name, $value] = explode(':', $line, 2);
                    $headers[strtolower(trim($name))] = trim($value);
                }

                return strlen($line);
            },
        ];
        if (!empty($CFG_GLPI['proxy_name']) && str_starts_with(self::$baseUrl, 'https://')) {
            $opts[CURLOPT_PROXY]     = $CFG_GLPI['proxy_name'];
            $opts[CURLOPT_PROXYPORT] = (int) ($CFG_GLPI['proxy_port'] ?? 8080);
            if (!empty($CFG_GLPI['proxy_user'])) {
                $opts[CURLOPT_PROXYUSERPWD] = $CFG_GLPI['proxy_user'] . ':' . (new GLPIKey())->decrypt((string) $CFG_GLPI['proxy_passwd']);
            }
        }
        curl_setopt_array($ch, $opts);
        $body   = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error  = curl_error($ch);
        if ($body === false) {
            throw new RuntimeException(sprintf(__('Cannot connect to AbuseIPDB (%s)', 'dmarc'), $error));
        }
        if ($status === 429) {
            throw new AbuseIpdbRateLimit(max(60, (int) ($headers['retry-after'] ?? 3600)));
        }
        $json = json_decode((string) $body, true);
        $data = is_array($json) ? ($json['data'] ?? null) : null;
        if ($status !== 200 || !is_array($data)) {
            $detail = is_array($json) ? (string) ($json['errors'][0]['detail'] ?? '') : '';
            throw new RuntimeException(sprintf(__('AbuseIPDB answered HTTP %1$d%2$s', 'dmarc'), $status, $detail !== '' ? ': ' . $detail : ''));
        }

        return $data;
    }

    /** API answer → columns of the source. */
    public static function toFields(array $data): array
    {
        $last = isset($data['lastReportedAt']) && is_string($data['lastReportedAt']) ? strtotime($data['lastReportedAt']) : false;

        return [
            'abuse_score'         => max(0, min(100, (int) ($data['abuseConfidenceScore'] ?? 0))),
            'abuse_reports'       => (int) ($data['totalReports'] ?? 0),
            'abuse_users'         => (int) ($data['numDistinctUsers'] ?? 0),
            'abuse_country'       => mb_substr((string) ($data['countryCode'] ?? ''), 0, 8) ?: null,
            'abuse_isp'           => mb_substr((string) ($data['isp'] ?? ''), 0, 255) ?: null,
            'abuse_usage'         => mb_substr((string) ($data['usageType'] ?? ''), 0, 128) ?: null,
            'abuse_domain'        => mb_substr(strtolower((string) ($data['domain'] ?? '')), 0, 255) ?: null,
            'abuse_tor'           => !empty($data['isTor']) ? 1 : 0,
            'abuse_whitelisted'   => !empty($data['isWhitelisted']) ? 1 : 0,
            'abuse_last_reported' => $last !== false ? date('Y-m-d H:i:s', $last) : null,
        ];
    }

    /** Short text for tooltips and alerts. */
    public static function describe(array $s): string
    {
        if (($s['abuse_score'] ?? null) === null || ($s['abuse_score'] ?? '') === '') {
            return '';
        }
        $parts = [sprintf('AbuseIPDB %d %%', (int) $s['abuse_score'])];
        if ((int) ($s['abuse_reports'] ?? 0) > 0) {
            $parts[] = sprintf(_n('%d report in 90 days', '%d reports in 90 days', (int) $s['abuse_reports'], 'dmarc'), (int) $s['abuse_reports']);
        }
        foreach (['abuse_country' => '', 'abuse_isp' => '', 'abuse_usage' => '', 'abuse_domain' => ''] as $k => $_) {
            if ((string) ($s[$k] ?? '') !== '') {
                $parts[] = (string) $s[$k];
            }
        }
        if (!empty($s['abuse_tor'])) {
            $parts[] = __('Tor node', 'dmarc');
        }

        return implode(' · ', $parts);
    }
}
