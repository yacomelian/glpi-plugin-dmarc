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
 * Fake AbuseIPDB API for the self-test, as a router of PHP's built-in server:
 *
 *   php -S 127.0.0.1:PORT fake-abuseipdb.php
 *
 * GET /check?ipAddress=IP  → score = last number of the IP (max 100);
 * an IP ending in .99 answers 429 (rate limit); without "Key" header, 401.
 */

header('Content-Type: application/json');
$path = parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH);
if (!str_ends_with((string) $path, '/check')) {
    http_response_code(404);
    echo json_encode(['errors' => [['detail' => 'not found']]]);

    return true;
}
if (($_SERVER['HTTP_KEY'] ?? '') === '') {
    http_response_code(401);
    echo json_encode(['errors' => [['detail' => 'Authentication failed. Your API key is either missing, incorrect, or revoked.']]]);

    return true;
}
$ip = (string) ($_GET['ipAddress'] ?? '');
if (str_ends_with($ip, '.99')) {
    http_response_code(429);
    header('Retry-After: 120');
    echo json_encode(['errors' => [['detail' => 'Daily rate limit of 1000 requests exceeded for this endpoint.']]]);

    return true;
}
preg_match('/(\d+)$/', $ip, $m);
$score = min(100, (int) ($m[1] ?? 0));
echo json_encode(['data' => [
    'ipAddress'            => $ip,
    'isPublic'             => true,
    'abuseConfidenceScore' => $score,
    'countryCode'          => 'ES',
    'usageType'            => 'Data Center/Web Hosting/Transit',
    'isp'                  => 'Test Provider Ltd',
    'domain'               => 'proveedor-prueba.example',
    'isTor'                => false,
    'isWhitelisted'        => false,
    'totalReports'         => $score * 3,
    'numDistinctUsers'     => $score,
    'lastReportedAt'       => $score > 0 ? '2026-11-10T08:00:00+00:00' : null,
]]);

return true;
