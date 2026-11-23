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
 * Router of PHP's built-in web server that imitates the token endpoint of
 * Google, for tests without Internet:
 *
 *   php -S 127.0.0.1:PORT fake-google.php
 *
 * Client "cid" / secret "csec". Authorization codes: "good-code" (account
 * dmarc@corp.example), "other-code" (other@corp.example), "no-refresh" (no
 * refresh token), anything else → invalid_grant. Refresh token "rt-1" →
 * access token "at-2".
 */

header('Content-Type: application/json');

$send = static function (int $status, array $body): void {
    http_response_code($status);
    echo json_encode($body);
    exit;
};
$jwt = static fn(string $email) => 'e30.' . rtrim(strtr(base64_encode(json_encode(['email' => $email, 'sub' => '1'])), '+/', '-_'), '=') . '.sig';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    $send(405, ['error' => 'method']);
}
if (($_POST['client_id'] ?? '') !== 'cid' || ($_POST['client_secret'] ?? '') !== 'csec') {
    $send(401, ['error' => 'invalid_client', 'error_description' => 'The OAuth client was not found.']);
}

switch ($_POST['grant_type'] ?? '') {
    case 'authorization_code':
        if (($_POST['redirect_uri'] ?? '') === '') {
            $send(400, ['error' => 'redirect_uri_mismatch']);
        }
        match ($_POST['code'] ?? '') {
            'good-code'  => $send(200, ['access_token' => 'at-1', 'refresh_token' => 'rt-1', 'expires_in' => 3599, 'id_token' => $jwt('Dmarc@Corp.Example')]),
            'other-code' => $send(200, ['access_token' => 'at-x', 'refresh_token' => 'rt-x', 'expires_in' => 3599, 'id_token' => $jwt('other@corp.example')]),
            'no-refresh' => $send(200, ['access_token' => 'at-1', 'expires_in' => 3599, 'id_token' => $jwt('dmarc@corp.example')]),
            default      => $send(400, ['error' => 'invalid_grant', 'error_description' => 'Bad Request']),
        };
        break;
    case 'refresh_token':
        if (($_POST['refresh_token'] ?? '') === 'rt-1') {
            $send(200, ['access_token' => 'at-2', 'expires_in' => 3599, 'token_type' => 'Bearer']);
        }
        $send(400, ['error' => 'invalid_grant', 'error_description' => 'Token has been expired or revoked.']);
        break;
    default:
        $send(400, ['error' => 'unsupported_grant_type']);
}
