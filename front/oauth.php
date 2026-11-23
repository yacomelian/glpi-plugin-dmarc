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
 * Redirect URI of the Google OAuth client (the address registered in Google
 * Cloud). Stateless and without authentication (see setup.php):
 *
 * Google sends the browser here with a cross-site navigation, and with
 * session.cookie_samesite=Strict the browser does not send GLPI's session
 * cookie. If this page used the session, GLPI would see no session, start a
 * new one and log the user out. So it only answers a tiny page that goes on
 * to oauth.callback.php: that navigation starts from GLPI itself (same site)
 * and carries the session cookie. Only "code", "state" and "error" go on.
 */

use Symfony\Component\HttpFoundation\Response;

$params = [];
foreach (['code', 'state', 'error'] as $key) {
    $value = $_GET[$key] ?? null;
    if (is_string($value) && $value !== '' && strlen($value) <= 2048 && preg_match('/^[\x21-\x7e]+$/', $value) === 1) {
        $params[$key] = $value;
    }
}
// relative to this page: same directory, no host taken from the request
$target = 'oauth.callback.php' . ($params === [] ? '' : '?' . http_build_query($params));
$url    = htmlspecialchars($target, ENT_QUOTES);
$json   = json_encode($target, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);

$html = <<<HTML
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta http-equiv="refresh" content="0;url={$url}">
<title>DMARC</title>
</head>
<body style="font-family: sans-serif; padding: 2rem">
<p>Back to GLPI… If nothing happens, <a href="{$url}">click here</a>.</p>
<script>window.location.replace({$json});</script>
</body>
</html>
HTML;

return new Response($html, 200, [
    'Content-Type'    => 'text/html; charset=UTF-8',
    'Cache-Control'   => 'no-store',
    'Referrer-Policy' => 'no-referrer',
]);
