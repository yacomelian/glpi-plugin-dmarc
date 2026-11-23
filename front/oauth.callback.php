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
 * OAuth of Google with the consent of the mailbox owner.
 *
 *   ?action=start   sends the browser to Google to authorize
 *   ?code=…&state=… back from Google, through oauth.php (the redirect URI,
 *                   which bounces here so that the session cookie is sent)
 *
 * Needs the configuration right of GLPI.
 */

use GlpiPlugin\Dmarc\GoogleAuth;
use GlpiPlugin\Dmarc\Settings;
use GlpiPlugin\Dmarc\Ui;
use Symfony\Component\HttpFoundation\RedirectResponse;

Session::checkRight('config', UPDATE);

$config = Ui::root() . '/plugins/dmarc/front/config.form.php';

$clientId     = trim((string) Settings::get('oauth_client_id'));
$clientSecret = (string) Settings::get('oauth_client_secret');
$redirect     = GoogleAuth::redirectUri();

// 1) start: remember a random state and send the user to Google
if (($_GET['action'] ?? '') === 'start') {
    if ($clientId === '' || $clientSecret === '') {
        Session::addMessageAfterRedirect(__s('Save the OAuth client ID and secret first.', 'dmarc'), false, ERROR);
        Html::redirect($config);
    }
    $state = bin2hex(random_bytes(16));
    $_SESSION['plugin_dmarc_oauth_state'] = $state;
    // an external address: a plain response (Html::redirect is meant for GLPI pages)
    return new RedirectResponse(GoogleAuth::authUrl($clientId, $redirect, $state, trim((string) Settings::get('username'))));
}

// 2) back from Google
$expected = (string) ($_SESSION['plugin_dmarc_oauth_state'] ?? '');
unset($_SESSION['plugin_dmarc_oauth_state']);

if (isset($_GET['error'])) {
    $why = (string) $_GET['error'];
    Session::addMessageAfterRedirect(
        htmlspecialchars($why === 'access_denied'
            ? __('The authorization was cancelled in Google.', 'dmarc')
            : sprintf(__('Google returned an error: %s', 'dmarc'), $why)),
        false,
        WARNING
    );
    Html::redirect($config);
}

$code  = (string) ($_GET['code'] ?? '');
$state = (string) ($_GET['state'] ?? '');
if ($code === '' || $expected === '' || !hash_equals($expected, $state)) {
    Session::addMessageAfterRedirect(__s('The answer from Google does not belong to a connection started here. Press "Connect with Google" again.', 'dmarc'), false, ERROR);
    Html::redirect($config);
}

try {
    $tokens  = GoogleAuth::exchangeCode($clientId, $clientSecret, $redirect, $code);
    $email   = $tokens['email'];
    $mailbox = strtolower(trim((string) Settings::get('username')));

    // Only the mailbox that was asked for: if somebody authorized another account, nothing is stored
    if ($email === '') {
        throw new RuntimeException(__('Google did not say which account was authorized.', 'dmarc'));
    }
    if ($mailbox !== '' && $email !== $mailbox) {
        throw new RuntimeException(sprintf(
            __('You authorized the account %1$s, but the configured mailbox is %2$s. Nothing was saved: connect again with the mailbox account.', 'dmarc'),
            $email,
            $mailbox
        ));
    }
    $values = ['oauth_refresh_token' => $tokens['refresh_token'], 'oauth_email' => $email, 'auth' => 'oauth_google'];
    if ($mailbox === '') {
        $values['username'] = $email;
    }
    Settings::set($values);
    Session::addMessageAfterRedirect(sprintf(__s('Connected with Google as %s. You can now test the connection.', 'dmarc'), htmlspecialchars($email)));
} catch (\Throwable $e) {
    Session::addMessageAfterRedirect(htmlspecialchars($e->getMessage()), false, ERROR);
}

Html::redirect($config);
