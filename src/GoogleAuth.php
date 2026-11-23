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

/**
 * OAuth 2.0 of Google with the consent of the mailbox owner (authorization
 * code flow). The owner of the mailbox authorizes the plugin once; Google
 * returns a refresh token that only gives access to THAT mailbox, and the
 * plugin exchanges it for short access tokens used with IMAP XOAUTH2.
 *
 * There is deliberately no service account / domain-wide delegation: it
 * could impersonate any user of the domain.
 *
 * Google side: an OAuth client of type "Web application" (consent screen
 * "Internal" so that refresh tokens do not expire) with the redirect URI
 * shown in the plugin configuration. Scope: https://mail.google.com/ (the
 * only one that allows IMAP) plus openid/email, to check whose mailbox
 * was authorized.
 */
final class GoogleAuth
{
    public const SCOPE     = 'https://mail.google.com/';
    public const AUTH_URI  = 'https://accounts.google.com/o/oauth2/v2/auth';
    public const TOKEN_URI = 'https://oauth2.googleapis.com/token';

    /** Token endpoint override (self-test against a simulated Google). */
    public static ?string $tokenUri = null;

    /** The address Google must send the user back to: set it in the OAuth client. */
    public static function redirectUri(): string
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        return rtrim((string) ($CFG_GLPI['url_base'] ?? ''), '/') . '/plugins/dmarc/front/oauth.php';
    }

    /** Where the user is sent to authorize. */
    public static function authUrl(string $clientId, string $redirectUri, string $state, string $loginHint = ''): string
    {
        $params = [
            'client_id'     => $clientId,
            'redirect_uri'  => $redirectUri,
            'response_type' => 'code',
            'scope'         => 'openid email ' . self::SCOPE,
            'access_type'   => 'offline', // we want a refresh token
            'prompt'        => 'consent', // and Google must give it again on re-connecting
            'state'         => $state,
        ];
        if ($loginHint !== '') {
            $params['login_hint'] = $loginHint;
        }

        return self::AUTH_URI . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * Exchanges the authorization code.
     *
     * @return array{refresh_token:string, access_token:string, email:string}
     */
    public static function exchangeCode(string $clientId, string $clientSecret, string $redirectUri, string $code): array
    {
        $data = self::token([
            'grant_type'    => 'authorization_code',
            'code'          => $code,
            'client_id'     => $clientId,
            'client_secret' => $clientSecret,
            'redirect_uri'  => $redirectUri,
        ]);
        $refresh = (string) ($data['refresh_token'] ?? '');
        if ($refresh === '') {
            throw new RuntimeException(__('Google did not return a refresh token. Remove the plugin\'s access in myaccount.google.com › Security › Third-party connections and connect again', 'dmarc'));
        }

        return [
            'refresh_token' => $refresh,
            'access_token'  => (string) ($data['access_token'] ?? ''),
            'email'         => self::idTokenEmail((string) ($data['id_token'] ?? '')),
        ];
    }

    /** Access token from the stored refresh token. */
    public static function accessToken(string $clientId, string $clientSecret, string $refreshToken): string
    {
        if ($clientId === '' || $clientSecret === '' || $refreshToken === '') {
            throw new RuntimeException(__('Connect with Google in the plugin configuration first', 'dmarc'));
        }
        $data = self::token([
            'grant_type'    => 'refresh_token',
            'refresh_token' => $refreshToken,
            'client_id'     => $clientId,
            'client_secret' => $clientSecret,
        ]);
        if (!is_string($data['access_token'] ?? null) || $data['access_token'] === '') {
            throw new RuntimeException(__('Google did not give an access token', 'dmarc'));
        }

        return $data['access_token'];
    }

    /**
     * Address of the account in the id_token. It comes straight from Google
     * over TLS in the token response, so its signature is not checked.
     */
    public static function idTokenEmail(string $idToken): string
    {
        $parts = explode('.', $idToken);
        if (count($parts) < 2) {
            return '';
        }
        $json   = base64_decode(strtr($parts[1], '-_', '+/') . str_repeat('=', (4 - strlen($parts[1]) % 4) % 4), true);
        $claims = is_string($json) ? json_decode($json, true) : null;

        return is_array($claims) ? strtolower((string) ($claims['email'] ?? '')) : '';
    }

    /** @return array<string, mixed> */
    private static function token(array $fields): array
    {
        [$status, $response] = self::post(self::$tokenUri ?? self::TOKEN_URI, http_build_query($fields));
        $data = json_decode($response, true);
        if ($status !== 200 || !is_array($data)) {
            $code  = is_array($data) ? (string) ($data['error'] ?? '') : '';
            $desc  = is_array($data) ? (string) ($data['error_description'] ?? '') : '';
            $hint  = match ($code) {
                'invalid_grant'      => ' — ' . __('the authorization expired or was revoked, or the code was already used: press "Connect with Google" again', 'dmarc'),
                'invalid_client'     => ' — ' . __('the OAuth client ID or secret is wrong', 'dmarc'),
                'redirect_uri_mismatch' => ' — ' . __('the redirect URI does not match the one authorized in the Google OAuth client', 'dmarc'),
                'unauthorized_client' => ' — ' . __('the OAuth client cannot use this kind of authorization', 'dmarc'),
                default              => '',
            };
            throw new RuntimeException(sprintf(__('Google rejected the request (HTTP %1$d%2$s)%3$s', 'dmarc'), $status, $code !== '' ? ', ' . trim($code . ': ' . $desc, ': ') : '', $hint));
        }

        return $data;
    }

    /** @return array{0:int, 1:string} */
    private static function post(string $url, string $body): array
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        $ch   = curl_init($url);
        $opts = [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 20,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_HTTPHEADER     => ['Content-Type: application/x-www-form-urlencoded'],
            CURLOPT_SSL_VERIFYPEER => true,
        ];
        // GLPI proxy, if any (Setup > General > Proxy)
        if (!empty($CFG_GLPI['proxy_name'])) {
            $opts[CURLOPT_PROXY]     = $CFG_GLPI['proxy_name'];
            $opts[CURLOPT_PROXYPORT] = (int) ($CFG_GLPI['proxy_port'] ?? 8080);
            if (!empty($CFG_GLPI['proxy_user'])) {
                $opts[CURLOPT_PROXYUSERPWD] = $CFG_GLPI['proxy_user'] . ':' . (new \GLPIKey())->decrypt((string) $CFG_GLPI['proxy_passwd']);
            }
        }
        curl_setopt_array($ch, $opts);
        $response = curl_exec($ch);
        $status   = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error    = curl_error($ch);
        if ($response === false) {
            throw new RuntimeException(sprintf(__('Cannot connect to Google (%s)', 'dmarc'), $error));
        }

        return [$status, (string) $response];
    }
}
