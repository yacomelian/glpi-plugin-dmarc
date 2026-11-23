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

/**
 * Fixed rules (no AI): why a record fails, which provider an IP belongs to,
 * organisational domains for alignment.
 */
final class Diagnosis
{
    // Causes, stored in records.cause
    public const PASS_BOTH        = 1;
    public const PASS_DKIM        = 2;
    public const PASS_SPF         = 3;
    public const FAIL_FORWARDED   = 10;
    public const FAIL_SPF_UNALIGN = 11;
    public const FAIL_DKIM_OTHER  = 12;
    public const FAIL_DKIM_BROKEN = 13;
    public const FAIL_NO_AUTH     = 14;

    /** Source classification (sources.status) */
    public const SOURCE_UNKNOWN      = 0;
    public const SOURCE_AUTHORIZED   = 1;
    public const SOURCE_UNAUTHORIZED = 2;
    public const SOURCE_FORWARDER    = 3;

    /** Multi-label public suffixes we may meet (enough for alignment hints). */
    private const SUFFIXES = [
        'com.es', 'org.es', 'gob.es', 'nom.es', 'edu.es', 'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
        'com.ar', 'com.mx', 'com.br', 'com.co', 'com.pe', 'com.ve', 'com.uy', 'com.au', 'co.jp',
        'co.nz', 'co.za', 'com.tr', 'com.cn', 'com.pt', 'gov.pt',
    ];

    /** [regex on PTR or authenticated domain, label] in order. */
    private const SENDERS = [
        ['/(^|\.)(google\.com|googlemail\.com|1e100\.net|gmail\.com|googleusercontent\.com)$/', 'Google'],
        ['/(^|\.)(outlook\.com|protection\.outlook\.com|hotmail\.com|office365\.com|microsoft\.com|onmicrosoft\.com)$/', 'Microsoft 365'],
        ['/(^|\.)(amazonses\.com|amazonaws\.com)$/', 'Amazon SES'],
        ['/(^|\.)(sendgrid\.net|sendgrid\.com)$/', 'SendGrid'],
        ['/(^|\.)(mcsv\.net|mcdlv\.net|mandrillapp\.com|rsgsv\.net|mailchimp\.com|mailchimpapp\.net)$/', 'Mailchimp'],
        ['/(^|\.)(mailgun\.org|mailgun\.net)$/', 'Mailgun'],
        ['/(^|\.)(sparkpostmail\.com|sparkpost\.com)$/', 'SparkPost'],
        ['/(^|\.)(sendinblue\.com|brevo\.com|sendibm\d*\.com|mailin\.fr)$/', 'Brevo'],
        ['/(^|\.)(zoho\.com|zoho\.eu|zohomail\.eu)$/', 'Zoho'],
        ['/(^|\.)(yahoo\.com|yahoodns\.net)$/', 'Yahoo'],
        ['/(^|\.)(salesforce\.com|exacttarget\.com)$/', 'Salesforce'],
        ['/(^|\.)(hubspot\.com|hubspotemail\.net)$/', 'HubSpot'],
        ['/(^|\.)(ovh\.net|ovh\.com)$/', 'OVH'],
        ['/(^|\.)(acens\.net|acens\.com)$/', 'Acens'],
        ['/(^|\.)(ionos\.com|ionos\.es|1and1\.com|kundenserver\.de)$/', 'IONOS'],
        ['/(^|\.)(mail\.ru)$/', 'Mail.ru'],
    ];

    public const CAUSES = [
        self::PASS_BOTH, self::PASS_DKIM, self::PASS_SPF, self::FAIL_FORWARDED,
        self::FAIL_SPF_UNALIGN, self::FAIL_DKIM_OTHER, self::FAIL_DKIM_BROKEN, self::FAIL_NO_AUTH,
    ];

    public static function label(int $cause): string
    {
        return match ($cause) {
            self::PASS_BOTH        => __('Pass (SPF and DKIM)', 'dmarc'),
            self::PASS_DKIM        => __('Pass (DKIM only)', 'dmarc'),
            self::PASS_SPF         => __('Pass (SPF only)', 'dmarc'),
            self::FAIL_FORWARDED   => __('Forwarding or mailing list', 'dmarc'),
            self::FAIL_SPF_UNALIGN => __('Provider SPF, not aligned and no DKIM', 'dmarc'),
            self::FAIL_DKIM_OTHER  => __('DKIM signed by another domain', 'dmarc'),
            self::FAIL_DKIM_BROKEN => __('Invalid DKIM of our domain', 'dmarc'),
            self::FAIL_NO_AUTH     => __('No authentication', 'dmarc'),
            default                => __('Unknown', 'dmarc'),
        };
    }

    public static function isPass(int $cause): bool
    {
        return $cause > 0 && $cause < 10;
    }

    /** Explanation shown for a failing cause, depending on who sends. */
    public static function explain(int $cause, int $sourceStatus = self::SOURCE_UNKNOWN): string
    {
        $mine = $sourceStatus === self::SOURCE_AUTHORIZED;

        return match ($cause) {
            self::FAIL_FORWARDED   => __('Messages forwarded by another server or a mailing list: forwarding breaks SPF and sometimes DKIM. This is normal and not spoofing; if the source is trusted, classify it as a forwarder.', 'dmarc'),
            self::FAIL_SPF_UNALIGN => $mine
                ? __('The provider sends with its own envelope sender (SPF of its domain) and does not sign with DKIM of our domain. Configure DKIM with our domain at that provider (or an envelope sender of our domain included in the SPF).', 'dmarc')
                : __('SPF passes, but for the sending server\'s domain, not ours, and there is no DKIM of our domain. If it is one of our providers, configure DKIM; if you do not know it, it is a third party using our domain.', 'dmarc'),
            self::FAIL_DKIM_OTHER  => $mine
                ? __('The provider signs with DKIM of its own domain (d=…), not ours. Publish in our DNS the DKIM key given by the provider to sign as our domain.', 'dmarc')
                : __('Messages signed with DKIM of another domain. If it is one of our providers, configure DKIM with our domain; otherwise it is a third party using our domain in the From.', 'dmarc'),
            self::FAIL_DKIM_BROKEN => __('It carries a DKIM signature of our domain but it does not validate: selector not published in DNS, rotated key or message modified on the way. If SPF fails too, the message fails.', 'dmarc'),
            self::FAIL_NO_AUTH     => $mine
                ? __('Authorized source without valid SPF or DKIM: add its IP or its include to the SPF and configure DKIM.', 'dmarc')
                : __('Neither SPF nor DKIM: possible spoofing of our domain. Review the source and classify it as unauthorized; with p=quarantine or p=reject those messages do not reach the inbox.', 'dmarc'),
            default                => '',
        };
    }

    /**
     * Cause of a parsed record (see ReportParser::parse) for a policy domain.
     */
    public static function cause(array $record, string $headerFrom): int
    {
        $dkimPass = $record['dkim_eval'] === 'pass';
        $spfPass  = $record['spf_eval'] === 'pass';
        if ($dkimPass && $spfPass) {
            return self::PASS_BOTH;
        }
        if ($dkimPass) {
            return self::PASS_DKIM;
        }
        if ($spfPass) {
            return self::PASS_SPF;
        }

        foreach ($record['reasons'] as $reason) {
            if (preg_match('/^(forwarded|mailing_list|trusted_forwarder)/i', $reason) === 1) {
                return self::FAIL_FORWARDED;
            }
        }
        $org = self::orgDomain($headerFrom);
        $ownDkim = false;
        $otherDkimPass = false;
        foreach ($record['dkim'] as $d) {
            if ($d['domain'] !== '' && self::orgDomain($d['domain']) === $org) {
                $ownDkim = true;
            } elseif ($d['result'] === 'pass') {
                $otherDkimPass = true;
            }
        }
        if ($ownDkim) {
            return self::FAIL_DKIM_BROKEN;
        }
        if ($otherDkimPass) {
            return self::FAIL_DKIM_OTHER;
        }
        foreach ($record['spf'] as $s) {
            if ($s['result'] === 'pass') {
                return self::FAIL_SPF_UNALIGN;
            }
        }

        return self::FAIL_NO_AUTH;
    }

    /** Organisational domain (approximation of the public suffix list). */
    public static function orgDomain(string $domain): string
    {
        $labels = explode('.', strtolower(trim($domain, '.')));
        $n      = count($labels);
        if ($n <= 2) {
            return implode('.', $labels);
        }
        $last2 = $labels[$n - 2] . '.' . $labels[$n - 1];

        return in_array($last2, self::SUFFIXES, true)
            ? $labels[$n - 3] . '.' . $last2
            : $last2;
    }

    /**
     * Provider label from the reverse name and the domains that authenticate
     * the source. Own networks win.
     *
     * @param string[] $authDomains
     */
    public static function sender(string $ip, string $ptr, array $authDomains, string $ownNetworks = ''): string
    {
        if ($ownNetworks !== '' && self::inNetworks($ip, $ownNetworks)) {
            return __('Own server', 'dmarc');
        }
        foreach (array_merge([strtolower(rtrim($ptr, '.'))], $authDomains) as $name) {
            if ($name === '') {
                continue;
            }
            foreach (self::SENDERS as [$re, $label]) {
                if (preg_match($re, $name) === 1) {
                    return $label;
                }
            }
        }
        if ($ptr !== '') {
            return self::orgDomain($ptr);
        }

        return '';
    }

    public static function inNetworks(string $ip, string $networks): bool
    {
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return false;
        }
        foreach (preg_split('/[\s,;]+/', $networks) ?: [] as $net) {
            if ($net === '') {
                continue;
            }
            [$base, $bits] = array_pad(explode('/', $net, 2), 2, null);
            $netBin = @inet_pton((string) $base);
            if ($netBin === false || strlen($netBin) !== strlen($bin)) {
                continue;
            }
            $bits = $bits === null ? strlen($bin) * 8 : max(0, min(strlen($bin) * 8, (int) $bits));
            $bytes = intdiv($bits, 8);
            if (substr($bin, 0, $bytes) !== substr($netBin, 0, $bytes)) {
                continue;
            }
            $rest = $bits % 8;
            if ($rest === 0) {
                return true;
            }
            $mask = (0xFF << (8 - $rest)) & 0xFF;
            if ((ord($bin[$bytes]) & $mask) === (ord($netBin[$bytes]) & $mask)) {
                return true;
            }
        }

        return false;
    }

    public static function sourceStatusLabel(int $status): string
    {
        return match ($status) {
            self::SOURCE_AUTHORIZED   => __('Authorized', 'dmarc'),
            self::SOURCE_UNAUTHORIZED => __('Unauthorized', 'dmarc'),
            self::SOURCE_FORWARDER    => __('Forwarder', 'dmarc'),
            default                   => __('Unclassified', 'dmarc'),
        };
    }
}
