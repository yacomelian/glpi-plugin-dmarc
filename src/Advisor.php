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

/**
 * Recommendations: fixed rules over the figures of a period (no AI).
 */
final class Advisor
{
    /**
     * @param array $domains Stats::domains() of the period
     *
     * @return list<array{level:string, domain:string, title:string, text:string}>
     */
    public static function recommendations(Stats $stats, ?array $domains = null): array
    {
        $domains ??= $stats->domains();
        $target   = (float) max(50, min(100, Settings::int('compliance_target')));
        $noneDays = max(1, Settings::int('none_days'));
        $silent   = max(1, Settings::int('notify_no_reports_days'));
        $out      = [];

        foreach ($domains as $d) {
            $name   = $d['domain'];
            $p      = (string) ($d['policy']['p'] ?? '');
            $sp     = (string) ($d['policy']['sp'] ?? '');
            $pct    = $d['policy']['pct'] ?? null;
            $since  = (string) ($d['policy']['since'] ?? '');
            $days   = $since !== '' ? (int) floor((time() - strtotime($since)) / 86400) : 0;
            $legit  = (float) $d['legit_pct'];

            if ($d['days_silent'] !== null && $d['days_silent'] > $silent) {
                $out[] = self::rec('warning', $name, __('No reports arriving', 'dmarc'), sprintf(
                    __('The last report is %1$d days old. Check that the _dmarc.%2$s record is still published with rua=, that the mails reach the folder and that the collection works.', 'dmarc'),
                    $d['days_silent'],
                    $name
                ));
            }

            if ($d['auth_fail'] > 0) {
                $out[] = self::rec('danger', $name, __('Authorized sources failing', 'dmarc'), sprintf(
                    __('%1$s messages from %2$d authorized source(s) fail DMARC. Look at the Failures tab: usually DKIM with our domain is missing at that provider, or its IP in the SPF.', 'dmarc'),
                    Format::int($d['auth_fail']),
                    $d['auth_fail_src']
                ));
            }

            if ($d['unk_fail_src'] > 0) {
                $out[] = self::rec('warning', $name, __('Unclassified sources failing', 'dmarc'), sprintf(
                    __('%1$d unclassified source(s) sent %2$s messages that fail. Classify them in Sending sources: authorized (and fix their SPF/DKIM), forwarders or unauthorized.', 'dmarc'),
                    $d['unk_fail_src'],
                    Format::int($d['unk_fail'])
                ));
            }

            if ($p === 'none') {
                if ($days >= $noneDays && $legit >= $target && $d['unk_fail_src'] === 0) {
                    $out[] = self::rec('info', $name, __('Ready to move to p=quarantine', 'dmarc'), sprintf(
                        __('%1$d days with p=none and %2$s of the legitimate mail passes DMARC. You can publish p=quarantine (with pct=25 at first, if you like) so that what fails goes to spam.', 'dmarc'),
                        $days,
                        Format::pct($legit)
                    ));
                } else {
                    $out[] = self::rec('info', $name, __('Policy in monitoring mode', 'dmarc'), sprintf(
                        __('With p=none receivers do not stop the mails that spoof the domain. Goal: legitimate mail passing at least %1$s and no unclassified sources left; now %2$s passes.', 'dmarc'),
                        Format::pct($target, 0),
                        Format::pct($legit)
                    ));
                }
            } elseif ($p === 'quarantine' && $days >= $noneDays && $legit >= $target && $d['unk_fail_src'] === 0 && $d['auth_fail'] === 0) {
                $out[] = self::rec('info', $name, __('Ready to move to p=reject', 'dmarc'), sprintf(
                    __('%1$d days with p=quarantine and %2$s of the legitimate mail passes. With p=reject the mails that spoof the domain are rejected.', 'dmarc'),
                    $days,
                    Format::pct($legit)
                ));
            }

            if ($pct !== null && $pct < 100 && $p !== 'none') {
                $out[] = self::rec('info', $name, __('The policy does not apply to all mail', 'dmarc'), sprintf(
                    __('pct=%1$d: the p=%2$s policy only applies to that percentage of the failing messages. Raise it to 100 when legitimate sources no longer fail.', 'dmarc'),
                    $pct,
                    $p
                ));
            }

            if ($p !== '' && $p !== 'none' && $sp === 'none') {
                $out[] = self::rec('warning', $name, __('Unprotected subdomains', 'dmarc'), sprintf(
                    __('sp=none: the subdomains of %1$s can be spoofed although the domain has p=%2$s. Publish sp=quarantine or sp=reject (or remove sp so that they inherit p).', 'dmarc'),
                    $name,
                    $p
                ));
            }

            if ($d['target_policy'] !== '' && self::rank($p) < self::rank($d['target_policy'])) {
                $out[] = self::rec('info', $name, __('Policy goal not reached', 'dmarc'), sprintf(
                    __('The goal is p=%1$s and p=%2$s is published.', 'dmarc'),
                    $d['target_policy'],
                    $p ?: '?'
                ));
            }
        }

        $order = ['danger' => 0, 'warning' => 1, 'info' => 2];
        usort($out, static fn($a, $b) => [$order[$a['level']], $a['domain']] <=> [$order[$b['level']], $b['domain']]);

        return $out;
    }

    public static function rank(string $p): int
    {
        return match ($p) {
            'reject'     => 3,
            'quarantine' => 2,
            'none'       => 1,
            default      => 0,
        };
    }

    private static function rec(string $level, string $domain, string $title, string $text): array
    {
        return ['level' => $level, 'domain' => $domain, 'title' => $title, 'text' => $text];
    }
}
