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

use Session;

/** Small helpers for the pages. */
final class Ui
{
    /**
     * CSRF token for the forms: GLPI 11 checks a token, GLPI 12 does not use
     * tokens any more (and deprecates the functions that create them).
     */
    public static function csrf(): string
    {
        return version_compare(GLPI_VERSION, '12.0.0-dev', '<') ? Session::getNewCSRFToken() : '';
    }

    public static function root(): string
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        return (string) $CFG_GLPI['root_doc'];
    }

    /** Version string to bust the browser cache of the plugin's JS/CSS. */
    public static function assetVersion(): string
    {
        return PLUGIN_DMARC_VERSION;
    }

    /** id => complete name of every entity (for the configuration). */
    public static function entities(): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $out = [];
        foreach ($DB->request(['SELECT' => ['id', 'completename'], 'FROM' => 'glpi_entities', 'ORDER' => 'completename']) as $row) {
            $out[(int) $row['id']] = (string) $row['completename'];
        }

        return $out;
    }

    public static function causeLabels(): array
    {
        $out = [];
        foreach (Diagnosis::CAUSES as $cause) {
            $out[$cause] = Diagnosis::label($cause);
        }

        return $out;
    }

    public static function sourceStatuses(): array
    {
        $out = [];
        foreach ([Diagnosis::SOURCE_UNKNOWN, Diagnosis::SOURCE_AUTHORIZED, Diagnosis::SOURCE_FORWARDER, Diagnosis::SOURCE_UNAUTHORIZED] as $s) {
            $out[$s] = Diagnosis::sourceStatusLabel($s);
        }

        return $out;
    }

    public static function messageStatuses(): array
    {
        $out = [];
        foreach (Importer::STATUSES as $s) {
            $out[$s] = Importer::statusLabel($s);
        }

        return $out;
    }
}
