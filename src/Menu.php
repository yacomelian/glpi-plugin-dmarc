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

use CommonGLPI;
use Session;

/**
 * Tools > DMARC. No `$rightname` on purpose (its type differs between GLPI 11
 * and 12): the right is checked by name.
 */
final class Menu extends CommonGLPI
{
    /** READ = dashboard; UPDATE = classify sources, collect, import, close alerts. */
    public const RIGHT = 'plugin_dmarc';

    public static function getTypeName($nb = 0)
    {
        return 'DMARC';
    }

    public static function getMenuName()
    {
        return self::getTypeName();
    }

    public static function getIcon()
    {
        return 'ti ti-mail-check';
    }

    public static function canView(): bool
    {
        return Session::haveRight(self::RIGHT, READ) && self::inEntity();
    }

    public static function canUpdate(): bool
    {
        return Session::haveRight(self::RIGHT, UPDATE) && self::inEntity();
    }

    /**
     * Is the plugin's entity in the user's active entities? (the active
     * entity itself, or a parent shown with its sub-entities). With
     * "entity_recursive", working in one of its child entities also counts.
     */
    public static function inEntity(): bool
    {
        if (isCommandLine() && !isset($_SESSION['glpiactiveentities'])) {
            return true;
        }
        $entity = Settings::int('entities_id');
        if (Session::haveAccessToEntity($entity)) {
            return true;
        }
        if (Settings::int('entity_recursive')) {
            $sons = getSonsOf('glpi_entities', $entity);

            return array_intersect(array_map('intval', (array) ($_SESSION['glpiactiveentities'] ?? [])), array_map('intval', $sons)) !== [];
        }

        return false;
    }

    public static function url(array $params = []): string
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        return $CFG_GLPI['root_doc'] . '/plugins/dmarc/front/dashboard.php' . ($params === [] ? '' : '?' . http_build_query($params));
    }

    public static function getMenuContent()
    {
        if (!self::canView()) {
            return false;
        }
        $menu = [
            'title' => self::getMenuName(),
            'page'  => '/plugins/dmarc/front/dashboard.php',
            'icon'  => self::getIcon(),
        ];
        if (Session::haveRight('config', UPDATE)) {
            $menu['links']['config'] = '/plugins/dmarc/front/config.form.php';
        }

        return $menu;
    }
}
