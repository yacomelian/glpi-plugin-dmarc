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

use CommonGLPI;
use Html;
use Profile as GlpiProfile;
use Session;

/**
 * Tab on Administration > Profiles to grant the plugin right. Editing a
 * profile's rights is governed by the core "profile" right.
 */
final class Profile extends CommonGLPI
{
    public static function getTypeName($nb = 0)
    {
        return 'DMARC';
    }

    public function getTabNameForItem(CommonGLPI $item, $withtemplate = 0)
    {
        if ($item instanceof GlpiProfile && $item->getField('id') && $item->getField('interface') === 'central') {
            return self::createTabEntry('DMARC', 0, null, Menu::getIcon());
        }

        return '';
    }

    public static function displayTabContentForItem(CommonGLPI $item, $tabnum = 1, $withtemplate = 0)
    {
        if ($item instanceof GlpiProfile && $item->getField('id') && Session::haveRight('profile', READ)) {
            $can_edit = Session::haveRight('profile', UPDATE);

            echo "<div class='spaced'>";
            if ($can_edit) {
                echo "<form method='post' action='" . htmlspecialchars(GlpiProfile::getFormURL()) . "'>";
            }
            $item->displayRightsChoiceMatrix(
                [[
                    'itemtype' => Alert::class,
                    'label'    => __('DMARC dashboard', 'dmarc'),
                    'field'    => Menu::RIGHT,
                    'rights'   => Alert::rightsList(),
                ]],
                ['canedit' => $can_edit, 'title' => 'DMARC']
            );
            if ($can_edit) {
                echo "<div class='text-center'>";
                echo Html::hidden('id', ['value' => $item->getID()]);
                echo Html::submit(_sx('button', 'Save'), ['name' => 'update']);
                echo '</div>';
                Html::closeForm();
            }
            echo '<p class="text-muted mt-2">' . htmlspecialchars(__('Read: see the dashboard. Update: classify sources, collect now, import files and close alerts. The mailbox connection is changed by whoever has the GLPI configuration right.', 'dmarc')) . '</p>';
            echo '</div>';
        }

        return true;
    }
}
