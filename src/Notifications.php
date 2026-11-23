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

use Notification;
use Notification_NotificationTemplate;
use NotificationTarget as CoreNotificationTarget;
use NotificationTemplate;
use NotificationTemplateTranslation;

/**
 * Creates on install one GLPI notification + template per alert event
 * (recipient: the GLPI administrator). They are then managed in
 * Setup > Notifications like any other. Nothing is sent while the plugin's
 * global switch ("notify_enabled") is off.
 */
final class Notifications
{
    public static function install(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        foreach (self::templates() as $event => [$subject, $text, $html]) {
            $name = 'DMARC - ' . Alert::eventLabel($event);

            $exists = $DB->request([
                'FROM'  => Notification::getTable(),
                'WHERE' => ['itemtype' => Alert::class, 'event' => $event],
                'LIMIT' => 1,
            ])->current();
            if ($exists !== null) {
                continue; // keep what the administrators changed
            }

            $template    = new NotificationTemplate();
            $template_id = (int) $template->add(['name' => $name, 'itemtype' => Alert::class, 'comment' => 'Plugin DMARC']);
            if ($template_id <= 0) {
                continue;
            }
            (new NotificationTemplateTranslation())->add([
                'notificationtemplates_id' => $template_id,
                'language'                 => '',
                'subject'                  => $subject,
                'content_text'             => $text,
                'content_html'             => $html,
            ]);

            $notification    = new Notification();
            $notification_id = (int) $notification->add([
                'name'         => $name,
                'entities_id'  => 0,
                'is_recursive' => 1,
                'is_active'    => 1,
                'itemtype'     => Alert::class,
                'event'        => $event,
                'comment'      => 'DMARC plugin. Nothing is sent while notifications are disabled in the plugin configuration.',
            ]);
            if ($notification_id <= 0) {
                continue;
            }
            (new Notification_NotificationTemplate())->add([
                'notifications_id'         => $notification_id,
                'mode'                     => Notification_NotificationTemplate::MODE_MAIL,
                'notificationtemplates_id' => $template_id,
            ]);
            (new CoreNotificationTarget())->add([
                'notifications_id' => $notification_id,
                'type'             => Notification::USER_TYPE,
                'items_id'         => Notification::GLOBAL_ADMINISTRATOR,
            ]);
        }
    }

    public static function uninstall(): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $notification = new Notification();
        foreach ($DB->request(['SELECT' => ['id'], 'FROM' => Notification::getTable(), 'WHERE' => ['itemtype' => Alert::class]]) as $row) {
            $notification->delete(['id' => $row['id']], true);
        }
        $template = new NotificationTemplate();
        foreach ($DB->request(['SELECT' => ['id'], 'FROM' => NotificationTemplate::getTable(), 'WHERE' => ['itemtype' => Alert::class]]) as $row) {
            $template->delete(['id' => $row['id']], true);
        }
        if ($DB->tableExists('glpi_queuednotifications')) {
            $DB->delete('glpi_queuednotifications', ['itemtype' => Alert::class]);
        }
    }

    /**
     * event => [subject, text, html]. Labels use ##lang.…## tags, so each
     * recipient gets them in their own language (see NotificationTargetAlert).
     */
    private static function templates(): array
    {
        $footer_text = "\n\n##lang.dmarc.url##: ##dmarc.url##";
        $footer_html = '<p><a href="##dmarc.url##">##lang.dmarc.open_dashboard##</a></p>';

        $source_text = "##dmarc.message##\n\n"
            . "##lang.dmarc.domain##: ##dmarc.domain##\n##lang.dmarc.ip##: ##dmarc.ip##\n##lang.dmarc.ptr##: ##dmarc.ptr##\n"
            . "##lang.dmarc.sender##: ##dmarc.sender##\n##lang.dmarc.messages##: ##dmarc.messages##\n"
            . "##lang.dmarc.compliance##: ##dmarc.compliance##\n\n##dmarc.diagnosis##";
        $source_html = '<p>##dmarc.message##</p><table>'
            . '<tr><td>##lang.dmarc.domain##</td><td><b>##dmarc.domain##</b></td></tr>'
            . '<tr><td>##lang.dmarc.ip##</td><td>##dmarc.ip##</td></tr>'
            . '<tr><td>##lang.dmarc.ptr##</td><td>##dmarc.ptr##</td></tr>'
            . '<tr><td>##lang.dmarc.sender##</td><td>##dmarc.sender##</td></tr>'
            . '<tr><td>##lang.dmarc.messages##</td><td>##dmarc.messages##</td></tr>'
            . '<tr><td>##lang.dmarc.compliance##</td><td>##dmarc.compliance##</td></tr>'
            . '</table><p>##dmarc.diagnosis##</p>';
        $plain_text = '##dmarc.message##' . $footer_text;
        $plain_html = '<p>##dmarc.message##</p>' . $footer_html;

        return [
            'unauthorized_source' => ['[DMARC] ##dmarc.event##: ##dmarc.domain## (##dmarc.ip##)', $source_text . $footer_text, $source_html . $footer_html],
            'failing_source'      => ['[DMARC] ##dmarc.event##: ##dmarc.sender## (##dmarc.domain##)', $source_text . $footer_text, $source_html . $footer_html],
            'no_reports'          => ['[DMARC] ##dmarc.event##: ##dmarc.domain##', $plain_text, $plain_html],
            'collect_error'       => ['[DMARC] ##dmarc.event##', $plain_text, $plain_html],
            'summary'             => [
                '[DMARC] ##dmarc.event## ##dmarc.period##',
                "##lang.dmarc.period##: ##dmarc.period##\n##lang.dmarc.total##: ##dmarc.total##\n##lang.dmarc.pass##: ##dmarc.pass##\n\n"
                . "##FOREACHdomains##- ##domain.name##: ##domain.messages## (##domain.compliance##), p=##domain.policy## (##domain.state##)\n##ENDFOREACHdomains##\n"
                . "##lang.recommendations##:\n##FOREACHrecommendations##- ##recommendation.text##\n##ENDFOREACHrecommendations##"
                . $footer_text,
                '<p>##lang.dmarc.period##: <b>##dmarc.period##</b> · ##lang.dmarc.total##: <b>##dmarc.total##</b> · ##lang.dmarc.pass##: <b>##dmarc.pass##</b></p>'
                . '<table border="1" cellpadding="4" style="border-collapse:collapse"><tr><th>##lang.domain.name##</th><th>##lang.domain.messages##</th>'
                . '<th>##lang.domain.compliance##</th><th>##lang.domain.policy##</th><th>##lang.domain.state##</th></tr>'
                . '##FOREACHdomains##<tr><td>##domain.name##</td><td>##domain.messages##</td><td>##domain.compliance##</td><td>##domain.policy##</td><td>##domain.state##</td></tr>##ENDFOREACHdomains##</table>'
                . '<p><b>##lang.recommendations##</b></p><ul>##FOREACHrecommendations##<li>##recommendation.text##</li>##ENDFOREACHrecommendations##</ul>'
                . $footer_html,
            ],
        ];
    }
}
