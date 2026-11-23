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

use NotificationTarget;

/**
 * Notification target of the DMARC alerts. GLPI finds it by name from the
 * item type (GlpiPlugin\Dmarc\Alert → GlpiPlugin\Dmarc\NotificationTargetAlert).
 * Recipients (administrator, profiles, groups, users…) are chosen in
 * Setup > Notifications like any other notification.
 */
class NotificationTargetAlert extends NotificationTarget
{
    public function getEvents()
    {
        $events = [];
        foreach (Alert::EVENTS as $event) {
            $events[$event] = Alert::eventLabel($event);
        }

        return $events;
    }

    public function addDataForTemplate($event, $options = [])
    {
        /** @var array $CFG_GLPI */
        global $CFG_GLPI;

        $fields  = $this->obj instanceof Alert ? $this->obj->fields : [];
        $payload = $this->obj instanceof Alert ? $this->obj->payload() : [];

        $this->data['##dmarc.event##']      = Alert::eventLabel((string) $event);
        $this->data['##dmarc.message##']    = (string) ($fields['message'] ?? '');
        $this->data['##dmarc.domain##']     = (string) ($payload['domain'] ?? '');
        $this->data['##dmarc.ip##']         = (string) ($payload['ip'] ?? '');
        $this->data['##dmarc.ptr##']        = (string) ($payload['ptr'] ?? '');
        $this->data['##dmarc.sender##']     = (string) ($payload['sender'] ?? '');
        $this->data['##dmarc.messages##']   = (string) ($payload['messages'] ?? '');
        $this->data['##dmarc.compliance##'] = isset($payload['compliance']) ? Format::pct((float) $payload['compliance']) : '';
        $this->data['##dmarc.diagnosis##']  = (string) ($payload['diagnosis'] ?? '');
        $this->data['##dmarc.period##']     = (string) ($payload['period'] ?? '');
        $this->data['##dmarc.total##']      = isset($payload['total']) ? Format::int((int) $payload['total']) : '';
        $this->data['##dmarc.pass##']       = isset($payload['pass_pct']) ? Format::pct((float) $payload['pass_pct']) : '';
        $this->data['##dmarc.date##']       = (string) ($fields['date_creation'] ?? '');
        $this->data['##dmarc.url##']        = rtrim((string) $CFG_GLPI['url_base'], '/') . '/plugins/dmarc/front/dashboard.php?tab='
            . ($event === 'summary' ? 'summary' : 'alerts');

        $this->data['domains'] = [];
        foreach ((array) ($payload['domains'] ?? []) as $d) {
            $this->data['domains'][] = [
                '##domain.name##'       => (string) ($d['domain'] ?? ''),
                '##domain.policy##'     => (string) ($d['policy'] ?? ''),
                '##domain.messages##'   => Format::int((int) ($d['total'] ?? 0)),
                '##domain.compliance##' => Format::pct((float) ($d['pass_pct'] ?? 0)),
                '##domain.state##'      => (string) ($d['state_label'] ?? ''),
            ];
        }
        $this->data['recommendations'] = [];
        foreach ((array) ($payload['recommendations'] ?? []) as $r) {
            $this->data['recommendations'][] = ['##recommendation.text##' => (string) $r];
        }

        $this->getTags();
        foreach ($this->tag_descriptions[NotificationTarget::TAG_LANGUAGE] as $tag => $values) {
            if (!isset($this->data[$tag])) {
                $this->data[$tag] = $values['label'];
            }
        }
    }

    public function getTags()
    {
        $tags = [
            'dmarc.event'      => __('Event', 'dmarc'),
            'dmarc.message'    => __('Message', 'dmarc'),
            'dmarc.domain'     => __('Domain', 'dmarc'),
            'dmarc.ip'         => __('Source IP', 'dmarc'),
            'dmarc.ptr'        => __('Reverse name (PTR)', 'dmarc'),
            'dmarc.sender'     => __('Sender', 'dmarc'),
            'dmarc.messages'   => __('Messages', 'dmarc'),
            'dmarc.compliance' => __('DMARC compliance', 'dmarc'),
            'dmarc.diagnosis'  => __('Diagnosis', 'dmarc'),
            'dmarc.period'     => __('Period', 'dmarc'),
            'dmarc.total'      => __('Messages of the period', 'dmarc'),
            'dmarc.pass'       => __('% passing DMARC', 'dmarc'),
            'dmarc.date'       => __('Date', 'dmarc'),
            'dmarc.url'        => __('Dashboard link', 'dmarc'),
            'domain.name'       => __('Domain', 'dmarc'),
            'domain.policy'     => __('Published policy', 'dmarc'),
            'domain.messages'   => __('Messages', 'dmarc'),
            'domain.compliance' => __('Compliance', 'dmarc'),
            'domain.state'      => __('Status', 'dmarc'),
            'recommendation.text' => __('Recommendation', 'dmarc'),
        ];
        foreach ($tags as $tag => $label) {
            $this->addTagToList(['tag' => $tag, 'label' => $label, 'value' => true]);
        }
        // labels only (##lang.…##), used by the default templates
        $this->addTagToList(['tag' => 'dmarc.open_dashboard', 'label' => __('Open the DMARC dashboard', 'dmarc'), 'value' => false]);
        $this->addTagToList(['tag' => 'recommendations', 'label' => __('Recommendations', 'dmarc'), 'value' => false]);
        $this->addTagToList(['tag' => 'domains', 'label' => __('List of domains', 'dmarc'), 'value' => false, 'foreach' => true]);
        $this->addTagToList(['tag' => 'recommendations', 'label' => __('List of recommendations', 'dmarc'), 'value' => false, 'foreach' => true]);

        asort($this->tag_descriptions);
    }
}
