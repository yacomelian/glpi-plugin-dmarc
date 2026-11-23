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

use CommonDBTM;
use NotificationEvent;
use Session;

/**
 * An alert of the plugin (unauthorized source, failing source, no reports,
 * collection error, periodic summary). It is the item GLPI notifications are
 * raised for: templates and recipients are managed in Setup > Notifications.
 *
 * An alert stays "open" while the situation lasts: the same key is not
 * notified twice while it is open.
 *
 * No `$rightname` on purpose (GLPI 11/12 differ in its type).
 */
final class Alert extends CommonDBTM
{
    public const OPEN   = 1;
    public const CLOSED = 2;

    public const EVENTS = ['unauthorized_source', 'failing_source', 'no_reports', 'collect_error', 'summary'];

    public static function getTypeName($nb = 0)
    {
        return _n('DMARC alert', 'DMARC alerts', $nb, 'dmarc');
    }

    public static function getIcon()
    {
        return Menu::getIcon();
    }

    public static function canView(): bool
    {
        return Menu::canView();
    }

    public static function canCreate(): bool
    {
        return Menu::canUpdate();
    }

    public static function canUpdate(): bool
    {
        return Menu::canUpdate();
    }

    public static function canDelete(): bool
    {
        return false;
    }

    public static function canPurge(): bool
    {
        return false;
    }

    /** Rights shown in the profile tab. */
    public static function rightsList(): array
    {
        return [READ => __('Read'), UPDATE => __('Update')];
    }

    public function getRights($interface = 'central')
    {
        return self::rightsList();
    }

    public static function eventLabel(string $event): string
    {
        return match ($event) {
            'unauthorized_source' => __('Unauthorized or unknown source', 'dmarc'),
            'failing_source'      => __('Authorized source failing', 'dmarc'),
            'no_reports'          => __('Domain without reports', 'dmarc'),
            'collect_error'       => __('Mailbox collection error', 'dmarc'),
            'summary'             => __('Periodic summary', 'dmarc'),
            default               => $event,
        };
    }

    /**
     * Opens (or refreshes) the alert of a key. A notification is raised only
     * when the alert is new, and only if notifications are enabled.
     *
     * @param bool $once never open again a key that was ever alerted (closed or not)
     *
     * @return bool true when a new alert was opened
     */
    public static function raise(string $event, string $key, string $message, array $payload = [], bool $once = false): bool
    {
        /** @var \DBmysql $DB */
        global $DB;

        $now   = date('Y-m-d H:i:s');
        $where = ['event' => $event, 'keyname' => $key];
        if (!$once) {
            $where['status'] = self::OPEN;
        }
        $existing = $DB->request(['FROM' => self::getTable(), 'WHERE' => $where, 'ORDER' => 'id DESC', 'LIMIT' => 1])->current();
        if ($existing !== null) {
            if ((int) $existing['status'] === self::OPEN) {
                $DB->update(self::getTable(), [
                    'message'  => $message,
                    'payload'  => json_encode($payload, JSON_UNESCAPED_UNICODE),
                    'count'    => (int) $existing['count'] + 1,
                    'date_mod' => $now,
                ], ['id' => $existing['id']]);
            }

            return false;
        }

        $DB->insert(self::getTable(), [
            'entities_id'   => Settings::int('entities_id'),
            'is_recursive'  => 1,
            'event'         => $event,
            'keyname'       => mb_substr($key, 0, 255),
            'domain'        => mb_substr((string) ($payload['domain'] ?? ''), 0, 255),
            'ip'            => mb_substr((string) ($payload['ip'] ?? ''), 0, 45),
            'message'       => $message,
            'payload'       => json_encode($payload, JSON_UNESCAPED_UNICODE),
            'status'        => $event === 'summary' ? self::CLOSED : self::OPEN,
            'count'         => 1,
            'date_creation' => $now,
            'date_mod'      => $now,
            'date_close'    => $event === 'summary' ? $now : null,
        ]);
        $id = (int) $DB->insertId();

        self::notify($id);

        return true;
    }

    /** Closes the open alert of a key (the situation is over). */
    public static function resolve(string $event, string $key): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::getTable(), [
            'status'     => self::CLOSED,
            'date_close' => date('Y-m-d H:i:s'),
        ], ['event' => $event, 'keyname' => $key, 'status' => self::OPEN]);
    }

    /** Closed by a user from the dashboard. */
    public static function closeById(int $id): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        $DB->update(self::getTable(), [
            'status'         => self::CLOSED,
            'date_close'     => date('Y-m-d H:i:s'),
            'users_id_close' => (int) Session::getLoginUserID(),
        ], ['id' => $id, 'status' => self::OPEN]);
    }

    /** Open keys of an event: [key => row]. */
    public static function openKeys(string $event): array
    {
        /** @var \DBmysql $DB */
        global $DB;

        $keys = [];
        foreach ($DB->request(['FROM' => self::getTable(), 'WHERE' => ['event' => $event, 'status' => self::OPEN]]) as $row) {
            $keys[$row['keyname']] = $row;
        }

        return $keys;
    }

    public function payload(): array
    {
        $data = json_decode((string) ($this->fields['payload'] ?? ''), true);

        return is_array($data) ? $data : [];
    }

    private static function notify(int $id): void
    {
        /** @var \DBmysql $DB */
        global $DB;

        if (!Settings::int('notify_enabled')) {
            return;
        }
        $alert = new self();
        if (!$alert->getFromDB($id)) {
            return;
        }
        try {
            NotificationEvent::raiseEvent((string) $alert->fields['event'], $alert, ['entities_id' => (int) $alert->fields['entities_id']]);
            $DB->update(self::getTable(), ['date_notified' => date('Y-m-d H:i:s')], ['id' => $id]);
        } catch (\Throwable $e) {
            trigger_error('[dmarc] notification: ' . $e->getMessage(), E_USER_WARNING);
        }
    }
}
