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
 * Actions of the dashboard (POST): classify sources, close alerts, collect,
 * reprocess, import files. Needs the UPDATE right of the plugin.
 */

use GlpiPlugin\Dmarc\Alert;
use GlpiPlugin\Dmarc\Diagnosis;
use GlpiPlugin\Dmarc\Importer;
use GlpiPlugin\Dmarc\Menu;
use GlpiPlugin\Dmarc\Settings;
use GlpiPlugin\Dmarc\Ui;
use GlpiPlugin\Dmarc\Worker;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

/** @var DBmysql $DB */
global $DB;

if (!Menu::canUpdate() || ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    throw new AccessDeniedHttpException();
}

$back = (string) ($_POST['back'] ?? '');
if (!str_starts_with($back, Ui::root() . '/plugins/dmarc/front/')) {
    $back = Menu::url();
}

$action = (string) ($_POST['action'] ?? '');
$ids    = array_values(array_filter(array_map('intval', (array) ($_POST['ids'] ?? []))));

switch ($action) {
    case 'classify':
        $status = (int) ($_POST['status'] ?? -1);
        if ($ids === [] || !in_array($status, array_keys(Ui::sourceStatuses()), true)) {
            Session::addMessageAfterRedirect(__s('Select some sources and choose a classification.', 'dmarc'), false, WARNING);
            break;
        }
        $update = [
            'status'          => $status,
            'users_id'        => (int) Session::getLoginUserID(),
            'date_classified' => date('Y-m-d H:i:s'),
        ];
        $comment = trim((string) ($_POST['comment'] ?? ''));
        if ($comment !== '') {
            $update['comment'] = mb_substr($comment, 0, 1000);
        }
        $DB->update('glpi_plugin_dmarc_sources', $update, ['id' => $ids]);

        // alerts of sources now trusted are over
        if (in_array($status, [Diagnosis::SOURCE_AUTHORIZED, Diagnosis::SOURCE_FORWARDER], true)) {
            foreach ($DB->request(['SELECT' => ['ip'], 'FROM' => 'glpi_plugin_dmarc_sources', 'WHERE' => ['id' => $ids]]) as $row) {
                $DB->update(Alert::getTable(), ['status' => Alert::CLOSED, 'date_close' => date('Y-m-d H:i:s'), 'users_id_close' => (int) Session::getLoginUserID()], [
                    'event'   => 'unauthorized_source',
                    'status'  => Alert::OPEN,
                    'keyname' => ['LIKE', 'src:' . $row['ip'] . ':%'],
                ]);
            }
        }
        Session::addMessageAfterRedirect(sprintf(__s('%1$d source(s) classified as "%2$s".', 'dmarc'), count($ids), htmlspecialchars(Diagnosis::sourceStatusLabel($status))));
        break;

    case 'close_alert':
        Alert::closeById((int) ($_POST['id'] ?? 0));
        break;

    case 'collect':
    case 'reprocess':
        if (!Settings::isMailboxConfigured()) {
            Session::addMessageAfterRedirect(__s('The mailbox is not configured.', 'dmarc'), false, ERROR);
            break;
        }
        $uids = null;
        if ($action === 'reprocess') {
            $uids = [];
            $validity = Settings::int('state_uidvalidity');
            foreach ($DB->request(['SELECT' => ['uid', 'uidvalidity'], 'FROM' => Importer::T_MESSAGES, 'WHERE' => ['id' => $ids ?: [0], 'source' => 'imap']]) as $row) {
                if ((int) $row['uidvalidity'] === $validity && (int) $row['uid'] > 0) {
                    $uids[] = (int) $row['uid'];
                }
            }
            if ($uids === []) {
                Session::addMessageAfterRedirect(__s('None of the selected mails can be read again from the mailbox (the folder changed or nothing is selected).', 'dmarc'), false, WARNING);
                break;
            }
        }
        // Never in this request: it would keep the session locked (GLPI stops
        // answering this user) for as long as the collection lasts.
        if (Worker::isRunning()) {
            Session::addMessageAfterRedirect(__s('A collection is already running in the background. Its progress is shown in the Collection tab.', 'dmarc'), false, WARNING);
            break;
        }
        $args = $uids === null ? ['--worker', '--collect', '--all'] : ['--worker', '--uids=' . implode(',', array_slice($uids, 0, 500))];
        if (Worker::spawn($args)) {
            Session::addMessageAfterRedirect(__s('Collection started in the background. You can keep using GLPI; the progress is shown in the Collection tab.', 'dmarc'));
        } else {
            Session::addMessageAfterRedirect(__s('This server cannot start background processes: the next "collect" automatic action will do the collection.', 'dmarc'), false, WARNING);
        }
        break;

    case 'import':
        $files = $_FILES['files'] ?? null;
        if (!is_array($files) || !is_array($files['tmp_name'] ?? null)) {
            Session::addMessageAfterRedirect(__s('No file was uploaded.', 'dmarc'), false, WARNING);
            break;
        }
        // The files wait in the plugin's inbox folder; the background worker imports them.
        $inbox = Worker::inboxDir();
        if (!is_dir($inbox)) {
            @mkdir($inbox, 0o770, true);
        }
        $saved = 0;
        // a reasonable batch: at most 500 files, each within the configured mail size limit
        $maxBytes = max(1, Settings::int('max_message_mb')) * 1048576;
        foreach (array_slice($files['tmp_name'], 0, 500, true) as $i => $tmp) {
            if (($files['error'][$i] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK || !is_string($tmp) || !is_uploaded_file($tmp)
                || (int) ($files['size'][$i] ?? 0) > $maxBytes) {
                continue;
            }
            $name = preg_replace('/[^\w.@!+-]+/u', '_', basename((string) ($files['name'][$i] ?? 'file'))) ?: 'file';
            if (@move_uploaded_file($tmp, sprintf('%s/%d-%s-%s', $inbox, time(), bin2hex(random_bytes(4)), mb_substr($name, 0, 150)))) {
                $saved++;
            }
        }
        if ($saved === 0) {
            Session::addMessageAfterRedirect(__s('No file could be saved.', 'dmarc'), false, ERROR);
            break;
        }
        if (Worker::isRunning()) {
            // the running worker looks at the inbox again before it finishes
            Session::addMessageAfterRedirect(sprintf(__s('%d file(s) queued: the job already running will import them when it ends.', 'dmarc'), $saved));
        } elseif (Worker::spawn(['--worker'])) {
            Session::addMessageAfterRedirect(sprintf(__s('%d file(s) received: they are imported in the background. The progress is shown in the Collection tab.', 'dmarc'), $saved));
        } else {
            Session::addMessageAfterRedirect(sprintf(__s('%d file(s) queued: the next "collect" automatic action will import them.', 'dmarc'), $saved), false, WARNING);
        }
        break;

    default:
        Session::addMessageAfterRedirect(__s('Unknown action.', 'dmarc'), false, ERROR);
}

Html::redirect($back);
