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
 * One report: header, published policy and all its rows; ?raw=1 downloads
 * the original XML.
 */

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Dmarc\Diagnosis;
use GlpiPlugin\Dmarc\Importer;
use GlpiPlugin\Dmarc\Menu;
use GlpiPlugin\Dmarc\Ui;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

/** @var DBmysql $DB */
global $DB;

if (!Menu::canView()) {
    throw new AccessDeniedHttpException();
}

$id     = (int) ($_GET['id'] ?? 0);
$report = $DB->request(['FROM' => Importer::T_REPORTS, 'WHERE' => ['id' => $id]])->current();
if ($report === null) {
    throw new NotFoundHttpException();
}

if (!empty($_GET['raw'])) {
    $xml = Importer::readRaw($report);
    if ($xml === null) {
        throw new NotFoundHttpException();
    }
    $name = preg_replace('/[^\w.!-]+/', '_', $report['org_name'] . '!' . $report['domain'] . '!' . $report['report_id']) . '.xml';

    return new Response($xml, 200, [
        'Content-Type'           => 'application/xml; charset=UTF-8',
        'Content-Disposition'    => 'attachment; filename="' . $name . '"',
        'X-Content-Type-Options' => 'nosniff',
    ]);
}

$records = [];
$auth    = [];
$rows    = iterator_to_array($DB->request([
    'SELECT'    => ['r.*', 's.ptr', 's.sender', 's.status AS source_status', 's.abuse_score', 's.abuse_reports', 's.abuse_country', 's.abuse_isp', 's.abuse_usage', 's.abuse_domain', 's.abuse_tor', 's.abuse_date', 's.abuse_error'],
    'FROM'      => Importer::T_RECORDS . ' AS r',
    'LEFT JOIN' => [Importer::T_SOURCES . ' AS s' => ['ON' => ['r' => 'sources_id', 's' => 'id']]],
    'WHERE'     => ['r.reports_id' => $id],
    'ORDER'     => 'r.count DESC',
]), false);
if ($rows !== []) {
    foreach ($DB->request(['FROM' => Importer::T_AUTH, 'WHERE' => ['records_id' => array_column($rows, 'id')], 'ORDER' => 'id']) as $a) {
        $auth[(int) $a['records_id']][] = $a;
    }
}
foreach ($rows as $row) {
    $row['auth']    = $auth[(int) $row['id']] ?? [];
    $row['abuse_public'] = \GlpiPlugin\Dmarc\AbuseIpdb::isPublic((string) $row['ip']);
    $row['explain'] = Diagnosis::isPass((int) $row['cause']) ? '' : Diagnosis::explain((int) $row['cause'], (int) $row['source_status']);
    $records[] = $row;
}
$message = $report['messages_id'] ? $DB->request(['FROM' => Importer::T_MESSAGES, 'WHERE' => ['id' => $report['messages_id']]])->current() : null;

Html::header('DMARC', '', 'tools', Menu::class);

TemplateRenderer::getInstance()->display('@dmarc/report.html.twig', [
    'report'       => $report,
    'records'      => $records,
    'message'      => $message,
    'has_raw'      => Importer::readRaw($report) !== null,
    'self'         => Ui::root() . '/plugins/dmarc/front/report.php',
    'dashboard'    => Menu::url(['tab' => 'reports']),
    'cause_labels' => Ui::causeLabels(),
    'source_statuses' => Ui::sourceStatuses(),
]);

Html::footer();
