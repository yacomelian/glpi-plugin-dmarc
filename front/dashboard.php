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

/*
 * Tools > DMARC: dashboard.
 */

use Glpi\Application\View\TemplateRenderer;
use GlpiPlugin\Dmarc\Dashboard;
use GlpiPlugin\Dmarc\Menu;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;

if (!Menu::canView()) {
    throw new AccessDeniedHttpException();
}

Html::requireJs('charts');
Html::header('DMARC', '', 'tools', Menu::class);

TemplateRenderer::getInstance()->display('@dmarc/dashboard.html.twig', Dashboard::build($_GET));

Html::footer();
