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

namespace GlpiPlugin\Dmarc\Command;

use Glpi\Console\AbstractCommand;
use GlpiPlugin\Dmarc\Importer;
use GlpiPlugin\Dmarc\Watcher;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 *   php bin/console plugins:dmarc:import /path/file-or-folder [...]
 *
 * Mails (.eml, also an mbox export split by hand) and reports (.zip, .gz,
 * .xml). Folders are read recursively. Reports already stored are skipped.
 */
final class ImportCommand extends AbstractCommand
{
    protected function configure(): void
    {
        $this->setName('plugins:dmarc:import');
        $this->setDescription('DMARC: import mails or reports from files');
        $this->addArgument('paths', InputArgument::REQUIRED | InputArgument::IS_ARRAY, 'Files or folders');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $files = [];
        foreach ((array) $input->getArgument('paths') as $path) {
            if (is_dir($path)) {
                foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS)) as $f) {
                    if ($f->isFile() && preg_match('/\.(eml|zip|gz|xml)$/i', $f->getFilename()) === 1) {
                        $files[] = $f->getPathname();
                    }
                }
            } elseif (is_file($path)) {
                $files[] = $path;
            } else {
                $output->writeln("<error>Not found: {$path}</error>");
            }
        }
        sort($files);

        $importer = Importer::fromSettings();
        $counts   = array_fill_keys(Importer::STATUSES, 0);
        $reports  = 0;
        foreach ($files as $i => $file) {
            $res = $importer->importFile(basename($file), (string) file_get_contents($file));
            $counts[$res['status']] = ($counts[$res['status']] ?? 0) + 1;
            $reports += $res['reports'];
            if ($res['status'] === Importer::ERROR || $res['status'] === Importer::NOT_REPORT) {
                $output->writeln(sprintf('  %s: %s%s', $file, Importer::statusLabel($res['status']), $res['error'] !== '' ? ' — ' . $res['error'] : ''));
            }
            if (($i + 1) % 200 === 0) {
                $output->writeln(sprintf('  … %d/%d', $i + 1, count($files)));
            }
        }
        $alerts = $reports > 0 ? Watcher::afterImport() : 0;

        $parts = [];
        foreach ($counts as $status => $n) {
            if ($n > 0) {
                $parts[] = Importer::statusLabel($status) . ': ' . $n;
            }
        }
        $output->writeln(sprintf('<info>%d files, %d new reports, %d alerts.</info> %s', count($files), $reports, $alerts, implode(' · ', $parts)));

        return 0;
    }
}
