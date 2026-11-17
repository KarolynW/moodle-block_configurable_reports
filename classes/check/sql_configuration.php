<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Checks how SQL reports are configured.
 *
 * @package    block_configurable_reports
 * @copyright  2026 Juan Leyva
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace block_configurable_reports\check;

use core\check\result;

/**
 * Warns when SQL reports are configured less safely than the plugin allows.
 *
 * @package    block_configurable_reports
 * @copyright  2026 Juan Leyva
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class sql_configuration extends \core\check\check {

    /**
     * Return result
     *
     * @return result
     */
    public function get_result(): result {
        global $DB;

        $problems = [];
        if (!get_config('block_configurable_reports', 'sqlsecurity')) {
            $problems[] = get_string('checksql_configuration_sqlsecurity', 'block_configurable_reports');
        }

        $forceremote = get_config('block_configurable_reports', 'forceremotesql');
        $forceremote = $forceremote === false || (bool) $forceremote;
        if (!$forceremote) {
            $local = $DB->count_records('block_configurable_reports', ['type' => 'sql', 'remote' => 0]);
            if ($local > 0) {
                $problems[] = get_string('checksql_configuration_local', 'block_configurable_reports', $local);
            }
        }

        if (trim((string) get_config('block_configurable_reports', 'allowedsqlusers')) === '') {
            $problems[] = get_string('checksql_configuration_allowlist', 'block_configurable_reports');
        }
        if ((int) get_config('block_configurable_reports', 'sqltimeout') <= 0) {
            $problems[] = get_string('checksql_configuration_timeout', 'block_configurable_reports');
        }

        $remotereports = $forceremote || $DB->record_exists('block_configurable_reports', [
            'type' => 'sql',
            'remote' => 1,
        ]);
        if ($remotereports) {
            $remoteconfig = ['dbhost', 'dbname', 'dbuser', 'dbpass'];
            foreach ($remoteconfig as $name) {
                if (trim((string) get_config('block_configurable_reports', $name)) === '') {
                    $problems[] = get_string('checksql_configuration_remote', 'block_configurable_reports');
                    break;
                }
            }
        }

        if ($problems) {
            $status = result::WARNING;
            $summary = get_string('checksql_configuration_warning', 'block_configurable_reports');
        } else {
            $status = result::OK;
            $summary = get_string('checksql_configuration_ok', 'block_configurable_reports');
        }

        $details = \html_writer::alist(array_map('s', $problems));
        if (!$problems) {
            $details = get_string('checksql_configuration_ok', 'block_configurable_reports');
        }

        return new result($status, $summary, $details);
    }

}
