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
 * Configurable Reports a Moodle block for creating customizable reports
 *
 * @copyright  2020 Juan Leyva <juan@moodle.com>
 * @package    block_configurable_reports
 * @author     Juan leyva <http://www.twitter.com/jleyvadelgado>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
defined('MOODLE_INTERNAL') || die;
require_once($CFG->dirroot . '/blocks/configurable_reports/plugin.class.php');

/**
 * Class plugin_bar
 *
 * @package   block_configurable_reports
 * @author    Juan leyva <http://www.twitter.com/jleyvadelgado>
 */
class plugin_bar extends plugin_base {

    /** @var int Largest canvas dimension pChart is allowed to allocate. */
    private const MAX_DIMENSION = 4000;

    /** @var int Smallest useful canvas dimension. */
    private const MIN_DIMENSION = 200;

    /**
     * Init
     *
     * @return void
     */
    public function init(): void {
        $this->fullname = get_string('bar', 'block_configurable_reports');
        $this->form = true;
        $this->ordering = true;
        $this->reporttypes = ['courses', 'sql', 'users', 'timeline', 'categories'];
    }

    /**
     * Summary
     *
     * @param object $data
     * @return string
     */
    public function summary(object $data): string {
        return get_string('barsummary', 'block_configurable_reports');
    }

    /**
     * Bound dimensions from stored/imported graph configuration before pChart allocates an image.
     *
     * @param object $data Graph configuration.
     * @return int[] Width and height.
     */
    public static function normalise_dimensions(object $data): array {
        $width = property_exists($data, 'width') ? (int) $data->width : 900;
        $height = property_exists($data, 'height') ? (int) $data->height : 500;

        return [
            min(max($width, self::MIN_DIMENSION), self::MAX_DIMENSION),
            min(max($height, self::MIN_DIMENSION), self::MAX_DIMENSION),
        ];
    }

    /**
     * Execute
     *
     * @param int $id
     * @param object $data
     * @param array $finalreport
     * @return string
     */
    public function execute($id, $data, $finalreport) {
        global $CFG;
        // Data -> Plugin configuration data.

        $series = [];
        if ($finalreport) {
            [$labelidx, $labelname] = explode(",", $data->label_field);
            $series[$labelname] = [];
            if (!is_array($data->value_fields)) {
                $data->value_fields = [$data->value_fields];
            }
            foreach ($finalreport as $r) {
                $series[$labelname][] = $r[$labelidx];
                foreach ($data->value_fields as $valuefields) {
                    [$idx, $name] = explode(",", $valuefields);
                    $value = $r[$idx];

                    if ($idx == $labelidx) {
                        debugging(
                            "moodle:configurable_reports:bar:  refusing to chart label field",
                            DEBUG_DEVELOPER
                        );
                        continue;
                    }

                    if (!is_numeric($value)) {
                        // Can't just skip. That would throw off the indexes if a column has bad values in some but not all rows.
                        debugging(
                            "moodle:configurable_reports:bar:  substituting 0 for non-numeric value '$value'",
                            DEBUG_DEVELOPER
                        );
                        $value = 0;
                    }

                    if (!array_key_exists($name, $series)) {
                        $series[$name] = [];
                    }
                    $series[$name][] = $value;
                }
            }
        }

        $token = cr_store_plot_data((int) $this->report->id, 'bar', $series);

        return $CFG->wwwroot . '/blocks/configurable_reports/components/plot/bar/graph.php?reportid=' . $this->report->id . '&id=' .
            $id . '&token=' . $token . '&courseid=' . $this->report->courseid;
    }

    /**
     * Get series
     *
     * @return array
     */
    public function get_series(): array {
        $token = required_param('token', PARAM_ALPHANUM);

        return cr_get_plot_data($token, (int) $this->report->id, 'bar');
    }

}
