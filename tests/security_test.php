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
 * Regression tests for the security review findings
 *
 * @package    block_configurable_reports
 * @copyright  2026 Juan Leyva
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace block_configurable_reports;

use advanced_testcase;
use PHPUnit\Framework\Attributes\CoversFunction;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->libdir . '/formslib.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/locallib.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/plugin.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/report.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/reports/sql/report.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/reports/timeline/report.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/export/slk/export.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/components/filters/yearhebrew/plugin.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/components/columns/userfield/plugin.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/components/conditions/cuserfield/plugin.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/components/conditions/ccoursefield/plugin.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/components/columns/reportcolumn/plugin.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/components/plot/bar/plugin.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/components/plot/line/plugin.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/components/plot/pie/plugin.class.php');

/**
 * Regression tests for the security review findings
 *
 * @package    block_configurable_reports
 * @covers     ::cr_import_xml
 */
#[CoversFunction('cr_import_xml')]
final class security_test extends advanced_testcase {

    protected function setUp(): void {
        parent::setUp();
        $this->resetAfterTest();
    }

    protected function tearDown(): void {
        unset($_GET['filter_yearhebrew']);
        parent::tearDown();
    }

    /**
     * Create a SQL report owned by the current user.
     *
     * @param string $query
     * @param array $filters
     * @return \stdClass
     */
    private function create_sql_report(string $query, array $filters = []): \stdClass {
        global $DB, $SITE, $USER;

        $components = [
            'customsql' => ['config' => (object) ['querysql' => $query]],
            'filters' => ['elements' => $filters],
        ];
        $report = (object) [
            'courseid' => $SITE->id,
            'ownerid' => $USER->id,
            'visible' => 1,
            'name' => 'SQL test report',
            'summary' => '',
            'type' => 'sql',
            'components' => cr_serialize($components),
            'remote' => 0,
        ];
        $report->id = $DB->insert_record('block_configurable_reports', $report);

        return $DB->get_record('block_configurable_reports', ['id' => $report->id]);
    }

    /**
     * Build an import XML like the one created by export.php.
     *
     * @param string $type
     * @param array $extra Extra report fields.
     * @param array|null $components Report components, or null for the default SQL component.
     * @return string
     */
    private function build_import_xml(string $type, array $extra = [], ?array $components = null): string {
        $components = cr_serialize($components ?? [
            'customsql' => ['config' => (object) ['querysql' => 'SELECT id, username FROM {user}']],
        ]);
        $fields = array_merge([
            'name' => 'Imported',
            'summary' => '',
            'type' => $type,
            'visible' => 1,
            'components' => base64_encode($components),
        ], $extra);

        $xml = '<?xml version="1.0" encoding="UTF-8" ?>' . "\n" . '<report version="2024051300">';
        foreach ($fields as $key => $value) {
            $xml .= "<$key><![CDATA[$value]]></$key>\n";
        }

        return $xml . '</report>';
    }

    /**
     * The Hebrew year filter value is bound as a parameter, so quotes cannot break out of the query.
     */
    public function test_yearhebrew_filter_is_bound(): void {
        $this->setAdminUser();
        $this->getDataGenerator()->create_user(['username' => 'crtest1', 'idnumber' => 'abc']);

        $query = "SELECT u.username FROM {user} u WHERE u.username LIKE 'crtest%' %%FILTER_YEARHEBREW:u.idnumber%%";
        $_GET['filter_yearhebrew'] = "x' UNION SELECT password FROM {user} WHERE username LIKE '";

        $plugin = new \plugin_yearhebrew($this->create_sql_report($query));
        [$sql, $params] = $plugin->execute_for_sql_report($query, new \stdClass());

        $this->assertStringNotContainsString('UNION', $sql);
        $this->assertArrayHasKey('filteryearhebrew', $params);

        $report = new \report_sql($this->create_sql_report($query, [['pluginname' => 'yearhebrew',
            'formdata' => new \stdClass()]]));
        $report->create_report();
        $this->assertEmpty($report->finalreport->table->data);
    }

    /**
     * Users without managesqlreports cannot import SQL reports.
     */
    public function test_import_sql_report_requires_capability(): void {
        global $DB, $SITE;

        $user = $this->getDataGenerator()->create_user();
        $roleid = $this->getDataGenerator()->create_role();
        assign_capability('block/configurable_reports:managereports', CAP_ALLOW, $roleid, \context_system::instance());
        role_assign($roleid, $user->id, \context_system::instance());
        $this->setUser($user);

        try {
            cr_import_xml($this->build_import_xml('sql'), $SITE);
            $this->fail('Exception expected');
        } catch (\moodle_exception $e) {
            $this->assertSame('nosqlpermissions', $e->errorcode);
        }
        $this->assertFalse($DB->record_exists('block_configurable_reports', []));

        // Unknown or path-like report types are rejected too.
        try {
            cr_import_xml($this->build_import_xml('../../sql'), $SITE);
            $this->fail('Exception expected');
        } catch (\moodle_exception $e) {
            $this->assertSame('nosqlpermissions', $e->errorcode);
        }
    }

    /**
     * Imports ignore fields that must be set by the current context, such as the owner and the course.
     */
    public function test_import_ignores_protected_fields(): void {
        global $DB, $SITE, $USER;

        $this->setAdminUser();
        $course = $this->getDataGenerator()->create_course();

        $xml = $this->build_import_xml('sql', ['ownerid' => 12345, 'courseid' => $course->id, 'id' => 999]);
        $this->assertTrue(cr_import_xml($xml, $SITE));

        $report = $DB->get_record('block_configurable_reports', []);
        $this->assertEquals($USER->id, $report->ownerid);
        $this->assertEquals($SITE->id, $report->courseid);
        $this->assertNotEquals(999, $report->id);
    }

    /**
     * A normal report manager cannot enable the separately configured remote database through an import.
     */
    public function test_import_remote_requires_sql_capability(): void {
        global $DB, $SITE;

        $user = $this->getDataGenerator()->create_user();
        $roleid = $this->getDataGenerator()->create_role();
        assign_capability('block/configurable_reports:managereports', CAP_ALLOW, $roleid, \context_system::instance());
        role_assign($roleid, $user->id, \context_system::instance());
        $this->setUser($user);

        $this->assertTrue(cr_import_xml($this->build_import_xml('users', ['remote' => 1]), $SITE));
        $this->assertEquals(0, $DB->get_field('block_configurable_reports', 'remote', []));
    }

    /**
     * The remote connection is an SQL-report feature, even for a fully trusted user.
     */
    public function test_import_remote_requires_sql_report(): void {
        global $DB, $SITE;

        $this->setAdminUser();
        $this->assertTrue(cr_import_xml($this->build_import_xml('users', ['remote' => 1]), $SITE));
        $this->assertEquals(0, $DB->get_field('block_configurable_reports', 'remote', []));
    }

    /**
     * Existing reports do not connect remotely after their owner loses the trusted SQL capability.
     */
    public function test_remote_database_requires_trusted_owner(): void {
        global $DB, $SITE, $remotedb;

        $owner = $this->getDataGenerator()->create_user();
        set_config('dbhost', '127.0.0.1', 'block_configurable_reports');
        set_config('dbname', 'database_that_does_not_exist', 'block_configurable_reports');
        set_config('dbuser', 'nobody', 'block_configurable_reports');
        set_config('dbpass', 'invalid', 'block_configurable_reports');

        $classname = cr_require_report_class('users');
        new $classname((object) [
            'id' => 1,
            'courseid' => $SITE->id,
            'ownerid' => $owner->id,
            'type' => 'users',
            'components' => cr_serialize([]),
            'remote' => 1,
        ]);

        $this->assertSame($DB, $remotedb);
    }

    /**
     * Import data is bounded before parsing and components must use valid base64.
     */
    public function test_import_rejects_oversized_or_invalid_data(): void {
        global $DB, $SITE;

        $this->setAdminUser();

        $this->assertFalse(cr_import_xml(str_repeat('x', (1024 * 1024) + 1), $SITE));
        $this->assertFalse(cr_import_xml($this->build_import_xml('users', ['components' => '%%%']), $SITE));
        $this->assertFalse($DB->record_exists('block_configurable_reports', []));
    }

    /**
     * Serialized data cannot instantiate classes other than stdClass.
     */
    public function test_unserialize_only_allows_stdclass(): void {
        $data = 'a:1:{s:1:"x";O:17:"core\\task\\manager":0:{}}';

        $result = cr_unserialize($data);

        $this->assertNotInstanceOf(\core\task\manager::class, $result['x']);
    }

    /**
     * Serialized component data has a nesting limit and malformed input fails closed.
     */
    public function test_unserialize_has_nesting_limit(): void {
        $data = 's:1:"x";';
        for ($i = 0; $i < 70; $i++) {
            $data = 'a:1:{i:0;' . $data . '}';
        }

        $this->assertSame([], cr_unserialize($data));
        $this->assertSame([], cr_unserialize('not serialized data'));
    }

    /**
     * SQL report cells are cleaned, so user-authored HTML cannot run script.
     */
    public function test_sql_report_cells_are_cleaned(): void {
        $this->setAdminUser();
        $this->getDataGenerator()->create_user(['username' => 'crtest1',
            'description' => '<img src="x" onerror="alert(1)"><a href="https://moodle.org">link</a>']);

        $report = new \report_sql($this->create_sql_report(
            "SELECT u.description FROM {user} u WHERE u.username = 'crtest1'"));
        $report->create_report();

        $cell = $report->finalreport->table->data[0][0];
        $this->assertStringNotContainsString('onerror', $cell);
        $this->assertStringContainsString('<a href="https://moodle.org">link</a>', $cell);
    }

    /**
     * Question marks go back into the cells before they are cleaned, so they cannot be used to get script past it.
     */
    public function test_sql_report_question_marks_do_not_bypass_cleaning(): void {
        $this->setAdminUser();
        $this->getDataGenerator()->create_user(['username' => 'crtest1',
            'description' => '<a href="javascript:alert(1)?x=[[QUESTIONMARK]]" onclick="alert(1)">?</a><img src="x?" onerror="alert(1)">']);

        $report = new \report_sql($this->create_sql_report(
            "SELECT u.description, '<script>alert(1)</script>?' AS other FROM {user} u WHERE u.username = 'crtest1'"));
        $report->create_report();

        $cells = implode('', $report->finalreport->table->data[0]);
        $this->assertStringNotContainsString('javascript:', $cells);
        $this->assertStringNotContainsString('onclick', $cells);
        $this->assertStringNotContainsString('onerror', $cells);
        $this->assertStringNotContainsString('<script>', $cells);
    }

    /**
     * User field columns escape plain fields.
     */
    public function test_userfield_column_is_escaped(): void {
        global $DB;

        $this->setAdminUser();
        $user = $this->getDataGenerator()->create_user(['description' => '<img src="x" onerror="alert(1)">']);
        $row = $DB->get_record('user', ['id' => $user->id]);
        $row->city = '<script>alert(1)</script>';

        $plugin = new \plugin_userfield($this->create_sql_report('SELECT 1'));

        $this->assertStringNotContainsString('<script>', $plugin->execute((object) ['column' => 'city'], clone $row));
        $this->assertStringNotContainsString('onerror', $plugin->execute((object) ['column' => 'description'], clone $row));
    }

    /**
     * Imports drop unknown plugins and export formats, and cast numeric flags.
     */
    public function test_import_cleans_components(): void {
        global $DB, $SITE;

        $this->setAdminUser();
        $components = [
            'columns' => ['elements' => [
                ['id' => 'a', 'pluginname' => 'userfield', 'formdata' => (object) ['column' => 'username']],
                ['id' => 'b', 'pluginname' => '../../../evil', 'formdata' => new \stdClass()],
            ]],
            'unknown' => ['elements' => []],
        ];
        $xml = $this->build_import_xml('users', ['export' => 'csv"><img src=x onerror=alert(1)>,xls,', 'visible' => '1x'],
            $components);

        $this->assertTrue(cr_import_xml($xml, $SITE));

        $report = $DB->get_record('block_configurable_reports', []);
        $this->assertSame('xls,', $report->export);
        $this->assertEquals(1, $report->visible);
        $stored = cr_unserialize($report->components);
        $this->assertSame(['columns'], array_keys($stored));
        $this->assertSame(['userfield'], array_column($stored['columns']['elements'], 'pluginname'));
    }

    /**
     * Unknown plugin names cannot be used to build include paths.
     */
    public function test_require_component_plugin_rejects_unknown(): void {
        $this->assertSame('plugin_userfield', cr_require_component_plugin('columns', 'userfield'));

        $this->expectException(\moodle_exception::class);
        cr_require_component_plugin('columns', '../conditions/cuserfield');
    }

    /**
     * Stored report types cannot be turned into include paths.
     */
    public function test_require_report_class_rejects_unknown(): void {
        $this->assertSame('report_users', cr_require_report_class('users'));

        $this->expectException(\moodle_exception::class);
        cr_require_report_class('../../sql');
    }

    /**
     * Chart data stays out of URLs and can only be read by the user who generated it.
     */
    public function test_plot_data_uses_user_bound_token(): void {
        global $SITE;

        $this->setAdminUser();
        $report = (object) ['id' => 123, 'courseid' => $SITE->id, 'type' => 'users'];
        $plugin = new \plugin_bar($report);
        $data = (object) ['label_field' => '0,Name', 'value_fields' => '1,Value'];

        $url = html_entity_decode($plugin->execute('chart1', $data, [['Sensitive label', 42]]));
        parse_str((string) parse_url($url, PHP_URL_QUERY), $params);

        $this->assertArrayHasKey('token', $params);
        $this->assertStringNotContainsString('Sensitive label', $url);
        $this->assertSame(
            ['Name' => ['Sensitive label'], 'Value' => [42]],
            cr_get_plot_data($params['token'], 123, 'bar')
        );

        $lineurl = html_entity_decode((new \plugin_line($report))->execute('chart2', (object) [
            'xaxis' => 1,
            'yaxis' => 2,
            'serieid' => 1,
        ], [['Private series', 99]]));
        parse_str((string) parse_url($lineurl, PHP_URL_QUERY), $lineparams);
        $this->assertArrayNotHasKey('min', $lineparams);
        $this->assertArrayNotHasKey('max', $lineparams);
        $this->assertStringNotContainsString('Private series', $lineurl);
        $this->assertSame(
            'Private series',
            cr_get_plot_data($lineparams['token'], 123, 'line')['series'][0]['name']
        );

        $pieurl = html_entity_decode((new \plugin_pie($report))->execute('chart3', (object) [
            'areaname' => 0,
            'areavalue' => 1,
            'group' => 0,
        ], [['Private slice', 7]]));
        parse_str((string) parse_url($pieurl, PHP_URL_QUERY), $pieparams);
        $this->assertStringNotContainsString('Private slice', $pieurl);
        $this->assertSame(
            [['Private slice'], [7]],
            cr_get_plot_data($pieparams['token'], 123, 'pie')['series']
        );

        $this->setUser($this->getDataGenerator()->create_user());
        $this->expectException(\invalid_parameter_exception::class);
        cr_get_plot_data($params['token'], 123, 'bar');
    }

    /**
     * Export values cannot terminate their XML CDATA section.
     */
    public function test_cdata_encoding_preserves_terminator_text(): void {
        global $CFG;

        $value = 'before]]><injected/>after';
        $xml = '<value><![CDATA[' . cr_encode_cdata($value) . ']]></value>';
        if (class_exists('\core\xml_parser')) {
            $parsed = (new \core\xml_parser())->parse($xml, 1, 'UTF-8');
        } else {
            require_once($CFG->dirroot . '/lib/xmlize.php');
            $parsed = xmlize($xml, 1, 'UTF-8');
        }

        $this->assertSame($value, $parsed['value']['#']);
        $this->assertStringNotContainsString(']]><injected', cr_encode_cdata($value));
    }

    /**
     * Imported bar chart dimensions cannot trigger unbounded image allocation.
     */
    public function test_bar_dimensions_are_bounded(): void {
        $this->assertSame([900, 500], \plugin_bar::normalise_dimensions(new \stdClass()));
        $this->assertSame([200, 4000], \plugin_bar::normalise_dimensions((object) [
            'width' => -1,
            'height' => PHP_INT_MAX,
        ]));
    }

    /**
     * Mutually embedded user and course reports terminate instead of recursing until resource exhaustion.
     */
    public function test_embedded_report_cycle_is_bounded(): void {
        global $DB, $SITE, $USER;

        $this->setAdminUser();
        $viewer = $USER;
        $student = $this->getDataGenerator()->create_user();
        $course = $this->getDataGenerator()->create_course();
        $this->getDataGenerator()->enrol_user($student->id, $course->id);

        $base = [
            'courseid' => $SITE->id,
            'ownerid' => $viewer->id,
            'visible' => 1,
            'summary' => '',
            'components' => cr_serialize([]),
            'remote' => 0,
        ];
        $usersid = $DB->insert_record('block_configurable_reports', (object) ($base + [
            'name' => 'Users cycle',
            'type' => 'users',
        ]));
        $coursesid = $DB->insert_record('block_configurable_reports', (object) ($base + [
            'name' => 'Courses cycle',
            'type' => 'courses',
        ]));

        $column = static function (int $reportid): array {
            return [
                'id' => 'cycle' . $reportid,
                'pluginname' => 'reportcolumn',
                'formdata' => (object) [
                    'reportid' => $reportid,
                    'column' => 0,
                    'columname' => 'Embedded',
                ],
            ];
        };
        $DB->set_field('block_configurable_reports', 'components', cr_serialize([
            'columns' => ['elements' => [$column($coursesid)]],
            'conditions' => ['elements' => []],
        ]), ['id' => $usersid]);
        $DB->set_field('block_configurable_reports', 'components', cr_serialize([
            'columns' => ['elements' => [$column($usersid)]],
            'conditions' => ['elements' => []],
        ]), ['id' => $coursesid]);

        $usersreport = $DB->get_record('block_configurable_reports', ['id' => $usersid]);
        $plugin = new \plugin_reportcolumn($usersreport);
        $result = $plugin->execute((object) ['reportid' => $coursesid, 'column' => 0], $student, $viewer, $SITE->id);

        $this->assertIsArray($result);
        $this->assertLessThanOrEqual(1, count($result));
    }

    /**
     * Field conditions ignore fields and operators that the form would not allow.
     */
    public function test_field_conditions_validate_formdata(): void {
        global $DB, $USER;

        $this->setAdminUser();
        $report = $this->create_sql_report('SELECT 1');
        $user = $DB->get_record('user', ['id' => $USER->id]);

        $cuserfield = new \plugin_cuserfield($report);
        $injected = (object) ['field' => 'id > 0 OR 1 = 1 OR id', 'operator' => '=', 'value' => 1];
        $this->assertSame([], $cuserfield->execute($injected, $user));
        $badoperator = (object) ['field' => 'id', 'operator' => '= 1 OR id =', 'value' => 1];
        $this->assertSame([], $cuserfield->execute($badoperator, $user));
        $password = (object) ['field' => 'password', 'operator' => 'LIKE', 'value' => '%'];
        $this->assertSame([], $cuserfield->execute($password, $user));
        $valid = (object) ['field' => 'id', 'operator' => '=', 'value' => $USER->id];
        $this->assertEquals([$USER->id], $cuserfield->execute($valid, $user));

        $ccoursefield = new \plugin_ccoursefield($report);
        $injected = (object) ['field' => 'id > 0 OR 1 = 1 OR id', 'operator' => '=', 'value' => 1];
        $this->assertSame([], $ccoursefield->execute($injected));
    }

    /**
     * The user field column never shows credentials.
     */
    public function test_userfield_column_hides_password(): void {
        global $DB, $USER;

        $this->setAdminUser();
        $row = $DB->get_record('user', ['id' => $USER->id]);
        $plugin = new \plugin_userfield($this->create_sql_report('SELECT 1'));

        $this->assertSame('', $plugin->execute((object) ['column' => 'password'], clone $row));
    }

    /**
     * The SQL security keyword check also applies when the query runs, not only in the form.
     */
    public function test_execute_query_checks_keywords(): void {
        $this->setAdminUser();
        set_config('sqlsecurity', 1, 'block_configurable_reports');

        $report = new \report_sql($this->create_sql_report('SELECT 1'));

        try {
            $report->execute_query('DELETE FROM {user} WHERE id = 0');
            $this->fail('Exception expected');
        } catch (\moodle_exception $e) {
            $this->assertSame('notallowedwords', $e->errorcode);
        }

        $this->expectException(\moodle_exception::class);
        $report->execute_query('SELECT id FROM {user}; SELECT 1');
    }

    /**
     * The scheduled task runs the SQL reports flagged to run daily, once a day after the configured time.
     */
    public function test_run_cron_reports_task(): void {
        global $DB;

        $this->setAdminUser();
        $report = $this->create_sql_report('SELECT id FROM {user}');
        $DB->set_field('block_configurable_reports', 'cron', 1, ['id' => $report->id]);
        set_config('cron_hour', 0, 'block_configurable_reports');
        set_config('cron_minute', 0, 'block_configurable_reports');

        $task = new \block_configurable_reports\task\run_cron_reports();
        ob_start();
        $task->execute();
        $output = ob_get_clean();
        $this->assertStringContainsString("Executing query 'SQL test report'", $output);
        $this->assertStringContainsString('...OK', $output);

        // It does not run again the same day.
        ob_start();
        $task->execute();
        $this->assertSame('', ob_get_clean());
    }

    /**
     * Imported column formats keep only the values the column form allows, as they end up in a style attribute.
     */
    public function test_column_format_is_validated(): void {
        $column = new \plugin_userfield((object) ['id' => 0, 'type' => 'users', 'components' => cr_serialize([]),
            'courseid' => SITEID]);

        $this->assertSame(['right', '50%', 1], $column->colformat((object) ['align' => 'right', 'size' => '50%', 'wrap' => 1]));
        $this->assertSame(['', '', ''], $column->colformat((object) [
            'align' => 'x;" onmouseover="alert(1)" data-x="',
            'size' => '10px;" onmouseover="alert(1)',
        ]));
    }

    /**
     * Imported element ids that are not alphanumeric are replaced, as they end up in the links of the report editor.
     */
    public function test_import_replaces_invalid_element_ids(): void {
        $components = cr_clean_imported_components(['columns' => ['elements' => [
            ['id' => 'abc123', 'pluginname' => 'userfield', 'formdata' => new \stdClass()],
            ['id' => '"><script>alert(1)</script>', 'pluginname' => 'userfield', 'formdata' => new \stdClass()],
            ['pluginname' => 'userfield', 'formdata' => new \stdClass()],
        ]]]);

        $ids = array_column($components['columns']['elements'], 'id');
        $this->assertSame('abc123', $ids[0]);
        $this->assertCount(3, $ids);
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9]{15}$/', $ids[1]);
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9]{15}$/', $ids[2]);
    }

    /**
     * A timeline with an interval below one day still ends, and a long range is cut at the report limit.
     */
    public function test_timeline_rows_are_bounded(): void {
        set_config('reportlimit', 100, 'block_configurable_reports');

        $config = (object) ['timemode' => 'fixeddate', 'starttime' => 0, 'endtime' => time(), 'interval' => 0,
            'ordering' => 'asc'];
        $report = new \report_timeline((object) ['id' => 0, 'courseid' => SITEID, 'type' => 'timeline', 'remote' => 0,
            'components' => cr_serialize(['timeline' => ['config' => $config]])]);

        $elements = $report->get_all_elements();

        $this->assertCount(100, $elements);
        $this->assertSame(DAYSECS, $elements[1] - $elements[0]);
    }

    /**
     * Cell values cannot start new SYLK records or fields.
     */
    public function test_slk_cells_are_escaped(): void {
        ob_start();
        dump_slk_row(["x\nC;Y1;X1;K0;E1+1", 'a;b']);
        $output = ob_get_clean();

        $lines = explode("\n", trim($output));
        $this->assertCount(2, $lines);
        $this->assertStringEndsWith('K"x C;;Y1;;X1;;K0;;E1+1"', $lines[0]);
        $this->assertStringEndsWith('K"a;;b"', $lines[1]);
    }
}
