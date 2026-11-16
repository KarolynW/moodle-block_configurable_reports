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

namespace block_configurable_reports;

use advanced_testcase;

defined('MOODLE_INTERNAL') || die();

global $CFG;
require_once($CFG->dirroot . '/blocks/configurable_reports/locallib.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/report.class.php');
require_once($CFG->dirroot . '/blocks/configurable_reports/reports/sql/report.class.php');

/**
 * Tests for the optional controls that restrict where and how long SQL reports run, the web service switch,
 * report ownership transfer, chart data retention and the configuration check.
 *
 * @package    block_configurable_reports
 * @copyright  2026 Juan Leyva
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers     \report_sql
 */
final class transition_controls_test extends advanced_testcase {

    protected function setUp(): void {
        parent::setUp();
        $this->resetAfterTest();
    }

    /**
     * Create a report owned by the current user.
     *
     * @param string $type Report type.
     * @return \stdClass
     */
    private function create_report(string $type = 'sql'): \stdClass {
        global $DB, $SITE, $USER;

        $components = $type === 'sql' ? ['customsql' => ['config' => (object) ['querysql' => 'SELECT 1']]] : [];
        $id = $DB->insert_record('block_configurable_reports', (object) [
            'courseid' => $SITE->id,
            'ownerid' => $USER->id,
            'visible' => 1,
            'name' => 'Test report',
            'summary' => '',
            'type' => $type,
            'components' => cr_serialize($components),
            'remote' => 0,
        ]);

        return $DB->get_record('block_configurable_reports', ['id' => $id]);
    }

    /**
     * Create a user holding the given capabilities in the system context.
     *
     * @param string[] $capabilities
     * @return \stdClass
     */
    private function create_user_with(array $capabilities): \stdClass {
        $user = $this->getDataGenerator()->create_user();
        $roleid = $this->getDataGenerator()->create_role();
        foreach ($capabilities as $capability) {
            assign_capability($capability, CAP_ALLOW, $roleid, \context_system::instance());
        }
        role_assign($roleid, $user->id, \context_system::instance());

        return $user;
    }

    /**
     * With the site-wide setting, an SQL report that is not marked remote still refuses to run locally.
     */
    public function test_force_remote_refuses_local_execution(): void {
        global $DB, $remotedb;

        $this->setAdminUser();
        $record = $this->create_report();
        $this->assertFalse(cr_sql_report_uses_remote($record));

        set_config('forceremotesql', 1, 'block_configurable_reports');
        $this->assertTrue(cr_sql_report_uses_remote($record));
        $this->assertFalse(cr_sql_report_uses_remote((object) ['type' => 'users', 'remote' => 1]));

        // No reporting database is configured, so the report must fail instead of using Moodle's database.
        $report = new \report_sql($record);
        $this->assertSame($DB, $remotedb);
        try {
            $report->execute_query('SELECT 1');
            $this->fail('Exception expected');
        } catch (\moodle_exception $e) {
            $this->assertSame('remotedatabaseunavailable', $e->errorcode);
        }
    }

    /**
     * With the site-wide setting, the query is sent to the reporting connection.
     */
    public function test_force_remote_uses_reporting_connection(): void {
        global $DB, $remotedb;

        $this->setAdminUser();
        set_config('forceremotesql', 1, 'block_configurable_reports');
        $report = new \report_sql($this->create_report());
        $remotedb = new class {
            /** @var int Number of queries received. */
            public int $queries = 0;

            /**
             * Stand-in for the reporting connection.
             *
             * @param string $sql
             * @param array $params
             * @param int $limitfrom
             * @param int $limitnum
             * @return array
             */
            public function get_recordset_sql(string $sql, array $params, int $limitfrom, int $limitnum): array {
                $this->queries++;
                return [];
            }
        };

        try {
            $report->execute_query('SELECT 1');
            $this->assertSame(1, $remotedb->queries);
        } finally {
            $remotedb = $DB;
        }
    }

    /**
     * No time limit is applied unless one is configured.
     */
    public function test_query_timeout_is_optional(): void {
        global $DB;

        $this->assertNull(cr_apply_query_timeout($DB));
    }

    /**
     * A configured time limit cancels a long query and is removed again afterwards.
     */
    public function test_query_timeout_cancels_long_query(): void {
        global $DB;

        if ($DB->get_dbfamily() !== 'postgres') {
            $this->markTestSkipped('The long-running query used here is specific to PostgreSQL.');
        }
        // A cancelled statement aborts the surrounding transaction, so this test cannot run inside one.
        $this->preventResetByRollback();
        $this->setAdminUser();
        set_config('sqltimeout', 1, 'block_configurable_reports');
        $report = new \report_sql($this->create_report());

        $start = microtime(true);
        try {
            $report->execute_query('SELECT count(*) FROM generate_series(1, 2000000000) AS s');
            $this->fail('Exception expected');
        } catch (\dml_exception $e) {
            $this->assertLessThan(10, microtime(true) - $start);
        }

        // The limit does not outlive the report query.
        $this->assertSame('0', (string) $DB->get_field_sql('SELECT setting FROM pg_settings WHERE name = ?',
            ['statement_timeout']));
    }

    /**
     * The web service can be switched off, and stays available on sites that never saved the setting.
     */
    public function test_webservice_can_be_disabled(): void {
        $this->setAdminUser();
        $record = $this->create_report('users');

        $result = external::get_report_data($record->id);
        $this->assertSame('', $result['warnings']);

        set_config('enablewebservice', 0, 'block_configurable_reports');
        try {
            external::get_report_data($record->id);
            $this->fail('Exception expected');
        } catch (\moodle_exception $e) {
            $this->assertSame('webservicedisabled', $e->errorcode);
        }
    }

    /**
     * A user who manages all reports and is trusted with SQL can take over an SQL report.
     */
    public function test_take_ownership_of_sql_report(): void {
        global $DB, $USER;

        $this->setAdminUser();
        $record = $this->create_report();
        $context = \context_system::instance();

        // Managing reports is not enough for an SQL report.
        $manager = $this->create_user_with(['block/configurable_reports:managereports']);
        $this->setUser($manager);
        try {
            cr_take_report_ownership($record, $context);
            $this->fail('Exception expected');
        } catch (\moodle_exception $e) {
            $this->assertSame('nosqlpermissions', $e->errorcode);
        }

        $sqlmanager = $this->create_user_with([
            'block/configurable_reports:managereports',
            'block/configurable_reports:managesqlreports',
        ]);
        $this->setUser($sqlmanager);
        $sink = $this->redirectEvents();
        cr_take_report_ownership($record, $context);
        $this->assertEquals($sqlmanager->id, $DB->get_field('block_configurable_reports', 'ownerid', ['id' => $record->id]));
        $events = $sink->get_events();
        $this->assertInstanceOf(event\report_updated::class, end($events));
        $this->assertTrue(end($events)->other['ownerchanged']);
    }

    /**
     * Ownership cannot be taken by someone who only manages their own reports.
     */
    public function test_take_ownership_requires_manage_all(): void {
        global $DB;

        $this->setAdminUser();
        $record = $this->create_report('users');
        $ownerid = $record->ownerid;

        $this->setUser($this->create_user_with(['block/configurable_reports:manageownreports']));
        try {
            cr_take_report_ownership($record, \context_system::instance());
            $this->fail('Exception expected');
        } catch (\required_capability_exception $e) {
            $this->assertEquals($ownerid, $DB->get_field('block_configurable_reports', 'ownerid', ['id' => $record->id]));
        }
    }

    /**
     * Chart data expires and the number of entries kept for one user is bounded.
     */
    public function test_plot_data_is_bounded(): void {
        $this->setAdminUser();
        $cache = \cache::make('block_configurable_reports', 'plotdata');

        // An entry older than its lifetime is refused.
        $old = cr_store_plot_data(1, 'bar', ['a' => [1]]);
        $payload = $cache->get($old);
        $payload['created'] = time() - CR_PLOT_DATA_LIFETIME - 1;
        $cache->set($old, $payload);
        try {
            cr_get_plot_data($old, 1, 'bar');
            $this->fail('Exception expected');
        } catch (\invalid_parameter_exception $e) {
            $this->assertStringContainsString('chart token', $e->getMessage());
        }

        // Storing more entries than the limit removes the oldest ones.
        $first = cr_store_plot_data(1, 'bar', ['a' => [1]]);
        $last = '';
        for ($i = 0; $i < CR_PLOT_DATA_MAX_PER_USER + 1; $i++) {
            $last = cr_store_plot_data(1, 'bar', ['a' => [$i]]);
        }
        $this->assertFalse($cache->get($first));
        $this->assertSame(['a' => [CR_PLOT_DATA_MAX_PER_USER]], cr_get_plot_data($last, 1, 'bar'));
    }

    /**
     * The configuration check warns about SQL reports that run on Moodle's own database.
     */
    public function test_configuration_check(): void {
        $this->setAdminUser();
        set_config('sqlsecurity', 1, 'block_configurable_reports');
        $check = new check\sql_configuration();
        $this->assertSame(\core\check\result::OK, $check->get_result()->get_status());

        $this->create_report();
        $this->assertSame(\core\check\result::WARNING, $check->get_result()->get_status());

        set_config('forceremotesql', 1, 'block_configurable_reports');
        $this->assertSame(\core\check\result::OK, $check->get_result()->get_status());

        set_config('sqlsecurity', 0, 'block_configurable_reports');
        $this->assertSame(\core\check\result::WARNING, $check->get_result()->get_status());
    }
}
