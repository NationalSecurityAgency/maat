/*
 * Copyright 2023 United States Government
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <config.h>
#include <check.h>
#include <errno.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <common/measurement_spec.h>

#include <test-data.h>

START_TEST (test_load_measurement_specification_info)
{
    mspec_info* ms;
    ms = load_measurement_specification_info(ATTESTER_MEAS_SPEC_FILE);
    fail_unless(ms != NULL, "Failed to load measurement specification");

    uuid_str_t uutmp;
    uuid_unparse(ms->uuid, uutmp);
    uuid_t expected;
    uuid_parse(ATTESTER_MEAS_SPEC_UUID, expected);
    fail_unless(uuid_compare(expected, ms->uuid) == 0,
                "Measurement specification uuid incorrect: %s", uutmp);
    free_measurement_specification_info(ms);
}
END_TEST

START_TEST (test_load_all_measurement_specifications_info)
{
    GList *meas_specs = NULL;
    meas_specs = load_all_measurement_specifications_info(SPEC_DIR);
    fail_unless(meas_specs != NULL, "Failed to load measurement specification list");
    mspec_info* ms;

    const char *dmsup = ATTESTER_MEAS_SPEC_UUID;
    uuid_t uutmp;
    uuid_parse(dmsup, uutmp);
    ms = find_measurement_specification_uuid(meas_specs, uutmp);
    fail_unless(ms != NULL, "Failed to find measurement specification");
    ms = NULL;
    g_list_free_full(meas_specs, (GDestroyNotify)free_measurement_specification_info);
}
END_TEST

Suite* ms_suite (void)
{
    Suite *s = suite_create ("Measurement Spec Tests");

    TCase *tc_basic = tcase_create ("Basic Tests");
    tcase_add_test (tc_basic, test_load_measurement_specification_info);
    tcase_add_test (tc_basic, test_load_all_measurement_specifications_info);
    suite_add_tcase (s, tc_basic);
    return s;
}


int main(void)
{
    int number_failed;
    Suite *s = ms_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_measurement_spec.log");
    srunner_set_xml(sr, "test_results_measurement_spec.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
