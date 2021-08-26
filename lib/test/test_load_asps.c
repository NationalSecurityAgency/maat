/*
 * Copyright 2020 United States Government
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
#include <glib.h>
#include <dirent.h>
#include <uuid/uuid.h>
#include <util/xml_util.h>
#include <check.h>
#include <dlfcn.h>
#include <common/asp.h>
#include <common/asp_info.h>
#include <util/util.h>
#include <apb/apb.h>
#include "test-data.h"
#include <common/apb_info.h>

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED)
{
    return -1;
}

START_TEST (test_asp_load_object)
{
    GList *asps = load_all_asps_info(ASP_DIR);
    GList *i;
    int ret;
    fail_unless(asps!=NULL,"XML Path is invalid or no asp xmls");
    for(i=asps; i; i = g_list_next(i)) {
        struct asp *a = (struct asp*)i->data;
        a->desired_sec_ctxt.uid = getuid();
        a->desired_sec_ctxt.gid = getgid();
        ret = run_asp(a, -1, -1, false, 0, NULL, -1);
        wait_asp(a);
        fail_unless(ret>-1,"failed load asp object call with %d",ret);
    }

}
END_TEST


START_TEST(test_asp_xml_parsing)
{
    // Tests to make sure asp can read all the
    // desired data from a asp xml
    GList *asps = load_all_asps_info(ASP_DIR);
    GList *i;
    fail_unless(asps!=NULL,"XML Path is invalid or no asp xmls");
    for(i=asps; i; i = g_list_next(i)) {
        struct asp *a = (struct asp*)i->data;
        fail_unless(a != NULL,"asp is null");
        fail_unless(a->filename != NULL,"filename of asp is null");
        fail_unless(a->name != NULL,"name of asp is null");
        fail_unless(a->desc != NULL,"desc of asp is null");
        fail_unless(a->uuid != NULL,"uuid of asp is null");
        dlog(2,"Tested: %s\n",a->filename);

    }
}
END_TEST

START_TEST(test_load_asp_info_w_null_param)
{
    /*
     * Test to make sure load_asp_info
     * will return a NULL if given a
     * NULL param.
     */
    fail_unless(!load_asp_info(NULL),"return not NULL");
}
END_TEST


START_TEST(test_load_all_asps_info_w_null_param)
{
    /*
     * Test to make sure load_all_asps_info
     * will return a NULL if given a
     * NULL param.
     */
    fail_unless(!load_all_asps_info(NULL),"return not NULL");
}
END_TEST

void teardown(void)
{
    libmaat_exit();
    return;
}

Suite * comms_suite (void)
{
    Suite *s = suite_create ("ASP Tests");

    /*Core test case */
    TCase *tc_feature = tcase_create ("Feature Tests");
    tcase_set_timeout(tc_feature, 10);
    tcase_add_checked_fixture(tc_feature, setup, teardown);
    tcase_add_test (tc_feature, test_asp_load_object);
    tcase_add_test (tc_feature, test_asp_xml_parsing);
    suite_add_tcase (s, tc_feature);
    TCase *tc_negative = tcase_create ("Negative Tests");
    tcase_add_checked_fixture(tc_negative, setup, teardown);
    tcase_add_test (tc_negative, test_load_asp_info_w_null_param);
    tcase_add_test (tc_negative, test_load_all_asps_info_w_null_param);
    suite_add_tcase (s, tc_negative);
    return s;
}


int main(void)
{
    int number_failed;
    Suite *s = comms_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_load_asps.log");
    srunner_set_xml(sr, "test_results_load_asps.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
