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

#include <glib.h>
#include <uuid/uuid.h>
#include <util/util.h>
#include <util/keyvalue.h>

#include <common/apb_info.h>
#include <common/copland.h>

#include <common/asp.h>
#include <common/measurement_spec.h>

#include "test-data.h"

#define DUMMY_APB_UUID APB_UUID
#define DUMMY_MEAS_SPEC_UUID ATTESTER_MEAS_SPEC_UUID
#define DUMMY_NAME ASP_NAME

START_TEST (test_load_apb_info)
{
    GList *meas_specs = NULL;
    meas_specs = load_all_measurement_specifications_info(SPEC_DIR);

    fail_unless(meas_specs != NULL, "No measurement specifications loaded");
    GList *asps = NULL;
    asps = load_all_asps_info(ASP_DIR);
    fail_unless(asps != NULL, "No asps loaded");

    struct apb* tapb;

    tapb = load_apb_info(APB_DIR "/dummy_apb.xml", asps, meas_specs);
    fail_unless(tapb != NULL, "Failed to load apb info");

    uuid_str_t uutmp;
    uuid_unparse(tapb->uuid, uutmp);
    fail_unless(strcmp(DUMMY_APB_UUID, uutmp) == 0,"APB uuid incorrect: %s", uutmp);

    int x = has_asp(tapb, DUMMY_NAME);
    fail_unless(x == 1, "APB does not contain the ASP %s", DUMMY_NAME);

    unload_apb(tapb);
    g_list_free_full(meas_specs, (GDestroyNotify)free_measurement_specification_info);
    g_list_free_full(asps, (GDestroyNotify)free_asp);
}
END_TEST

START_TEST (test_load_all_apbs_info)
{
    GList *apbs = NULL;
    GList *meas_specs = NULL;
    meas_specs = load_all_measurement_specifications_info(SPEC_DIR);
    GList *asps = NULL;
    asps = load_all_asps_info(ASP_DIR);

    apbs = load_all_apbs_info(APB_DIR, asps, meas_specs);
    fail_unless(apbs != NULL, "Failed to load apb list");

    struct apb* tapb;
    const char *apbup = DUMMY_APB_UUID;
    uuid_t uutmp;
    uuid_parse(apbup, uutmp);
    tapb = find_apb_uuid(apbs, uutmp);
    fail_unless(tapb != NULL, "Failed to find an APB");

    int x = 0;
    struct apb *tmp;
    uuid_str_t tmp_uuid;
    uuid_str_t tmp_ms_uuid;
    GList *mss;
    for( ; apbs && apbs->data; apbs = apbs->next) {
        tmp = (struct apb*)apbs->data;
        uuid_unparse(tmp->uuid, tmp_uuid);
        if(strcasecmp(tmp_uuid, DUMMY_APB_UUID) == 0) {
            for(mss = tmp->phrase_specs; mss && mss->data != NULL; mss = g_list_next(mss)) {
                struct phrase_meas_spec_pair *ms = mss->data;
                uuid_unparse(ms->spec_uuid, tmp_ms_uuid);
                if(strcasecmp(tmp_ms_uuid, DUMMY_MEAS_SPEC_UUID) == 0 && strcasecmp(ms->copl->phrase, ATTESTER_PHRASE) == 0) {
                    x = 1;
                }
            }
        }
    }
    fail_unless(x == 1, "No matching APB found");

    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(meas_specs, (GDestroyNotify)free_measurement_specification_info);
    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
}
END_TEST

START_TEST (test_apb_search)
{
    int x = 0;
    struct apb *tmp = NULL;
    GList *asps = NULL;
    asps = load_all_asps_info(ASP_DIR);

    GList *tapbs = NULL;
    tapbs = find_apbs_with_asp(APB_DIR, asps, DUMMY_NAME);
    fail_unless(tapbs != NULL, "Failed to find any asps");
    for( ; tapbs && tapbs->data; tapbs = tapbs->next) {
        tmp = (struct apb*)tapbs->data;
        if(has_asp(tmp,DUMMY_NAME)) {
            x = 1;
        }
    }
    fail_unless(x == 1, "Incorrect asp found");

    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(tapbs, (GDestroyNotify)unload_apb);
}
END_TEST

Suite* apb_suite (void)
{
    Suite *s = suite_create ("AM APB Tests");

    TCase *tc_basic = tcase_create ("Basic Tests");

    tcase_add_test (tc_basic, test_load_apb_info);
    tcase_add_test (tc_basic, test_load_all_apbs_info);
    tcase_add_test (tc_basic, test_apb_search);

    suite_add_tcase (s, tc_basic);
    return s;
}


int main(void)
{
    int number_failed;

    Suite *s = apb_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_apb.log");
    srunner_set_xml(sr, "test_results_apb.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
