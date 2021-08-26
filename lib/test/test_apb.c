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
#include <check.h>
#include <errno.h>
#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include <glib.h>
#include <uuid/uuid.h>
#include <util/util.h>
#include <util/keyvalue.h>

#include <apb/apb.h>
#include <common/copland.h>
#include <common/apb_info.h>
#include <common/asp.h>
#include <common/measurement_spec.h>

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

#include "test-data.h"

START_TEST (test_load_apb_info)
{
    dlog(3, "Running %s\n", __func__);

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
    fail_unless(strcmp(APB_UUID, uutmp) == 0,"APB uuid incorrect: %s", uutmp);

    int x = has_asp(tapb, ASP_NAME);
    fail_unless(x == 1, "APB does not contain the ASP %s", ASP_NAME);

    unload_apb(tapb);
    g_list_free_full(meas_specs, (GDestroyNotify)free_measurement_specification_info);
    g_list_free_full(asps, (GDestroyNotify)free_asp);

    dlog(3, "Completed %s\n", __func__);
}
END_TEST

START_TEST (test_load_all_apbs_info)
{
    dlog(3, "Running %s\n", __func__);
    GList *apbs = NULL;
    GList *meas_specs = NULL;
    meas_specs = load_all_measurement_specifications_info(SPEC_DIR);
    GList *asps = NULL;
    asps = load_all_asps_info(ASP_DIR);

    apbs = load_all_apbs_info(APB_DIR, asps, meas_specs);
    fail_unless(apbs != NULL, "Failed to load apb list");

    struct apb* tapb;
    const char *apbup = APB_UUID;
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
        if(strcasecmp(tmp_uuid, APB_UUID) == 0) {
            for(mss = tmp->phrase_specs; mss && mss->data != NULL; mss = g_list_next(mss)) {
                struct phrase_meas_spec_pair *ms = mss->data;
                uuid_unparse(ms->spec_uuid, tmp_ms_uuid);
                if(strcasecmp(tmp_ms_uuid, ATTESTER_MEAS_SPEC_UUID) == 0 && strcasecmp(ms->copl->phrase, ATTESTER_PHRASE) == 0) {
                    x = 1;
                }
            }
        }
    }
    fail_unless(x == 1, "No matching APB found");

    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(meas_specs,(GDestroyNotify)free_measurement_specification_info);
    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    dlog(3, "Completed %s\n", __func__);
}
END_TEST

START_TEST (test_apb_search)
{
    dlog(3, "Running %s\n", __func__);
    int x = 0;
    struct apb *tmp = NULL;
    GList *asps = NULL;
    asps = load_all_asps_info(ASP_DIR);

    GList *tapbs = NULL;
    tapbs = find_apbs_with_asp(APB_DIR, asps, ASP_NAME);
    fail_unless(tapbs != NULL, "Failed to find any asps");
    for( ; tapbs && tapbs->data; tapbs = tapbs->next) {
        tmp = (struct apb*)tapbs->data;
        if(has_asp(tmp,ASP_NAME)) {
            x = 1;
        }
    }
    fail_unless(x == 1, "Incorrect asp found");

    unload_apb(tmp);
    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(tapbs, (GDestroyNotify)unload_apb);
    dlog(3, "Completed %s\n", __func__);
}
END_TEST

START_TEST(test_run_asp_return_success)
{
    dlog(3, "Running %s\n", __func__);
    /*
     * Test to make sure that the return value
     * of run_asp is zero on ASP success
     */
    GList *asps = NULL;
    struct asp *dummy_asp = NULL;
    int ret;
    asps = load_all_asps_info(ASP_DIR);

    //Find the dummy ASP
    dummy_asp = find_asp(asps, "dummy");
    fail_if(dummy_asp == NULL, "couldn't find dummy asp");

    //This should succeed
    ret = run_asp(dummy_asp, STDIN_FILENO, STDOUT_FILENO, false, 0, NULL, -1);
    fail_unless(ret == 0, "run_asp returned %d instead of zero for success %s\n", ret, dummy_asp->name);

    unload_all_asps(asps);
    dlog(3, "Completed %s\n", __func__);
}
END_TEST

START_TEST(test_run_asp_return_failure)
{
    dlog(3, "Running %s\n", __func__);
    /*
     * Test to make sure that the return value
     * of run_asp is non-zero on ASP error
     */
    GList *asps = NULL;
    struct asp *dummy_asp = NULL;
    int ret;
    char *argv[1];
    argv[0] = "fail";

    asps = load_all_asps_info(ASP_DIR);
    //Find the dummy ASP
    dummy_asp = find_asp(asps, "dummy");
    fail_if(dummy_asp == NULL, "couldn't find dummy asp");

    //Dummy ASP will fail if passed arguments
    ret = run_asp(dummy_asp, -1, -1, false, 1, argv, -1);
    fail_unless(ret != 0, "run_asp should fail\n");

    unload_all_asps(asps);
    dlog(3, "Completed %s\n", __func__);
}
END_TEST

START_TEST(test_parse_copland)
{
    dlog(3, "Running %s\n", __func__);
    int err;
    const char *correct_args = "a1=2";
    const char *no_num_args = "a1=blah";
    const char *two_args = "a1=2,a2=bad";
    const char *phrase = "(USM hashfile)";
    copland_phrase *template, *parsed;

    template = malloc(sizeof(copland_phrase));

    /* Setup template */
    fail_unless(template != NULL, "Cannot allocate memory for test\n");

    /* (USM hashfiles) with one integer argument */
    template->phrase = strdup(phrase);
    template->num_args = 1;
    template->role = BASE;

    template->args = malloc(sizeof(phrase_arg *));
    template->args[0] = malloc(sizeof(phrase_arg));
    template->args[0]->type = INTEGER;
    template->args[0]->data = NULL;
    template->args[0]->name = strdup("a1");

    /* test success cases */
    err = parse_copland_phrase(phrase, correct_args, template, &parsed);
    fail_unless(err == 0, "Unable to correctly parse copland phrase");
    fail_unless((*(int *)parsed->args[0]->data) == 2, "Did not parse integer correctly\n");
    fail_unless(strcmp(phrase, parsed->phrase) == 0, "Did not save off phrase correctly\n");

    free_copland_phrase(parsed);

    /* meant-to-fail case */
    err = parse_copland_phrase(phrase, no_num_args, template, &parsed);
    fail_unless(err != 0, "That phrase should not parse properly");
    err = parse_copland_phrase(phrase, two_args, template, &parsed);
    fail_unless(err != 0, "That phrase should not parse properly");

    free_copland_phrase(template);
    dlog(3, "Completed %s\n", __func__);
}
END_TEST

void teardown(void)
{
    libmaat_exit();
    return;
}

Suite* apb_suite (void)
{
    Suite *s = suite_create ("APB Tests");

    TCase *tc_basic = tcase_create ("Basic Tests");

    tcase_add_test (tc_basic, test_load_apb_info);
    tcase_add_test (tc_basic, test_load_all_apbs_info);
    tcase_add_test (tc_basic, test_apb_search);
    tcase_add_test (tc_basic, test_parse_copland);

    TCase *tc_run_asp = tcase_create("Running ASP Tests");
    tcase_add_checked_fixture(tc_run_asp, setup, teardown);
    tcase_add_test (tc_run_asp, test_run_asp_return_success);
    tcase_add_test (tc_run_asp, test_run_asp_return_failure);

    suite_add_tcase (s, tc_basic);
    suite_add_tcase (s, tc_run_asp);
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
