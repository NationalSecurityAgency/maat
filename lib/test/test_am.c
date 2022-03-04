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
#include <common/am.h>
#include <common/selector.h>
#include "test-data.h"
#include <sys/stat.h>
#include <sys/fcntl.h>
static apb_meas_spec_pair* get_default_pair();

START_TEST (test_new_am)
{
    struct attestation_manager* am;
    am = new_attestation_manager(ASP_DIR, SPEC_DIR, APB_DIR, "XML", SELECTOR_CFG,
                                 EXECCON_RESPECT_DESIRED, EXECCON_SET_UNIQUE_CATEGORIES);
    fail_unless(am != NULL, "Failed to create a am");
    free_attestation_manager(am);
}
END_TEST

//TODO:: make selector unit tests
START_TEST(test_load_selector)
{
    struct selectordb *selector;
    int selectrc = load_selector(SELECTOR_NAME_XML, SELECTOR_CFG, &selector);
    fail_unless(selectrc == AM_OK, "Error return from load_selector");
    free(selector);
}
END_TEST

START_TEST (test_appraiser_initial_options)
{
    struct attestation_manager* am;
    GList *out = NULL;
    struct scenario scen;

    init_scenario(&scen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, APPRAISER);
    am = new_attestation_manager(ASP_DIR, SPEC_DIR, APB_DIR,
                                 SELECTOR_NAME_XML, SELECTOR_CFG,
                                 EXECCON_RESPECT_DESIRED,
                                 EXECCON_SET_UNIQUE_CATEGORIES);
    fail_unless(am != NULL, "Failed to create an am");

    int ret = am->appraiser_callbacks.get_initial_options(am, &scen, &out);
    fail_unless(ret == AM_OK, "Error return from initial options");

    apb_meas_spec_pair* opt =
        (apb_meas_spec_pair *)(g_list_first(out)->data);
    apb_meas_spec_pair* expected = get_default_pair();
    ck_assert(memcmp(&expected->apb_uuid, &opt->apb_uuid, sizeof(uuid_t)) == 0);
    ck_assert(
        memcmp(&expected->spec_uuid, &opt->spec_uuid, sizeof(uuid_t)) == 0);

    free(expected);
    free_attestation_manager(am);
}
END_TEST

START_TEST (test_attester_select_options)
{
    struct attestation_manager* am;
    GList *init_opts = NULL;
    struct scenario appraiser_scen, attester_scen;

    init_scenario(&attester_scen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, APPRAISER);
    init_scenario(&appraiser_scen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, ATTESTER);

    am = new_attestation_manager(ASP_DIR, SPEC_DIR, APB_DIR,
                                 SELECTOR_NAME_XML, SELECTOR_CFG,
                                 EXECCON_RESPECT_DESIRED,
                                 EXECCON_SET_UNIQUE_CATEGORIES);
    fail_unless(am != NULL, "Failed to create a am");

    int ret = am->appraiser_callbacks.get_initial_options(am, &appraiser_scen,
              &init_opts);
    ck_assert_int_eq(AM_OK, ret);

    GList *selected_options = NULL;
    ret = am->attester_callbacks.select_options(am, &attester_scen,
            init_opts,
            &selected_options);
    ck_assert(selected_options != NULL);
    ck_assert_int_eq(AM_OK, ret);

    apb_meas_spec_pair* opt =
        (apb_meas_spec_pair *)(g_list_first(selected_options)->data);
    apb_meas_spec_pair* expected = get_default_pair();
    ck_assert(memcmp(&expected->apb_uuid, &opt->apb_uuid, sizeof(uuid_t)) == 0);
    ck_assert(
        memcmp(&expected->spec_uuid, &opt->spec_uuid, sizeof(uuid_t)) == 0);

    free(expected);
    free_attestation_manager(am);
}
END_TEST

START_TEST (test_appraiser_select_option)
{
    struct attestation_manager* am;
    struct scenario appraiser_scen, attester_scen;

    init_scenario(&attester_scen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, APPRAISER);
    init_scenario(&appraiser_scen, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0, ATTESTER);

    GList *init_opts = NULL;
    am = new_attestation_manager(ASP_DIR, SPEC_DIR, APB_DIR,
                                 SELECTOR_NAME_XML, SELECTOR_CFG,
                                 EXECCON_RESPECT_DESIRED,
                                 EXECCON_SET_UNIQUE_CATEGORIES);
    fail_unless(am != NULL, "Failed to create a am");

    int ret = am->appraiser_callbacks.get_initial_options(am, &appraiser_scen,
              &init_opts);
    ck_assert_int_eq(AM_OK, ret);

    GList *selected_options = NULL;
    ret = am->attester_callbacks.select_options(am, &attester_scen, init_opts,
            &selected_options);
    ck_assert(selected_options != NULL);
    ck_assert_int_eq(AM_OK, ret);

    apb_meas_spec_pair *ap_selected_option = NULL;
    ret = am->appraiser_callbacks.select_option(am, &appraiser_scen,
            selected_options,
            &ap_selected_option);
    ck_assert(ap_selected_option != NULL);
    ck_assert_int_eq(AM_OK, ret);

    apb_meas_spec_pair* expected = get_default_pair();
    ck_assert(memcmp(&expected->apb_uuid, ap_selected_option->apb_uuid,
                     sizeof(uuid_t)) == 0);
    ck_assert(
        memcmp(&expected->spec_uuid, ap_selected_option->spec_uuid,
               sizeof(uuid_t)) == 0);

    free(expected);
    free_attestation_manager(am);
}
END_TEST

static apb_meas_spec_pair* get_default_pair()
{
    apb_meas_spec_pair *my_pair =
        malloc(sizeof(apb_meas_spec_pair));
    uuid_parse(APB_UUID, my_pair->apb_uuid);
    uuid_parse(ATTESTER_MEAS_SPEC_UUID, my_pair->spec_uuid);
    return my_pair;
}

Suite* am_suite (void)
{
    Suite *s = suite_create ("AM Tests");

    /*Core test case */
    TCase *tc_feature = tcase_create ("Feature Tests");
    tcase_add_test (tc_feature, test_new_am);

    tcase_add_test(tc_feature, test_load_selector);
    tcase_add_test (tc_feature, test_appraiser_initial_options);
    tcase_add_test (tc_feature, test_attester_select_options);
    tcase_add_test (tc_feature, test_appraiser_select_option);

    suite_add_tcase (s, tc_feature);
    return s;
}


int main(void)
{
    int number_failed;
    Suite *s = am_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_am.log");
    srunner_set_xml(sr, "test_results_am.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
