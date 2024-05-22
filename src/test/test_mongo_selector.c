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
#include <util/util.h>
#include <util/xml_util.h>
#include <util/keyvalue.h>

#include <am/selector.h>
#include <am/am.h>

#include <common/apb_info.h>
#include <common/asp.h>

#include <maat-basetypes.h>

#include <maat-envvars.h>

#include <mongoc.h>

/*Please change if the number of tests changes!*/
#define NUM_TESTS 5
#define MS_PATH       SRCDIR "/xml/specs/dummy_attester_spec.xml"
#define ASP_DIR       SRCDIR "/xml/asp-info"
#define SPEC_DIR      SRCDIR "/xml/meas-info"
#define APB_DIR       SRCDIR "/xml/apb-info/"

#undef SELECTOR_PATH
#define SELECTOR_PATH SRCDIR "/../test/mongo"
#define DUMMY_MEAS_SPEC_UUID "15c7ba17-ef11-4676-8f8e-5cdeb23d13a2"

#define DB_NAME "maat"
#define COLL_NAME "selector"
#define TMP_NAME "old_selector"
#define URI "mongodb://localhost:27017/?minPoolSize=8"
#define SELECTOR_LOC "./mongo/selector.json"

GList *g_all_apbs;
int g_selector_terms;

START_TEST (test_load_selector)
{
    GList *asps, *apbs;
    selectordb_t* selector_ref = NULL;

    int result = load_selector("MONGO", NULL, g_all_apbs, &selector_ref);
    if(result == 0)
        free_selector(selector_ref);
    fail_unless(result == 0, "Could not load Mongo selector db");
}
END_TEST

START_TEST (test_get_first_action_with_no_matches)
{
    selectordb_t* selector_ref = NULL;
    int result = load_selector("MONGO", NULL, g_all_apbs, &selector_ref);
    int loc_result = 0;
    if(result == 0) {
        char *phrase = NULL;
        role_t r = APPRAISER;
        enum phase p = INITL;
        enum selector_action a = REJECT;
        GList *list = NULL;
        struct scenario* scen = malloc(sizeof(struct scenario));
        scen->attester_hostname = "127.0.0.1";
        scen->partner_cert = "D6:79:C4:82:6A:DE:F4:D0:97:9B:CC:0C:15:9C:37:68:BF:7E:33:34";
        scen->resource = "default";
        loc_result = selector_get_first_action(selector_ref, r, p, a, scen, list, &phrase);
        fail_unless(loc_result != 0, "Returned record instead of empty set");
    }

    if(result == 0)
        free_selector(selector_ref);
    fail_unless(result == 0, "Could not load Mongo selector db");
}
END_TEST

START_TEST (test_get_first_action_success)
{
    selectordb_t* selector_ref = NULL;
    int result = load_selector("MONGO", NULL, g_all_apbs, &selector_ref);
    int loc_result = 0;
    if(result == 0) {
        char *phrase = NULL;
        role_t r = APPRAISER;
        enum phase p = INITL;
        enum selector_action a = ACCEPT;
        GList *list = NULL;
        struct scenario* scen = malloc(sizeof(struct scenario));
        scen->attester_hostname = "127.0.0.1";
        scen->partner_cert = "D6:79:C4:82:6A:DE:F4:D0:97:9B:CC:0C:15:9C:37:68:BF:7E:33:34";
        scen->resource = "default";
        loc_result = selector_get_first_action(selector_ref, r, p, a, (struct scenario *) scen, list, &phrase);
        fail_unless(loc_result == 0, "Returned empty set instead of record");
        fail_unless(strcmp(phrase, "((USM mtab) -> SIG)") == 0, "phrase did not match the expected");
    }

    if(result == 0)
        free_selector(selector_ref);
    fail_unless(result == 0, "Could not load Mongo selector db");
}
END_TEST

START_TEST (test_get_all_conditions_success)
{
    selectordb_t* selector_ref = NULL;
    int result = load_selector("MONGO", NULL, g_all_apbs, &selector_ref);
    int loc_result = 0;
    if(result == 0) {
        GList *condition_list = NULL;
        role_t r = APPRAISER;
        enum phase p = INITL;
        enum selector_action a = ACCEPT;
        GList *list = NULL;
        struct scenario* scen = malloc(sizeof(struct scenario));
        scen->attester_hostname = "127.0.0.1";
        scen->partner_cert = "D6:79:C4:82:6A:DE:F4:D0:97:9B:CC:0C:15:9C:37:68:BF:7E:33:34";
        scen->resource = "D6:79:C4:82:6A:DE:F4:D0:97:9B:CC:0C:15:9C:37:68:BF:7E:33:34";
        loc_result = selector_get_all_conditions(selector_ref, r, p, a, (struct scenario*) scen, list, &condition_list);
        fail_unless(loc_result == 1, "1 condition should be returned.");
    }

    if(result == 0)
        free_selector(selector_ref);
    fail_unless(result == 0, "Could not load Mongo selector db");
}
END_TEST

static int import_schema(mongoc_collection_t *coll, const char *filename)
{
    int err;
    bson_error_t error;
    bson_t *doc;
    bson_json_reader_t *reader;

    doc = bson_new();
    if(doc == NULL) {
        dlog(0, "ERROR: Cannot allocate BSON object");
        err = -1;
        goto bson_err;
    }

    if(!(reader = bson_json_reader_new_from_file(filename, &error))) {
        dlog(0, "ERROR: Unable to open test file %s : %s", filename, error.message);
        err = -1;
        goto open_err;
    }

    while((err = bson_json_reader_read(reader, doc, &error))) {
        if(err < 0) {
            dlog(0, "ERROR: Unable to parse JSON in file %s : %s", filename, error.message);
            err = -1;
            goto read_err;
        }

        if(!mongoc_collection_insert_one(coll, doc, NULL, NULL, &error)) {
            dlog(0, "ERROR: Unable to insert into database a line from file %s : %s", filename, error.message);
            err = -1;
            goto insert_err;
        }

        bson_reinit(doc);
    }

    err = 0;

insert_err:
read_err:
    bson_json_reader_destroy(reader);
open_err:
    bson_destroy(doc);
bson_err:
    return err;
}

void setup(void)
{
    libmaat_init(0, 4);
}

void teardown(void)
{
    libmaat_exit();
}

Suite* sel_suite (void)
{
    Suite *s = suite_create ("Selector Tests");

    TCase *tc_basic = tcase_create ("Basic Tests");
    tcase_add_checked_fixture(tc_basic, setup, teardown);
    tcase_add_test (tc_basic, test_load_selector);
    tcase_add_test (tc_basic, test_get_first_action_with_no_matches);
    tcase_add_test (tc_basic, test_get_first_action_success);
    tcase_add_test (tc_basic, test_get_all_conditions_success);
    suite_add_tcase (s, tc_basic);
    return s;
}

int main(void)
{
    int number_failed, i;
    mongoc_uri_t *uri;
    mongoc_client_t *client;
    mongoc_database_t *db;
    mongoc_collection_t *old_coll = NULL, *coll;
    bson_error_t err;
    GList *all_asps, *all_specs;

    Suite *s = sel_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_mongo_selector.log");
    srunner_set_xml(sr, "test_results_mongo_selector.xml");

    /* Load global variable (APB list) needed for loading seectors */
    all_asps = load_all_asps_info(ASP_DIR);

    all_specs = load_all_measurement_specifications_info(SPEC_DIR);

    g_all_apbs = load_all_apbs_info(APB_DIR, all_asps, all_specs);

    /* Initialize mongoc for future operations */
    mongoc_init();

    /* Establish a connection to the maat database */
    uri = mongoc_uri_new(URI);
    if(!uri) {
        /* TODO: Check implications of a negative number failed */
        number_failed = NUM_TESTS;
        dlog(0, "ERROR: Unable to create URI object");
        goto uri_err;
    }

    client = mongoc_client_new_from_uri(uri);
    if(!client) {
        number_failed = NUM_TESTS;
        dlog(0, "ERROR: Unable to open new mongo client");
        goto client_err;
    }

    db = mongoc_client_get_database(client, DB_NAME);
    if(!db) {
        number_failed = NUM_TESTS;
        dlog(0, "ERROR: Unable to open database");
        goto db_error;
    }

    /* If there's already a selector that has been placed into the DB, we don't want to clobber it */
    if(mongoc_database_has_collection(db, COLL_NAME, NULL)) {
        old_coll = mongoc_database_get_collection(db, COLL_NAME);
        if(old_coll == NULL) {
            number_failed = NUM_TESTS;
            dlog(0, "ERROR: Unable to open existing selector for backup");
            goto get_old_coll_err;
        }

        if(!mongoc_collection_rename_with_opts(old_coll, DB_NAME, TMP_NAME, true, NULL, &err)) {
            number_failed = NUM_TESTS;
            dlog(0, "ERROR: Unable to backup existing selector: %s", err.message);
            goto rename_err;
        }
    }

    /* Create selector collection in database */
    coll = mongoc_database_get_collection(db, COLL_NAME);
    if(coll == NULL) {
        dlog(0, "ERROR: Unable to open selector");
        number_failed = NUM_TESTS;
        goto coll_err;
    }

    if(import_schema(coll, SELECTOR_LOC)) {
        dlog(0, "ERROR: Unable to import test selector");
        number_failed = NUM_TESTS;
        goto import_error;
    }

    /* Execute tests */
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    dlog(6, "Finished testing!\n");

    /* Clean up mongo table */
    if(old_coll == NULL) {
        mongoc_collection_drop(coll, NULL);
    } else {
        mongoc_collection_rename_with_opts(old_coll, DB_NAME, COLL_NAME, true, NULL, NULL);
    }

    /* Unload APB, ASP, and other information */
import_error:
bson_alloc_err:
    mongoc_collection_destroy(coll);
coll_err:
rename_err:
    if(old_coll) {
        mongoc_collection_destroy(old_coll);
    }
get_old_coll_err:
db_error:
    mongoc_client_destroy(client);
client_err:
    mongoc_uri_destroy(uri);
uri_err:
    g_list_free_full(g_all_apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(all_asps, (GDestroyNotify)free_asp);
    g_list_free_full(all_specs, (GDestroyNotify)free_measurement_specification_info);
    return number_failed;
}
