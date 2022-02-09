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
#include <stdlib.h>
#include <check.h>
#include <stdio.h>

#include <util/csv.h>

#include "test-data.h"

#define MAX_LINE_LEN 36

#define ROW_INDEX_ONE "1,e,f,g,h\n"
#define ROW_IND_3_COL_IND_2 "n"

#define WRITE_ROW "1,2,3\n"

START_TEST (test_get_row)
{
    int err;
    char *buf = NULL;

    err = read_line_csv(CSV_FILE, "1", 0, MAX_LINE_LEN,
                        &buf);

    fail_unless(err == 0, "Read of CSV file failed\n");
    fail_unless(buf != NULL,
                "Buffer is NULL but should be set\n");
    fail_unless(strcmp(buf, ROW_INDEX_ONE) == 0,
                "Got wrong line from CSV\n");
    free(buf);
}
END_TEST

START_TEST (test_get_val)
{
    int err;
    char *buf = NULL;

    err = read_val_csv(CSV_FILE, "4", 0, 2,
                       MAX_LINE_LEN, &buf);

    fail_unless(err == 0, "Read of CSV file failed\n");
    fail_unless(buf != NULL,
                "Buffer is NULL but should be set\n");
    fail_unless(strcmp(buf, ROW_IND_3_COL_IND_2) == 0,
                "Got wrong line from CSV\n");
    free(buf);
}
END_TEST

START_TEST (test_get_val_from_line)
{
    int err;
    char *buf = NULL;
    char *val;

    err = read_line_csv(CSV_FILE, "4", 0,
                        MAX_LINE_LEN, &buf);

    fail_unless(err == 0, "Read of CSV file failed\n");
    fail_unless(buf != NULL,
                "Buffer is NULL but should be set\n");

    err = get_col_from_csv_line(buf, 2, MAX_LINE_LEN,
                                &val);

    free(buf);
    fail_unless(err == 0, "Extract value from CSV line failed\n");
    fail_unless(strcmp(val, ROW_IND_3_COL_IND_2) == 0,
                "Got wrong value from CSV line\n");
    free(val);
}
END_TEST

START_TEST (test_append_line)
{
    int err;
    char *buf = NULL;

    err = append_toks_to_csv(CSV_WRITE_FILE, 3,
			     "1", "2", "3");

    fail_unless(err == 0, "Write of CSV file failed\n");

    err = read_line_csv(CSV_WRITE_FILE, "1", 0,
			MAX_LINE_LEN, &buf);

    fail_unless(err == 0, "Read of CSV file failed\n");
    fail_unless(buf != NULL,
                "Buffer is NULL but should be set\n");
    fail_unless(strcmp(buf, WRITE_ROW) == 0,
                "Got wrong line from CSV\n");
    free(buf);

    err = remove(CSV_WRITE_FILE);
    fail_unless(err == 0, "Unable to delete test file\n");
}
END_TEST

void checked_teardown(void) {}
Suite * graph_suite (void)
{
    Suite *s = suite_create ("CSV Tests");

    /*Core test case */
    TCase *tc_feature = tcase_create ("Feature Tests");

    tcase_add_test (tc_feature, test_get_row);
    tcase_add_test (tc_feature, test_get_val);
    tcase_add_test (tc_feature, test_get_val_from_line);
    tcase_add_test (tc_feature, test_append_line);

    suite_add_tcase (s, tc_feature);

    return s;
}


int main(void)
{
    int number_failed;
    Suite *s = graph_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_csv.log");
    srunner_set_xml(sr, "test_results_csv.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
