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
#include <glib.h>
#include <util/util.h>
#include <measurement_spec/find_types.h>

#include "dummy_types.h"
#include "test-data.h"

#include <check.h>

START_TEST(test_marshall_unmarshall)
{
    measurement_data *d = alloc_measurement_data(&dummy_measurement_type);
    marshalled_data *md = NULL;
    measurement_data *dd = NULL;

    fail_if(d == NULL, "failed to allocate dummy measurement data");
    ((dummy_measurement_data*)d)->x = 0xdeadbeef;

    md = marshall_measurement_data(d);
    fail_if(md == NULL, "failed to marshall measurement data");

    dd = unmarshall_measurement_data(md);
    fail_if(dd == NULL, "failed to unmarshall measurement data");

    fail_if(dd->type != &dummy_measurement_type,
            "Unmarshalled data is not of the correct type");

    fail_if(((dummy_measurement_data*)d)->x != ((dummy_measurement_data*)dd)->x,
            "unmarshalled data doesn't match original data");

    free_measurement_data(d);
    free_measurement_data(&md->meas_data);
    free_measurement_data(dd);
}
END_TEST

START_TEST(test_marshall_get_feature)
{
    measurement_data *d = alloc_measurement_data(&dummy_measurement_type);
    marshalled_data *md = NULL;
    GList *d_value,*d_iter;
    GList *m_value,*m_iter;

    fail_if(d == NULL, "failed to allocate dummy measurement data");
    ((dummy_measurement_data*)d)->x = 0xdeadbeef;

    md = marshall_measurement_data(d);
    fail_if(md == NULL, "failed to marshall measurement data");

    fail_unless(measurement_data_get_feature(d, "x", &d_value) == 0,
                "Failed to get feature \"x\" of original data");

    fail_unless(measurement_data_get_feature(&md->meas_data, "x", &m_value) == 0,
                "Failed to get feature \"x\" of marshalled data");

    fail_if(g_list_length(m_value) != g_list_length(d_value),
            "Feature \"x\" of marshalled data should have %d value(s), got %d.",
            g_list_length(d_value),
            g_list_length(m_value));

    d_iter = g_list_first(d_value);
    m_iter = g_list_first(m_value);
    while(d_iter != NULL && m_iter != NULL) {
        fail_unless(strcmp((char*)d_iter->data, (char*)m_iter->data) == 0,
                    "Value for feature \"x\" of marshalled data should be \"%s\" but got \"%s\"",
                    (char*)d_iter->data, (char*)m_iter->data);

        d_iter = g_list_next(d_iter);
        m_iter = g_list_next(m_iter);
    }

    g_list_free_full(d_value, free);
    g_list_free_full(m_value, free);

    free_measurement_data(d);
    free_measurement_data(&md->meas_data);
}
END_TEST

void checked_setup()
{
    setup();
    register_measurement_type(&dummy_measurement_type);
}

void checked_teardown(void)
{
    teardown();
}

int main(void)
{
    int number_failed;
    Suite *s = suite_create("Marshalled Data Tests");
    TCase *tc_feature = tcase_create("Feature tests");
    tcase_set_timeout(tc_feature, 10);
    tcase_add_checked_fixture(tc_feature, checked_setup, checked_teardown);
    tcase_add_test(tc_feature, test_marshall_unmarshall);
    tcase_add_test(tc_feature, test_marshall_get_feature);
    suite_add_tcase(s, tc_feature);
    SRunner *sr = srunner_create(s);
    srunner_set_log(sr, "test_marshall_data.log");
    srunner_set_xml(sr, "test_marshall_data.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
