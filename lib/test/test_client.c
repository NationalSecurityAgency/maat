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
#include <string.h>
#include <check.h>
#include <maat-client.h>

START_TEST(test_create_request)
{
    xmlChar *buf;
    int size;
    fail_if(create_integrity_request(TARGET_TYPE_HOST_PORT,
                                     (xmlChar*)"localhost",
                                     (xmlChar*)"1234",
                                     (xmlChar*)"ipsec",
                                     NULL,
                                     NULL,
                                     NULL,
                                     NULL,
                                     &buf, &size) != 0,
            "Failed to create integrity check request");
    free(buf);
    /* XXX: should check that it's parsable... */
}
END_TEST

START_TEST(test_parse_response_pass)
{
    char *response_msg ="<?xml version=\"1.0\"?>\n"
                        "<contract type=\"response\">\n"
                        "\t<target type=\"host-port\">localhost:1234</target>\n"
                        "\t<resource>ipsec</resource>\n"
                        "\t<result>pass</result>\n"
                        "\t<data identifier=\"d1\">value 1</data>\n"
                        "\t<data identifier=\"d2\">value 2</data>\n"
                        "</contract>\n";
    int msg_size = (int)strlen(response_msg);

    target_id_type_t target_typ;
    xmlChar *target_id;
    xmlChar *resource;
    int result;
    size_t data_count;
    xmlChar **data_idents;
    xmlChar **data_vals;
    size_t i;

    fail_if(parse_integrity_response(response_msg, msg_size,
                                     &target_typ, &target_id,
                                     &resource, &result,
                                     &data_count,
                                     &data_idents,
                                     &data_vals) < 0,
            "Failed to parse passing integrity response");

    fail_if(result != 0, "Expected passing result but got failure\n");

    fail_if(target_typ != TARGET_TYPE_HOST_PORT,
            "Expected target type %d but got %d\n", TARGET_TYPE_HOST_PORT, target_typ);

    fail_if(strcmp((char*)target_id, "localhost:1234"),
            "Expected target id \"localhost:1234\" but got \"%s\"\n", target_id);

    fail_if(strcmp((char*)resource, "ipsec"),
            "Expected resource \"ipsec\" but got \"%s\"\n", resource);

    fail_if(result != 0, "Expected passing result, but got %d\n", result);

    fail_if(data_count != 2, "Expected 2 data but got %d\n", data_count);

    fail_if(strcmp((char*)data_idents[0], "d1"),
            "Data identifier 0 should be \"d1\" but got \"%s\"\n", data_idents[0]);
    fail_if(strcmp((char*)data_idents[1], "d2"),
            "Data identifier 1 should be \"d2\" but got \"%s\"\n", data_idents[1]);

    fail_if(strcmp((char*)data_vals[0], "value 1"),
            "Data value 0 should be \"value 1\" but got \"%s\"\n", data_vals[0]);
    fail_if(strcmp((char*)data_vals[1], "value 2"),
            "Data value 1 should be \"value 2\" but got \"%s\"\n", data_vals[1]);


    xmlFree(target_id);
    xmlFree(resource);

    for(i = 0; i<data_count; i++) {
        xmlFree(data_idents[i]);
        xmlFree(data_vals[i]);
    }

    free(data_idents);
    free(data_vals);
}
END_TEST


Suite * client_suite (void)
{
    Suite *s = suite_create ("Maat Client Tests");

    /*Core test case */
    TCase *tc_feature = tcase_create ("Maat Client Feature Tests");
    tcase_add_test (tc_feature, test_create_request);
    tcase_add_test (tc_feature, test_parse_response_pass);
    suite_add_tcase (s, tc_feature);

    return s;
}


int main(void)
{
    int number_failed;
    Suite *s    = client_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_client.log");
    srunner_set_xml(sr, "test_client.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}


