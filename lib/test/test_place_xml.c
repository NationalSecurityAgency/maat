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
#include <dirent.h>
#include <uuid/uuid.h>
#include <util/xml_util.h>
#include <check.h>
#include <dlfcn.h>
#include <util/util.h>
#include <apb/apb.h>
#include <common/copland.h>
#include <common/scenario.h>

#include "test-data.h"

START_TEST (test_valid_xml_file)
{
    int ret;
    char filename[] = XML_DIR"/places_test.xml";
    char id[] = "1";
    place_info *plinfo;
    xmlDoc *doc = NULL;

    GList *values_check;
    gchar *val_check = NULL;
    gchar *orig_key  = NULL;
    const gchar val_truth[] = "500.200.100.40";
    const gchar key_check[] = "thing";
    GHashTable *ht;
    gboolean gb;

    doc = xmlReadFile(filename,NULL,0);
    ret = get_place_information_xml_doc(doc, id, &plinfo);
    // see if we read and stored information from the xml correctly
    fail_if(ret, "getting place info from valid xml failed");

    // pointer with a shorter name
    ht = plinfo->hash_table;
    gb = g_hash_table_contains(ht, key_check);
    fail_unless(gb, "hash table does not contain key: %s", key_check);

    // check that we have a key we expect from a known xml
    gb = g_hash_table_lookup_extended( ht, key_check, (void**) &orig_key, (void**) &values_check);
    val_check = values_check->data;
    fail_unless( gb, "hash lookup returned false for key '%s'.", key_check);

    // make sure the value for the known key is as expected
    fail_if( strcmp( val_check, val_truth), "expected value did not match");
    free_place_info(plinfo);
}
END_TEST

START_TEST (test_not_xml)
{
    int ret;
    char filename[] = XML_DIR"/places_test_not_xml.xml";
    char id[] = "1";
    place_info *plinfo;
    xmlDocPtr doc = xmlReadFile(filename,NULL,0);
    ret = get_place_information_xml_doc(doc, id, &plinfo);
    fail_unless(ret, "somehow we read from an invalid xml file: %s?", filename);
}
END_TEST

START_TEST (test_duplicate_id)
{
    int ret;
    char filename[] = XML_DIR"/places_test_dup_id.xml";
    char id[] = "2";
    place_info *plinfo;
    xmlDocPtr doc = xmlReadFile(filename,NULL,0);
    ret = get_place_information_xml_doc(doc, id, &plinfo);
    fail_unless(ret, "should have failed, duplicate ids in: %s?", filename);
}
END_TEST

START_TEST (test_duplicate_field)
{
    int ret;
    char filename[] = XML_DIR"/places_test_dup_field_no_type.xml";
    char id[] = "1";
    place_info *plinfo;
    xmlDocPtr doc = xmlReadFile(filename,NULL,0);
    ret = get_place_information_xml_doc(doc, id, &plinfo);
    fail_unless(ret, "should have failed, duplicate field names in: %s?", filename);
}
END_TEST

START_TEST (test_missing_id)
{
    int ret;
    char filename[] = XML_DIR"/places_test_dup_field_no_type.xml";
    char id[] = "bad_place";
    place_info *plinfo;

    xmlDocPtr doc = xmlReadFile(filename,NULL,0);

    ret = get_place_information_xml_doc(doc, id, &plinfo);
    fail_unless(ret, "should have failed, id %s is not in  %s?", id, filename);

}
END_TEST

START_TEST (test_query_with_writer)
{
    int ret;
    GList *perms = NULL;
    // make xml doc
    char filename[] = XML_DIR"/places_test.xml";
    char filename_out[] = XML_DIR"/written_place.xml";
    xmlNode *root_in_element = NULL;
    xmlNode *root_out_element = NULL;
    xmlNode *cur_node = NULL;
    xmlNode *out_node = NULL;
    xmlNode *in_node = NULL;

    xmlDocPtr places_xml_doc_ptr;
    xmlDocPtr place_out_doc_ptr;
    places_xml_doc_ptr = xmlParseFile(filename);

    // make xml writer
    xmlTextWriterPtr writer;
    writer = xmlNewTextWriterFilename(filename_out, 0);
    fail_if(writer == NULL, "writer failed to create");

    ret = xmlTextWriterStartDocument(writer, NULL, XML_ENCODING, NULL);
    fail_if(ret, "could not start document for xml writer");
    ret = xmlTextWriterStartElement(writer, "places");
    fail_if(ret, "could not write first node xml writer");

    /* Enqueue testing permissions */
    perms = g_list_append(perms, "id");
    perms = g_list_append(perms, "type");
    perms = g_list_append(perms, "field");
    perms = g_list_append(perms, "value");
    perms = g_list_append(perms, "thing");
    perms = g_list_append(perms, "another_thing");
    perms = g_list_append(perms, "a_list");
    perms = g_list_append(perms, "b_list");
    perms = g_list_append(perms, "value2");

    // id of the place we want to copy to file
    char *id = "1";

    // call
    ret = query_place_info( places_xml_doc_ptr,
                            perms,
                            id,
                            writer);

    // id of the place we want to copy to file
    char *id3 = "3";

    // call
    ret = query_place_info( places_xml_doc_ptr,
                            perms,
                            id3,
                            writer);

    // id of the place we want to copy to file
    char *id2 = "2";

    // call
    ret = query_place_info( places_xml_doc_ptr,
                            perms,
                            id2,
                            writer);

    xmlTextWriterEndElement(writer);
    fail_unless( xmlTextWriterEndDocument(writer), "Error at xmlTextWriterEndDocument\n");

    xmlFreeTextWriter(writer);

    // read the written file
    place_out_doc_ptr = xmlParseFile(filename_out);
    fail_unless(place_out_doc_ptr, "could not open written xml file");

    // make sure it has the correct fields and values at every spot
    // get root node of out file
    root_out_element = xmlDocGetRootElement(place_out_doc_ptr );
    root_in_element  = xmlDocGetRootElement(places_xml_doc_ptr);

    // does the out file place exist in the places xml file?
    int place_exists = 0;
    out_node = xmlFirstElementChild(root_out_element);
    for( cur_node = xmlFirstElementChild(root_in_element); cur_node; cur_node = xmlNextElementSibling(cur_node)) {
        fprintf(stderr, "out_node->name %p cur_node->name %p\n", out_node->name, cur_node->name);
        fprintf(stderr, "out_node->name %s cur_node->name %s\n", out_node->name, cur_node->name);
        if( !strcmp( out_node->name, cur_node->name) ) {
            place_exists = 1;
            break;
        }
    }
    fail_unless(place_exists,"places dont match with between original and written");
    // check all of the children of both places
    out_node = xmlFirstElementChild(out_node);
    for( in_node = xmlFirstElementChild(cur_node); in_node != NULL; in_node = xmlNextElementSibling(in_node)) {
        /* If out_node is NULL while in_node is not, we are missing fields */
        fail_if(out_node == NULL, "Missing field in the out node");
        fail_if(strcmp(in_node->name,out_node->name), "mismatched fields in written xml");
        out_node = xmlNextElementSibling(out_node);
    }
    // close files and cleanup
    xmlFreeDoc(places_xml_doc_ptr);
    xmlFreeDoc(place_out_doc_ptr);

}
END_TEST

START_TEST (test_missing_file)
{
    int ret;
    char *filename = strdup(XML_DIR"/places_test_does_not_exist.xml");
    char id[] = "bad_place";
    place_info *plinfo;
    xmlDocPtr doc = xmlReadFile(filename,NULL,0);
    ret = get_place_information_xml_doc(doc, id, &plinfo);
    fail_unless(ret, "should have failed, id %s is not in  %s?", id, filename);
}
END_TEST

START_TEST (convenience_functions)
{
    int ret, n;
    char filename[] = XML_DIR"/places_test.xml";
    char id[] = "1";
    place_info *plinfo;
    xmlDoc *doc = NULL;

    gchar *val_check = NULL;
    const gchar val_truth[] = "500.200.100.40";
    const gchar key_check[] = "thing";
    const gchar key_list_check[] = "a_list";
    const gchar val_list_truth[] = "tree";
    const gchar key_int_check[] = "another_thing";
    int         val_int_truth = 66;
    int         val_int_check;
    const gchar key_int_list_check[] = "b_list";
    int         val_int_list_truth = 3;
    int* val_int_array_check;
    int val_int_array_truth[] = {1,2,3,4,5};

    doc = xmlReadFile(filename,NULL,0);
    fail_if(doc == NULL, "failed to read xml file");

    ret = get_place_information_xml_doc(doc, id, &plinfo);
    // see if we read and stored information from the xml correctly
    fail_if(ret, "getting place info from valid xml failed");

    // get place info string
    ret = get_place_info_string(plinfo, key_check, &val_check);
    fail_if(ret, "getting string from %s failed", key_check);
    fail_if(strcmp( val_check, val_truth),
            "did not get expected result for string");
    free(val_check);

    // get place info string nth
    ret = get_place_info_string_nth(plinfo, key_list_check, 2, &val_check);
    fail_if(ret, "getting string from %s failed", key_list_check);
    fail_if(strcmp( val_check, val_list_truth),
            "did not get expected result for string list");
    free(val_check);

    // get place info int
    ret = get_place_info_int(plinfo, key_int_check, &val_int_check);

    fail_if(ret, "getting int from %s failed", key_int_check);
    fail_if( val_int_check != val_int_truth,
             "did not get expected result for int");
    // get place info int nth
    ret = get_place_info_int_nth(plinfo, key_int_list_check, 2, &val_int_check);
    fail_if(ret, "getting int from %s failed", key_int_list_check);
    fail_if( val_int_check != val_int_list_truth,
             "did not get expected result for int list");

    n = get_place_info_list_length(plinfo, key_list_check);
    fail_if(n != 5, "wrong list length for key %s, : %d", key_list_check, n);

    n = get_place_info_list_length(plinfo, key_int_list_check);
    fail_if(n != 5, "wrong list length for key %s, : %d", key_int_list_check, n);

    val_int_array_check = malloc( n * sizeof(int));
    ret = fill_place_info_int_array(plinfo, key_int_list_check, val_int_array_check);
    fail_if(ret, "getting int array from %s failed", key_int_list_check);

    for(int i = 0; i < n; i++) {
        fail_if( val_int_array_check[i] != val_int_array_truth[i],
                 "did not get expected result for int array at position %d",i);
    }
    free(val_int_array_check);
    free_place_info(plinfo);

}
END_TEST

Suite * places_xml_suite (void)
{
    Suite *s = suite_create ("Places XML Tests");

    /*Core test case */
    TCase *tc_feature = tcase_create ("Feature Tests");
    tcase_set_timeout(tc_feature, 10);
    tcase_add_checked_fixture (tc_feature, setup, teardown);
    tcase_add_test (tc_feature, test_valid_xml_file);
    tcase_add_test (tc_feature, test_not_xml);
    tcase_add_test (tc_feature, test_duplicate_field);
    tcase_add_test (tc_feature, test_missing_file);
    tcase_add_test (tc_feature, convenience_functions);
    tcase_add_test (tc_feature, test_query_with_writer);
    tcase_add_test (tc_feature, test_missing_id);
    suite_add_tcase (s, tc_feature);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = places_xml_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_place_xml.log");
    srunner_set_xml(sr, "test_results_place_xml.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
