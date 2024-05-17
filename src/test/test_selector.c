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
#include <am/copland_selector.c>
#include <am/am.h>

#include <common/apb_info.h>
#include <common/asp.h>

#define MS_PATH       SRCDIR "/xml/specs/dummy_attester_spec.xml"
#define ASP_DIR       SRCDIR "/xml/asp-info"
#define SPEC_DIR      SRCDIR "/xml/meas-info"
#define APB_DIR       SRCDIR "/xml/apb-info/"

#undef SELECTOR_PATH
#define SELECTOR_PATH SRCDIR "/../test/xml/am-selector/"

#define DUMMY_MEAS_SPEC_UUID "15c7ba17-ef11-4676-8f8e-5cdeb23d13a2"

START_TEST (test_load_collection)
{
    int i;
    xmlDoc *doc = get_doc_from_file(SELECTOR_PATH "docorig.xml");
    xmlNode *root = xmlDocGetRootElement(doc);
    xmlNode *node;
    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "collection") == 0) {
            break;
        }
    }
    struct collection *out;

    i = load_collection(0, node, &out);
    fail_unless(i == 0, "Unable to load collection");

    fail_unless(! strcasecmp((char*)out->name, "known-clients"),
                "Names do not match");

    //TODO: need to go through and verify entries variables
    //fail_unless(g_list_find((*out)->entries, (gconstpointer)"<entry>127.0.0.1<entry>") != NULL, "Missing entry from list");

    free_collection(out);
    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

    doc = get_doc_from_file(SELECTOR_PATH "docnoname.xml");
    root = xmlDocGetRootElement(doc);
    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "collection") == 0) {
            break;
        }
    }
    i = load_collection(0, node, &out);
    fail_unless(i == -1, "No name error should have occurred");
    free_collection(out);
    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

    doc = get_doc_from_file(SELECTOR_PATH "docnochild.xml");
    root = xmlDocGetRootElement(doc);
    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "collection") == 0) {
            break;
        }
    }

    i = load_collection(0, node, &out);
    fail_unless(i == -1, "No child error should have occurred");
    free_collection(out);
    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

    doc = get_doc_from_file(SELECTOR_PATH "docnoentry.xml");
    root = xmlDocGetRootElement(doc);
    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "collection") == 0) {
            break;
        }
    }
    i = load_collection(0, node, &out);
    fail_unless(i == -1, "No entry error should have occurred");
    free_collection(out);

    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);
}
END_TEST

START_TEST (test_load_match_condition)
{
    int i;
    xmlDoc *doc = get_doc_from_file(SELECTOR_PATH "docorig.xml");
    xmlNode *root = xmlDocGetRootElement(doc);
    xmlNode *node;
    GList *asps, *specs, *apbs;

    asps = load_all_asps_info(ASP_DIR);
    fail_if(asps == NULL, "Could not load ASPs\n");

    specs = load_all_measurement_specifications_info(SPEC_DIR);
    fail_if(specs == NULL, "Could not load measurement specs\n");

    apbs = load_all_apbs_info(APB_DIR, asps, specs);
    fail_if(apbs == NULL, "Could not load APBs\n");

    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "rule") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "match_condition") == 0) {
            break;
        }
    }
    struct match_condition **out = malloc(sizeof(struct collection *));
    i = load_match_condition(0, node, apbs, out);
    fail_unless(i == 0, "Unable to load match condition");

    //examine match condition properties
    fail_unless(! strcasecmp((*out)->attr, "client"), \
                "Attributes do not match");
    fail_unless((*out)->operator == get_operator("in"), "Operators do not match");
    fail_unless(! strcasecmp((*out)->value, "known-clients"), \
                "Values do not match");

    free_match_condition(*out);
    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

    doc = get_doc_from_file(SELECTOR_PATH "docnoname.xml");
    root = xmlDocGetRootElement(doc);

    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "rule") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "match_condition") == 0) {
            break;
        }
    }

    i = load_match_condition(0, node, apbs, out);
    fail_unless(i == -1, "Match should have no attr");

    free_match_condition(*out);
    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

    doc = get_doc_from_file(SELECTOR_PATH "docnoname.xml");
    root = xmlDocGetRootElement(doc);

    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "rule") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "match_condition") == 0) {
            break;
        }
    }

    i = load_match_condition(0, node, apbs, out);
    fail_unless(i == -1, "Match should have no operator");
    free(*out);
    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

    doc = get_doc_from_file(SELECTOR_PATH "docnoname.xml");
    root = xmlDocGetRootElement(doc);

    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "rule") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "match_condition") == 0) {
            break;
        }
    }

    i = load_match_condition(0, node, apbs, out);
    fail_unless(i == -1, "Match should have no value");

    free_match_condition(*out);
    free(out);

    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(specs, (GDestroyNotify)free_measurement_specification_info);

    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);
}
END_TEST

START_TEST (test_load_condition)
{
    int i;
    xmlDoc *doc = get_doc_from_file(SELECTOR_PATH "docorig.xml");
    xmlNode *root = xmlDocGetRootElement(doc);
    xmlNode *node;
    GList *asps, *specs, *apbs;

    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "rule") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "action") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "condition") == 0) {
            break;
        }
    }

    copland_phrase *phrase;
    asps = load_all_asps_info(ASP_DIR);
    fail_if(asps == NULL, "Could not load ASPs\n");

    specs = load_all_measurement_specifications_info(SPEC_DIR);
    fail_if(specs == NULL, "Could not load measurement specs\n");

    apbs = load_all_apbs_info(APB_DIR, asps, specs);
    fail_if(apbs == NULL, "Could not load APBs\n");

    i = load_condition(0, node, apbs, &phrase);
    fail_unless(i == 0, "Unable to load condition");

    //examine match condition properties
    uuid_t tmp;

    uuid_parse("7d70e1c4-b4e2-4935-be6d-c8692a941793", tmp);
    fail_unless(0 == strcmp(phrase->phrase, "dummy"), "Phrases don't match");

    free(phrase);
    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

    doc = get_doc_from_file(SELECTOR_PATH "docnoname.xml");
    root = xmlDocGetRootElement(doc);
    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "rule") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "action") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "condition") == 0) {
            break;
        }
    }

    struct collection *col = NULL;
    i = load_collection(0, node, &col);
    fail_unless(i == -1, "No collections should be found");
    free(col);


    node=node->next;
    col = NULL;
    i = load_collection(0, node, &col);
    fail_unless(i == -1, "No collections property should be found");
    free(col);

    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

    doc = get_doc_from_file(SELECTOR_PATH "docnochild.xml");
    root = xmlDocGetRootElement(doc);
    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "rule") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "action") == 0) {
            break;
        }
    }
    for (node = node->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "condition") == 0) {
            break;
        }
    }

    col = NULL;
    i = load_collection(0, node, &col);
    fail_unless(i == -1, "collection should be bad");
    free(col);
    node=node->next;

    col = NULL;
    i = load_collection(0, node, &col);
    fail_unless(i == -1, "collection should be bad");
    free(col);

    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(specs, (GDestroyNotify)free_measurement_specification_info);

    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);
}
END_TEST

START_TEST (test_load_rule)
{
    GList *asps, *apbs, *specs;

    asps = load_all_asps_info(ASP_DIR);
    fail_if(asps == NULL, "Could not load ASPs\n");

    specs = load_all_measurement_specifications_info(SPEC_DIR);
    fail_if(specs == NULL, "Could not load measurement specs\n");

    apbs = load_all_apbs_info(APB_DIR, asps, specs);
    fail_if(apbs == NULL, "Could not load APBs\n");

    xmlDoc *doc = get_doc_from_file(SELECTOR_PATH "docorig.xml");
    xmlNode *root = xmlDocGetRootElement(doc);
    xmlNode *node;
    for (node = root->children; node; node = node->next) {
        if (strcasecmp((char*)node->name, "rule") == 0) {
            break;
        }
    }

    int i;
    struct rule *out;
    i = load_rule(0, node, apbs, &out);
    fail_unless(i == 0, "Unable to load rule");

    //examine rule
    fail_unless(out->role == get_role("appraiser"), "Role does not match");
    fail_unless(out->phase == INITL, "Phase does not match");

    free_rule(out);
    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(specs, (GDestroyNotify)free_measurement_specification_info);
    root = NULL;
    node = NULL;
    xmlFreeDoc(doc);

}
END_TEST

START_TEST (test_load_selector)
{
    int i;
    selectordb_t *out;
    GList *asps, *apbs, *specs;

    asps = load_all_asps_info(ASP_DIR);
    fail_if(asps == NULL, "Unable to load ASPs");

    specs = load_all_measurement_specifications_info(SPEC_DIR);
    fail_if(specs == NULL, "Unable to load specs");

    apbs = load_all_apbs_info(APB_DIR, asps, specs);
    fail_if(apbs == NULL, "Unable to load APBs");

    i = load_selector("COPLAND", SELECTOR_PATH "userspace-selector-test.xml", apbs, &out );
    fail_unless(i == 0, "Unable to load selector");

    free_selector(out);
    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(specs, (GDestroyNotify)free_measurement_specification_info);
}
END_TEST

START_TEST (test_fail_load_selector)
{
    int i;
    selectordb_t *out;
    GList *asps, *apbs, *specs;

    asps = load_all_asps_info(ASP_DIR);
    fail_if(asps == NULL, "Unable to load ASPs");

    specs = load_all_measurement_specifications_info(SPEC_DIR);
    fail_if(specs == NULL, "Unable to load specs");

    apbs = load_all_apbs_info(APB_DIR, asps, specs);
    fail_if(apbs == NULL, "Unable to load APBs");

    i = load_selector("COPLAND", SELECTOR_PATH "userspace-selector-test-negative.xml", apbs, &out);
    fail_unless(i != 0, "Able to load selector with at least one invalid copland phrase");

    free_selector(out);
    g_list_free_full(asps, (GDestroyNotify)free_asp);
    g_list_free_full(apbs, (GDestroyNotify)unload_apb);
    g_list_free_full(specs, (GDestroyNotify)free_measurement_specification_info);
}
END_TEST

START_TEST (test_compare)
{
    //TODO: devise a section for Copland
    struct attr_pair *attr = malloc(sizeof(struct attr_pair));
    attr->type = CHAR;
    attr->char_value = "7d70e1c4-b4e2-4935-be6d-c8692a941793";

    int i;
    i = compare("7d70e1c4-b4e2-4935-be6d-c8692a941793", attr);
    fail_unless(i == 0, "CHARs should be equal");

    attr->char_value = NULL;
    i = compare("7d70e1c4-b4e2-4935-be6d-c8692a941793", attr);
    fail_unless(i == -1, "Shouldn't compare to NULL");

    attr->type = 2;
    i = compare("7d70e1c4-b4e2-4935-be6d-c8692a941793", attr);
    fail_unless(i == -1, "Should generate invalid type error");

    free(attr);
}
END_TEST

START_TEST (test_attr_is)
{
    int i;
    GList *attrs = NULL;
    struct attr_pair *attr1 = malloc(sizeof(struct attr_pair));
    struct attr_pair *attr2 = malloc(sizeof(struct attr_pair));
    match_condition *condition = malloc(sizeof(match_condition));
    condition->attr = "blabla";
    condition->operator = IS;
    condition->value = "7d70e1c4-b4e2-4935-be6d-c8692a941793";

    attrs = g_list_prepend(attrs, NULL);
    i = attr_is(condition, attrs);
    fail_unless(i == 0, "Found in NULL?");

    attr1->type = CHAR;
    attr1->char_value = "7d70e1c4-b4e2-4935-be6d-c8692a941793";
    attrs = g_list_prepend(attrs, attr1);
    i = attr_is(condition, attrs);
    fail_unless(i == 1, "Failed to find matching entry");

    attr2->type = CHAR;
    attr2->char_value = NULL;
    attrs = g_list_prepend(attrs, attr2);
    i = attr_is(condition, attrs);
    fail_unless(i == 0, "Did not fail to find matching entry");

    g_list_free_full(attrs, free);
    free(condition);
}
END_TEST

START_TEST (test_attr_in)
{
    int i;
    GList *attrs = NULL;
    GList *collections = NULL;
    GList *entries = NULL;
    match_condition *condition = malloc(sizeof(match_condition));
    condition->attr = "blabla";
    condition->operator = IN;
    condition->value = "blab";

    struct attr_pair *attr1 = malloc(sizeof(struct attr_pair));
    attr1->type = CHAR;
    attr1->char_value = "7d70e1c4-b4e2-4935-be6d-c8692a941793";

    struct collection *coll1 = malloc(sizeof(struct collection));
    coll1->name = strdup("bla");
    coll1->entries = entries;

    i = attr_in(condition, attrs, collections);
    fail_unless(i == 0, "Found in NULL?");

    attrs = g_list_prepend(attrs, attr1);
    i = attr_in(condition, attrs, collections);
    fail_unless(i == 0, "NULL collection works?");

    collections = g_list_prepend(collections, coll1);
    i = attr_in(condition, attrs, collections);
    fail_unless(i == 0, "Collection names shouldn't match");

    condition->value = "bla";
    i = attr_in(condition, attrs, collections);
    fail_unless(i == 0, "Matches to NULL entry?");

    entries = g_list_prepend(entries, strdup("7d70e1c4-b4e2-4935-be6d-c8692a941793"));
    coll1->entries = entries;
    i = attr_in(condition, attrs, collections);
    fail_unless(i == 1, "Should find matching attr in coll");

    g_list_free_full(collections, &free_collection);
    free(condition);
    g_list_free_full(attrs, free);
}
END_TEST

START_TEST (test_attr_include)
{
    int i;
    GList *attrs = NULL;
    struct attr_pair *attr1 = malloc(sizeof(struct attr_pair));
    struct attr_pair *attr2 = malloc(sizeof(struct attr_pair));
    attr1->type = CHAR;
    attr1->char_value = NULL;
    attr2->type = CHAR;
    attr2->char_value="7d70e1c4-b4e2-4935-be6d-c8692a941793";

    match_condition *condition = malloc(sizeof(match_condition));
    condition->attr = "bla";
    condition->operator = INCLUDE;
    condition->value = "7d70e1c4-b4e2-4935-be6d-c8692a941793";

    bzero(attr1, sizeof(*attr1));

    i = attr_include(condition, attrs);
    fail_unless(i == 0, "Found in NULL?");


    attrs = g_list_prepend(attrs, attr1);
    i = attr_include(condition, attrs);
    fail_unless(i == 0, "Matched with NULL attr?");

    attrs = g_list_append(attrs, attr2);
    i = attr_include(condition, attrs);
    fail_unless(i == 1, "Did not find in attrs?");

    free(condition);
    g_list_free_full(attrs, free);
}
END_TEST

START_TEST (test_parse_copland)
{
    int i = 0;
    struct attestation_manager *am = NULL;
    struct copland_phrase *copl, *template, *copy;
    GList *phrases = NULL, *templates = NULL, *out = NULL;

    /* Create Attestation Manager */
    am = new_attestation_manager(ASP_DIR, SPEC_DIR, APB_DIR, "COPLAND", SELECTOR_PATH"userspace-selector-test.xml",0,0);
    fail_if(am == NULL, "Unable to load attestation manager");

    /* Parse a Copland phrase */
    i = am_parse_copland(am, "(USM test):file=/bin/ls", &copl);
    fail_if(i != 0, "This phrase should load");
    fail_if(strcmp((char *)copl->args[0]->data, "/bin/ls") != 0, "Argument was not correctly parsed");

    /* Allocate template -> will lead to failure */
    template = malloc(sizeof(copland_phrase));
    fail_if(template == NULL, "Unable to allocate memory for a Copland template");

    template->phrase = strdup("(USM test)");
    fail_if(template->phrase == NULL, "Unable to allocate memory for a Copland phrase");

    template->role = BASE;
    template->num_args = 1;

    template->args = malloc(sizeof(phrase_arg *) * template->num_args);
    fail_if(template->args == NULL, "Unable to allocate memory for the arguments");

    template->args[0] = malloc(sizeof(phrase_arg));
    fail_if(template->args[0] == NULL, "Unable to allocate memory for an argument");

    template->args[0]->type = INTEGER;
    template->args[0]->name = strdup("quantity");
    fail_if(template->args[0]->name == NULL, "Unable to allocate memory for argument name");

    templates = g_list_append(templates, template);
    phrases = g_list_append(phrases, copl);

    i = copy_bounded_phrases(phrases, templates, &out);
    fail_if(i < 0, "Reached error trying to copy phrases");
    fail_if(out != NULL, "Parsed a phrase that shouldn't match");

    /* Alter previous template to lead to success */
    template->args[0]->type = STRING;
    free(template->args[0]->name);
    template->args[0]->name = strdup("file");
    fail_if(template->args[0]->name == NULL, "Unable to allocate memory for function name");
    template->args[0]->data = strdup(".*");
    fail_if(template->args[0]->data == NULL, "Unable to alocate memory for template");

    i = copy_bounded_phrases(phrases, templates, &out);
    fail_if(i < 0, "Reached error trying to copy phrase");
    fail_if(out == NULL || out->data == NULL, "Did not copy phrase that should match");
    copy = (struct copland_phrase *)out->data;

    /* Check if the copy is in fact a copy */
    fail_if(strcmp(copy->phrase, "(USM test)") != 0, "Copland phrase does not match");
    fail_if(copy->num_args != 1, "Copland phrase does not have the correct number of arguments");
    fail_if(copy->args == NULL, "Didn't allocate an argument structure");
    fail_if(strcmp(copy->args[0]->name, copl->args[0]->name) != 0, "Didn't copy the argument name properly");
    fail_if(strcmp(copy->args[0]->data, copy->args[0]->data) != 0, "Didn't copy the argument value correctly");

    /* Cleanup */
    free_copland_phrase(copy);
    g_list_free(out);
    g_list_free(templates);
    g_list_free(phrases);
    free_copland_phrase(copl);
    free_copland_phrase(template);
    free_attestation_manager(am);
}
END_TEST

/* START_TEST (test_check_match_conditions) */
/* { */
/*     int i; */
/*     GList *match_conditions = NULL; */
/*     GList *attrs = NULL; */
/*     GList *collections = NULL; */
/*     GList *entries = NULL; */
/*     struct collection *coll1 = malloc(sizeof(struct collection)); */
/*     coll1->name = strdup("bla"); */
/*     entries = g_list_prepend(entries, strdup("7d70e1c4-b4e2-4935-be6d-c8692a941793")); */
/*     coll1->entries = entries; */

/*     struct match_condition *mtch1 = malloc(sizeof(struct match_condition)); */
/*     mtch1->attr = strdup("bla"); */
/*     mtch1->operator = IS; */
/*     mtch1->value = strdup("7d70e1c4-b4e2-4935-be6d-c8692a941793"); */

/*     struct attr_pair *attr1 = malloc(sizeof(struct attr_pair)); */
/*     attr1->key = "bla"; */
/*     attr1->type = CHAR; */
/*     attr1->char_value = "7d70e1c4-b4e2-4935-be6d-c8692a941793"; */

/*     match_conditions = g_list_prepend(match_conditions, mtch1); */
/*     attrs = g_list_prepend(attrs, attr1); */

/*     i = check_match_conditions(match_conditions, attrs, collections); */
/*     fail_unless(i == AM_OK, "Should match"); */

/*     mtch1->operator = INCLUDE; */
/*     i = check_match_conditions(match_conditions, attrs, collections); */
/*     fail_unless(i == AM_OK, "Should match"); */

/*     mtch1->operator = IN; */
/*     i = check_match_conditions(match_conditions, attrs, collections); */
/*     fail_unless(i == AM_OK, "Should match"); */

/*     mtch1->operator = 5; */
/*     i = check_match_conditions(match_conditions, attrs, collections); */
/*     fail_unless(i == -2, "Should be no case"); */

/*     g_list_free_full(match_conditions, free); */
/*     g_list_free_full(attrs, free); */
/* } */
/* END_TEST */

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
    TCase *tc_higher = tcase_create ("Higher Level Tests");
    tcase_add_checked_fixture(tc_higher, setup, teardown);

    tcase_add_test (tc_basic, test_load_collection);
    tcase_add_test (tc_basic, test_load_match_condition);
    tcase_add_test (tc_basic, test_load_condition);
    tcase_add_test (tc_basic, test_load_rule);
    tcase_add_test (tc_basic, test_load_selector);
    tcase_add_test (tc_basic, test_fail_load_selector);
    tcase_add_test (tc_basic, test_compare);
    tcase_add_test (tc_higher, test_attr_is);
    tcase_add_test (tc_higher, test_attr_in);
    tcase_add_test (tc_higher, test_attr_include);
    tcase_add_test (tc_higher, test_parse_copland);
//    tcase_add_test (tc_higher, test_check_match_conditions);
    suite_add_tcase (s, tc_basic);
    suite_add_tcase (s, tc_higher);
    return s;
}

int main(void)
{
    int number_failed;
    Suite *s = sel_suite ();
    SRunner *sr = srunner_create (s);
    srunner_set_log(sr, "test_results_selector.log");
    srunner_set_xml(sr, "test_results_selector.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed (sr);
    srunner_free(sr);
    return number_failed;
}
