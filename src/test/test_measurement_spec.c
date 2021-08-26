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

#include <check.h>
#include <glib.h>
#include <libxml/parser.h>
#include <measurement_spec/measurement_spec.h>
#include <measurement_spec/measurement_spec_priv.h>
#include <measurement_spec/find_types.h>

#include <inttypes.h>
#include <stdlib.h>
#include <util/util.h>

typedef struct simple_address {
    address a;
    uint32_t addr;
} simple_address;

address *alloc_simple_address()
{
    return malloc(sizeof(simple_address));
}
void free_simple_address(address *a)
{
    free(a);
}
address *simple_copy_address(const address *a);
gboolean simple_address_equal(const address *a, const address *b)
{
    return (memcmp(a, b, sizeof(simple_address)) == 0);
}

guint simple_address_hash(const address *a)
{
    return 0;
}
char *serialize_simple_address(const address *a)
{
    return strdup("{address}");
}
address *parse_simple_address(const char *str, size_t sz);

address *simple_from_human_readable(const char *str)
{
    return parse_simple_address(str, strlen(str));
}

static target_type dummy_target_type = {
    .magic = 0xdeadbeef,
    .name  = "dummy"
};


static address_space simple_address_space = {
    .magic		= 0xdeadbeef,
    .alloc_address      = alloc_simple_address,
    .free_address       = free_simple_address,
    .copy_address       = simple_copy_address,
    .address_equal      = simple_address_equal,
    .address_hash       = simple_address_hash,
    .serialize_address  = serialize_simple_address,
    .parse_address      = parse_simple_address,
    .human_readable     = serialize_simple_address,
    .from_human_readable= simple_from_human_readable
};

address *parse_simple_address(const char *str, size_t sz)
{
    return alloc_address(&simple_address_space);
}

address *simple_copy_address(const address *a)
{
    address *b = alloc_address(&simple_address_space);
    memcpy(b, a, sizeof(simple_address));
    return b;
}

static measurement_type dummy_measurement_type = {
    .name	= "dummy",
    .magic	= 0xdeadbeef
};

START_TEST(test_parse_meas_variable)
{
    xmlNode *var, *address;
    struct variable_spec *res = NULL;

    var = xmlNewNode(NULL, (xmlChar*)"variable");
    fail_if(var == NULL, "Couldn't create variable node");

    fail_unless(parse_variable_spec(var) == NULL,
                "Successfully parsed totally empty variable!");

    fail_if(xmlNewProp(var, (xmlChar*)"instruction", (xmlChar*)"foobar") == NULL,
            "Failed to add instruction attribute to variable node");

    fail_unless(parse_variable_spec(var) == NULL,
                "Successfully parsed variable node with only an instruction!");

    fail_if((address = xmlNewChild(var, NULL, (xmlChar*)"address", NULL)) == NULL,
            "Failed to add address node");

    fail_unless(parse_variable_spec(var) == NULL,
                "Succesfully parsed variable with empty address node");

    fail_if(xmlNewProp(address, (xmlChar*)"operation", (xmlChar*)"equal") == NULL,
            "Failed to create operation attribute of address node");

    fail_unless(parse_variable_spec(var) == NULL,
                "Successfully parsed variable with contentless address node");

    xmlNodeAddContent(address, (xmlChar*)"/foo/bar/baz");
    fail_if((res = parse_variable_spec(var)) == NULL,
            "Failed to parse valid variable node");

    free_variable_spec(res);
    xmlFreeNode(var);
}
END_TEST

START_TEST(test_parse_simple_instruction)
{
    xmlNode *instr, *tmp;
    instruction_spec *res = NULL;

    instr = xmlNewNode(NULL, (xmlChar *)"instruction");
    fail_if(instr == NULL, "Couldn't create instruction node");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed totally empty instruction spec!");

    fail_if(xmlNewProp(instr, (xmlChar *)"type", (xmlChar *)"simple") == NULL,
            "Failed to create type=\"simple\" attribute for instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed empty simple instruction spec");

    fail_if(xmlNewProp(instr, (xmlChar *)"name", (xmlChar *)"my-simple") == NULL,
            "Failed to create name=\"my-simple\" attribute for instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed empty named simple instruction spec");

    fail_if((tmp = xmlNewChild(instr, NULL, "target_type", NULL)) == NULL,
            "Failed to add target_type child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed simple instruction spec with invalid target_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"magic", (xmlChar *)"0xdeadbeef") == NULL,
            "Failed to create magic=\"0xdeadbeef\" attribute for target_type");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed simple instruction spec with only target_type child");


    fail_if((tmp = xmlNewChild(instr, NULL, "address_type", NULL)) == NULL,
            "Failed to add target_type child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed simple instruction spec with invalid address_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"magic", (xmlChar *)"0xdeadbeef") == NULL,
            "Failed to create magic=\"0xdeadbeef\" attribute for address_type");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed simple instruction spec with only target_type and address_type children");


    fail_if((tmp = xmlNewChild(instr, NULL, "measurement_type", NULL)) == NULL,
            "Failed to add target_type child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed simple instruction spec with invalid measurement_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"magic", (xmlChar *)"0xdeadbeef") == NULL,
            "Failed to create magic=\"0xdeadbeef\" attribute for instruction");

    fail_if((res = parse_instruction_spec(instr)) == NULL,
            "Failed to parse valid simple instruction spec");

    free_instruction_spec(res);
    xmlFreeNode(instr);
}
END_TEST


START_TEST(test_parse_submeasure_instruction)
{
    xmlNode *instr, *tmp;
    instruction_spec *res = NULL;

    instr = xmlNewNode(NULL, (xmlChar *)"instruction");
    fail_if(instr == NULL, "Couldn't create instruction node");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed totally empty instruction spec!");

    fail_if(xmlNewProp(instr, (xmlChar *)"type", (xmlChar *)"submeasure") == NULL,
            "Failed to create type=\"submeasure\" attribute for instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed empty submeasure instruction spec");


    fail_if(xmlNewProp(instr, (xmlChar *)"name", (xmlChar *)"my-submeasure") == NULL,
            "Failed to create name=\"my-submeasure\" attribute for instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed empty named submeasure instruction spec");


    /* add <target_type magic="0xdeadbeef" /> */
    fail_if((tmp = xmlNewChild(instr, NULL, "target_type", NULL)) == NULL,
            "Failed to add target_type child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed submeasure instruction spec with invalid target_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"magic", (xmlChar *)"0xdeadbeef") == NULL,
            "Failed to create magic=\"0xdeadbeef\" attribute for target_type");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed submeasure instruction spec with only target_type child");


    /* add <address_type magic="0xdeadbeef" /> */
    fail_if((tmp = xmlNewChild(instr, NULL, "address_type", NULL)) == NULL,
            "Failed to add target_type child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed submeasure instruction spec with invalid address_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"magic", (xmlChar *)"0xdeadbeef") == NULL,
            "Failed to create magic=\"0xdeadbeef\" attribute for address_type");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed submeasure instruction spec with only target_type and "
                "address_type children");

    /* add <measurement_type magic="0xdeadbeef" /> */
    fail_if((tmp = xmlNewChild(instr, NULL, "measurement_type", NULL)) == NULL,
            "Failed to add target_type child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed submeasure instruction spec with invalid measurement_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"magic", (xmlChar *)"0xdeadbeef") == NULL,
            "Failed to create magic=\"0xdeadbeef\" attribute for <target_type> node.");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed submeasure instruction spec with only "
                "target_type, address_type, and measurement_type children");


    /* add <action feature=\"a1\" instruction=\"foobar\"> node to specify new measurement instruction to apply */
    fail_if((tmp = xmlNewChild(instr, NULL, "action", NULL)) == NULL,
            "Failed to add action child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with invalid action node");

    fail_if(xmlNewProp(tmp, (xmlChar*)"feature", (xmlChar*)"a1") == NULL,
            "Failed to create feature=\"a1\" attribute for <action> node.");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with invalid action node");

    fail_if(xmlNewProp(tmp, (xmlChar *)"instruction", (xmlChar *)"foobar") == NULL,
            "Failed to create instruction=\"foobar\" attribute for action node");


    /* Yay now it works */
    fail_if((res = parse_instruction_spec(instr)) == NULL,
            "Failed to parse valid submeasure instruction");

    free_instruction_spec(res);
    xmlFreeNode(instr);
}
END_TEST

static inline void mkPredicateNode(xmlNode *instr, xmlNode *parent, const char *mtype,
                                   const char *feature, const char *op, const char *val)
{
    xmlNode *tmp;
    fail_if((tmp = xmlNewChild(parent, NULL, "predicate", NULL)) == NULL,
            "Failed to recreate predicate node of filter expression");
    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter insturction spec with an empty predicate node");

    fail_if((xmlNewProp(tmp, (xmlChar*)"measurement_type_magic", (xmlChar*)mtype) == NULL),
            "Failed to create measurement_type_magic=\"%s\" attribute of predicate node", mtype);
    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter insturction spec with an invalid predicate node");

    fail_if((xmlNewProp(tmp, (xmlChar*)"quantifier", (xmlChar*)"all") == NULL),
            "Failed to create quantifier=\"all\" attribute of predicate node");
    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter insturction spec with an invalid predicate node");

    fail_if((xmlNewProp(tmp, (xmlChar*)"feature", (xmlChar*)feature) == NULL),
            "Failed to create feature=\"%s\" attribute of predicate node", feature);
    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter insturction spec with an invalid predicate node");

    fail_if((xmlNewProp(tmp, (xmlChar*)"operator", (xmlChar*)op) == NULL),
            "Failed to create operation=\"%s\" attribute of predicate node", op);
    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter insturction spec with an invalid predicate node");

    fail_if((xmlNewProp(tmp, (xmlChar*)"value", (xmlChar*)val) == NULL),
            "Failed to create value=\"%s\" attribute of predicate node", val);
}

START_TEST(test_parse_filter_instruction)
{
    xmlNode *instr, *tmp, *filter;
    instruction_spec *res = NULL;
    xmlNode *notNode, *andNode, *orNode;

    instr = xmlNewNode(NULL, (xmlChar *)"instruction");
    fail_if(instr == NULL, "Couldn't create instruction node");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed totally empty instruction spec!");

    fail_if(xmlNewProp(instr, (xmlChar *)"type", (xmlChar *)"filter") == NULL,
            "Failed to create type=\"filter\" attribute for instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed empty filter instruction spec");


    fail_if(xmlNewProp(instr, (xmlChar *)"name", (xmlChar *)"my-filter") == NULL,
            "Failed to create name=\"my-filter\" attribute for instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed empty named filter instruction spec");

    fail_if((tmp = xmlNewChild(instr, NULL, "target_type", NULL)) == NULL,
            "Failed to add target_type child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with invalid target_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"magic", (xmlChar *)"0xdeadbeef") == NULL,
            "Failed to create magic=\"0xdeadbeef\" attribute for target_type");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with only target_type child");


    fail_if((tmp = xmlNewChild(instr, NULL, "address_type", NULL)) == NULL,
            "Failed to add address_type child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with invalid address_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"magic", (xmlChar *)"0xdeadbeef") == NULL,
            "Failed to create magic=\"0xdeadbeef\" attribute for address_type");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with only target_type and "
                "address_type children");

    /* action to perform */
    fail_if((tmp = xmlNewChild(instr, NULL, "action", NULL)) == NULL,
            "Failed to add action child to instruction");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with invalid address_type");

    fail_if(xmlNewProp(tmp, (xmlChar *)"name", (xmlChar *)"foobar") == NULL,
            "Failed to create name=\"foobar\" attribute for action node");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with no filter");

    /* Now we create the filter
       <filter>
           <and>
           <not>
               <predicate measurement_type_magic="0xdeadbeef"
    	              feature="a1" operator="equal" value="v1" />
           </not>
           <or>
               <predicate measurement_type_magic="0xdeadbeef"
                              feature="a2" operator="equal" value="v2" />
    	   <predicate measurement_type_magic="0xdeadbeef"
    	              feature="a3" operator="equal" value="v3" />
               </or>
       </and>
       </filter>
    */
    fail_if((filter = xmlNewChild(instr, NULL, "filter", NULL)) == NULL,
            "Failed to create filter node of filter expression");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with an empty <filter> node");

    fail_if((andNode = xmlNewChild(filter, NULL, "and", NULL)) == NULL,
            "Failed to create and node of filter expression");
    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with an empty <and> node");

    /*
     * TODO: extend tests; the 'and' node here is also invalid, should
     * test for one error at a time
     */
    fail_if((notNode = xmlNewChild(andNode, NULL, "not", NULL)) == NULL,
            "Failed to create not node of filter expression");
    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction spec with an empty <not> node");

    mkPredicateNode(instr, notNode, "0xdeadbeef", "a1", "equal", "v1");

    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction with <and> node having only one child");

    fail_if((orNode = xmlNewChild(andNode, NULL, "or", NULL)) == NULL,
            "Failed to create or node of filter expression");
    mkPredicateNode(instr, orNode, "0xdeadbeef", "a2", "equal", "v2");
    fail_unless(parse_instruction_spec(instr) == NULL,
                "Successfully parsed filter instruction with <or> node having only one child");
    mkPredicateNode(instr, orNode, "0xdeadbeef", "a3", "equal", "v3");

    fail_if((res = parse_instruction_spec(instr)) == NULL,
            "Failed to parse valid filter instruction spec");

    free_instruction_spec(res);
    xmlFreeNode(instr);
}
END_TEST

void checked_setup()
{
    register_target_type(&dummy_target_type);
    register_measurement_type(&dummy_measurement_type);
    register_address_space(&simple_address_space);
}

void checked_teardown()
{
}

static GQueue *enumerate_variables(void *ctxt, target_type *ttype,
                                   address_space *aspace, char *op,
                                   char *val)
{
    GQueue *q = g_queue_new();
    address *addr = alloc_address(aspace);

    dlog(5, "Enumerating variables\n");
    fail_if(q == NULL, "Failed to allocate queue");
    fail_if(addr == NULL, "Failed to allocate an address");
    g_queue_push_tail(q, new_measurement_variable(ttype, addr));
    return q;
}

static int measure_variable(void *ctxt, measurement_variable *v,
                            measurement_type *t)
{
    dlog(5, "measuring variable\n");
    (*(int*)ctxt)++;
    return 0;
}

static GList *get_measurement_feature(void *ctxt, measurement_variable *var,
                                      measurement_type *mtype, char *feature)
{
    char *res = NULL;
    dlog(5, "Getting feature %s\n", feature);
    if(mtype->magic == 0xdeadbeef) {
        res = strdup(feature);
        if(res) {
            res[0] = 'v';
        }
    }
    return g_list_append(NULL, res);
}

static int check_predicate(void *ctxt, measurement_variable *var, measurement_type *mtype,
                           predicate_quantifier quant, char *feature,
                           char *operator, char *value)
{
    int res = -1;
    dlog(5, "Checking predicate %s %s %s\n", feature, operator, value);
    if(mtype->magic == 0xdeadbeef) {
        GList *x = get_measurement_feature(ctxt, var, mtype, feature);
        if(x != NULL) {
            res = (strcmp(operator, "equal") == 0) && (strcmp(x->data, value) == 0);
            g_list_free_full(x, free);
        }
    }
    return res;
}

static measurement_spec_callbacks callbacks = {
    .enumerate_variables	= enumerate_variables,
    .measure_variable		= measure_variable,
    .get_measurement_feature	= get_measurement_feature,
    .check_predicate		= check_predicate
};

START_TEST(test_evaluate_simple)
{
    int counter = 0;

    meas_spec *spec = malloc(sizeof(meas_spec));
    fail_if(spec == NULL, "Failed to allocate measurement specification");

    bzero(spec, sizeof(*spec));
    do {
        simple_instruction_spec *instr = malloc(sizeof(simple_instruction_spec));
        fail_if(instr == NULL, "Failed to allocate simple measurement instruction.");
        instr->i.instr_type   = SIMPLE_INSTR;
        instr->i.name	      = strdup("simple");
        fail_if(instr->i.name == NULL, "Failed to allocate simple instruction name");

        instr->i.target_type  = &dummy_target_type;
        instr->i.address_space= &simple_address_space;
        instr->mtype	      = &dummy_measurement_type;

        spec->instruction_list = g_list_append(NULL, instr);
        fail_if(spec->instruction_list == NULL, "Failed to add simple instruction to spec's instruction list");
    } while(0);

    do {
        variable_spec *var = malloc(sizeof(variable_spec));
        address_spec *addr = malloc(sizeof(address_spec));

        fail_if(var == NULL,  "Failed to allocate variable spec");
        fail_if(addr == NULL, "Failed to allocate address spec");

        var->instruction_name = strdup("simple");
        addr->operation       = strdup("ignore");
        addr->value           = strdup("me");
        var->address_list     = g_list_append(NULL, addr);
        fail_if(var->address_list == NULL, "Failed to add address to variable spec");

        spec->variable_list = g_list_append(NULL, var);
        fail_if(spec->variable_list == NULL, "Failed to add variable to variable list");
    } while(0);

    fail_unless(evaluate_measurement_spec(spec, &callbacks, &counter) == 0,
                "Error while evaluating measurement spec");

    fail_unless(counter == 1, "Should measure variable should have been called once, but was called %d times",
                counter);

    free_meas_spec(spec);
}
END_TEST

START_TEST(test_evaluate_submeasure)
{
    int counter = 0;
    meas_spec *spec = malloc(sizeof(meas_spec));
    dlog(0, "TESTING SUBMEASURE NODE\n");
    fail_if(spec == NULL, "Failed to allocate measurement specification");

    bzero(spec, sizeof(*spec));
    do {
        simple_instruction_spec *instr = malloc(sizeof(simple_instruction_spec));
        fail_if(instr == NULL, "Failed to allocate simple measurement instruction.");
        instr->i.instr_type   = SIMPLE_INSTR;
        instr->i.name	      = strdup("simple");
        fail_if(instr->i.name == NULL, "Failed to allocate simple instruction name");

        instr->i.target_type  = &dummy_target_type;
        instr->i.address_space= &simple_address_space;
        instr->mtype	      = &dummy_measurement_type;

        spec->instruction_list = g_list_append(NULL, instr);
        fail_if(spec->instruction_list == NULL, "Failed to add simple instruction to spec's instruction list");
    } while(0);

    do {
        submeasure_instruction_spec *instr = malloc(sizeof(submeasure_instruction_spec));
        feature_instruction_pair *p = malloc(sizeof(feature_instruction_pair));
        fail_if(instr == NULL, "Failed to allocate submeasure measurement instruction.");
        fail_if(p == NULL, "Failed to allocate feature_instruction_pair.");

        instr->i.instr_type   = SUBMEASURE_INSTR;
        instr->i.name	      = strdup("submeasure");
        fail_if(instr->i.name == NULL, "Failed to allocate submeasure instruction name");

        instr->i.target_type  = &dummy_target_type;
        instr->i.address_space= &simple_address_space;
        instr->mtype	      = &dummy_measurement_type;

        instr->actions        = NULL;
        p->feature            = strdup("a1");
        fail_if(p->feature == NULL, "Failed to allocate submeasure instruction feature");
        p->instruction        = strdup("simple");
        fail_if(p->instruction == NULL, "Failed to allocate submeasure instruction action");
        fail_if((instr->actions = g_list_append(instr->actions, p)) == NULL,
                "Failed to append action to submeasure instruction actions list");

        spec->instruction_list = g_list_append(spec->instruction_list, instr);
        fail_if(spec->instruction_list == NULL,
                "Failed to add simple instruction to spec's instruction list");
    } while(0);

    do {
        variable_spec *var = malloc(sizeof(variable_spec));
        address_spec *addr = malloc(sizeof(address_spec));

        fail_if(var == NULL,  "Failed to allocate variable spec");
        fail_if(addr == NULL, "Failed to allocate address spec");

        var->instruction_name = strdup("submeasure");
        addr->operation       = strdup("ignore");
        addr->value           = strdup("me");
        var->address_list     = g_list_append(NULL, addr);
        fail_if(var->address_list == NULL, "Failed to add address to variable spec");

        spec->variable_list = g_list_append(NULL, var);
        fail_if(spec->variable_list == NULL, "Failed to add variable to variable list");
    } while(0);

    fail_unless(evaluate_measurement_spec(spec, &callbacks, &counter) == 0,
                "Error while evaluating submeasure instruction");

    fail_unless(counter == 2, "Should measure variable should have been called once, but was called %d times",
                counter);

    free_meas_spec(spec);
}
END_TEST

START_TEST(test_evaluate_filter)
{
    int counter = 0;
    meas_spec *spec = malloc(sizeof(meas_spec));
    dlog(0, "TESTING FILTER NODE\n");
    fail_if(spec == NULL, "Failed to allocate measurement specification");

    bzero(spec, sizeof(*spec));
    do {
        simple_instruction_spec *instr = malloc(sizeof(simple_instruction_spec));
        fail_if(instr == NULL, "Failed to allocate simple measurement instruction.");
        instr->i.instr_type   = SIMPLE_INSTR;
        instr->i.name	      = strdup("simple");
        fail_if(instr->i.name == NULL, "Failed to allocate simple instruction name");

        instr->i.target_type  = &dummy_target_type;
        instr->i.address_space= &simple_address_space;
        instr->mtype	      = &dummy_measurement_type;

        spec->instruction_list = g_list_append(NULL, instr);
        fail_if(spec->instruction_list == NULL, "Failed to add simple instruction to spec's instruction list");
    } while(0);

    do {
        filter_instruction_spec *instr = malloc(sizeof(filter_instruction_spec));
        fail_if(instr == NULL, "Failed to allocate filter measurement instruction.");
        instr->i.instr_type   = FILTER_INSTR;
        instr->i.name	      = strdup("filter");
        fail_if(instr->i.name == NULL, "Failed to allocate filter instruction name");

        instr->i.target_type  = &dummy_target_type;
        instr->i.address_space= &simple_address_space;
        instr->action         = strdup("simple");
        fail_if(instr->action == NULL, "Failed to allocate filter instruction action");
        instr->filter	       = malloc(sizeof(instruction_filter));
        fail_if(instr->filter == NULL, "Failed to allocate filter instruction filter");
        instr->filter->type     = BASE_FILTER;
        instr->filter->u.b.mtype    = &dummy_measurement_type;
        instr->filter->u.b.feature = strdup("a1");

        instr->filter->u.b.operator = strdup("equal");
        instr->filter->u.b.value    = strdup("v1");
        fail_if(instr->filter->u.b.feature == NULL, "Failed to allocate filter feature");
        fail_if(instr->filter->u.b.operator == NULL, "Failed to allocate filter operator");
        fail_if(instr->filter->u.b.value == NULL, "Failed to allocate filter value");

        spec->instruction_list = g_list_append(spec->instruction_list, instr);
        fail_if(spec->instruction_list == NULL, "Failed to add simple instruction to spec's instruction list");
    } while(0);

    do {
        variable_spec *var = malloc(sizeof(variable_spec));
        address_spec *addr = malloc(sizeof(address_spec));

        fail_if(var == NULL,  "Failed to allocate variable spec");
        fail_if(addr == NULL, "Failed to allocate address spec");

        var->instruction_name = strdup("filter");
        addr->operation       = strdup("ignore");
        addr->value           = strdup("me");
        var->address_list     = g_list_append(NULL, addr);
        fail_if(var->address_list == NULL, "Failed to add address to variable spec");

        spec->variable_list = g_list_append(NULL, var);
        fail_if(spec->variable_list == NULL, "Failed to add variable to variable list");
    } while(0);

    fail_unless(evaluate_measurement_spec(spec, &callbacks, &counter) == 0,
                "Error while evaluating submeasure instruction");

    fail_unless(counter == 2, "Should measure variable should have been called once, but was called %d times",
                counter);

    free_meas_spec(spec);
}
END_TEST

int main(int argc, char *argv[])
{
    Suite *s;
    SRunner *sr;
    TCase *tcase;
    int number_failed;

    s = suite_create("Measurement Specification");
    tcase = tcase_create("Parsing");
    tcase_add_checked_fixture(tcase, checked_setup, checked_teardown);
    tcase_add_test(tcase, test_parse_meas_variable);
    tcase_add_test(tcase, test_parse_simple_instruction);
    tcase_add_test(tcase, test_parse_submeasure_instruction);
    tcase_add_test(tcase, test_parse_filter_instruction);
    suite_add_tcase(s, tcase);

    tcase = tcase_create("Evaluation");
    tcase_add_test(tcase, test_evaluate_simple);
    tcase_add_test(tcase, test_evaluate_submeasure);
    tcase_add_test(tcase, test_evaluate_filter);
    suite_add_tcase(s, tcase);

    sr = srunner_create(s);
    srunner_set_log(sr, "test_measurement_spec.log");
    srunner_set_xml(sr, "test_measurement_spec.xml");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return number_failed;
}
