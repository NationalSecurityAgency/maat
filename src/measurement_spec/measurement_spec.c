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

#include <stdio.h>
#include <string.h>

#include <util/util.h>
#include <util/keyvalue.h>
#include <util/xml_util.h>
#include <glib.h>

#include <measurement_spec.h>
#include <measurement_spec_priv.h>
#include <measurement_spec/find_types.h>

#include <common/measurement_spec.h>
#include <maat-envvars.h>

struct meas_spec *load_meas_spec_info(const char *xmlfile)
{
    xmlDoc *doc;
    xmlNode *root;
    xmlNode *tmp;
    struct meas_spec *meas_spec;

    dlog(3, "Parsing file %s\n", xmlfile);

    meas_spec = (struct meas_spec *)malloc(sizeof(struct meas_spec));
    if (!meas_spec) {
        dlog(0,"Error allocating memory for meas_spec struct");
        goto error_alloc_spec;
    }
    memset(meas_spec, 0, sizeof(struct meas_spec));

    if ((doc = xmlReadFile(xmlfile, NULL, 0)) == NULL) {
        dlog(0,"Error parsing MEAS_SPEC xml file\n");
        goto error_xml_parse;
    }

    if((root = xmlDocGetRootElement(doc)) == NULL) {
        dlog(0, "Error getting root element of MEAS_SPEC xml file\n");
        goto error_bad_root;
    }

    if (strcasecmp((char *)root->name, "measurement_specification") != 0) {
        dlog(0, "XML file %s is not a valid measurement specification XML file\n", xmlfile);
        goto error_bad_root;
    }

    meas_spec->filename = strdup(xmlfile);

    for (tmp = root->children; tmp; tmp = tmp->next) {
        char *tmp_name;
        if (tmp->type != XML_ELEMENT_NODE) {
            continue;
        }
        tmp_name = validate_cstring_ascii(tmp->name, SIZE_MAX);
        if (tmp_name == NULL)
            continue;

        if (strcasecmp(tmp_name, "name") == 0) {
            meas_spec->name = xmlNodeGetContent(tmp);
        } else if (strcasecmp(tmp_name, "desc") == 0) {
            meas_spec->desc = xmlNodeGetContent(tmp);
        } else if (strcasecmp(tmp_name, "uuid") == 0) {
            xmlChar *uuidstr = xmlNodeGetContent(tmp);
            if(uuidstr == NULL) {
                dlog(0, "UUID node has no content.");
                goto error_parse_meas_spec;
            }
            /* cast below is safe since uuid_parse bounds checks the chars */
            uuid_parse((char*)uuidstr, meas_spec->uuid);
            xmlFree(uuidstr);
        }
    }

    if(meas_spec->name && meas_spec->desc && meas_spec->uuid)  {
        char uuidstr[37];
        uuid_unparse(meas_spec->uuid, uuidstr);
        dlog(3,"Loaded Measurement Specification: \n");
        dlog(3,"name: %s\n", meas_spec->name);
        dlog(3,"desc: %s\n", meas_spec->desc);
        dlog(3,"uuid: %s\n", uuidstr);
    }

    if(parse_meas_spec(meas_spec, root) != 0)  {
        dlog(0, "Error parsing measurement specification.\n");
        goto error_parse_meas_spec;
    }

    xmlFreeDoc(doc);


    dlog(3,"Measurement specification parsed successfully.\n");
    return meas_spec;

error_parse_meas_spec:
error_bad_root:
    xmlFreeDoc(doc);
error_xml_parse:
    free_meas_spec(meas_spec);
error_alloc_spec:
    return NULL;

}

/**
 * Parse the <instructions> and <variables> descendants of the
 * <measurement_specification> node referenved by @meas_specs_node
 * into the ->instruction_list and ->variable_list members of the
 * struct meas_spec referenced by @mspec.
 *
 * This function is used internally to measurement_specification
 * parsing and should not be called from external code (except for
 * testing.)
 *
 * Returns 0 on success or < 0 on failure. On failure, the contents of
 * @mspec are not well defiend, but are guaranteed to be suitable for
 * passing into free_meas_spec.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
int parse_meas_spec(struct meas_spec *mspec, xmlNode *meas_specs_node)
{
    xmlNode *meas_spec;
    mspec->instruction_list = NULL;
    mspec->variable_list = NULL;

    for (meas_spec = meas_specs_node->children; meas_spec; meas_spec=meas_spec->next) {
        char *child_name;
        if (meas_spec->type != XML_ELEMENT_NODE) {
            continue;
        }

        child_name = validate_cstring_ascii(meas_spec->name, SIZE_MAX);
        if(child_name == NULL) {
            continue;
        }

        if (strcasecmp(child_name, "instructions") == 0) {
            if(mspec->instruction_list != NULL) {
                dlog(0, "Error: measurement spec specifies multiple instructions blocks\n");
                goto error;
            }

            dlog(3, "Parsing measurement instructions...\n");
            mspec->instruction_list = parse_meas_instructions(meas_spec);
        } else if (strcasecmp(child_name, "variables") == 0) {
            if(mspec->variable_list != NULL) {
                dlog(0, "Error: measurement spec specifies multiple variables blocks\n");
                goto error;
            }
            dlog(3, "Parsing measurement variables...\n");
            mspec->variable_list = parse_meas_variables(mspec, meas_spec);
        }
    }

    if (mspec->instruction_list == NULL) {
        dlog(0, "Invalid measurement specification:  no instructions found.\n");
        return -1;
    }

    if (mspec->variable_list == NULL) {
        dlog(0, "Invalid measurement specification:  no variables  found.\n");
        return -1;
    }

    return 0;

error:
    /* the caller is responsible for freeing the half formed
       measurement spec */
    return -1;
}



/**
 * Function to parse measurement_specification variabless.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
GList*  parse_meas_variables(struct meas_spec *mspec, xmlNode *meas_specs_node)
{
    xmlNode *child;
    GList *variable_list;

    variable_list = NULL;

    for (child = meas_specs_node->children; child; child=child->next) {
        char *child_name;
        if (child->type != XML_ELEMENT_NODE)
            continue;
        child_name = validate_cstring_ascii(child->name, SIZE_MAX);
        if(child_name == NULL)
            continue;

        if (strcasecmp(child_name, "variable") == 0) {
            struct variable_spec *newv = parse_variable_spec(child);
            GList *tmp;
            if(newv == NULL )  {
                dlog(0, "Error parsing measurement variable.\n");
                goto error;
            }
            tmp = g_list_append(variable_list, newv);
            if(tmp == NULL) {
                dlog(0, "Error adding new variable to list.\n");
                free_variable_spec(newv);
                goto error;
            }
            variable_list = tmp;
        }
    }

    print_variables(variable_list);
    return variable_list;

error:
    g_list_free_full(variable_list, (GDestroyNotify)free_variable_spec);
    return NULL;
}

/**
 * Function to parse a single variable.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
struct variable_spec *parse_variable_spec(xmlNode *meas_specs_node)
{
    xmlNode *meas_spec				= NULL;
    xmlChar *operation				= NULL;
    xmlChar *address				= NULL;
    struct variable_spec *new_variable		= NULL;
    struct address_spec *new_address_spec	= NULL;

    //Initialize new_variable
    new_variable = init_variable_spec();
    if(!new_variable)  {
        dlog(0, "Error initializing new variable.\n");
        goto error;
    }

    new_variable->instruction_name = xmlGetProp(meas_specs_node, (xmlChar*)"instruction");
    if(new_variable->instruction_name == NULL) {
        dlog(0, "Error creating measurement variable: no instruction name specified\n");
        goto error;
    }

    for (meas_spec = meas_specs_node->children; meas_spec; meas_spec=meas_spec->next) {
        if (meas_spec->type != XML_ELEMENT_NODE)
            continue;

        if (strcasecmp((char *) meas_spec->name, "address") == 0) {
            GList *tmpaddrlist;

            new_address_spec = init_address_spec();
            if(new_address_spec == NULL)  {
                dlog(0,"Error initializing address.\n");
                goto error;
            }

            operation	= xmlGetProp(meas_spec, (const xmlChar *)"operation");
            address	= xmlNodeListGetString(NULL, meas_spec->children, 1);

            if(operation == NULL) {
                dlog(0, "Error adding variable: no operation specified\n");
                goto error;
            }

            if(address == NULL) {
                dlog(0, "Error adding variable: address node has no content\n");
                goto error;
            }

            new_address_spec->operation = validate_cstring_ascii(operation, SIZE_MAX);
            if(new_address_spec->operation == NULL) {
                dlog(0, "Error: address spec operation is invalid\n");
                goto error;
            }
            operation = NULL;

            new_address_spec->value = validate_cstring_ascii(address, SIZE_MAX);
            if(new_address_spec->value == NULL) {
                dlog(0, "Error: address spec value is invalid.\n");
                goto error;
            }
            address   = NULL;

            tmpaddrlist = g_list_append(new_variable->address_list,
                                        (gpointer) new_address_spec);
            if(tmpaddrlist == NULL)  {
                dlog(0, "Error adding address to the list.\n");
                goto error;
            }
            new_variable->address_list = tmpaddrlist;
            new_address_spec = NULL;
        }
    }

    if(new_variable->address_list == NULL) {
        dlog(0, "Error: variable node has no address specifier\n");
        goto error;
    }

    return new_variable;

error:
    xmlFree(operation);
    xmlFree(address);
    free_address_spec(new_address_spec);
    free_variable_spec(new_variable);
    return NULL;
}

/**
 * Allocate a new variable_spec node and zeroize its fields. Returns
 * the new variable_spec on success or NULL on failiure.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
struct variable_spec* init_variable_spec()
{
    struct variable_spec *new;

    new = (struct variable_spec *)calloc(1, sizeof(struct variable_spec));
    if(!new)  {
        dlog(0, "Error: Not enough memory for new variable.\n");
        return NULL;
    }

    return new;
}

/**
 * Deep free of an address_spec. Recursively frees all fields. It
 * is safe to pass a NULL pointer to this function.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
void free_address_spec(struct address_spec *aspec)
{
    if(aspec) {
        free(aspec->operation);
        free(aspec->value);
        free(aspec);
    }
}

/**
 * Deep free of a variable_spec. Recursively frees all fields. It
 * is safe to pass a NULL pointer to this function.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
void free_variable_spec(struct variable_spec *aspec)
{
    if(aspec) {
        free(aspec->instruction_name);
        free_address_list(aspec->address_list);
        free(aspec);
    }
}

/**
 * Deep free of a list of instruction_specs. Calls
 * free_instruction_spec on each node and frees the list. It is safe
 * to pass a NULL pointer to this function.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
void free_instruction_list(GList *instruction_list)
{
    if(instruction_list) {
        g_list_free_full(instruction_list, (GDestroyNotify)free_instruction_spec);
    }
}

/**
 * Deep free of a list of variable_specs. Calls
 * free_variable_spec on each node and frees the list. It is safe
 * to pass a NULL pointer to this function.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
void free_variable_list(GList *variable_list)
{
    if(variable_list) {
        g_list_free_full(variable_list, (GDestroyNotify)free_variable_spec);
    }
}

/**
 * Deep free of a list of address_specs. Calls
 * free_address_spec on each node and frees the list. It is safe
 * to pass a NULL pointer to this function.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
void free_address_list(GList *address_list)
{
    if(address_list) {
        g_list_free_full(address_list, (GDestroyNotify)free_address_spec);
    }
}

/**
 * Deep free function for a struct meas_spec. Recursively frees all
 * fields of the mspec. It is safe to pass a NULL pointer to this
 * function.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
void free_meas_spec(struct meas_spec *aspec)
{
    if(aspec) {
        free(aspec->filename);
        free(aspec->name);
        if(aspec->file)
            free_xml_file_info(aspec->file);
        free(aspec->desc);
        if(aspec->instruction_list)
            free_instruction_list(aspec->instruction_list);
        if(aspec->variable_list)
            free_variable_list(aspec->variable_list);
        free(aspec);
    }
}

/**
 * Function to initialize a new address and zeroize it's fields.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
struct address_spec* init_address_spec()
{
    struct address_spec *new;

    new = (struct address_spec *)calloc(1, sizeof(struct address_spec));
    if(!new)  {
        dlog(0, "Error: Not enough memory for new address.\n");
        return NULL;
    }


    return new;
}

/**
 * Function to print parsed variable list via dlog() level 2.
 *
 * This function is used internally to measurement spec parsing and
 * should not be accessed from external code (except for testing).
 */
int print_variables(GList *variable_list)
{
    struct variable_spec *variable;
    struct address_spec *address;
    GList *address_list;
    GList *var_iter;
    GList *addr_iter;

    dlog(2, "Variable list.\n");
    for(var_iter=g_list_first(variable_list); var_iter; var_iter=g_list_next(var_iter))  {

        variable = (struct variable_spec *)var_iter->data;
        address_list = variable->address_list;

        dlog(2, "Variable Instruction: %s\n", variable->instruction_name);

        for(addr_iter=g_list_first(address_list); addr_iter; addr_iter=g_list_next(addr_iter))  {
            address = (struct address_spec *)addr_iter->data;
            dlog(2, "\t Address: %s %s.\n", address->operation, address->value);
        }
    }
    return 0;
}


/**
 * Main function to parse a measurement specification.  This is the function
 * that will be called by APBs. It returns a struct meas_spec with metadata
 * of the measurement specification, a GList of variables, and a GList of
 * instructions.
 *
 * Measurement specifications should follow the following informal format:
 *
 * <measurement_specification>
 *     <name>human readable name</name>
 *     <uuid>XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX</uuid>
 *     <descritpion>
 *         Some informative description
 *     </description>
 *     <instructions>
 *         <instruction name="instr-name">
 *             <target_type      name="name of type"
 *                               magic="0xABCDABCD" />
 *             <address_type     name="address space name"
 *                               magic="0xABCDABCD" />
 *             <measurement_type name="measurement name"
 *                               magic="0xABCDABCD" />
 *         <instruction>
 *         ...
 *     </instructions>
 *     <variables>
 *         <variable instruction="instr-name" scope="all" >
 *             <address operation="equal">/bin/bash</address>
 *             ...
 *         </variable>
 *         ...
 *     </variables>
 * </measurement_specification>
 *
 *
 * Each <instruction> node describes measurement obligations (what
 * kind of measurement evidence to collect) for measurement variables
 * (target type, address pairs) matching a given type signature.
 *
 * Each <variable> node describes a query for generating measurement
 * variables that should be measured using the instruction referenced
 * (by name) in the instruction="..." attribute. The variables are
 * assumed to be of the correct target type, and the addresses are
 * generated by considering the scope attribute of the <variable>
 * block and the operation listed in each child <address> node. Valid
 * scopes are "all", "one", and "r" (for recursive). Valid operations
 * are "equal", "less than", "greater than", "less than or equal",
 * "greater than or equal", and "pattern match".
 *
 * An APB executing a measurement spec is expected to produce
 * measurements of the type governed by the <instruction> nodes for
 * each <variable> identified by a <variable> node.
 *
 * Note:
 *
 *  + The specification name and description provided for human
 *    readability, the UUID is referenced by APBs and during AM <-> AM
 *    negotiation.
 *
 *  + An <instruction> node may include a <submeasure> node that
 *    describes how additional measurement variables should be
 *    recursively included when interpreting this instruction.
 *
 *  + The name and magic fields of target_type, address_type, and
 *    measurement_type nodes should match the names and magic numbers
 *    declared for their respective types (for more detail see
 *    maat/lib/measurement_spec/meas_spec-api.h).
 *
 *  + The exact semantics of variable scopes and address operations is
 *    currently left up to the APB.
 */
struct meas_spec *parse_measurement_spec(char *meas_spec_file)
{
    struct meas_spec *test_spec;
    char *test_meas_spec;

    if(meas_spec_file == NULL) {
        dlog(0, "No measurement specification file provided.\n");
        return 0;
    }

    test_meas_spec = meas_spec_file;
    test_spec = load_meas_spec_info(test_meas_spec);

    return test_spec;
}



/* BEGIN REWRITE */

static int simple_instruction_spec_to_str(instruction_spec *spec, char *buf, size_t buflen)
{
    simple_instruction_spec *sspec = (simple_instruction_spec*)spec;
    return snprintf(buf, buflen,
                    "%s:(%s, 0x%x, %s)",
                    sspec->i.name,
                    sspec->i.target_type->name,
                    sspec->i.address_space->magic,
                    sspec->mtype->name);
}

static inline int get_magic_number(xmlNode *n, magic_t *magic_number)
{
    char *magic_str;
    char *magic_end;

    magic_str  = xmlGetPropASCII(n, "magic");
    if(magic_str == NULL) {
        dlog(1, "Error: target_type node has no magic number\n");
        return -1;
    }

    errno = 0;
    *magic_number = (magic_t)strtoul(magic_str, &magic_end, 0);
    if(errno != 0 || *magic_end != '\0') {
        dlog(1, "Error: magic number '%s' failed to parse.\n", magic_str);
        free(magic_str);
        return -1;
    }
    free(magic_str);
    return 0;
}

static int handle_target_type_node(xmlNode *n, target_type **ttype)
{
    magic_t magic_number;

    if(*ttype != NULL) {
        dlog(0, "Error: multiple target_type nodes found\n");
        return -1;
    }

    if(get_magic_number(n, &magic_number) < 0) {
        return -1;
    }

    if((*ttype = find_target_type(magic_number)) == NULL) {
        dlog(0, "Error: no target type found with magic number 0x%x", magic_number);
        return -1;
    }
    return 0;
}

static int handle_address_type_node( xmlNode *n, address_space **space)
{
    magic_t magic_number;

    if(*space != NULL) {
        dlog(0, "Error: multiple address_type nodes found\n");
        return -1;
    }

    if(get_magic_number(n, &magic_number) < 0) {
        return -1;
    }

    if((*space = find_address_space(magic_number)) == NULL) {
        dlog(0, "Error: no address space found with magic number 0x%x", magic_number);
        return -1;
    }
    return 0;
}

static int handle_measurement_type_node( xmlNode *n, measurement_type **mtype)
{
    magic_t magic_number;

    if(*mtype != NULL) {
        dlog(0, "Error: multiple measurement_type nodes found\n");
        return -1;
    }

    if(get_magic_number(n, &magic_number) < 0) {
        return -1;
    }

    if((*mtype = find_measurement_type(magic_number)) == NULL) {
        dlog(0, "Error: no measurement type found with magic number 0x%x\n", magic_number);
        return -1;
    }
    return 0;
}

static instruction_spec *parse_simple_instruction_spec(xmlNode *n)
{
    simple_instruction_spec *instr = malloc(sizeof(simple_instruction_spec));
    xmlNode *child;
    if(instr == NULL) {
        dlog(0, "Error: Failed to allocate simple instruction spec.\n");
        return NULL;
    }

    bzero(instr, sizeof(*instr));
    instr->i.name = xmlGetProp(n, (xmlChar*)"name");
    if(instr->i.name == NULL) {
        dlog(0, "Error: Measurement instruction has no name!\n");
        goto error;
    }

    for(child = n->children; child != NULL; child = child->next) {
        char *child_name;

        if(child->type != XML_ELEMENT_NODE) {
            continue;
        }

        child_name = validate_cstring_ascii(child->name, SIZE_MAX);
        if(child_name == NULL) {
            continue;
        }

        if(strcasecmp(child_name, "target_type") == 0) {
            if(handle_target_type_node(child, &instr->i.target_type) < 0) {
                break;
            }
        } else if(strcasecmp(child_name, "address_type") == 0) {
            if(handle_address_type_node(child, &instr->i.address_space) < 0) {
                break;
            }
        } else if(strcasecmp(child_name, "measurement_type") == 0) {
            if(handle_measurement_type_node(child, &instr->mtype) < 0) {
                break;
            }
        }
    }

    if(instr->mtype              == NULL ||
            instr->i.target_type      == NULL ||
            instr->i.address_space    == NULL) {
        dlog(0, "Error: simple instruction must specify target type, address type, "
             "and measurement type.\n");
        goto error;
    }

    return &instr->i;

error:
    free_instruction_spec(&instr->i);
    return NULL;
}

static void free_feature_instruction_pair(void *p)
{
    feature_instruction_pair *action = (feature_instruction_pair*)p;
    free(action->feature);
    xmlFree(action->instruction);
    free(p);
}

static void free_submeasure_instruction_spec(instruction_spec *spec)
{
    if(spec != NULL) {
        submeasure_instruction_spec *sspec = (submeasure_instruction_spec*)spec;
        g_list_free_full(sspec->actions, free_feature_instruction_pair);
        free(spec);
    }
}

static int submeasure_instruction_spec_to_str(instruction_spec *spec, char *buf, size_t buflen)
{
    submeasure_instruction_spec *sspec = (submeasure_instruction_spec*)spec;
    int count;
    int total = 0;
    GList *iter;
    if((count = snprintf(buf, buflen, "%s:submeasure(%s, 0x%x, ",
                         sspec->i.name,
                         sspec->i.target_type->name,
                         sspec->i.address_space->magic)) >= buflen) {
        return count;
    }
    total   = count;
    buflen -= count;
    buf    += count;

    for(iter = g_list_first(sspec->actions) ; iter != NULL; iter = g_list_next(iter)) {
        feature_instruction_pair *p = (feature_instruction_pair *)iter->data;
        if((count = snprintf(buf, buflen, "%s, %s%s",
                             p->feature, (char*)p->instruction,
                             (g_list_next(iter) == NULL ? ")" : ", "))) >= buflen) {
            return (total + count);
        }
        total  += count;
        buflen -= count;
        buf    += count;
    }
    return total;
}

static instruction_spec *parse_submeasure_instruction_spec(xmlNode *n)
{
    submeasure_instruction_spec *instr = malloc(sizeof(submeasure_instruction_spec));
    xmlNode *child;
    if(instr == NULL) {
        dlog(0, "Error: Failed to allocate submeasure instruction spec.\n");
        goto error;
    }
    bzero(instr, sizeof(*instr));

    instr->i.instr_type	= SUBMEASURE_INSTR;
    instr->i.name	= xmlGetProp(n, (xmlChar*)"name");
    if(instr->i.name == NULL) {
        dlog(0, "Error: Measurement instruction has no name!\n");
        goto error;
    }

    for(child = n->children; child != NULL; child = child->next) {
        char *child_name;

        if(child->type != XML_ELEMENT_NODE) {
            continue;
        }

        child_name = validate_cstring_ascii(child->name, SIZE_MAX);
        if(child_name == NULL) {
            continue;
        }

        if(strcasecmp(child_name, "target_type") == 0) {
            if(handle_target_type_node(child, &instr->i.target_type) < 0) {
                break;
            }
        } else if(strcasecmp(child_name, "address_type") == 0) {
            if(handle_address_type_node(child, &instr->i.address_space) < 0) {
                break;
            }
        } else if(strcasecmp(child_name, "measurement_type") == 0) {
            if(handle_measurement_type_node(child, &instr->mtype) < 0) {
                break;
            }
        } else if(strcasecmp(child_name, "action") == 0) {
            char *feature = NULL;
            xmlChar *instruction = NULL;
            feature_instruction_pair *p = NULL;
            GList *tmplist;
            if((feature = xmlGetPropASCII(child, "feature")) == NULL) {
                dlog(0, "Error: while parsing submeasure instruction: "
                     "action node has invalid \"feature\" attribute\n");
                break;
            }
            if((instruction = xmlGetProp(child, "instruction")) == NULL) {
                dlog(0, "Error: while parsing submeasure instruction: "
                     "action node has invalid \"instruction\" attribute\n");
                free(feature);
                break;
            }
            if((p = malloc(sizeof(feature_instruction_pair))) == NULL) {
                dlog(0, "Error: while parsing submeasure instruction: "
                     "failed to allocate feature_instruction_pair\n");
                free(feature);
                free(instruction);
                break;
            }
            p->feature = feature;
            p->instruction = instruction;
            if((tmplist = g_list_append(instr->actions, p)) == NULL) {
                dlog(0, "Error: while parsing submeasure instruction: "
                     "failed to add action to action list\n");
                free_feature_instruction_pair(p);
            }
            instr->actions = tmplist;
        }
    }

    if(instr->mtype              == NULL ||
            instr->i.target_type      == NULL ||
            instr->i.address_space    == NULL ||
            instr->actions            == NULL) {
        dlog(0, "Error: submeasure instruction must specify target type, address type, "
             "and measurement type.\n");
        goto error;
    }

    return &instr->i;

error:
    free_instruction_spec(&instr->i);
    return NULL;
}

void free_instruction_filter(instruction_filter *f)
{
    if(f != NULL) {
        if(f->type == BASE_FILTER) {
            free(f->u.b.feature);
            free(f->u.b.operator);
            free(f->u.b.value);
        } else {
            free_instruction_filter(f->u.o.e1);
            free_instruction_filter(f->u.o.e2);
        }
        free(f);
    }
}

static instruction_filter *parse_instruction_filter(xmlNode *n);

static inline int parse_instruction_filter_subexprs(xmlNode *n, instruction_filter *f)
{
    xmlNode *es[2], *tmp;
    int count = 0;
    for(tmp = n->children; tmp != NULL; tmp = tmp->next) {
        if(tmp->type == XML_ELEMENT_NODE) {
            if(count < 2) {
                es[count] = tmp;
            }
            count++;
        }
    }
    if(count >= 1) {
        f->u.o.e1 = parse_instruction_filter(es[0]);
    }
    if(count >= 2) {
        f->u.o.e2 = parse_instruction_filter(es[1]);
    }

    return count;
}

static instruction_filter *parse_instruction_filter(xmlNode *n)
{
    instruction_filter *filter = malloc(sizeof(instruction_filter));
    char *name = validate_cstring_ascii(n->name, SIZE_MAX);

    if(filter == NULL) {
        dlog(0, "Error: failed to allocate instruction filter\n");
        goto error;
    }

    bzero(filter, sizeof(instruction_filter));

    if(name == NULL) {
        dlog(0, "Invalid (non-asci) filter node type\n");
        goto error;
    } else if(strcasecmp(name, "and") == 0) {
        int count	= parse_instruction_filter_subexprs(n, filter);
        filter->type   	= LOGICAL_OP_FILTER;
        filter->u.o.op	= FILTER_AND_OP;
        if(count != 2) {
            dlog(0, "Error parsing <and> filter expression: "
                 "Expected exactly two children but got %d\n", count);
            goto error;
        }
        if(filter->u.o.e1 == NULL || filter->u.o.e2 == NULL) {
            goto error;
        }
    } else if(strcasecmp(name, "or") == 0) {
        int count	= parse_instruction_filter_subexprs(n, filter);
        filter->type   	= LOGICAL_OP_FILTER;
        filter->u.o.op	= FILTER_OR_OP;
        if(count != 2) {
            dlog(0, "Error parsing <or> filter expression: "
                 "Expected exactly two children but got %d\n", count);
            goto error;
        }
        if(filter->u.o.e1 == NULL || filter->u.o.e2 == NULL) {
            goto error;
        }
    } else if(strcasecmp(name, "not") == 0) {
        int count	= parse_instruction_filter_subexprs(n, filter);
        filter->type   	= LOGICAL_OP_FILTER;
        filter->u.o.op	= FILTER_NOT_OP;
        if(count != 1) {
            dlog(0, "Error parsing <not> filter expression: "
                 "Expected exactly one child but got %d\n", count);
            goto error;
        }
        if(filter->u.o.e1 == NULL) {
            goto error;
        }
    } else if(strcasecmp(name, "predicate") == 0) {
        char *mtype_magic_str, *endptr;
        magic_t mtype_magic;
        char *quant = NULL;
        filter->type = BASE_FILTER;
        mtype_magic_str = xmlGetPropASCII(n, "measurement_type_magic");
        if(mtype_magic_str == NULL) {
            dlog(0, "Error: predicate node has no measurement_type_magic attribute\n");
            goto error;
        }
        errno = 0;
        mtype_magic = strtoul(mtype_magic_str, &endptr, 0);
        if(errno != 0 || *endptr != '\0') {
            dlog(0, "Error: invalid magic number '%s' for measurement_type.\n",
                 mtype_magic_str);
            free(mtype_magic_str);
            goto error;
        }
        free(mtype_magic_str);
        filter->u.b.mtype = find_measurement_type(mtype_magic);
        if(filter->u.b.mtype == NULL) {
            dlog(0, "Error: in predicate: no measurement type found with magic number 0x%x\n",
                 mtype_magic);
            goto error;
        }

        quant = xmlGetPropASCII(n, "quantifier");
        if(quant == NULL) {
            dlog(0, "Error: predicate has no/invalid quantifier attribute\n");
            free(quant);
            goto error;
        }
        if(strcasecmp(quant, "all") == 0) {
            filter->u.b.quantifier = ALL_VALUES;
        } else if(strcasecmp(quant, "any") == 0) {
            filter->u.b.quantifier = ANY_VALUE;
        } else {
            dlog(0,
                 "Error: predicate quantifier should be \"all\" or \"any\" (got \"%s\")\n",
                 quant);
            free(quant);
            goto error;
        }
        free(quant);

        filter->u.b.feature = xmlGetPropASCII(n, "feature");
        if(filter->u.b.feature == NULL) {
            dlog(0, "Error: predicate has no/invalid feature attribute\n");
            goto error;
        }

        filter->u.b.operator  = xmlGetPropASCII(n, "operator");
        if(filter->u.b.operator == NULL) {
            dlog(0, "Error: predicate has no/invalid operator attribute\n");
            goto error;
        }

        filter->u.b.value  = xmlGetPropASCII(n, "value");
        if(filter->u.b.value == NULL) {
            dlog(0, "Error: predicate has no/invalid value attribute\n");
            goto error;
        }
    } else {
        dlog(0, "Unknown filter node type \"%s\"\n", name);
        goto error;
    }
    return filter;

error:
    free_instruction_filter(filter);
    return NULL;
}

static int instruction_filter_to_str(instruction_filter *f, char *buf, size_t buflen)
{
    switch(f->type) {
    case BASE_FILTER:
        return snprintf(buf, buflen, "(%s %s \"%s\")",
                        f->u.b.operator,
                        f->u.b.feature,
                        f->u.b.value);
        break;
    case LOGICAL_OP_FILTER:
        if(f->u.o.op == FILTER_NOT_OP) {
            int used = snprintf(buf, buflen, "(not ");
            if(used < 0 || used >= buflen) {
                return used;
            }
            used += instruction_filter_to_str(f->u.o.e1, buf + used, buflen - used);
            if(used < 0 || used >= buflen) {
                return used;
            }
            used += snprintf(buf, buflen - used, ")");
            return used;
        } else {
            int used = snprintf(buf, buflen, "(%s ",
                                (f->u.o.op == FILTER_AND_OP ? "and" : "or"));
            if(used < 0 || used >= buflen) {
                return used;
            }
            used += instruction_filter_to_str(f->u.o.e1, buf + used, buflen - used);
            if(used < 0 || used >= buflen) {
                return used;
            }
            used += snprintf(buf, buflen, " ");
            if(used < 0 || used >= buflen) {
                return used;
            }
            used += instruction_filter_to_str(f->u.o.e1, buf + used, buflen - used);
            if(used < 0 || used >= buflen) {
                return used;
            }
            used += snprintf(buf, buflen, ")");
            return used;
        }
    }
    return -1;
}

static int evaluate_filter(instruction_filter *filter, measurement_variable *v,
                           measurement_spec_callbacks *callbacks, void *ctxt)
{
    int rc = -1;
    switch(filter->type) {
    case BASE_FILTER:
        rc = callbacks->measure_variable(ctxt, v, filter->u.b.mtype);
        if(rc == 0) {
            rc = callbacks->check_predicate(ctxt, v, filter->u.b.mtype,
                                            filter->u.b.quantifier,
                                            filter->u.b.feature,
                                            filter->u.b.operator,
                                            filter->u.b.value);
        } else if(rc > 0) {
            rc = -1;
        } else {
            if(callbacks->handle_error) {
                rc = callbacks->handle_error(ctxt, rc, v, filter->u.b.mtype);
                rc = -1; /* FIXME: this makes all errors in filter
			    predicates fatal because it'll be bubbled
			    out to the main evaluator as a -1. We'd
			    rather be able to signal that we aborted
			    the filtering because we hit an error, but
			    the error was handled so we can keep
			    evaluating the measurement spec.
			 */
            }
        }
        break;
    case LOGICAL_OP_FILTER:
        switch(filter->u.o.op) {
        case FILTER_NOT_OP:
            rc = evaluate_filter(filter->u.o.e1, v, callbacks, ctxt);
            if(rc == 0) {
                rc = 1;
            } else if(rc == 1) {
                rc = 0;
            }
            break;
        case FILTER_AND_OP:
            rc = evaluate_filter(filter->u.o.e1, v, callbacks, ctxt);
            if(rc > 0) {
                rc = evaluate_filter(filter->u.o.e2, v, callbacks, ctxt);
            }
            break;
        case FILTER_OR_OP:
            rc = evaluate_filter(filter->u.o.e1, v, callbacks, ctxt);
            if(rc == 0) {
                rc = evaluate_filter(filter->u.o.e2, v, callbacks, ctxt);
            }
            break;
        }
        break;
    }
    return rc;
}

static void free_filter_instruction_spec(instruction_spec *spec)
{
    filter_instruction_spec *fspec = (filter_instruction_spec *)spec;
    free_instruction_filter(fspec->filter);
    xmlFree(fspec->action);
    free(fspec);
}

static int filter_instruction_spec_to_str(instruction_spec *spec, char *buf, size_t buflen)
{
    char specbuf[2048];
    filter_instruction_spec *fspec = (filter_instruction_spec*)spec;
    int specbuflen = instruction_filter_to_str(fspec->filter, specbuf, 2048);
    if(specbuflen < 0) {
        memcpy(specbuf, "(?)", 4);
    }
    return snprintf(buf, buflen, "%s:filter(%s, 0x%x, %s, %s)",
                    fspec->i.name,
                    fspec->i.target_type->name,
                    fspec->i.address_space->magic,
                    specbuf,
                    fspec->action);
}

static inline int handle_filter_node(xmlNode *n, filter_instruction_spec *instr)
{
    xmlNode *child;
    for(child = n->children; child != NULL; child = child->next) {
        if(child->type != XML_ELEMENT_NODE)
            continue;
        if(instr->filter != NULL) {
            dlog(0, "Error: while parsing instruction %s: "
                 "filter node has multiple children.\n",
                 instr->i.name);
            return -1;
        }
        if((instr->filter = parse_instruction_filter(child)) == NULL) {
            return -1;
        }
    }
    return instr->filter == NULL ? -1 : 0;
}

static instruction_spec *parse_filter_instruction_spec(xmlNode *n)
{
    filter_instruction_spec *instr = malloc(sizeof(filter_instruction_spec));
    xmlNode *child;
    if(instr == NULL) {
        dlog(0, "Error: Failed to allocate filter instruction spec.\n");
        goto error;
    }

    bzero(instr, sizeof(*instr));
    instr->i.instr_type	= FILTER_INSTR;
    instr->i.name	= xmlGetProp(n, (xmlChar*)"name");
    if(instr->i.name == NULL) {
        dlog(0, "Error: Measurement instruction has no name!\n");
        goto error;
    }

    for(child = n->children; child != NULL; child = child->next) {
        char *child_name;

        if(child->type != XML_ELEMENT_NODE) {
            continue;
        }

        child_name = validate_cstring_ascii(child->name, SIZE_MAX);
        if(child_name == NULL) {
            continue;
        }

        if(strcasecmp(child_name, "target_type") == 0) {
            if(handle_target_type_node(child, &instr->i.target_type) < 0) {
                break;
            }
        } else if(strcasecmp(child_name, "address_type") == 0) {
            if(handle_address_type_node(child, &instr->i.address_space) < 0) {
                break;
            }
        } else if(strcasecmp(child_name, "filter") == 0) {
            if(handle_filter_node(child, instr) < 0) {
                break;
            }
        } else if(strcasecmp(child_name, "action") == 0) {
            if(instr->action != NULL) {
                dlog(0, "Error: while parsing filter instruction: "
                     "multiple action child nodes found\n");
                break;
            }
            if((instr->action = xmlGetProp(child, (xmlChar*)"name")) == NULL) {
                dlog(0, "Error: while parsing filter instruction: "
                     "action node has no \"name\" attribute\n");
                break;
            }
        }
    }

    if(instr->i.target_type      == NULL ||
            instr->i.address_space    == NULL ||
            instr->filter             == NULL ||
            instr->action             == NULL) {
        dlog(0, "Error: filter instruction %s must specify target_type, address_type, "
             "filter, and action\n", instr->i.name);
        goto error;
    }

    return &instr->i;

error:
    free_instruction_spec(&instr->i);
    return NULL;
}

static const struct {
    void (*free)(instruction_spec *spec);
    int (*to_str)(instruction_spec *spec, char *buf, size_t buflen);
    instruction_spec *(*parse)(xmlNode *node);
} instruction_spec_vtables[NR_INSTRUCTION_TYPES] = {
    [SIMPLE_INSTR]     = {
        .free   = (void (*)(instruction_spec *))free,
        .to_str = simple_instruction_spec_to_str,
        .parse  = parse_simple_instruction_spec
    },
    [SUBMEASURE_INSTR] = {
        .free   = free_submeasure_instruction_spec,
        .to_str = submeasure_instruction_spec_to_str,
        .parse = parse_submeasure_instruction_spec
    },
    [FILTER_INSTR]     = {
        .free   = free_filter_instruction_spec,
        .to_str = filter_instruction_spec_to_str,
        .parse  = parse_filter_instruction_spec
    }
};

void free_instruction_spec(instruction_spec *spec)
{
    if(spec == NULL) {
        return;
    }

    xmlFree(spec->name);

    if(spec->instr_type >= NR_INSTRUCTION_TYPES) {
        dlog(0, "Error: invalid instruction spec type: %d\n", spec->instr_type);
    } else {
        instruction_spec_vtables[spec->instr_type].free(spec);
    }
}

int instruction_spec_to_str(instruction_spec *spec, char *buf, size_t buflen)
{
    if(spec->instr_type >= NR_INSTRUCTION_TYPES) {
        dlog(0, "Error: invalid instruction spec type %d\n", spec->instr_type);
        if(buflen > 0) {
            buf[0] = '\0';
        }
        return -1;
    }
    return instruction_spec_vtables[spec->instr_type].to_str(spec, buf, buflen);
}

instruction_spec *parse_instruction_spec(xmlNode *node)
{
    char *type = xmlGetPropASCII(node, "type");
    instruction_spec *res = NULL;
    if(type == NULL) {
        dlog(0, "Error: instruction spec node has no/invalid type attribute\n");
    } else if(strcasecmp(type, "simple") == 0) {
        res = instruction_spec_vtables[SIMPLE_INSTR].parse(node);
    } else if(strcasecmp(type, "submeasure") == 0) {
        res = instruction_spec_vtables[SUBMEASURE_INSTR].parse(node);
    } else if(strcasecmp(type, "filter") == 0) {
        res = instruction_spec_vtables[FILTER_INSTR].parse(node);
    } else {
        dlog(0, "Error: unknown instruction spec type: %s\n", type);
    }
    xmlFree(type);
    return res;
}

GList *parse_meas_instructions(xmlNode *instructions)
{
    GList *res = NULL;
    xmlNode *child;

    for(child = instructions->children; child != NULL; child = child->next) {
        char *name = validate_cstring_ascii(child->name, SIZE_MAX);
        if(name == NULL) {
            continue;
        }

        if(strcasecmp(name, "instruction") == 0) {
            instruction_spec *instr = parse_instruction_spec(child);
            GList *tmp;
            if(instr == NULL) {
                goto error;
            }
            tmp = g_list_append(res, instr);
            if(tmp == NULL) {
                free_instruction_spec(instr);
                goto error;
            }
            res = tmp;
        }
    }

    return res;
error:
    g_list_free_full(res, (GDestroyNotify)free_instruction_spec);
    return NULL;
}

typedef struct {
    measurement_variable *var;
    instruction_spec     *instr;
} measurement_obligation;

/**
 * Free a measurement obligation.
 *
 * NB: the instruction referenced by the measurement obligation is
 * owned by the spec it came from (not duplicated) so we don't free it
 * here.
 */
static inline void free_measurement_obligation(measurement_obligation *o)
{
    if(o != NULL) {
        free_measurement_variable(o->var);
        /* don't free o->instr, it's owned by the spec */
        free(o);
    }
}

instruction_spec *get_instruction_spec(struct meas_spec *mspec, xmlChar *name)
{
    GList *iter;
    for(iter = g_list_first(mspec->instruction_list); iter != NULL;
            iter = g_list_next(iter)) {
        instruction_spec *instr = (instruction_spec *)iter->data;
        if(xmlStrcasecmp(instr->name, name) == 0) {
            return instr;
        }
    }
    dlog(0, "Error: reference to undefined measurement instruction \"%s\"\n", name);
    return NULL;
}

static int enqueue_measurement_roots(struct meas_spec *mspec,
                                     GQueue *queue,
                                     measurement_spec_callbacks *callbacks,
                                     void *ctxt)
{
    GList *iter = NULL;
    GQueue *vars = NULL;
    measurement_variable *tmpvar = NULL;

    /*
      create the initial queue of measurement variables by
      enumerating all variables matching variable_specs found in the
      measurement specification.
    */
    for(iter = g_list_first(mspec->variable_list); iter != NULL;
            iter = g_list_next(iter)) {
        variable_spec *vspec = (variable_spec *)iter->data;
        GList *addr_iter;
        instruction_spec *instr = get_instruction_spec(mspec, vspec->instruction_name);

        if(instr == NULL) {
            goto error_adding_obligations;
        }

        for(addr_iter = g_list_first(vspec->address_list); addr_iter != NULL;
                addr_iter = g_list_next(addr_iter)) {
            address_spec *aspec = (address_spec *)addr_iter->data;

            vars = callbacks->enumerate_variables(ctxt, instr->target_type,
                                                  instr->address_space,
                                                  aspec->operation,
                                                  aspec->value);

            while((tmpvar = (measurement_variable *)g_queue_pop_head(vars)) != NULL) {
                measurement_obligation *o = malloc(sizeof(measurement_obligation));
                if(o == NULL) {
                    dlog(0, "Error: failed to allocate measurement obligation structure.\n");
                    goto error_adding_obligations;
                }
                o->var		= tmpvar;
                o->instr	= instr;
                g_queue_push_tail(queue, o);
            }
            g_queue_free(vars);
            tmpvar = NULL;
            vars   = NULL;
        }
    }
    return 0;

error_adding_obligations:
    free_measurement_variable(tmpvar);
    g_queue_free_full(vars, (GDestroyNotify)free_measurement_variable);
    g_queue_free_full(queue, (GDestroyNotify)free_measurement_obligation);
    queue = NULL;
    return -1;
}


static int enqueue_obligations_by_feature(measurement_spec_callbacks *callbacks,
        void *ctxt, measurement_variable *var,
        measurement_type *mtype, char *feature,
        instruction_spec *target_instr, GQueue *measure_q)
{
    GList *value_iter;
    address *child_addr;
    measurement_variable *child_var;
    GList *attr_values = callbacks->get_measurement_feature(ctxt, var, mtype,
                         feature);

    for(value_iter = g_list_first(attr_values); value_iter != NULL;
            value_iter = g_list_next(value_iter)) {
        measurement_obligation *obl;
        char *attr_value = (char*)value_iter->data;

        child_addr   = address_from_human_readable(target_instr->address_space,
                       attr_value);
        if(child_addr == NULL) {
            dlog(0, "Error: Failed to parse address from \"%s\"\n", attr_value);
            continue;
        }

        child_var = new_measurement_variable(target_instr->target_type, child_addr);
        if(child_var == NULL) {
            dlog(0, "Error: failed to allocate measurement variable\n");
            free_address(child_addr);
            continue;
        }

        if(callbacks->connect_variables != NULL) {
            /* name the edge by "mtype.feature" */
            size_t labellen = strlen(mtype->name) + 1 + strlen(feature) + 1;
            char labelbuf[labellen];
            char *label = labelbuf;
            if(sprintf(labelbuf, "%s.%s", mtype->name, feature) != 2) {
                dlog(1, "Warning: failed to construct child variable lable.\n");
                label = NULL;
            }

            if(callbacks->connect_variables(ctxt, var, label, child_var) < 0) {
                free_measurement_variable(child_var);
                continue;
            }
        }

        obl = malloc(sizeof(*obl));
        if(obl == NULL) {
            dlog(0, "Error: failed to allocate measurement obligation\n");
            free_measurement_variable(child_var);
            continue;
        }
        obl->var	= child_var;
        obl->instr	= target_instr;
        g_queue_push_tail(measure_q, obl);
    }
    g_list_free_full(attr_values, free);
    return 0;
}

static int enqueue_obligations_by_relationship(measurement_spec_callbacks *callbacks,
        void *ctxt, measurement_variable *var,
        measurement_type *type, char *feature,
        instruction_spec *target_instr,
        GQueue *measure_q)
{
    GList *childvars = NULL;
    GList *variter;

    if(callbacks->get_related_variables(ctxt, var, type, feature, &childvars) != 0) {
        return -1;
    }
    for(variter = g_list_first(childvars); variter != NULL; variter = g_list_next(variter)) {
        measurement_variable *child_var = (measurement_variable *)variter->data;
        if(child_var->type != target_instr->target_type) {
            free_measurement_variable(child_var);
        }
        measurement_obligation *child_obligation = calloc(1, sizeof(*child_obligation));
        if(child_obligation == NULL) {
            free_measurement_variable(child_var);
            g_list_free(childvars);
            return -1;
        }
        child_obligation->var = child_var;
        child_obligation->instr = target_instr;
        g_queue_push_tail(measure_q, child_obligation);
    }
    g_list_free(childvars);
    return 0;
}

int evaluate_measurement_spec(struct meas_spec *mspec,
                              measurement_spec_callbacks *callbacks,
                              void *ctxt)
{
    GQueue *measure_q = g_queue_new();
    measurement_obligation *o = NULL;
    int rc;

    if(!measure_q || mspec == NULL) {
        return -1;
    }

    rc = enqueue_measurement_roots(mspec, measure_q, callbacks, ctxt);
    if(rc < 0) {
        goto error;
    }

    while((o = g_queue_pop_head(measure_q)) != NULL) {
        char instr_str[1024];
        instruction_spec_to_str(o->instr, instr_str, 1024);
        dlog(3, "Evaluating instruction %s\n", instr_str);
        switch(o->instr->instr_type) {
        case SIMPLE_INSTR: {
            simple_instruction_spec *spec = (simple_instruction_spec*)o->instr;
            dlog(4, "Evaluating simple measurement instruction\n");
            rc = callbacks->measure_variable(ctxt, o->var, spec->mtype);
            if(rc < 0) {
                if(callbacks->handle_error) {
                    rc = callbacks->handle_error(ctxt, rc, o->var, spec->mtype);
                    if(rc < 0) {
                        goto error;
                    }
                } else {
                    dlog(1, "WARNING: Error evaluating instruction %s...muddling on\n", instr_str);
                }
            }
            free_measurement_obligation(o);
            break;
        }
        case SUBMEASURE_INSTR: {
            submeasure_instruction_spec *spec = (submeasure_instruction_spec*)o->instr;
            GList *action_iter;


            rc = callbacks->measure_variable(ctxt, o->var, spec->mtype);
            if(rc < 0) {
                if(callbacks->handle_error) {
                    rc = callbacks->handle_error(ctxt, rc, o->var, spec->mtype);
                    if(rc < 0) {
                        goto error;
                    }
                } else {
                    dlog(1, "WARNING: Error evaluating instruction %s...muddling on\n", instr_str);
                }
            }

            for(action_iter = g_list_first(spec->actions) ; action_iter != NULL; action_iter = g_list_next(action_iter)) {
                feature_instruction_pair *action = (feature_instruction_pair*)action_iter->data;
                instruction_spec *target_instr = get_instruction_spec(mspec, action->instruction);
                if(target_instr == NULL) {
                    dlog(0, "ERROR: Submeasure instruction %s refers to undefined target instruction %s\n",
                         instr_str, action->instruction);
                    goto error;
                }

                if(callbacks->get_related_variables == NULL) {
                    enqueue_obligations_by_feature(callbacks,
                                                   ctxt, o->var, spec->mtype, action->feature,
                                                   target_instr, measure_q);
                } else {
                    enqueue_obligations_by_relationship(callbacks,
                                                        ctxt, o->var, spec->mtype, action->feature,
                                                        target_instr, measure_q);
                }
            }
            free_measurement_obligation(o);
            break;
        }

        case FILTER_INSTR: {
            filter_instruction_spec *spec = (filter_instruction_spec *)o->instr;
            rc = evaluate_filter(spec->filter, o->var, callbacks, ctxt);
            if(rc < 0) {
                goto error;
            }

            if(rc) {
                /* filter passed, add the new obligation */
                instruction_spec *target_instr;

                target_instr = get_instruction_spec(mspec, spec->action);
                if(target_instr == NULL) {
                    goto error;
                }
                o->instr = target_instr;
                g_queue_push_tail(measure_q, o);
            } else {
                free_measurement_obligation(o);
            }
            break;
        }

        default:
            dlog(0, "Error: invalid measurement instruction type %d\n",
                 o->instr->instr_type);
            goto error;
        }
    }

    g_queue_free(measure_q);

    return 0;
error:
    g_queue_free_full(measure_q, (GDestroyNotify)free_measurement_obligation);
    free_measurement_obligation(o);
    return -1;
}

/* END REWRITE */

int get_target_meas_spec(uuid_t meas_spec_uuid, struct meas_spec **mspec)
{
    mspec_info *mspec_info;
    GList *meas_specs;

    int rc = -1;

    char *mspec_dir = getenv(ENV_MAAT_MEAS_SPEC_DIR);
    if(mspec_dir == NULL) {
        dlog(1, "Warning: environment variable " ENV_MAAT_MEAS_SPEC_DIR
             " not set. Using default path " DEFAULT_MEAS_SPEC_DIR);
        mspec_dir = DEFAULT_MEAS_SPEC_DIR;
    }

    meas_specs = load_all_measurement_specifications_info(mspec_dir);
    if (meas_specs == NULL) {
        dlog(0, "Couldn't find measurement specifications in the chosen directory %s\n", mspec_dir);
        goto exit;
    }

    mspec_info = find_measurement_specification_uuid(meas_specs, meas_spec_uuid);
    if(mspec_info == NULL) {
        char buf[32] = {0};
        uuid_unparse(meas_spec_uuid, buf);
        dlog(0, "Couldn't find measurement specification with uuid: %s\n", buf);
        goto exit;
    } else {
        dlog(0, "Parsing %s\n", mspec_info->filename);
        *mspec = parse_measurement_spec(mspec_info->filename);
    }

    if(*mspec == NULL) {
        dlog(0, "Failed to parse measurement specification from file %s\n", mspec_info->filename);
        goto exit;
    }

    rc = 0;

exit:
    return rc;
}


/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
