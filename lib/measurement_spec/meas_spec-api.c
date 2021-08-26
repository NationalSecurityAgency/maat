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

#include <measurement_spec/find_types.h>
#include <glib.h>

/**
 * Measurement variable equivalence requires the target type magic
 * and the address space magic to be the same.
 * Returns 0 for equality, and -1 for non-equality
 */
int compare_measurement_variable(measurement_variable *v1, measurement_variable *v2)
{
    //check the target type magic
    if(v1->type->magic == v2->type->magic) {
        //check the address
        if(address_equal(v1->address, v2->address)) {
            return 0;
        }
    }
    return -1;
}

measurement_variable *new_measurement_variable(target_type *type, address *addr)
{
    measurement_variable *v = malloc(sizeof(measurement_variable));
    if(v) {
        v->type	= type;
        v->address	= addr;
    }
    return v;
}

measurement_variable *copy_measurement_variable(measurement_variable *v)
{
    address *addr_cpy         = copy_address(v->address);
    measurement_variable *ret = NULL;
    if(!addr_cpy)
        return NULL;
    ret = new_measurement_variable(v->type, addr_cpy);
    if(!ret) {
        free_address(addr_cpy);
    }
    return ret;
}

static inline int convert_vals_to_longs(char *val1, long *out1, char *val2, long *out2)
{
    char *endptr;
    errno   = 0;
    *out1 = strtol(val1, &endptr, 0);
    if(errno != 0 || *endptr != '\0') {
        return -1;
    }
    *out2 = strtol(val2, &endptr, 0);
    if(errno != 0 || *endptr != '\0') {
        return -1;
    }
    return 0;
}

static inline int convert_vals_to_ulongs(char *val1, unsigned long *out1, char *val2, unsigned long *out2)
{
    char *endptr;
    errno   = 0;
    *out1 = strtoul(val1, &endptr, 0);
    if(errno != 0 || *endptr != '\0') {
        return -1;
    }
    *out2 = strtoul(val2, &endptr, 0);
    if(errno != 0 || *endptr != '\0') {
        return -1;
    }
    return 0;
}

int measurement_data_check_predicate(measurement_data *d, predicate_quantifier q,
                                     char *feature, char *operator,
                                     char *value)
{
    int defer = 0;
    GList *attr_list = NULL, *iter = NULL;
    int rc;

    if(d->type->check_predicate != NULL) {
        rc = d->type->check_predicate(d, q, feature, operator, value, &defer);
        if(defer == 0) {
            return rc;
        }
    }

    /*
     * data type either doesn't implement check_predicate, or deferred
     * to the default implementation.
     */
    rc = measurement_data_get_feature(d, feature, &attr_list);
    if(rc < 0) {
        return rc;
    }

    for(iter = g_list_first(attr_list); iter != NULL; iter = g_list_next(iter)) {
        char *attrval = (char *)iter->data;
        if(strcasecmp("equal", operator) == 0) {
            rc = strcmp(attrval, value) == 0;
        } else if(strcasecmp("startswith", operator) == 0) {
            rc = strncmp(attrval, value, strlen(value)) == 0;
        } else if(strcasecmp("endswith", operator) == 0) {
            rc = strcmp(attrval + (strlen(attrval) - strlen(value)), value) == 0;
        } else if(strcasecmp("case-equal", operator) == 0) {
            rc = strcasecmp(attrval, value) == 0;
        } else if(strcasecmp("case-startswith", operator) == 0) {
            rc = strncasecmp(attrval, value, strlen(value)) == 0;
        } else if(strcasecmp("case-endswith", operator) == 0) {
            rc = strcasecmp(attrval + (strlen(attrval) - strlen(value)), value) == 0;
        } else if(strcasecmp("<",   operator) == 0) {
            long attrnum, valnum;
            rc = (convert_vals_to_longs(attrval, &attrnum,
                                        value, &valnum) == 0) ? (attrnum < valnum) : -1;
        } else if(strcasecmp("<=",  operator) == 0) {
            long attrnum, valnum;
            rc = (convert_vals_to_longs(attrval, &attrnum,
                                        value, &valnum) == 0) ? (attrnum <= valnum) : -1;
        } else if(strcasecmp("=",   operator) == 0) {
            long attrnum, valnum;
            rc = (convert_vals_to_longs(attrval, &attrnum,
                                        value, &valnum) == 0) ? (attrnum == valnum) : -1;
        } else if(strcasecmp(">=",  operator) == 0) {
            long attrnum, valnum;
            rc = (convert_vals_to_longs(attrval, &attrnum,
                                        value, &valnum) == 0) ? (attrnum >= valnum) : -1;
        } else if(strcasecmp(">",   operator) == 0) {
            long attrnum, valnum;
            rc = (convert_vals_to_longs(attrval, &attrnum,
                                        value, &valnum) == 0) ? (attrnum > valnum) : -1;
        } else if(strcasecmp("u<",  operator) == 0) {
            unsigned long attrnum, valnum;
            rc = (convert_vals_to_ulongs(attrval, &attrnum,
                                         value, &valnum) == 0) ? (attrnum < valnum) : -1;
        } else if(strcasecmp("u<=", operator) == 0) {
            unsigned long attrnum, valnum;
            rc = (convert_vals_to_ulongs(attrval, &attrnum,
                                         value, &valnum) == 0) ? (attrnum <= valnum) : -1;
        } else if(strcasecmp("u=",  operator) == 0) {
            unsigned long attrnum, valnum;
            rc = (convert_vals_to_ulongs(attrval, &attrnum,
                                         value, &valnum) == 0) ? (attrnum == valnum) : -1;
        } else if(strcasecmp("u>=", operator) == 0) {
            unsigned long attrnum, valnum;
            rc = (convert_vals_to_ulongs(attrval, &attrnum,
                                         value, &valnum) == 0) ? (attrnum >= valnum) : -1;
        } else if(strcasecmp("u>",  operator) == 0) {
            unsigned long attrnum, valnum;
            rc = (convert_vals_to_ulongs(attrval, &attrnum,
                                         value, &valnum) == 0) ? (attrnum > valnum) : -1;
        }

        if(rc < 0 ||
                (q == ANY_VALUE && rc > 0) ||
                (q == ALL_VALUES && rc == 0)) {
            break;
        }
    }

    g_list_free_full(attr_list, free);
    return rc;
}

marshalled_data *marshall_measurement_data(measurement_data *d)
{
    marshalled_data *md = NULL;
    char *serial = NULL;
    size_t size;
    int rc = d->type->serialize_data(d, &serial, &size);
    if(rc == 0) {
        md				= (typeof(md))alloc_measurement_data(&marshalled_data_measurement_type);
        md->unmarshalled_type		= d->type->magic;
        md->marshalled_data		= serial;
        md->marshalled_data_length	= size;
    }
    return md;
}

measurement_data *unmarshall_measurement_data(marshalled_data *md)
{
    measurement_data *d = NULL;
    int rc;
    measurement_type *t = find_measurement_type(md->unmarshalled_type);
    if(!t) {
        return NULL;
    }
    rc = t->unserialize_data(md->marshalled_data,
                             md->marshalled_data_length, &d);
    return rc == 0 ? d : NULL;
}
