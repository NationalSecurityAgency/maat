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

#include <stdlib.h>
#include <string.h>

#include <common/taint.h>
#include <measurement_spec/find_types.h>


static measurement_data *copy_marshalled_data(measurement_data *d)
{
    marshalled_data *md;
    marshalled_data *new;
    if(d->type != &marshalled_data_measurement_type)
        return NULL;

    md  = (marshalled_data*)d;
    new = (typeof(new))alloc_measurement_data(&marshalled_data_measurement_type);
    if(new) {
        /* FIXME: how can we prevent taint from ever getting to this field? */
        size_t len			= UNTAINT(md->marshalled_data_length);
        new->unmarshalled_type		= md->unmarshalled_type;
        new->marshalled_data_length	= len;
        new->marshalled_data		= malloc(new->marshalled_data_length);
        if(!new->marshalled_data) {
            free(new);
            new = NULL;
        } else {
            memcpy(new->marshalled_data, md->marshalled_data, len);
        }
    } else {
        return NULL;
    }

    return &new->meas_data;
}

static measurement_data *marshalled_data_alloc_data()
{
    marshalled_data *md = NULL;

    md = (marshalled_data *)malloc(sizeof(*md));
    if (!md)
        return NULL;

    md->meas_data.type = &marshalled_data_measurement_type;
    md->marshalled_data_length = 0;
    md->marshalled_data = NULL;
    md->unmarshalled_type = INVALID_MEAS_TYPE;

    return (measurement_data *)md;
}
static void free_marshalled_data(measurement_data *md)
{
    marshalled_data *fmd = (marshalled_data *)md;

    free(fmd->marshalled_data);
    free(fmd);

    return;
}


static int marshalled_data_get_feature(measurement_data *md, char *feature, GList **out)
{
    measurement_data *d = unmarshall_measurement_data((marshalled_data *)md);
    int rc;
    if(d == NULL) {
        return -1;
    }
    rc = measurement_data_get_feature(d, feature, out);
    free_measurement_data(d);
    return rc;
}

static int marshalled_data_check_predicate(measurement_data *md,
        predicate_quantifier q,
        char *feature, char *operator,
        char *value, int *defer)
{
    measurement_data *d = unmarshall_measurement_data((marshalled_data *)md);
    int rc;
    if(d == NULL) {
        return -1;
    }

    rc = measurement_data_check_predicate(d, q, feature, operator, value);
    *defer = 0;

    free_measurement_data(d);
    return rc;
}

static int human_readable(measurement_data *md, char **out, size_t *outsize)
{
    marshalled_data *x = container_of(md, marshalled_data, meas_data);
    measurement_data *d = unmarshall_measurement_data(x);
    if(d == NULL) {
        return -1;
    }
    int rc = measurement_data_human_readable(d, out, outsize);
    free_measurement_data(d);
    return rc;
}

/**
 * serializing function for a marshalled_data
 * don't want to double serialize as the marshalled data is already serialized
 * use the marshalled_data_to_serialize_data func to create the serialized data elements
 */

int serialize_marshalled_data(measurement_data *d UNUSED,
                              char **serial_data UNUSED,
                              size_t *serial_data_size UNUSED)
{
    return -ENOTSUP;
}


/**
 * unserializing function for the marshalled_data
 * similarly to the marshalled_data_serialize_data func
 * don't want to unserialize the marshalled_data as this has no meaning
 * if the measurement_data for the measurement_type of the encoded data is
 * desired then use that measurement_type function to retrieve it.
 * if a marshalled_data instance from the serialized data elements is needed
 * use serialized_data_to_marshalled_data helper func.
 */
int unserialize_marshalled_data(char *sd UNUSED, size_t sd_size UNUSED,
                                measurement_data **d UNUSED)
{
    return -ENOTSUP;
}


char marshalled_data_type_uuname[19] = "marshalleddatatype";


measurement_type marshalled_data_measurement_type = {
    .magic		= 0xffffffff,
    .name		= marshalled_data_type_uuname,
    .alloc_data		= &marshalled_data_alloc_data,
    .copy_data		= &copy_marshalled_data,
    .free_data		= &free_marshalled_data,
    .serialize_data	= &serialize_marshalled_data,
    .unserialize_data	= &unserialize_marshalled_data,
    .get_feature        = &marshalled_data_get_feature,
    .check_predicate    = &marshalled_data_check_predicate,
    .human_readable     = &human_readable,
};



