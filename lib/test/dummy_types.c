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
#include <dummy_types.h>


measurement_data *alloc_dummy_measurement_data()
{
    dummy_measurement_data *d = malloc(sizeof(*d));
    if(d) {
        d->d.type = &dummy_measurement_type;
        d->x = 0;
    }
    return &d->d;
}


void free_dummy_measurement_data(measurement_data *d)
{
    free(d);
}

measurement_data *copy_dummy_measurement_data(measurement_data *d)
{
    dummy_measurement_data *dd  = (dummy_measurement_data *)d;
    dummy_measurement_data *res = (dummy_measurement_data *)alloc_measurement_data(&dummy_measurement_type);
    if(res)
        res->x = dd->x;
    return &res->d;
}

int serialize_dummy_measurement_data(measurement_data *d, char **sd, size_t*size_sd)
{
    int ret_val = 0;
    dummy_measurement_data *dd = (dummy_measurement_data *)d;

    char *buf = malloc(9);
    if(buf) {
        sprintf(buf, "%08"PRIx32, dd->x);
        *sd       = buf;
        *size_sd = 9;
    } else {
        *sd = NULL;
        *size_sd = 0;
        ret_val = -1; // find right errno value !!!!
    }

    return ret_val;
}

int unserialize_dummy_measurement_data(char *sd, size_t sd_size UNUSED,
                                       measurement_data **out)
{
    int ret_val = 0;

    dummy_measurement_data *d = (dummy_measurement_data *)alloc_measurement_data(&dummy_measurement_type);
    if(d) {
        sscanf((char*)sd, "%08"PRIx32, &d->x);
    }

    *out = (measurement_data*)d;
    return ret_val;
}

address *alloc_simple_address()
{
    simple_address *a = malloc(sizeof(simple_address));
    if(a)
        a->a.space = &simple_address_space;
    return &a->a;
}

void free_simple_address(address *a)
{
    free(a);
}

char *serialize_simple_address(const address *a)
{
    char *buf = malloc(9);
    if(buf)
        sprintf(buf, "%08"PRIx32, ((const simple_address*)a)->addr);
    return buf;
}

address *parse_simple_address(const char *str, size_t maxbytes)
{
    address *a;
    if(maxbytes != 9) {
        return NULL;
    }

    if((a = alloc_address(&simple_address_space)) != NULL) {
        sscanf(str, "%08"PRIx32, &((simple_address*)a)->addr);
    }
    return a;
}

address *simple_copy_address(const address *a)
{
    simple_address *sa = (simple_address *)malloc(sizeof(simple_address));
    if(sa == NULL) {
        return NULL;
    }
    sa->addr = ((simple_address *)a)->addr;
    sa->a.space = &simple_address_space;
    return (address *)sa;
}

gboolean simple_address_equal(const address *a, const address *b)
{
    return ((simple_address *)a)->addr ==
           ((simple_address *)b)->addr;
}

guint simple_address_hash(const address *a)
{
    return (guint)((simple_address *)a)->addr;
}

static int dummy_measurement_data_get_feature(measurement_data *d,
        char *feature, GList **out)
{
    if(strcmp(feature, "x") == 0) {
        char *buf = malloc(sizeof(char)*11);
        if(buf == NULL) {
            return -1;
        }
        sprintf(buf, "0x%08"PRIx32, ((dummy_measurement_data *)d)->x);
        *out = g_list_append(NULL, buf);
        return 0;
    } else {
        dlog(1, "Warning: no such feature \"%s\" for measurement_type dummy\n",
             feature);
    }
    return -1;
}

target_type dummy_target_type = {
    .magic = 0xbeefdead,
    .name  = "dummy"
};


address_space simple_address_space = {
    .magic		= 0xdeadbeef,
    .alloc_address	= alloc_simple_address,
    .copy_address   = simple_copy_address,
    .free_address	= free_simple_address,
    .serialize_address	= serialize_simple_address,
    .parse_address	= parse_simple_address,
    .address_equal	= simple_address_equal,
    .address_hash	= simple_address_hash
};


measurement_type dummy_measurement_type = {
    .name			= "dummy",
    .magic		= 0xdeadbeef,
    .alloc_data		= alloc_dummy_measurement_data,
    .copy_data		= copy_dummy_measurement_data,
    .free_data		= free_dummy_measurement_data,
    .serialize_data	= serialize_dummy_measurement_data,
    .unserialize_data	= unserialize_dummy_measurement_data,
    .get_feature      = dummy_measurement_data_get_feature
};
