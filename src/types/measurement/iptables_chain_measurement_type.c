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

#include <glib.h>
#include <string.h>
#include <errno.h>
#include <util/base64.h>
#include <util/util.h>
#include "iptables_chain_measurement_type.h"
#include <tpl.h>

static measurement_data *alloc_iptables_measurement_data()
{
    iptables_chain_data *fd = NULL;
    fd = (iptables_chain_data *)malloc(sizeof(*fd));
    if (!fd) {
        return NULL;
    }
    fd->meas_data.type = &iptables_chain_measurement_type;
    fd->rules = NULL;
    return (measurement_data *)fd;
}

/*
 * XXX: could change implementation to have each iptables rule
 * as a separate node with edges connecting to this root node
 * instead of a glist hanging off of the measurement data of
 * this node
 */
iptables_rule *allocate_iptables_rule()
{
    iptables_rule *rule = malloc(sizeof(iptables_rule));
    if (!rule ) {
        return NULL;
    }
    rule->protocol = NULL;
    rule->src = NULL;
    rule->dst = NULL;
    rule->target = NULL;
    return rule;
}

void free_iptables_rule(void *data)
{
    iptables_rule *ir = (iptables_rule *)data;
    if(ir != NULL) {
        free(ir->protocol);
        g_free(ir->src);
        free(ir->dst);
        free(ir->target);
        free(ir);
    }
    return;
}

static void free_iptables_measurement_data(measurement_data *d)
{
    iptables_chain_data *id = (iptables_chain_data*)d;
    if(!id) {
        return;
    }
    g_list_free_full(id->rules, (GDestroyNotify)free_iptables_rule);
    free(id);
}

iptables_rule *copy_iptables_rule(const void *src, void *data)
{
    iptables_rule *ir = (iptables_rule *)src;
    iptables_rule *ret = allocate_iptables_rule();
    if(!ret) {
        return NULL;
    }
    ret->protocol = strdup(ir->protocol);
    ret->src = strdup(ir->src);
    ret->dst = strdup(ir->dst);
    ret->target = strdup(ir->target);
    return ret;
}

static measurement_data *copy_iptables_measurement_data(measurement_data *d)
{
    iptables_chain_data *id = (iptables_chain_data *)d;
    iptables_chain_data *new = (iptables_chain_data*)alloc_measurement_data(&iptables_chain_measurement_type);
    if(!new) {
        return NULL;
    }
    new->rules = g_list_copy_deep(id->rules, (GCopyFunc)copy_iptables_rule, NULL);
    return &new->meas_data;
}

static int iptables_serialize_data(measurement_data *d, char **serial_data,
                                   size_t *serial_data_size)
{
    size_t sz = 0;
    char *buf = NULL;
    tpl_node *tn = NULL;
    GList *iter = NULL;
    iptables_chain_data *id = (iptables_chain_data*)d;
    iptables_rule *ir = NULL;
    char *proto, *src, *dst;
    char *target;

    *serial_data = NULL;
    *serial_data_size = 0;

    tn = tpl_map("uA(ssss)", &id->meas_data.type->magic, &proto,
                 &src, &dst, &target);

    if(tn == NULL) {
        dlog(0, "Error, tpl_map returned NULL.\n");
        return -1;
    }
    tpl_pack(tn, 0);
    //Pack IPtables information into TPL node
    for(iter = g_list_first(id->rules); iter!= NULL && iter->data != NULL;
            iter = g_list_next(iter)) {
        ir = (iptables_rule *)iter->data;
        proto = ir->protocol;
        src = ir->src;
        dst = ir->dst;
        target = ir->target;
        tpl_pack(tn, 1);
    }

    tpl_dump(tn, TPL_MEM, &buf, &sz);
    tpl_free(tn);

    /* Now, convert this to a string... base64 encode it */
    // Cast is justified because the decode operation does not affect the
    // signedness of the buffer contents
    *serial_data = (char *)b64_encode((unsigned char *)buf, sz);
    free(buf);
    if(*serial_data == NULL) {
        dlog(0, "Error while b64 encoding buffer, returned NULL.\n");
        return -1;
    }

    *serial_data_size = strlen(*serial_data)+1;
    return 0;
}

static int iptables_unserialize_data(char *sd, size_t sd_size,
                                     measurement_data **d)
{
    measurement_data *data = NULL;
    iptables_chain_data *id  = NULL;
    iptables_rule * rule  = NULL;
    tpl_node *tn   = NULL;
    void *tplbuf   = NULL;
    size_t tplsize = 0;
    int ret_val    = 0;
    char * proto = NULL;
    char * src = NULL;
    char * dst = NULL;
    char * target = NULL;

    uint32_t as_magic;

    tplbuf = b64_decode(sd, &tplsize);
    if(!tplbuf) {
        dlog(0, "Error: tplbuf is NULL\n");
        ret_val = -1;
        goto error_decode;
    }

    id = (iptables_chain_data *) alloc_measurement_data(&iptables_chain_measurement_type);
    if (!id) {
        dlog(0, "Error alloc'ing data\n");
        ret_val = -ENOMEM;
        goto error_alloc;
    }

    tn = tpl_map("uA(ssss)", &as_magic, &proto, &src, &dst, &target);
    if(!tn) {
        dlog(0, "Error: tpl_map failed\n");
        goto error_tpl_map;
    }

    tpl_load(tn, TPL_MEM, tplbuf, tplsize);

    ret_val = tpl_unpack(tn, 0);
    if(ret_val <= 0) {
        dlog(0, "Error tpl_unpack failed\n");
        goto error_tpl_unpack;
    }

    if(as_magic != iptables_chain_measurement_type.magic) {
        dlog(1, "Error, magic %x != %x\n", as_magic, iptables_chain_measurement_type.magic);
        ret_val = -EINVAL;
        goto error_magic;
    }

    //Unpack the GList chain
    while(tpl_unpack(tn,1) >0) {
        rule = allocate_iptables_rule();
        if(!rule) {
            goto error_allocate_rule;
        }
        rule->protocol = proto;
        rule->src = src;
        rule->dst = dst;
        rule->target = target;
        id->rules = g_list_append(id->rules, rule);
    }

    *d = &id->meas_data;

    b64_free(tplbuf);
    tpl_free(tn);

    return ret_val;

error_allocate_rule:
error_magic:
error_tpl_unpack:
    tpl_free(tn);
error_tpl_map:
    free_measurement_data(data);
error_alloc:
    b64_free(tplbuf);
error_decode:
    return ret_val;
}


GList *get_rule_feature(iptables_chain_data *id, rule_attr ra)
{
    GList *iter, *ret = NULL;
    for(iter = g_list_first(id->rules); iter != NULL && iter->data != NULL; iter = g_list_next(iter)) {
        char *p;
        switch(ra) {
        case PROTOCOL:
            p = strdup(((iptables_rule *)iter->data)->protocol);
            break;
        case SOURCE:
            p = strdup(((iptables_rule *)iter->data)->src);
            break;
        case DESTINATION:
            p = strdup(((iptables_rule *)iter->data)->dst);
            break;
        case TARGET:
            p = strdup(((iptables_rule *)iter->data)->target);
            break;
        default:
            dlog(3, "Unknown rule_attr: %d\n", ra);
            goto error;
        }
        if(p == NULL) {
            goto error;
        }
        ret = g_list_append(ret, p);
    }
    return ret;
error:
    g_list_free_full(ret, free);
    return NULL;
}

static int get_feature(measurement_data *d, char *feature, GList **out)
{
    rule_attr ra;
    dlog(3, "iptables measurement type getting feature %s\n", feature);
    if(strcmp(feature, "iptables_protocol") == 0) {
        ra = PROTOCOL;
    } else if(strcmp(feature, "iptables_source") == 0) {
        ra = SOURCE;
    } else if(strcmp(feature, "iptables_destination") == 0) {
        ra = DESTINATION;
    } else if(strcmp(feature, "iptables_target") == 0) {
        ra = TARGET;
    } else {
        dlog(3, "Feature not supported: %s\n", feature);
        return -ENOENT;
    }
    iptables_chain_data *id = (iptables_chain_data*)d;
    GList *res = get_rule_feature(id, ra);
    if(res == NULL) {
        *out = NULL;
        return -1;
    }
    *out = res;
    return 0;
}

static int human_readable(measurement_data *d, char **out, size_t *outsize)
{

    iptables_chain_data *md = container_of(d, iptables_chain_data, meas_data);
    char *buf = NULL;

    GList * iter;
    for (iter = g_list_first(md->rules); iter != NULL; iter = g_list_next(iter)) {
        iptables_rule *rule = (iptables_rule*)iter->data;
        char *tmp = g_strdup_printf("%s%sRule:\n\tprotocol:\t%s\n"
                                    "\tsource:\t\t%s\n"
                                    "\tdestination:\t%s\n"
                                    "\ttarget:\t\t%s\n",
                                    buf == NULL ? "" : buf,
                                    buf == NULL ? "" : "\n",
                                    rule->protocol,
                                    rule->src,
                                    rule->dst,
                                    rule->target);

        free(buf);
        if (tmp == NULL) {
            return -1;
        }
        buf = tmp;
    }

    if (buf == NULL) {
        buf = strdup("");
    }

    if(buf == NULL) {
        return -1;
    }

    *outsize = strlen(buf) + 1;
    *out = buf;
    return 0;
}

measurement_type iptables_chain_measurement_type = {
    .name             = IPTABLES_CHAIN_TYPE_NAME,
    .magic            = IPTABLES_CHAIN_TYPE_MAGIC,
    .alloc_data       = alloc_iptables_measurement_data,
    .copy_data        = copy_iptables_measurement_data,
    .free_data        = free_iptables_measurement_data,
    .serialize_data   = iptables_serialize_data,
    .unserialize_data = iptables_unserialize_data,
    .get_feature      = get_feature,
    .human_readable   = human_readable
};
