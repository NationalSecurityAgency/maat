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

/*
 * Simplified graph library for Maat
 *
 * json.c: Serialize the graph to and from JSON
 */
#include <sgraph_internal.h>
#include <json.h>

/*
 * A preprocessor macro to avoid code duplication when converting from
 * a JSON array to a list of a specific type
 */

#define ARRAY_TO_LIST_TYPE(TYPE) 					\
static GList *json_array_to_##TYPE##_list(json_object *array) 		\
{									\
	GList *list = NULL;						\
	int arraylen;							\
	int i;								\
									\
	if (json_object_get_type(array) != json_type_array) {		\
		log("Non-array passed to array parser\n");		\
		return NULL;						\
	}								\
									\
	arraylen = json_object_array_length(array);			\
									\
	for(i=0; i<arraylen; i++) {					\
		json_object *tmp = json_object_array_get_idx(array, i);	\
		struct sg_##TYPE *x = json_to_##TYPE(tmp);			\
		if (x != NULL) {					\
			list = g_list_append(list, x);			\
		}							\
	}								\
									\
	return list;							\
}


/*
 * Address handling functions.
 */
static json_object *address_to_json(const struct sg_address *a)
{
    json_object *ja;
    json_object *jspace;
    json_object *jaddr;

    if (a == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    ja = json_object_new_object();
    if (ja == NULL) {
        log("Error allocating JSON address object");
        return NULL;
    }

    jspace = json_object_new_string(a->space);
    if (jspace == NULL) {
        log("Error allocating JSON address space string");
        json_object_put(ja);
        return NULL;
    }

    jaddr = json_object_new_string(a->addr);
    if (jaddr == NULL) {
        log("Error allocating JSON address string");
        json_object_put(ja);
        return NULL;
    }

#if JSON_C_MINOR_VERSION > 12
    int ret;

    ret = json_object_object_add(ja, "space", jspace);
    if (ret != 0) {
        log("Error adding JSON address space");
        json_object_put(ja);
        return NULL;
    }

    ret = json_object_object_add(ja, "addr", jaddr);
    if (ret != 0) {
        log("Error adding JSON address");
        json_object_put(ja);
        return NULL;
    }
#else
    json_object_object_add(ja, "space", jspace);
    json_object_object_add(ja, "addr", jaddr);
#endif
    return ja;
}

static struct sg_address *json_to_address(json_object *a)
{
    char *addr = NULL;
    char *space = NULL;
    struct sg_address *sa;

    if (a == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    json_object_object_foreach(a, key, val) {
        if (json_object_get_type(val) == json_type_string) {
            if (strcmp(key, "space") == 0) {
                space = strdup(json_object_get_string(val));
            }
            if (strcmp(key, "addr") == 0) {
                addr = strdup(json_object_get_string(val));
            }
        }
    }

    if (space == NULL || addr == NULL) {
        log("Failed to parse JSON address struct");
        free(space);
        free(addr);
        return NULL;
    }

    sa = sg_address_create(space, addr);
    free(space);
    free(addr);
    return sa;
}

/*
 * Data handling functions
 *
 * Note: aways encode blob as base64.
 */
static json_object *data_to_json(const struct sg_data *d)
{
    json_object *jd;
    json_object *jtag;
    json_object *jblob;
    char *b64;

    if (d == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    b64 = g_base64_encode(d->blob, d->len);
    if (b64 == NULL) {
        log("Error base64 encoding data entry");
        return NULL;
    }

    jd = json_object_new_object();
    if (jd == NULL) {
        log("Error allocating JSON data object");
        g_free(b64);
        return NULL;
    }

    jtag = json_object_new_string(d->tag);
    if (jtag == NULL) {
        log("Error allocating JSON data tag string");
        json_object_put(jd);
        g_free(b64);
        return NULL;
    }

    jblob = json_object_new_string(b64);
    if (jblob == NULL) {
        log("Error allocating JSON blob");
        json_object_put(jd);
        g_free(b64);
        return NULL;
    }
    g_free(b64);

#if JSON_C_MINOR_VERSION > 12
    int ret;

    ret = json_object_object_add(jd, "tag", jtag);
    if (ret != 0) {
        log("Error adding JSON data tag");
        json_object_put(jd);
        return NULL;
    }

    ret = json_object_object_add(jd, "blob", jblob);
    if (ret != 0) {
        log("Error adding JSON data blob");
        json_object_put(jd);
        return NULL;
    }
#else
    json_object_object_add(jd, "tag", jtag);
    json_object_object_add(jd, "blob", jblob);
#endif
    return jd;
}

static struct sg_data *json_to_data(json_object *d)
{
    char *tag = NULL;
    char *b64 = NULL;
    uint8_t *blob = NULL;
    size_t len = 0;
    struct sg_data *sd;

    if (d == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    json_object_object_foreach(d, key, val) {
        if (json_object_get_type(val) == json_type_string) {
            if (strcmp(key, "tag") == 0) {
                tag = strdup(json_object_get_string(val));
            }
            if (strcmp(key, "blob") == 0) {
                b64 = strdup(json_object_get_string(val));
            }
        }
    }

    if (tag == NULL || b64 == NULL) {
        log("Failed to parse JSON address struct");
        free(tag);
        free(b64);
        return NULL;
    }

    blob = g_base64_decode(b64, &len);
    if (blob == NULL) {
        log("Error b64 decoding JSON data blob");
        free(tag);
        free(b64);
        return NULL;
    }
    free(b64);

    sd = sg_data_create(tag,blob,len);
    g_free(blob);
    free(tag);
    return sd;
}

/*
 * node handling functions
 */
static json_object *node_to_json(const struct sg_node *n)
{
    json_object *jn;
    json_object *ja;
    json_object *jdata_array;
    json_object *jdata;
    json_object *jlabel_array;
    json_object *jlabel;
    GList *iter;

    if (n == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    jn = json_object_new_object();
    if (jn == NULL) {
        log("Error allocating JSON node object\n");
        return NULL;
    }

    ja = address_to_json(&n->a);
    if (ja == NULL) {
        json_object_put(jn);
        return NULL;
    }

    jdata_array = json_object_new_array();
    if (jdata_array == NULL) {
        log("Error allocating JSON node data array\n");
        json_object_put(jn);
        json_object_put(ja);
        return NULL;
    }

    for (iter = g_list_first(n->data); iter && iter->data;
            iter = iter->next) {
        struct sg_data *d = (struct sg_data *)iter->data;
        jdata = data_to_json(d);
        if (jdata != NULL) {
            //XXX silent error pre 0.13.x
            json_object_array_add(jdata_array, jdata);
        }
    }

    jlabel_array = json_object_new_array();
    if (jlabel_array == NULL) {
        log("Error allocating JSON node label array\n");
        json_object_put(jn);
        json_object_put(ja);
        json_object_put(jdata_array);
        return NULL;
    }

    for (iter = g_list_first(n->labels); iter && iter->data;
            iter = iter->next) {
        char *l = (char *)iter->data;
        jlabel = json_object_new_string(l);
        if (jlabel != NULL) {
            //XXX silent error pre 0.13.x
            json_object_array_add(jlabel_array, jlabel);
        }
    }

#if JSON_C_MINOR_VERSION > 12
    int ret;

    ret = json_object_object_add(jn, "address", ja);
    if (ret != 0) {
        log("Error adding JSON node address");
        json_object_put(jn);
        json_object_put(ja);
        json_object_put(jdata_array);
        json_object_put(jlabel_array);
        return NULL;
    }

    ret = json_object_object_add(jn, "data", jdata_array);
    if (ret != 0) {
        log("Error adding JSON node data array");
        json_object_put(jn);
        json_object_put(jdata_array);
        json_object_put(jlabel_array);
        return NULL;
    }

    ret = json_object_object_add(jn, "labels", jlabel_array);
    if (ret != 0) {
        log("Error adding JSON node data array");
        json_object_put(jn);
        json_object_put(jlabel_array);
        return NULL;
    }
#else
    json_object_object_add(jn, "address", ja);
    json_object_object_add(jn, "data", jdata_array);
    json_object_object_add(jn, "labels", jlabel_array);
#endif
    return jn;
}

/*
 * JSON array to GList utility function for strings
 */
static GList *json_array_to_string_list(json_object *array)
{
    GList *strs = NULL;
    int arraylen;
    int i;

    if (json_object_get_type(array) != json_type_array) {
        log("Non-array passed to array parser\n");
        return NULL;
    }

    arraylen = json_object_array_length(array);

    for(i=0; i<arraylen; i++) {
        json_object *tmp = json_object_array_get_idx(array, i);
        const char *str = json_object_get_string(tmp);
        if (str != NULL) {
            char *stmp = strdup(str);
            if (stmp != NULL) {
                strs = g_list_append(strs, stmp);
            }
        }
    }

    return strs;
}

ARRAY_TO_LIST_TYPE(data);

static struct sg_node *json_to_node(json_object *n)
{
    struct sg_node *sn;
    struct sg_address *a = NULL;
    GList *data = NULL;
    GList *labels = NULL;

    if (n == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    json_object_object_foreach(n, key, val) {
        if (json_object_get_type(val) == json_type_object &&
                strcmp(key, "address") == 0) {
            a = json_to_address(val);
        }

        if (json_object_get_type(val) == json_type_array) {
            if (strcmp(key, "data") == 0) {
                data = json_array_to_data_list(val);
            }
            if (strcmp(key, "labels") == 0) {
                labels = json_array_to_string_list(val);
            }
        }
    }

    if (a == NULL) {
        log("Failed to parse JSON address struct");
        g_list_free_full(data, (void (*)(void *))sg_free_data);
        g_list_free_full(labels, free);
        return NULL;
    }

    sn = sg_node_create(a->space, a->addr);
    if (!sn) {
        log("Error allocating JSON node");
        sg_free_address(a);
        g_list_free_full(data, (void (*)(void *))sg_free_data);
        g_list_free_full(labels, free);
        return NULL;
    }
    sg_free_address(a);

    sn->data = data;
    sn->labels = labels;

    return sn;
}

/*
 * edge handling functions
 */
static json_object *edge_to_json(const struct sg_edge *e)
{
    json_object *je;
    json_object *jsrc;
    json_object *jdest;
    json_object *jlabel_array;
    json_object *jlabel;
    GList *iter;

    if (e == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }


    je = json_object_new_object();
    if (je == NULL) {
        log("Error allocating JSON node object\n");
        return NULL;
    }

    jsrc = address_to_json(&e->source);
    if (jsrc == NULL) {
        json_object_put(je);
        return NULL;
    }

    jdest = address_to_json(&e->dest);
    if (jsrc == NULL) {
        json_object_put(je);
        json_object_put(jsrc);
        return NULL;
    }

    jlabel_array = json_object_new_array();
    if (jlabel_array == NULL) {
        log("Error allocating JSON node label array\n");
        json_object_put(je);
        json_object_put(jsrc);
        json_object_put(jdest);
        return NULL;
    }

    for (iter = g_list_first(e->labels); iter && iter->data;
            iter = iter->next) {
        char *l = (char *)iter->data;
        jlabel = json_object_new_string(l);
        if (jlabel != NULL) {
            //XXX silent error pre 0.13.x
            json_object_array_add(jlabel_array, jlabel);
        }
    }

#if JSON_C_MINOR_VERSION > 12
    int ret;

    ret = json_object_object_add(je, "source", jsrc);
    if (ret != 0) {
        log("Error adding JSON edge src address");
        json_object_put(je);
        json_object_put(jsrc);
        json_object_put(jdest);
        json_object_put(jlabel_array);
        return NULL;
    }

    ret = json_object_object_add(je, "dest", jdest);
    if (ret != 0) {
        log("Error adding JSON edge dest address");
        json_object_put(je);
        json_object_put(jdest);
        json_object_put(jlabel_array);
        return NULL;
    }

    ret = json_object_object_add(je, "labels", jlabel_array);
    if (ret != 0) {
        log("Error adding JSON edge labels array");
        json_object_put(je);
        json_object_put(jlabel_array);
        return NULL;
    }

#else
    json_object_object_add(je, "source", jsrc);
    json_object_object_add(je, "dest", jdest);
    json_object_object_add(je, "labels", jlabel_array);
#endif
    return je;
}


static struct sg_edge *json_to_edge(json_object *e)
{
    struct sg_edge *se;
    struct sg_address *src = NULL;
    struct sg_address *dest = NULL;
    GList *labels = NULL;

    if (e == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    json_object_object_foreach(e, key, val) {
        if (json_object_get_type(val) == json_type_object &&
                strcmp(key, "source") == 0) {
            src = json_to_address(val);
        }

        if (json_object_get_type(val) == json_type_object &&
                strcmp(key, "dest") == 0) {
            dest = json_to_address(val);
        }

        if (json_object_get_type(val) == json_type_array) {
            if (strcmp(key, "labels") == 0) {
                labels = json_array_to_string_list(val);
            }
        }
    }

    if (src == NULL || dest == NULL) {
        log("Failed to parse JSON address structs for edge");
        sg_free_address(src);
        sg_free_address(dest);
        g_list_free_full(labels, free);
        return NULL;
    }

    se = sg_edge_create_from_addr(src, dest);
    if (!se) {
        log("Error allocating JSON edge");
        sg_free_address(src);
        sg_free_address(dest);
        g_list_free_full(labels, free);
        return NULL;
    }
    sg_free_address(src);
    sg_free_address(dest);
    se->labels = labels;

    return se;
}

/*
 * graph handling functions
 */

ARRAY_TO_LIST_TYPE(node);
ARRAY_TO_LIST_TYPE(edge);

static json_object *graph_to_json(const struct sg_graph *g)
{
    json_object *jg;
    json_object *jver;
    json_object *jnode_array;
    json_object *jnode;
    json_object *jedge_array;
    json_object *jedge;
    json_object *jlabel_array;
    json_object *jlabel;
    GList *iter;

    if (g == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    jg = json_object_new_object();
    if (jg == NULL) {
        log("Error allocating JSON graph object\n");
        return NULL;
    }

    jver = json_object_new_string(SGRAPH_VERSION);
    if (jver == NULL) {
        log("Error allocating JSON version string");
        json_object_put(jg);
        return NULL;
    }

    jnode_array = json_object_new_array();
    if (jnode_array == NULL) {
        log("Error allocating JSON graph nodes array\n");
        json_object_put(jg);
        return NULL;
    }

    for (iter = g_list_first(g->nodes); iter && iter->data;
            iter = iter->next) {
        struct sg_node *n = (struct sg_node *)iter->data;
        jnode = node_to_json(n);
        if (jnode != NULL) {
            //XXX silent error pre 0.13.x
            json_object_array_add(jnode_array, jnode);
        }
    }

    jedge_array = json_object_new_array();
    if (jedge_array == NULL) {
        log("Error allocating JSON graph edges array\n");
        json_object_put(jg);
        json_object_put(jnode_array);
        return NULL;
    }

    for (iter = g_list_first(g->edges); iter && iter->data;
            iter = iter->next) {
        struct sg_edge *n = (struct sg_edge *)iter->data;
        jedge = edge_to_json(n);
        if (jedge != NULL) {
            //XXX silent error pre 0.13.x
            json_object_array_add(jedge_array, jedge);
        }
    }

    jlabel_array = json_object_new_array();
    if (jlabel_array == NULL) {
        log("Error allocating JSON graph label array\n");
        json_object_put(jg);
        json_object_put(jnode_array);
        json_object_put(jedge_array);
        return NULL;
    }

    for (iter = g_list_first(g->labels); iter && iter->data;
            iter = iter->next) {
        char *l = (char *)iter->data;
        jlabel = json_object_new_string(l);
        if (jlabel != NULL) {
            //XXX silent error pre 0.13.x
            json_object_array_add(jlabel_array, jlabel);
        }
    }

#if JSON_C_MINOR_VERSION > 12
    int ret;

    ret = json_object_object_add(jg, "nodes", jnode_array);
    if (ret != 0) {
        log("Error adding JSON graph nodes array");
        json_object_put(jg);
        json_object_put(jnode_array);
        json_object_put(jedge_array);
        json_object_put(jlabel_array);
        return NULL;
    }

    ret = json_object_object_add(jg, "edges", jedge_array);
    if (ret != 0) {
        log("Error adding JSON graph edges array");
        json_object_put(jg);
        json_object_put(jedge_array);
        json_object_put(jlabel_array);
        return NULL;
    }

    ret = json_object_object_add(jg, "labels", jlabel_array);
    if (ret != 0) {
        log("Error adding JSON graph labels array");
        json_object_put(jg);
        json_object_put(jlabel_array);
        return NULL;
    }

    ret = json_object_object_add(jg, "version", jver);
    if (ret != 0) {
        log("Error adding JSON version");
        json_object_put(jg);
        return NULL;
    }



#else
    json_object_object_add(jg, "version", jver);
    json_object_object_add(jg, "nodes", jnode_array);
    json_object_object_add(jg, "edges", jedge_array);
    json_object_object_add(jg, "labels", jlabel_array);
#endif
    return jg;
}

static struct sg_graph *json_to_graph(json_object *g)
{
    struct sg_graph *sg;
    GList *nodes = NULL;
    GList *edges = NULL;
    GList *labels = NULL;

    if (g == NULL) {
        log("Invalid arguments\n");
        return NULL;
    }

    json_object_object_foreach(g, key, val) {
        if (json_object_get_type(val) == json_type_array) {
            if (strcmp(key, "nodes") == 0) {
                nodes = json_array_to_node_list(val);
            }
            if (strcmp(key, "edges") == 0) {
                edges = json_array_to_edge_list(val);
            }
            if (strcmp(key, "labels") == 0) {
                labels = json_array_to_string_list(val);
            }
        }
    }

    sg = sg_graph_create();
    if (!sg) {
        log("Error allocating graph");
        g_list_free_full(nodes, (void (*)(void *))sg_free_node);
        g_list_free_full(edges, (void (*)(void *))sg_free_edge);
        g_list_free_full(labels, free);
        return NULL;
    }
    sg->nodes = nodes;
    sg->edges = edges;
    sg->labels = labels;

    return sg;
}

char *sg_graph_to_string(struct sg_graph *g)
{
    char *tmp;

    if (g == NULL) {
        return NULL;
    }

    json_object *jg = graph_to_json(g);
    tmp = strdup(json_object_to_json_string(jg));
    json_object_put(jg);
    return tmp;
}

struct sg_graph *sg_string_to_graph(const char *str)
{
    if (str == NULL) {
        return NULL;
    }
    json_object *json = json_tokener_parse(str);
    struct sg_graph *ret = json_to_graph(json);
    json_object_put(json);
    return ret;
}
