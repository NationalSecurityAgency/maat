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

/**
 * graph-serialization.c: Loading and parsing of measurement graph in
 * the GraphML XML format.
 */
#include <config.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>

#include <util/util.h>
#include <util/xml_util.h>
#include <util/keyvalue.h>
#include <util/base64.h>
#include <inttypes.h>

#include <graph-core.h>
#include "graph-fs-private.h"

#include <measurement_spec/find_types.h>
#include <common/taint.h>

/* Serializing */

/**
 * Internal function to add a measurement_node as an XML node to the
 * parent node. Used by serialize_measurement_graph().
 */
static int xml_add_node(xmlNode *node, char* id_value,
                        measurement_graph *g, node_id_t mn)
{
    int numchar = 0;
    char buf[256];
    measurement_iterator *iter;
    xmlNode *tmp, *addr_node, *node_meas;
    char *serialized_address;

    target_type *type = measurement_node_get_target_type(g, mn);
    address *address;
    if(type == NULL) {
        dlog(1, "Failed to get target type of measurement node\n");
        return -1;
    }

    address  = measurement_node_get_address(g, mn);
    if(address == NULL) {
        dlog(1, "Failed to get address of measurement node\n");
        return -1;
    }

    tmp = xmlNewTextChild(node, NULL, (xmlChar*)"node", NULL);
    xmlNewProp(tmp, (xmlChar*)"id", (xmlChar*)id_value);

    xmlNewProp(tmp, (xmlChar*)"type", (xmlChar*)type->name);
    numchar = snprintf(buf,256,"%"PRIx32,type->magic);
    if(numchar > 0) {
        xmlNewProp(tmp, (xmlChar*)"type_magic",(xmlChar*)buf);
    }

    serialized_address = serialize_address(address);
    if(serialized_address == NULL) {
        dlog(1, "Failed to serialize measurement address\n");
        free_address(address);
        return -1;
    }

    addr_node = xmlNewTextChild(tmp, NULL, (xmlChar*)"address",
                                (xmlChar*)serialized_address);
    free(serialized_address);

    numchar = snprintf(buf,256,"%"PRIx32,address->space->magic);
    if(numchar > 0) {
        xmlNewProp(addr_node, (xmlChar*)"space", (xmlChar*)buf);
    }
    free_address(address);
    address = NULL;

    for(iter = measurement_node_iterate_data(g, mn); iter != NULL ;
            iter = measurement_iterator_next(iter)) {
        magic_t mtyp        = measurement_iterator_get_type(iter);
        measurement_type *typ = find_measurement_type(mtyp);
        marshalled_data *md;

        if(typ == NULL) {
            continue;
        }

        if(measurement_node_get_data(g, mn, typ, &md) != 0) {
            continue;
        }
        node_meas = xmlNewTextChild(tmp, NULL, (xmlChar*)"measurement", NULL);
        //snprintf(buf,256,"%zu",md->length);
        numchar = snprintf(buf,256,"%zd",md->marshalled_data_length);
        if(numchar > 0) {
            xmlNewProp(node_meas,(xmlChar*)"data_size",(xmlChar*)buf);
            xmlNewProp(node_meas,(xmlChar*)"meas_data",(xmlChar*)md->marshalled_data);
        }

        numchar = snprintf(buf,256,"%"PRIx32,md->unmarshalled_type);
        if(numchar > 0) {
            xmlNewProp(node_meas,(xmlChar*)"meas_type_magic",(xmlChar*)buf);
        }

        xmlNewProp(node_meas,(xmlChar*)"meas_type_name",(xmlChar*)md->meas_data.type->name);

        free_measurement_data(&md->meas_data);
    }
    return 0;
}

/**
 * Internal function to add a measurement_edge as an XML node to the
 * parent node. Used by serialize_measurement_graph().
 */
static int xml_add_edge(xmlNode *node,
                        char* s_id_value,
                        char *label,
                        char* d_id_value)
{
    xmlNode *tmp;

    tmp = xmlNewTextChild(node, NULL, (xmlChar*)"edge", NULL);
    if(label) {
        xmlNewProp(tmp, (xmlChar*)"label", (xmlChar*)label);
    }
    xmlNewProp(tmp, (xmlChar*)"source", (xmlChar*)s_id_value);
    xmlNewProp(tmp, (xmlChar*)"target", (xmlChar*)d_id_value);
    return 0;
}

/**
 * Serialize a measurement graph to a NULL terminated string
 * Returns a char * that needs to be freed.
 */
int serialize_measurement_graph(measurement_graph *g, size_t *sz,
                                unsigned char **serial)
{
    dlog(1, "Serializing Measurement Graph\n");
    node_id_t node_id_max;
    xmlDoc *doc;
    xmlNode *root, *node;
    int32_t size;
    xmlChar *tmp;
    node_id_t nr_nodes = 0;
    xmlAttrPtr docprop = NULL;

    node_id_max = max_node_id(g);
    if(node_id_max  == INVALID_NODE_ID) {
        dlog(0, "Unable to get max node from the graph\n");
        return -1;
    }

    node_id_t node_id_map[node_id_max]; /* FIXME: this increments the node id on each call */

    xmlKeepBlanksDefault(0);
    doc = xmlNewDoc((xmlChar*)"1.0");

    memset(node_id_map, -1, node_id_max*sizeof(node_id_map[0]));

    if(!doc) {
        dlog( 1, "XML: null doc\n");
        return -1;
    }
    docprop = xmlNewDocProp(doc,(xmlChar*)"encoding",(xmlChar*)"UTF-8");
    root = xmlNewNode(NULL, (xmlChar*)"graphml");
    if(!root) {
        dlog(1, "XML: null root\n");
        return -1;
    }
    xmlDocSetRootElement(doc, root);
    xmlNewProp(root, (xmlChar*)"xmlns",(xmlChar*)"http://graphdrawing.org/xmlns");
    xmlNewProp(root, (xmlChar*)"xmlns:xsi",(xmlChar*)"http://www.w3.org/2001/XMLSchema-instance");
    xmlNewProp(root, (xmlChar*)"xsi:schemaLocation",
               (xmlChar*)"http://www.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd");


    node = xmlNewTextChild(root, NULL, (xmlChar*)"graph", NULL);
    xmlNewProp(node, (xmlChar*)"mgversion", (xmlChar*)"0");
    xmlNewProp(node, (xmlChar*)"id",(xmlChar*)"G");
    xmlNewProp(node, (xmlChar*)"edgedefault",(xmlChar*)"undirected");
    //compact edge and node vectors

    do {
        node_iterator *n_iter;
        dlog(6, "Serializing nodes\n");
        for(n_iter = measurement_graph_iterate_nodes(g); n_iter != NULL; n_iter = node_iterator_next(n_iter)) {
            node_id_t n = node_iterator_get(n_iter);
            if(n != INVALID_NODE_ID) {
                node_id_str idstr;
                str_of_node_id(nr_nodes, idstr);
                node_id_map[n] = nr_nodes;
                nr_nodes++;
                if(xml_add_node(node, idstr, g, n) != 0) {
                    dlog(1, "Error failed to serialize node "ID_FMT"\n", nr_nodes-1);
                }
            }
        }
    } while(0);


    do {
        edge_iterator *e_iter;
        dlog(6, "Serializing edges\n");
        for(e_iter = measurement_graph_iterate_edges(g); e_iter != NULL;
                e_iter = edge_iterator_next(e_iter)) {
            edge_id_t e = edge_iterator_get(e_iter);
            if(e != INVALID_EDGE_ID) {
                node_id_t s_node_id, d_node_id;
                node_id_str s_node_id_str, d_node_id_str;
                char *label;

                s_node_id = measurement_edge_get_source(g, e);
                d_node_id = measurement_edge_get_destination(g, e);

                if(s_node_id == INVALID_NODE_ID || s_node_id >= node_id_max ||
                        d_node_id ==INVALID_NODE_ID || d_node_id >= node_id_max) {
                    dlog(1, "Edge has invalid source/destination node\n");
                    continue;
                }

                s_node_id = node_id_map[s_node_id];
                d_node_id = node_id_map[d_node_id];
                if(s_node_id == INVALID_NODE_ID || s_node_id >= nr_nodes ||
                        d_node_id ==INVALID_NODE_ID || d_node_id >= nr_nodes) {
                    dlog(1, "Edge has invalid source/destination node\n");
                    continue;
                }

                str_of_node_id(s_node_id, s_node_id_str);
                str_of_node_id(d_node_id, d_node_id_str);

                label = measurement_edge_get_label(g, e);

                dlog(5, "creating edge %s -> %s (label = %s)\n",
                     s_node_id_str, d_node_id_str, label ? label : "");

                xml_add_edge(node, s_node_id_str, label, d_node_id_str);
                free(label);
            }
        }
    } while(0);

    xmlDocDumpFormatMemory(doc, &tmp, &size, 1);
    xmlFreeProp(docprop); /* for some reason this doesn't get freed with the doc. */
    xmlFreeDoc(doc);
    if(size < 0) {
        dlog(1, "Failed to serialize graph xml document.");
        free(tmp);
        return -1;
    }

    *serial = tmp;
    *sz =  (size_t)size;
    return 0;
}

/* Loading */

/**
   internal function to extract a measurement_edge structure from an
   xmlNode (used by parse_measurement_graph())
*/
static edge_id_t parse_edge(unsigned long mgversion UNUSED,
                            struct measurement_graph *g, xmlNode *n,
                            node_id_t *node_id_map, size_t nr_nodes)
{
    char *label;
    char *src_id_str = NULL;
    char *dst_id_str = NULL;
    node_id_t src_id;
    node_id_t dst_id;
    edge_id_t ret;

    label = xmlGetPropASCII(n, "label");
    if((src_id_str = xmlGetPropASCII(n, "source")) == NULL) {
        dlog(1, "Edge has no source attribute\n");
        goto error;
    }

    src_id = node_id_of_str(src_id_str);
    if(src_id == INVALID_NODE_ID || src_id >= nr_nodes ||
            ((src_id = node_id_map[src_id]) == INVALID_NODE_ID)) {
        dlog(1, "Invalid source %s for edge\n", src_id_str);
        goto error;
    }

    if((dst_id_str = xmlGetPropASCII(n, "target")) == NULL) {
        dlog(1, "Edge has no target attribute\n");
        goto error;
    }
    dst_id = node_id_of_str(dst_id_str);

    if(dst_id == INVALID_NODE_ID || dst_id >= nr_nodes ||
            ((dst_id = node_id_map[dst_id]) == INVALID_NODE_ID)) {
        dlog(1, "Invalid destination %s for edge\n", dst_id_str);
        goto error;
    }

    if(measurement_graph_add_edge(g, src_id, label, dst_id, &ret) != 0) {
        dlog(1, "Failed to add edge ("ID_FMT"-> "ID_FMT")\n", src_id, dst_id);
        goto error;
    }

    xmlFree(src_id_str);
    xmlFree(dst_id_str);
    xmlFree(label);
    return ret;

error:
    xmlFree(src_id_str);
    xmlFree(dst_id_str);
    xmlFree(label);
    return INVALID_EDGE_ID;
}

/**
   internal function to extract a measurement_data structure from an
   xmlNode (used by parse_node())
*/
static struct marshalled_data *parse_measurement(unsigned long mgversion UNUSED,
        xmlNode *n)
{
    marshalled_data *md  = (marshalled_data *)alloc_measurement_data(&marshalled_data_measurement_type);
    unsigned long m;
    char *data_size;
    char *type_magic;
    char *strend;

    if(md == NULL) {
        dlog(1, "Malloc error\n");
        goto error_cleanup;
    }

    /* this doesn't get used */
    if((data_size = xmlGetPropASCII(n, "data_size")) == NULL) {
        dlog(1, "Measurement data has no size attribute\n");
        goto error_cleanup;
    }
    errno = 0;
    md->marshalled_data_length = strtoul(data_size, &strend, 10);
    if(errno != 0 || *strend != '\0') {
        dlog(1, "Measurement data has invalid size attribute\n");
        goto error_cleanup;
    }
    xmlFree(data_size);

    md->marshalled_data = xmlGetPropASCII(n, "meas_data");
    if(md->marshalled_data == NULL) {
        dlog(1, "Measurement data has no data property!\n");
        goto error_cleanup;
    }

    if(strlen(md->marshalled_data) != md->marshalled_data_length-1) {
        dlog(1, "Measurement data does not match advertised length. Got %zd expected %zd\n",
             strlen(md->marshalled_data), md->marshalled_data_length);
        goto error_cleanup;
    }

    if((type_magic = xmlGetPropASCII(n, "meas_type_magic")) == NULL) {
        dlog(1, "Measurement data has no type magic\n");
        goto error_cleanup;
    }

    m = strtoul(type_magic, NULL, 16);
    xmlFree(type_magic);
    if(m > MAGIC_MAX) {
        dlog(1, "Measurement type magic %s is too large\n", type_magic);
        goto error_cleanup;
    }
    md->unmarshalled_type = (magic_t)m;
    return md;

error_cleanup:
    free_measurement_data(&md->meas_data);
    return NULL;
}

/**
   internal function to extract a measurement_variable structure from
   an xmlNode (used by parse_measurement_graph())
*/
static measurement_variable *parse_node(unsigned long mgversion UNUSED,
                                        xmlNode *n, node_id_t *id)
{
    magic_t addr_magic;
    address_space *as;
    xmlNode *addr_node	        = NULL, *tmp;
    measurement_variable *var	= NULL;
    char *tmpstr		= NULL;
    char *idstr			= NULL;

    if((idstr = xmlGetPropASCII(n, "id")) == NULL) {
        dlog(1, "Error: no node id\n");
        goto error;
    }

    if((*id = node_id_of_str(idstr)) == INVALID_NODE_ID) {
        dlog(1, "Error: invalid node id\n");
        goto error;
    }

    for(tmp = n->children; tmp; tmp = tmp->next) {
        char *tmpname = validate_cstring_ascii(tmp->name, SIZE_MAX);
        if(tmpname != NULL && strcmp(tmpname, "address")==0) {
            addr_node = tmp;
            break;
        }
    }

    if(addr_node == NULL) {
        dlog(1, "Parse node could not find address tag in node\n");
        goto error;
    }

    var = malloc(sizeof(measurement_variable));
    if(var == NULL) {
        dlog(1, "Malloc fail\n");
        goto error;
    }

    if((tmpstr = xmlGetPropASCII(addr_node, "space")) == NULL) {
        dlog(1, "Node has no address space\n");
        goto error;
    }
    addr_magic = ((uint32_t)strtoul(tmpstr, NULL, 16));
    xmlFree(tmpstr);

    as = find_address_space(addr_magic);

    if(as == NULL) {
        dlog(1, "Error, failed to find address space by magic number %"PRIx32"\n",
             addr_magic);
        goto error;
    }

    if((tmpstr = xmlGetPropASCII(n, "type_magic")) == NULL) {
        dlog(1, "Node has no type magic\n");
        goto error;
    }
    var->type = find_target_type((uint32_t)strtoul(tmpstr, NULL, 16));
    xmlFree(tmpstr);

    if(var->type == NULL) {
        dlog(1, "find_target_type returned NULL\n");
        goto error;
    }

    if(((tmpstr = xmlGetPropASCII(n, "type")) == NULL) ||
            (strcmp(var->type->name, tmpstr) != 0)) {
        dlog(1, "target type name found is different then stored in xml (%s , %s)\n",
             var->type->name, tmpstr ? tmpstr : "(null)");
        xmlFree(tmpstr);
        goto error;
    }
    xmlFree(tmpstr);

    tmpstr = (char*)xmlNodeGetContentASCII(addr_node);
    if(tmpstr == NULL) {
        dlog(1, "Graph node address element has no content.\n");
        goto error;
    }
    var->address = parse_address(as, tmpstr, strlen(tmpstr)+1);
    xmlFree(tmpstr);

    if(var->address == NULL) {
        dlog(1, "parse_address returned NULL\n");
        goto error;
    }
    free(idstr);
    return var;

error:
    free(idstr);
    free(var);
    *id = INVALID_NODE_ID;
    return NULL;
}


/**
   Parse a serialized measurement graph.

   @s contains the serialized XML graph with size @size (NULL
   determination is not assumed).

   Returns a pointer to the graph on success or NULL on failure.
*/
measurement_graph *parse_measurement_graph(char *s, size_t size)
{
    xmlNode *root, *node, *iter, *meas;
    struct measurement_graph *ret_graph = NULL;
    xmlDoc *doc = NULL;
    node_id_t *node_map = NULL;
    node_id_t node_map_capacity;
    unsigned long mgversion = 0;

    dlog(6, "Parse Measurement Graph\n");

    if(size > INT_MAX) {
        dlog(1, "Error: buffer of size %zd is too large to parse\n", size);
        goto error;
    }

    ret_graph = create_measurement_graph(NULL);
    if(ret_graph == NULL ) {
        dlog(1, "Error creating new measurement graph (Parse)\n");
        goto error;
    }

    if((node_map = malloc(sizeof(node_id_t)*64)) == NULL) {
        dlog(1, "Error: failed to allocate node map when parsing measurement graph\b");
        goto error;
    }
    node_map_capacity = 64;

    /* FIXME: we should do schema validation here */
    if((doc = xmlReadMemory(s, (int)size, NULL, NULL, XML_PARSE_HUGE)) == NULL) {
        dlog(1, "Error Parsing MG: doc is null\n");
    }

    if((root = xmlDocGetRootElement(doc)) == NULL) {
        dlog(1, "Error Parsing MG: root is null\n");
        goto error;
    }

    /* Something fragile about the serialized graphs.
     *  Sometimes root->children is graph, sometimes it's text */
    //TODO: handle case where multiple graphs exist in graphml document
    node = NULL;


    if(root->children) {
        char *childname = validate_cstring_ascii(root->children->name, SIZE_MAX);
        if (childname != NULL && strcmp(childname, "graph")==0) {
            node = root->children;
        }

        if(root->children->next) {
            childname = validate_cstring_ascii(root->children->next->name, SIZE_MAX);
            if (childname != NULL && strcmp(childname, "graph")==0) {
                node = root->children->next;
            }
        }
    }

    if(!node) {
        dlog(1, "Error Parsing MG: node is null\n");
        goto error;
    }

    char *mgversionstr = xmlGetPropASCII(node, "mgversion");
    if(mgversionstr == NULL) {
        mgversion = 0;
    } else {
        char *endptr;
        mgversion = strtoul(mgversionstr, &endptr, 10);
        if(mgversion == ULONG_MAX || *endptr != '\0') {
            dlog(4, "Warning: invalid version specifier in measurement graph: \"%s\"",
                 mgversionstr);
            mgversion = 0;
        }
        free(mgversionstr);
    }

    for(iter = xmlFirstElementChild(node); iter != NULL; iter = xmlNextElementSibling(iter)) {
        char *itername = validate_cstring_ascii(iter->name, SIZE_MAX);
        if(itername == NULL) {
            continue;
        }

        if(strcmp(itername, "node")==0) {
            dlog(5, "Parsing new node\n");
            node_id_t node;
            node_id_t original_id;
            measurement_variable *var = parse_node(mgversion, iter, &original_id);

            if(var == NULL) {
                dlog(1, "Null measurement variable\n");
                goto error;
            }

            if(original_id >= node_map_capacity) {
                node_id_t *tmp;
                if(original_id >= NODE_ID_MAX) {
                    dlog(1, "Error: node id "ID_FMT" out of bounds\n", original_id);
                    free_measurement_variable(var);
                    goto error;
                }
                if(original_id >= NODE_ID_MAX/2) {
                    node_map_capacity = original_id + 1;
                } else {
                    node_map_capacity = 2*original_id;
                }

                if((tmp = realloc(node_map, (size_t)node_map_capacity*sizeof(node_id_t))) == NULL) {
                    dlog(1, "Error parsing graph: too many nodes (allocation failed)!\n");
                    free_measurement_variable(var);
                    goto error;
                }
                node_map = tmp;
            }

            if(measurement_graph_add_node(ret_graph, var, NULL, &node)<0) {
                dlog(1, "Parse_node: add node failed\n");
                free_measurement_variable(var);
                goto error;
            }
            node_map[original_id] = node;

            free_measurement_variable(var);
            if(node == INVALID_NODE_ID) { //generate measurement_node failed
                dlog(1, "Error Parsing MG: measurment_node is null\n");
                goto error;
            }
            for(meas = iter->children; meas != NULL; meas = meas->next) {
                char *measname = validate_cstring_ascii(meas->name, SIZE_MAX);

                if(measname == NULL || strcmp(measname, "measurement") != 0) {
                    continue;
                }

                dlog(6, "Parsing measurement in node\n");
                //create new measurement data node
                marshalled_data *md = parse_measurement(mgversion, meas);
                if(md != NULL) {
                    measurement_node_add_data(ret_graph, node, md);
                    free_measurement_data(&md->meas_data);
                }
            }
        } else if(strcmp(itername, "edge")==0) {
            dlog(5, "Parsing new edge\n");
            edge_id_t edge = parse_edge(mgversion, ret_graph, iter, node_map, (size_t)node_map_capacity);
            if(edge == INVALID_EDGE_ID) {
                dlog(1, "Error parsing edge\n");
                goto error;
            }
        } else if(strcmp(itername, "text")==0) {
        } else {
            dlog(1, "Error parsing graph: a non-node/edge: %s\n",iter->name);
            goto error;
        }
    }
    dlog(6, "Done parsing measurement graph\n");
    xmlFreeDoc(doc);
    free(node_map);
    return ret_graph;

error:
    free(node_map);
    xmlFreeDoc(doc);
    destroy_measurement_graph(ret_graph);
    return NULL;
}
