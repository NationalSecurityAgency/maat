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

#include "config.h"
#include <stdio.h>
#include "graph-core.h"
#include <measurement_spec/find_types.h>
#include <measurement_spec/meas_spec-api.h>
#include <ctype.h>

#ifdef HAVE_LIBREADLINE
#  if defined(HAVE_READLINE_READLINE_H)
#    include <readline/readline.h>
#  elif defined(HAVE_READLINE_H)
#    include <readline.h>
#  else /* !defined(HAVE_READLINE_H) */
extern char *readline (char *prompt);
#  endif /* !defined(HAVE_READLINE_H) */
#else /* !defined(HAVE_READLINE_READLINE_H) */
/* no readline */
static char *readline(char *prompt)
{
    char *buf = NULL;
    size_t bufsz = 0;
    printf("%s", prompt);
    ssize_t read = getline(&buf, &bufsz, stdin);
    if(read < 0) {
        free(buf);
        return NULL;
    }
    return buf;
}
#endif /* HAVE_LIBREADLINE */

#ifdef HAVE_READLINE_HISTORY
#  if defined(HAVE_READLINE_HISTORY_H)
#    include <readline/history.h>
#  elif defined(HAVE_HISTORY_H)
#    include <history.h>
#  else /* !defined(HAVE_HISTORY_H) */
extern void add_history ();
#  endif /* defined(HAVE_READLINE_HISTORY_H) */
#else
/* no history */
static inline void add_history(char *line UNUSED) {}
#endif /* HAVE_READLINE_HISTORY */


#include <inttypes.h>
#include "graph-fs-private.h"
#include <dlfcn.h>

#define PROMPT_SIZE 32

/**
 * Copied from ../dummy_types.[ch]
 */

typedef struct simple_address {
    address a;
    uint32_t addr;
} simple_address;

typedef struct dummy_measurement_data {
    measurement_data d;
    uint32_t x;
} dummy_measurement_data;

address *alloc_simple_address();
void free_simple_address(address *a);
address *simple_copy_address(const address *a);
gboolean simple_address_equal(const address *a, const address *b);
guint simple_address_hash(const address *a);
char *serialize_simple_address(const address *a);
address *parse_simple_address(const char *str, size_t);
address *simple_address_from_human_readable(const char *str);

measurement_data *alloc_dummy_measurement_data();
void free_dummy_measurement_data(measurement_data *d);
measurement_data *copy_dummy_measurement_data(measurement_data *d);
int serialize_dummy_measurement_data(measurement_data *d, char **, size_t*);
int unserialize_dummy_measurement_data(char *sd, size_t sd_size, measurement_data **out);
static int dummy_measurement_data_get_feature(measurement_data *d,
        char *feature, GList **out);

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
    .address_hash	= simple_address_hash,
    .human_readable     = serialize_simple_address,
    .from_human_readable = simple_address_from_human_readable
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

measurement_data *alloc_dummy_measurement_data()
{
    dummy_measurement_data *d = malloc(sizeof(*d));
    if(d) {
        d->d.type = &dummy_measurement_type;
        d->x = 0;
    } else {
        return NULL;
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
        ret_val = -1; // XXX: find right errno value !!
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
    if(a) {
        a->a.space = &simple_address_space;
    } else {
        return NULL;
    }
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

address *simple_address_from_human_readable(const char *str)
{
    return parse_simple_address(str, strlen(str)+1);
}

address *simple_copy_address(const address *a)
{
    address *res = alloc_address(&simple_address_space);
    if(res == NULL) {
        return NULL;
    }
    simple_address *sa = container_of(res, simple_address, a);
    sa->addr = ((simple_address *)a)->addr;
    return &sa->a;
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
        char *buf = g_strdup_printf("0x%08"PRIx32,
                                    ((dummy_measurement_data *)d)->x);
        if(buf == NULL) {
            return -1;
        }
        *out = g_list_append(NULL, buf);
        return 0;
    } else {
        dlog(4, "Warning: no such feature \"%s\" for measurement_type dummy\n",
             feature);
    }
    return -1;
}

static void print_edge(measurement_graph *graph, edge_id_t e)
{
    node_id_t src = measurement_edge_get_source(graph, e);
    node_id_t dst = measurement_edge_get_destination(graph, e);
    printf(ID_FMT": "ID_FMT " -> "ID_FMT"\n", e, src, dst);
}

static void print_node(measurement_graph *graph, node_id_t n)
{
    target_type *ttype    = measurement_node_get_target_type(graph, n);
    address *node_address = measurement_node_get_address(graph, n);
    char *address_str     = node_address ? address_human_readable(node_address) : NULL;
    if(ttype && address_str) {
        printf(ID_FMT": (%s *)%s\n", n, ttype->name, address_str);
        free(address_str);
    } else {
        printf(ID_FMT"\n", n);
    }
    free_address(node_address);
}

static void print_address_space(const address_space *s, void *arg UNUSED)
{
    printf(MAGIC_FMT"\t%s\n", s->magic, s->name);
}

static void print_target_type(const target_type *t, void *arg UNUSED)
{
    printf(MAGIC_FMT"\t%s\n", t->magic, t->name);
}

static void print_measurement_type(const measurement_type *t, void *arg UNUSED)
{
    printf(MAGIC_FMT"\t%s\n", t->magic, t->name);
}


int main(int __attribute__((unused)) argc, char __attribute__((unused)) *argv[])
{
    int done=0;
    char prompt[PROMPT_SIZE] = "graph()> ";
    measurement_graph *graph = NULL;

    register_target_type(&dummy_target_type);
    register_measurement_type(&dummy_measurement_type);
    register_address_space(&simple_address_space);

    while(!done) {
        char *line = readline(prompt);
        char *cmd, *args;
        if(!line) {
            fprintf(stderr, "Error: readline() failed.\n");
            break;
        }

        cmd = line;
        while(isspace(*cmd)) cmd++;
        if(cmd[0] == '\0') {
            free(line);
            continue;
        }
        add_history(line);

        if(cmd[0] == '!') {
            if(system(&cmd[1]) != 0) {
                fprintf(stderr, "Warning: command \"%s\" failed\n", &cmd[1]);
            }
            goto next;
        }

        args = cmd;
        while(!isspace(*args) && *args != '\0') {
            args++;
        }
        if(isspace(*args)) {
            *args='\0';
            args++;
        }

        /* we now have a buffer like:
         * line = "   cmd\0arg1 arg2...\0"
         *            ^    ^
         *           cmd  args
         */
        if(strcmp(cmd, "quit") == 0) {
            done = 1;
        } else if(strcmp(cmd, "types") == 0) {
            char *ptr = args;
            void *lib;
            while((!isspace(*ptr)) && (*ptr != '\0')) {
                ptr++;
            }
            if(*ptr == '\0') {
                fprintf(stderr, "Error: types <lib.so> <register>...\n");
                goto next;
            }
            *ptr = '\0';
            lib = dlopen(args, RTLD_NOW | RTLD_LOCAL);
            if(lib == NULL) {
                fprintf(stderr, "dlopen(\"%s\") failed\n", args);
                goto next;
            }
            args = ptr+1;
            while(*args != '\0') {
                int done = 0;
                while(isspace(*args)) {
                    args++;
                    if(*args == '\0') goto next;
                }
                ptr = args+1;
                while((!isspace(*ptr)) && *ptr != '\0') {
                    ptr++;
                }
                if(*ptr == '\0') done = 1;
                *ptr = '\0';
                int (*reg)(void) = dlsym(lib, args);
                if(reg == NULL) {
                    fprintf(stderr, "failed to find symbol %s in library\n", args);
                } else {
                    if(reg() != 0) {
                        fprintf(stderr, "registration function %s returned nonzero\n", args);
                    }
                }
                if(!done) {
                    *ptr = ' ';
                }
                args = ptr;
            }
        } else if(strcmp(cmd, "ls-address-spaces") == 0) {
            foreach_address_space(&print_address_space, NULL);
        } else if(strcmp(cmd, "ls-target-types") == 0) {
            foreach_target_type(&print_target_type, NULL);
        } else if(strcmp(cmd, "ls-measurement-types") == 0) {
            foreach_measurement_type(&print_measurement_type, NULL);
        } else if(strcmp(cmd, "new") == 0) {
            if(graph != NULL) {
                destroy_measurement_graph(graph);
            }
            graph = create_measurement_graph(NULL);
            if(graph != NULL) {
                printf("Graph created at %s\n", graph->path);
                snprintf(prompt, PROMPT_SIZE, "graph(%.22s)> ", graph->path);
            } else {
                fprintf(stderr, "Failed to create graph\n");
            }
        } else if(strcmp(cmd, "map") == 0) {
            if(graph != NULL) {
                destroy_measurement_graph(graph);
                snprintf(prompt, PROMPT_SIZE, "graph()> ");
            }
            char *ptr = args;
            while((!isspace(*ptr)) && (*ptr != '\0')) {
                ptr++;
            }
            *ptr = '\0';
            if(map_measurement_graph(args, &graph) != 0) {
                fprintf(stderr, "Error: map <path>\n");
                graph = NULL;
                goto next;
            }
            snprintf(prompt, PROMPT_SIZE, "graph(%.22s)> ", graph->path);
        } else if(strcmp(cmd, "delete") == 0) {
            destroy_measurement_graph(graph);
            graph = NULL;
            snprintf(prompt, PROMPT_SIZE, "graph()> ");
        } else if(strcmp(cmd, "add-node") == 0) {
            address_space *space;
            magic_t type_magic;
            magic_t space_magic;
            char *addr_str;
            int offset;
            measurement_variable v;
            node_id_t n = INVALID_NODE_ID;
            int rc;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }
            if(sscanf(args, " "MAGIC_FMT" "MAGIC_FMT" %n", &type_magic, &space_magic, &offset) != 2) {
                fprintf(stderr, "Error: add-node <type> <address-space> <address>\n");
                goto next;
            }
            addr_str = args + offset;
            v.type = find_target_type(type_magic);
            if(v.type == NULL) {
                fprintf(stderr, "Error: No type found with magic "MAGIC_FMT"\n", type_magic);
                goto next;
            }

            space = find_address_space(space_magic);
            if(space == NULL) {
                fprintf(stderr, "Error: No address space found with magic "MAGIC_FMT"\n", space_magic);
                goto next;
            }

            v.address = address_from_human_readable(space, addr_str);
            if(v.address == NULL) {
                fprintf(stderr, "Error: Failed to parse address \"%s\"\n", addr_str);
                goto next;
            }

            rc = measurement_graph_add_node(graph, &v, NULL, &n);
            if(rc == 0 || rc == 1) {
                printf(ID_FMT"\n", n);
            } else {
                fprintf(stderr, "Error adding node\n");
            }
            free_address(v.address);
        } else if(strcmp(cmd, "add-edge") == 0) {
            node_id_t src, dst;
            char *label = NULL;
            int offset;
            int rc;
            edge_id_t e;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }
            if(sscanf(args, " "ID_FMT" "ID_FMT" %n", &src, &dst, &offset) != 2) {
                fprintf(stderr, "Error: add-edge <srcid> <dstid> [<label>]\n");
                goto next;
            }
            if(args[offset] != '\0') {
                label = args+offset;
            }
            rc = measurement_graph_add_edge(graph, src, label, dst, &e);
            if(rc == 0) {
                printf(ID_FMT"\n", e);
            } else {
                fprintf(stderr, "Error adding edge\n");
            }
        } else if(strcmp(cmd, "add-data") == 0) {
            node_id_t node;
            magic_t data_type;
            marshalled_data *data;
            int offset;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if(sscanf(args, " "ID_FMT" "MAGIC_FMT" %n", &node, &data_type, &offset) != 2) {
                fprintf(stderr, "Error: add-data <node id> <type> <data>\n");
                goto next;
            }

            if((data = (marshalled_data*)alloc_measurement_data(&marshalled_data_measurement_type)) == NULL) {
                fprintf(stderr, "Failed to allocate marshalled data\n");
                goto next;
            }

            data->unmarshalled_type		= data_type;
            data->marshalled_data		= strdup(args+offset);
            if(data->marshalled_data == NULL) {
                fprintf(stderr, "Error: failed to duplicate marshalled data string\n");
                free_measurement_data(&data->meas_data);
                goto next;
            }

            data->marshalled_data_length	= strlen(data->marshalled_data)+1;
            measurement_node_add_data(graph, node, data);
            free_measurement_data(&data->meas_data);
        } else if(strcmp(cmd, "rm-node") == 0) {
            node_id_t node;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if(sscanf(args, " "ID_FMT, &node) != 1) {
                fprintf(stderr, "Error: rm-node <node id>\n");
                goto next;
            }
            measurement_graph_delete_node(graph, node);
        } else if(strcmp(cmd, "rm-edge") == 0) {
            edge_id_t edge;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if(sscanf(args, " "ID_FMT, &edge) != 1) {
                fprintf(stderr, "Error: rm-edge <edge id>\n");
                goto next;
            }
            measurement_graph_delete_edge(graph, edge);
        } else if(strcmp(cmd, "node-type") == 0) {
            node_id_t n;
            target_type *type;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if(sscanf(args, ID_FMT, &n) != 1) {
                fprintf(stderr, "Error: node-type <id>\n");
                goto next;
            }
            type = measurement_node_get_target_type(graph, n);
            if(type == NULL) {
                fprintf(stderr, "Error: failed to get target type for node id "ID_FMT"\n", n);
                goto next;
            }
            printf("%s "MAGIC_FMT"\n", type->name, type->magic);
        } else if(strcmp(cmd, "node-address") == 0) {
            node_id_t n;
            address *addr;
            char *buf;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if(sscanf(args, ID_FMT, &n) != 1) {
                fprintf(stderr, "Error: node-type <id>\n");
                goto next;
            }
            addr = measurement_node_get_address(graph, n);
            if(addr == NULL) {
                fprintf(stderr, "Error: failed to get address of node id "ID_FMT"\n", n);
                goto next;
            }
            buf = address_human_readable(addr);
            if(buf) {
                printf("%s\n", buf);
                free(buf);
            } else {
                fprintf(stderr, "Error: failed to get human readable address\n");
            }
            free_address(addr);
        } else if(strcmp(cmd, "edge-source") == 0) {
            edge_id_t eid;
            node_id_t n;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if(sscanf(args, ID_FMT, &eid) != 1) {
                fprintf(stderr, "Error: edge-source <id>\n");
                goto next;
            }

            n = measurement_edge_get_source(graph, eid);
            if(n == INVALID_NODE_ID) {
                fprintf(stderr, "Error: failed to get source of edge "ID_FMT"\n", eid);
                goto next;
            }
            printf(ID_FMT"\n", n);
        } else if(strcmp(cmd, "edge-destination") == 0) {
            edge_id_t eid;
            node_id_t n;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if(sscanf(args, ID_FMT, &eid) != 1) {
                fprintf(stderr, "Error: edge-destination <id>\n");
                goto next;
            }

            n = measurement_edge_get_destination(graph, eid);
            if(n == INVALID_NODE_ID) {
                fprintf(stderr, "Error: failed to get destination of edge "ID_FMT"\n", eid);
                goto next;
            }
            printf(ID_FMT"\n", n);
        } else if(strcmp(cmd, "edge-label") == 0) {
            edge_id_t eid;
            char *label;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if(sscanf(args, ID_FMT, &eid) != 1) {
                fprintf(stderr, "Error: edge-label <id>\n");
                goto next;
            }

            label = measurement_edge_get_label(graph, eid);
            if(label == NULL) {
                fprintf(stderr, "Error: failed to get label of edge "ID_FMT"\n", eid);
                goto next;
            }
            printf("%s\n", label);
            free(label);
        } else if(strcmp(cmd, "ls-edges") == 0) {
            node_id_t src = INVALID_NODE_ID;
            node_id_t dst = INVALID_NODE_ID;
            char *label = NULL;
            char *ptr;
            edge_iterator *it = NULL;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }

            if((ptr = strstr(args, "->")) != NULL && (ptr == args || isspace(*(ptr-1))) ) {
                if(sscanf(ptr, "->"ID_FMT" ", &dst) != 1) {
                    fprintf(stderr, "Error: expected destination id after '->' token");
                    goto next;
                }
                if((it = measurement_node_iterate_inbound_edges(graph, dst)) == NULL) {
                    fprintf(stderr, "Error: failed to get inbound edge iterator for node "ID_FMT"\n", dst);
                    goto next;
                }

            }
            if((ptr = strstr(args, "<-")) != NULL && (ptr == args || isspace(*(ptr-1)))) {
                if(sscanf(ptr, "<-"ID_FMT" ", &src) != 1) {
                    fprintf(stderr, "Error: expected source id after '<-' token");
                    goto next;
                }
                if((it == NULL) &&
                        ((it = measurement_node_iterate_outbound_edges(graph, src)) == NULL)) {
                    fprintf(stderr, "Error: failed to get outbound edge iterator for node "ID_FMT"\n", src);
                    goto next;
                }
            }

            while(*args != '\0') {
                if(isspace(*args)) {
                    args++;
                    continue;
                }
                if(strncmp(args, "<-", 2) == 0) {
                    while(!isspace(*args) && *args != '\0') {
                        args++;
                    }
                    continue;
                }
                if(strncmp(args, "->", 2) == 0) {
                    while(!isspace(*args) && *args != '\0') {
                        args++;
                    }
                    continue;
                }
                label = args;
                while(!isspace(*args) && *args != '\0') {
                    args++;
                }
                *args = '\0';
                break;
            }

            if((it == NULL) &&
                    ((it = measurement_graph_iterate_edges(graph)) == NULL)) {
                fprintf(stderr, "Error: failed to get edge iterator for graph\n");
                goto next;
            }
            for(; it != NULL; it = edge_iterator_next(it)) {
                edge_id_t e = edge_iterator_get(it);
                if(e == INVALID_EDGE_ID) {
                    fprintf(stderr, "Warning: graph contains an invalid edge.\n");
                    continue;
                }

                if(src != INVALID_NODE_ID && dst != INVALID_NODE_ID) {
                    node_id_t e_src = measurement_edge_get_source(graph, e);
                    if(e_src != src) {
                        continue;
                    }
                }
                if(label != NULL) {
                    char *e_label = measurement_edge_get_label(graph, e);
                    if(e_label == NULL || strcmp(e_label, label) != 0) {
                        free(e_label);
                        continue;
                    }
                    free(e_label);
                }
                print_edge(graph, e);
            }
        } else if(strcmp(cmd, "ls-nodes") == 0) {
            node_iterator *it;
            for(it = measurement_graph_iterate_nodes(graph); it != NULL; it = node_iterator_next(it)) {
                node_id_t n = node_iterator_get(it);
                print_node(graph, n);
            }
        } else if(strcmp(cmd, "find-node") == 0) {
            address_space *space;
            magic_t type_magic;
            magic_t space_magic;
            char *addr_str;
            int offset;
            measurement_variable v;
            node_id_t n = INVALID_NODE_ID;

            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }
            if(sscanf(args, " "MAGIC_FMT" "MAGIC_FMT" %n", &type_magic, &space_magic, &offset) != 2) {
                fprintf(stderr, "Error: get-node <type> <address-space> <address>\n");
                goto next;
            }
            addr_str = args + offset;
            v.type = find_target_type(type_magic);
            if(v.type == NULL) {
                fprintf(stderr, "Error: No type found with magic "MAGIC_FMT"\n", type_magic);
                goto next;
            }

            space = find_address_space(space_magic);
            if(space == NULL) {
                fprintf(stderr, "Error: No address space found with magic "MAGIC_FMT"\n", space_magic);
                goto next;
            }

            v.address = address_from_human_readable(space, addr_str);
            if(v.address == NULL) {
                fprintf(stderr, "Error: Failed to parse address \"%s\"\n", addr_str);
                goto next;
            }

            n = measurement_graph_get_node(graph, &v);
            if(n != INVALID_NODE_ID) {
                printf(ID_FMT"\n", n);
            } else {
                fprintf(stderr, "Error getting node\n");
            }
            free_address(v.address);
        } else if(strcmp(cmd, "ls-data") == 0) {
            node_id_t node;
            measurement_iterator *it;
            if(sscanf(args, " "ID_FMT, &node) != 1) {
                fprintf(stderr, "Error: ls-data <node id>\n");
                goto next;
            }
            for(it = measurement_node_iterate_data(graph, node); it != NULL;
                    it = measurement_iterator_next(it)) {
                magic_t typ_magic = measurement_iterator_get_type(it);
                measurement_type *typ = find_measurement_type(typ_magic);
                printf(MAGIC_FMT": %s\n", typ_magic, typ == NULL ? "<unknown>" : typ->name);
            }
        } else if(strcmp(cmd, "cat-data") == 0) {
            node_id_t node;
            magic_t type_magic;
            measurement_type *type;
            marshalled_data *data;
            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }
            if(sscanf(args, " "ID_FMT" "MAGIC_FMT, &node, &type_magic) != 2) {
                fprintf(stderr, "Error: cat-data <node id> <data type>\n");
                goto next;
            }
            if((type = find_measurement_type(type_magic)) == NULL) {
                fprintf(stderr, "Error: no type with magic = "MAGIC_FMT, type_magic);
                goto next;
            }
            if((measurement_node_get_data(graph, node, type, &data)) != 0) {
                fprintf(stderr, "Error: failed to get measurement of type "MAGIC_FMT"\n", type_magic);
                goto next;
            }
            char *dbuf = NULL;
            size_t dsz = 0;
            if(measurement_data_human_readable(&data->meas_data, &dbuf, &dsz) == 0) {
                printf("%s\n", dbuf);
                free(dbuf);
            } else {
                printf("%s\n", data->marshalled_data);
            }
            free_measurement_data(&data->meas_data);
        } else if(strcmp(cmd, "serialize") == 0) {
            unsigned char *buf;
            size_t sz;
            char *outfile;
            int fd = STDOUT_FILENO;
            ssize_t written;
            if(graph == NULL) {
                fprintf(stderr, "Error: must create a graph with 'new' first\n");
                goto next;
            }
            if(serialize_measurement_graph(graph, &sz, &buf) != 0) {
                fprintf(stderr, "Error: failed to serialize measurement graph\n");
                free(buf);
                goto next;
            }

            if(sscanf(args, " %ms", &outfile) == 1) {
                fd = open(outfile, O_WRONLY | O_CREAT, 0664);
                if(fd < 0) {
                    fprintf(stderr, "Error: failed to open out file %s\n", outfile);
                    free(outfile);
                    free(buf);
                    goto next;
                }
                free(outfile);
            }
            if(((written = write(fd, buf, sz)) < 0) ||
                    ((size_t)written != sz)) {
                fprintf(stderr, "Error: writing serialized graph failed\n");
            }
            if(fd != STDOUT_FILENO) {
                close(fd);
            }
            free(buf);
        } else if(strcmp(cmd, "parse") == 0) {
            int fd;
            char *path;
            char *buf;
            struct stat stats;
            ssize_t nread;
            measurement_graph *tmpgraph;
            if(sscanf(args, " %ms", &path) != 1) {
                fprintf(stderr, "Error: parse <file>");
                goto next;
            }
            fd = open(path, O_RDONLY);
            if(fd < 0) {
                fprintf(stderr, "Error: Unable to open file %s\n", path);
                free(path);
                goto next;
            }
            if((fstat(fd, &stats)) < 0) {
                fprintf(stderr, "Error: Failed to stat file %s\n", path);
                free(path);
                close(fd);
                goto next;
            }

            if((buf = malloc((size_t)stats.st_size)) == NULL) {
                fprintf(stderr, "Error: Failed to allocate buffer of size %zu\n", stats.st_size);
                free(path);
                close(fd);
                goto next;
            }
            if(((nread = read(fd, buf, (size_t)stats.st_size)) < 0) || (nread < stats.st_size)) {
                fprintf(stderr, "Error: Failed to read contents of file %s\n", path);
                free(path);
                free(buf);
                close(fd);
                goto next;
            }
            free(path);
            close(fd);
            if((tmpgraph = parse_measurement_graph(buf, (size_t)stats.st_size)) == NULL) {
                fprintf(stderr, "Error: Failed to parse measurement graph\n");
                free(buf);
                goto next;
            }
            free(buf);
            if(graph != NULL) {
                destroy_measurement_graph(graph);
            }
            graph = tmpgraph;
            snprintf(prompt, PROMPT_SIZE, "graph(%.22s)> ", graph->path);
        } else {
            fprintf(stderr, "Unknown command \"%s\"\n", cmd);
            fprintf(stderr, "Available commands are:\n"
                    "\ttypes <lib.so> <register>...         -- load types from file calling registration functions\n"
                    "\tls-target-types                      -- list known target types\n"
                    "\tls-address-spaces                    -- list known address spaces\n"
                    "\tls-measurement-types                 -- list known measurement types\n"
                    "\tnew                                  -- create a new graph\n"
                    "\tmap <path>                           -- map an existing graph from path\n"
                    "\tdelete                               -- delete the current graph\n"
                    "\tadd-node <type> <space> <address>    -- add a node to the graph\n"
                    "\tadd-edge <srcid> <dstid> [<label>]   -- add an edge to the graph\n"
                    "\tadd-data <node id> <type> <data>     -- attach data of the given type to the node\n"
                    "\trm-node <id>                         -- delete the node with the given id\n"
                    "\trm-edge <id>                         -- delete the node with the given id\n"
                    "\tnode-type <id>                       -- get the target type of a node\n"
                    "\tnode-address <id>                    -- get the address of a node\n"
                    "\tedge-source <id>                     -- get the source of an edge\n"
                    "\tedge-destination <id>                -- get the defination of an edge\n"
                    "\tedge-label <id>                      -- get the label of an edge\n"
                    "\tls-edges [->id] [<-id] [label]       -- list edges with optional source, dest, and label\n"
                    "\tls-nodes                             -- list nodes\n"
                    "\tfind-node <type> <space> <address>   -- get the id of the node with the given type and address\n"
                    "\tls-data <id>                         -- list data types attached to node\n"
                    "\tcat-data <node id> <type>            -- dump the data of the given type attached to the node\n"
                    "\tserialize [<file>]                   -- serialize the graph to the given file (or stdout)\n"
                    "\tparse <file>                         -- parse the contents of the given file as a new graph\n"
                    "\tquit                                 -- quit\n"
                    "\t!<shell command>                     -- run a command in a subshell\n");
        }

next:
        free(line);
    }

    unmap_measurement_graph(graph);
    return 0;
}
