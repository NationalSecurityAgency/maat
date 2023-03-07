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

#include <errno.h>
#include <sys/types.h>

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include <util/util.h>
#include <util/maat-io.h>

#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <client/maat-client.h>

#include <mongoc.h>

#define ASP_NAME  "passport_retriever_asp"

#define COLL_NAME "passports"
#define TIMEOUT 100

/*! \file retriever_asp.c
 *
 * This ASP retrieves the passport from the database
 */

int asp_init(int argc, char *argv[])
{
    asp_logdebug("Initialized retriever_ASP\n");
    return 0;
}


int asp_exit(int status)
{
    asp_logdebug("Exiting retriever_ASP\n");
    return 0;
}

static size_t get_passport(char ** buffer)
{
    mongoc_uri_t *uri;
    mongoc_client_t *client;

    mongoc_collection_t *collection;
    mongoc_cursor_t *cursor;
    const bson_t *doc;
    bson_t *query;
    bson_t *opts;
    mongoc_read_prefs_t *read_prefs;

    char *my_buf = NULL;
    size_t bsize = -1; //return value

    //connect to mongodb and create a new client instance
    mongoc_init();
    asp_logdebug("default mongo loc = %s and default mongo db %s\n", DEFAULT_MAAT_MONGO_LOC, DEFAULT_MONGO_DB);
    uri = mongoc_uri_new(DEFAULT_MAAT_MONGO_LOC);
    if (uri == NULL) {
        asp_logerror("error with parsing uri string\n");
        goto cleanup;
    }
    client = mongoc_client_new_from_uri(uri);
    if (client == NULL) {
        goto cleanup;
    }

    //get collection and set up query to get the latest passport
    collection = mongoc_client_get_collection (client, DEFAULT_MONGO_DB, COLL_NAME);
    query = BCON_NEW("type", BCON_UTF8("passport"));
    opts = BCON_NEW ("limit", BCON_INT64 (1), "sort", "{", "_id", BCON_INT32 (-1), "}");
    read_prefs = mongoc_read_prefs_new (MONGOC_READ_SECONDARY);

    cursor = mongoc_collection_find_with_opts(collection, query, opts, read_prefs);
    if (cursor == NULL) {
        asp_logerror("unable to query cert from database\n");
        goto cleanup;
    }

    if (mongoc_cursor_next (cursor, &doc)) {
        my_buf = bson_as_json (doc, NULL);
    } else {
        asp_logerror("no document found\n");
        goto cleanup;
    }

    //write passport into passed-in buffer
    bsize = strlen(my_buf);

    *buffer = malloc(bsize);
    if (*buffer == NULL) {
        asp_logerror("buffer not allocated\n");
        bsize = -1;
        goto cleanup;
    }

    memcpy(*buffer, my_buf, bsize);

    //cleanup libmongoc
cleanup:
    if (my_buf)
        bson_free(my_buf);
    if (query)
        bson_destroy(query);
    if (cursor)
        mongoc_cursor_destroy (cursor);
    if (collection)
        mongoc_collection_destroy (collection);
    if (uri)
        mongoc_uri_destroy (uri);
    if (client)
        mongoc_client_destroy (client);
    mongoc_cleanup ();

    return bsize;
}


int asp_measure(int argc, char *argv[])
{
    int ret_val = 0;

    measurement_graph *graph = NULL;
    node_id_t node_id = 0;

    blob_data *blob = NULL;
    char *buffer = NULL;
    size_t length = 0;
    marshalled_data *md = NULL;

    //check arguments
    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        goto err;
    }

    //get passport from database and write into buffer
    length = get_passport(&buffer);
    if (length == 0) {
        asp_logdebug("No passport in database\n");
        goto err;
    } else if (length < 0) {
        asp_logerror("error with retrieving passport from database\n");
        goto err;
    }

    //allocate measurement data
    measurement_data *data = NULL;
    data = alloc_measurement_data(&blob_measurement_type);
    if (data == NULL) {
        asp_logerror("failed to allocate blob data\n");
        goto err;
    }

    blob = container_of(data, blob_data, d);
    blob->buffer = malloc(length);
    if (!blob->buffer) {
        asp_logerror("failed to allocate buffer data\n");
        goto err;
    }
    memcpy(blob->buffer, buffer, length);
    blob->size = length;

    //serialize measurement
    md = marshall_measurement_data(&blob->d);
    if (md == NULL) {
        asp_logerror("could not serialize data\n");
        goto err;
    }

    free(buffer);
    buffer = NULL;

    //add measurement to graph
    ret_val = measurement_node_add_data(graph, node_id, md);

    free_measurement_data(&md->meas_data);
    unmap_measurement_graph(graph);

    return ret_val;

err:
    if (buffer)
        free(buffer);
    unmap_measurement_graph(graph);
    return -1;
}

