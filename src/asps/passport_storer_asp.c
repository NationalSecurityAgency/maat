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
#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <client/maat-client.h>

#include <mongoc.h>

/*! \file storer_asp.c
 *
 * This ASP stores a passport in the database
 */

#define ASP_NAME  "passport_storer_asp"

#define COLL_NAME "passports"
#define NUM_VALUES 8

#define TIMEOUT 100

int out_fd = 0, in_fd = 0;


int asp_init(int argc, char *argv[])
{
    asp_logdebug("Initialized storer_ASP\n");
    return 0;
}


int asp_exit(int status)
{
    asp_logdebug("Exiting storer_ASP\n");
    return 0;
}


int add_passport(char *buffer)
{
    int ret_val = 0;

    char *passport_values[NUM_VALUES] = {NULL};
    int n = 0;

    mongoc_uri_t *uri;
    mongoc_client_t *client;
    mongoc_collection_t *collection;

    bson_error_t error;
    bson_t *doc;
    bson_t child, child2;
    char *m_str = NULL;

    char *token = strtok(buffer, ",");
    if (token == NULL) {
        asp_logerror("passport in invalid format\n");
        return -1;
    }
    while(token != NULL && n < NUM_VALUES) {
        passport_values[n] = token;
        n++;
        token = strtok(NULL, ",");
    }

    //connect to mongodb
    mongoc_init();
    asp_logdebug("default mongo loc = %s and default mongo db %s\n", DEFAULT_MAAT_MONGO_LOC, DEFAULT_MONGO_DB);
    uri = mongoc_uri_new(DEFAULT_MAAT_MONGO_LOC);
    if (uri == NULL) {
        asp_logerror("error with parsing uri string\n");
        ret_val = -1;
        goto cleanup;
    }
    client = mongoc_client_new_from_uri(uri);
    if (client == NULL) {
        ret_val = -1;
        goto cleanup;
    }

    collection = mongoc_client_get_collection (client, DEFAULT_MONGO_DB, COLL_NAME);
    if (collection == NULL) {
        ret_val = -1;
        goto cleanup;
    }

    //create document
    doc = bson_new();
    BSON_APPEND_UTF8(doc, "type", "passport");
    BSON_APPEND_DOCUMENT_BEGIN(doc, "passport", &child);
    BSON_APPEND_DOCUMENT_BEGIN(&child, "target", &child2);
    BSON_APPEND_UTF8(&child2, "type", passport_values[0]);
    BSON_APPEND_UTF8(&child2, "ip", passport_values[1]);
    bson_append_document_end(&child, &child2);
    BSON_APPEND_UTF8(&child, "resource", passport_values[2]);
    BSON_APPEND_UTF8(&child, "copland phrase", passport_values[3]);
    BSON_APPEND_UTF8(&child, "result", passport_values[4]);
    BSON_APPEND_UTF8(&child, "startdate", passport_values[5]);
    BSON_APPEND_UTF8(&child, "period", passport_values[6]);
    BSON_APPEND_UTF8(&child, "signature", passport_values[7]);
    bson_append_document_end(doc, &child);

    //insert document
    if (!mongoc_collection_insert(collection, MONGOC_INSERT_NONE, doc, NULL, &error)) {
        asp_logerror("failed to insert document into mongodb\n");
        ret_val = -1;
    }

    bson_destroy(doc);
    free(buffer);

    //cleanup libmongoc
cleanup:
    if (collection)
        mongoc_collection_destroy (collection);
    if (uri)
        mongoc_uri_destroy (uri);
    if (client)
        mongoc_client_destroy (client);
    mongoc_cleanup ();

    return ret_val;
}


int asp_measure(int argc, char *argv[])
{
    asp_logdebug("in storer_ASP MEASURE()\n");

    int ret_val = 0;
    char *buffer = NULL;
    size_t buf_sz = 0;
    size_t bytes_read = 0;
    int eof_enc = 0;
    char *result = NULL;
    gsize bytes_written = 0;

    if (argc == 3) {
        in_fd = atoi(argv[1]);
        out_fd = atoi(argv[2]);
        if (in_fd < 0 || out_fd < 0) {
            asp_logerror("Error getting input and output channels\n");
            return -1;
        }
    } else {
        asp_logerror("Usage: "ASP_NAME" <in_fd> <out_fd>\n");
        return -1;
    }

    //read passport from pipe
    ret_val = maat_read_sz_buf(in_fd, &buffer, &buf_sz, &bytes_read, &eof_enc, TIMEOUT, -1);
    if (ret_val != 0 || buffer == NULL || eof_enc != 0) {
        asp_logerror("error reading passport\n");
        return -1;
    }

    ret_val = add_passport(buffer);
    if (ret_val == 0)
        result = "PASS";
    else
        result = "FAIL";

    //send result to appraiser
    ret_val = maat_write_sz_buf(out_fd, result, strlen(result), &bytes_written, TIMEOUT);
    if (ret_val != 0) {
        asp_logerror("failed to send result to apb: %s\n", strerror(-ret_val));
        return -1;
    }

    return ret_val;
}
