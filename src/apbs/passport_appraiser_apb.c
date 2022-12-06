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

/*! \file
 * This APB is an appraiser for a passport
 */

#define _USE_XOPEN
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#include <util/util.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/select.h>

#include <common/apb_info.h>
#include <apb/apb.h>
#include <graph/graph-core.h>
#include <measurement_spec/find_types.h>
#include <maat-basetypes.h>
#include <measurement_spec/measurement_spec.h>
#include <common/measurement_spec.h>
#include <maat-envvars.h>

#include <client/maat-client.h>
#include <apb/contracts.h>
#include <util/maat-io.h>
#include <util/keyvalue.h>
#include <util/base64.h>
#include <util/sign.h>
#include <common/asp.h>

#include <json-c/json.h>
#include <string.h>
#include <time.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <mongoc.h>

#define PASSPORT_CONFIG_FN "passport-config.txt"

#define MAX_CONFIGS 3
#define MAX_RESOURCES 8
#define MAX_SZ 1000

#define COLL_NAME "certificates"

const char dflt_all_resources[MAX_RESOURCES][MAX_SZ] = {"packages", "processes", "hashfiles", "mtab",
                                                        "got_measure", "hashfile", "userspace", "full"
                                                       };
const char *dflt_certfile = "trustedThirdParty.pem";

char resources_arr[MAX_RESOURCES][MAX_SZ] = {0};
size_t num_resources = 0;

char **certfiles_arr = NULL;
size_t num_certfiles = 0;

char *cacert_file = NULL;
char *user_exp = NULL;

char *appraisal_target = NULL;


static char *get_apbinfo_dir(void)
{
    char *apbdir = getenv(ENV_MAAT_APB_DIR);
    if (apbdir == NULL) {
        dlog(4, "Warning: environment variable ENV_MAAT_APB_DIR not set. Using default pat %s\n", DEFAULT_APB_DIR);
        apbdir = DEFAULT_APB_DIR;
    }

    return apbdir;
}


static char *strip_all_whitespace(char *line)
{
    char *m_line = malloc(strlen(line)+1);
    int i = 0, j = 0;

    while (line[i] != '\0') {
        if (isspace(line[i]) == 0) {
            m_line[j++] = line[i];
        }
        i++;
    }
    m_line[j] = '\0';

    return m_line;
}


static size_t getCount(char *str, char delims)
{
    size_t count = 1;
    char *temp = NULL;
    for (temp = str; *temp != '\0'; temp++) {
        if (*temp == delims) {
            count++;
        }
    }
    return count;
}


/**
 * if provided, read in values to appraise the passport against:
 *    accepted userspace resources
 *    expiration period in seconds
 *    name of third party appraiser's public certificate in mongodb
 *
 * otherwise, set values to defaults
 */
static int read_config_file()
{
    FILE *fp;
    char *full_filename;

    char line[MAX_CONFIGS][MAX_SZ];
    int i = 0;

    char *resources = NULL;
    char *certfiles = NULL;
    const char *delims = ",";
    size_t num = 0, len;

    full_filename = g_strdup_printf("%s/%s", get_apbinfo_dir(), PASSPORT_CONFIG_FN);
    if (!full_filename) {
        dlog(3, "Failed to allocate memory for config filename\n");
        return -1;
    }

    fp = fopen(full_filename, "r");
    if (fp == NULL) {
        dlog(3, "Failed to open filename\n");
        g_free(full_filename);
        return -1;
    }
    g_free(full_filename);

    while(!feof(fp)) {
        char *key, *value;
        char *kvdelim = "=";

        char *err = fgets(line[i], MAX_SZ, fp);
        if (err == NULL) {
            dlog(3, "fgets() returned NULL\n");
            break;
        }

        //strip all whitespace from line
        char *s_line = strip_all_whitespace(line[i]);

        //ignore starting line comments and empty lines
        if (s_line[0] == '#' || strlen(s_line) <= 1) {
            free(s_line);
            continue;
        }

        //get key value pair
        char *tok = strtok(s_line, kvdelim);
        if (tok == NULL) {
            free(s_line);
            continue;
        }
        key = tok;
        tok = strtok(NULL, kvdelim);
        value = tok;

        //save values
        if (strncmp(key, "Resources", strlen("Resources")) == 0) {
            if (value) {
                resources = strdup(value);
                i++;
            } else {
                resources = NULL;
            }
        } else if (strncmp(key, "Cert", strlen("Cert")) == 0) {
            if (value) {
                certfiles = strdup(value);
                i++;
            } else {
                certfiles = NULL;
            }
        } else if (strncmp(key, "Expiration", strlen("Expiration")) == 0) {
            if (value) {
                user_exp = strdup(value);
                i++;
            } else {
                user_exp = NULL;
            }
        }

        if (i >= MAX_CONFIGS) {
            free(s_line);
            break;
        }
        free(s_line);
    }

    //create array of resources
    if (resources != NULL) {
        for(resources = strtok(resources, delims); resources && num < MAX_RESOURCES; resources = strtok(NULL, delims)) {
            if ((len = strlen(resources)) < MAX_SZ) {
                strcpy(resources_arr[num++], resources);
            }
        }
        num_resources = num;
        free(resources);
    }

    //create array of certfiles
    num = 0;
    if (certfiles != NULL) {
        num_certfiles = getCount(certfiles, delims[0]);
        certfiles_arr = malloc(num_certfiles * sizeof(char*));

        for (certfiles = strtok(certfiles, delims); certfiles && num < num_certfiles; certfiles = strtok(NULL, delims)) {
            if ((len = strlen(certfiles)) < MAX_SZ) {
                certfiles_arr[num] = (char*)malloc(len+1);
                strncpy(certfiles_arr[num], certfiles, len);
                certfiles_arr[num][len] = '\0';
                num++;
            }
        }
        free(certfiles);
    }

    fclose(fp);
    return 0;
}


/**
 * passport is valid if the timestamp of its appraisal
 * is within a given time period
 *
 * by default a passport is valid within 300s of its creation, but this
 * time period can be overriden in the passport-config.txt file
 */
static int check_time_validity(const char *n_time, const char *passport_exp)
{
    struct tm tm = {0};
    struct tm *tm1;
    time_t start_time, curr_time;

    time_t period;
    double seconds = 0.0;

    strptime(n_time, "%Y-%m-%dT%H:%M:%SZ", &tm);
    start_time = mktime(&tm);

    time(&curr_time);
    tm1 = gmtime(&curr_time);
    curr_time = mktime(tm1);

    //if given, user provided expiration overrides passport expiration
    if (user_exp != NULL) {
        period = atol(user_exp);
        if (period <= 0)
            period = atol(passport_exp);
    } else {
        period = atol(passport_exp);
    }

    seconds = difftime(curr_time, start_time+period);
    if (seconds > 0) {
        return -1;
    }

    return 0;
}


/**
 * if the appraisal target is 'localhost', then resolve its ip address
 * and check against the target in passport
 */
static int resolve_localhost(const char *target_ip)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s, n;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        dlog(3, "Error: could not get network interfaces\n");
        return -1;
    }

    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        //for an AF_INET* interface, get the address to compare with target_ip
        if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                            (family == AF_INET) ? sizeof(struct sockaddr_in) :
                            sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                dlog(3, "Error: could not resolve address information\n");
                return -1;
            }

            if (strncmp(host, target_ip, strlen(host)) == 0) {
                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }

    dlog(5, "not valid: targets do not match\n");
    return -1;
}


/**
 * retrieve the specified third party appraiser's
 * public certificate from the mongodb
 */
static char *get_certfile(int index)
{
    char *cert_path = NULL;

    mongoc_uri_t *uri;
    mongoc_client_t *client;

    mongoc_collection_t *collection;
    mongoc_cursor_t *cursor;
    const bson_t *doc;
    bson_t *query;
    bson_t *opts;
    mongoc_read_prefs_t *read_prefs;

    struct json_object *parsed_json;
    struct json_object *m_certfile;
    const char *certfile_contents;

    char *buf = NULL;
    size_t bsize = 0;

    mongoc_init();
    dlog(6, "default mongo loc = %s and default mongo db %s\n", DEFAULT_MAAT_MONGO_LOC, DEFAULT_MONGO_DB);
    uri = mongoc_uri_new(DEFAULT_MAAT_MONGO_LOC);
    if (uri == NULL) {
        dlog(3, "error with parsing uri string\n");
        goto cleanup;
    }
    client = mongoc_client_new_from_uri(uri);
    if (client == NULL) {
        goto cleanup;
    }

    //set up query to get the latest passport
    collection = mongoc_client_get_collection (client, DEFAULT_MONGO_DB, COLL_NAME);
    query = BCON_NEW("name", BCON_UTF8(certfiles_arr[index]));
    opts = BCON_NEW ("limit", BCON_INT64 (1));
    read_prefs = mongoc_read_prefs_new (MONGOC_READ_SECONDARY);

    cursor = mongoc_collection_find_with_opts(collection, query, opts, read_prefs);
    if (cursor == NULL) {
        dlog(3, "unable to query cert from database\n");
        goto cleanup;
    }

    if (mongoc_cursor_next (cursor, &doc)) {
        buf = bson_as_json (doc, NULL);
    } else {
        dlog(3, "no document found with name %s\n", certfiles_arr[index]);
        goto cleanup;
    }

    parsed_json = json_tokener_parse(buf);
    json_object_object_get_ex(parsed_json, "certfile", &m_certfile);
    certfile_contents = json_object_get_string(m_certfile);
    bsize = strlen(certfile_contents);

    //create temporary file
    cert_path = g_strdup_printf("%s/%s", get_apbinfo_dir(), certfiles_arr[index]);
    if (!cert_path) {
        dlog(3, "Failed to allocate memory for certfile filename\n");
        cert_path = NULL;
        goto cleanup;
    }

    FILE *fp;
    fp = fopen(cert_path, "w");
    if (fp == NULL) {
        dlog(3, "Failed to open cert_path\n");
        g_free(cert_path);
        cert_path = NULL;
        goto cleanup;
    }
    fprintf(fp, "%s", certfile_contents);
    fclose(fp);

    //cleanup libmongoc
cleanup:
    if (buf)
        bson_free(buf);
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

    return cert_path;
}


static int appraise_passport(struct json_object *contract)
{
    struct json_object *m_target_type;
    struct json_object *m_target;
    struct json_object *m_resource;
    struct json_object *m_copland;
    struct json_object *m_result;
    struct json_object *m_startdate;
    struct json_object *m_period;
    struct json_object *m_signature;

    const char *target_type, *target_ip;
    const char *resource;
    const char *copland;
    const char *result;
    const char *startdate, *period;

    char *certfile_path;
    char *b64sig;
    unsigned char *signature;
    char *passport_buf;
    size_t signature_sz, passport_sz;

    size_t index = 0;
    int i;
    int found = -1;
    int ret_val;
    int res = 0;

    //get appraisal config values for passport
    ret_val = read_config_file();
    if (ret_val < 0) {
        dlog(3, "failed to read config file\n");
    }

    //check that read-in values exist, else assign them to defaults
    //leave user_exp as NULL to be overriden by passport_exp
    if (num_resources == 0) {
        memcpy(resources_arr, dflt_all_resources, sizeof(dflt_all_resources));
        num_resources = MAX_RESOURCES;
    }
    if (num_certfiles == 0) {
        num_certfiles = 1;
        int len = strlen(dflt_certfile);

        certfiles_arr = malloc(num_certfiles * sizeof(char *));
        certfiles_arr[0] = (char *)malloc(len+1);
        strncpy(certfiles_arr[0], dflt_certfile, len);
        certfiles_arr[len] = '\0';
    }

    dlog(8, "num_certfiles: %ld\n", num_certfiles);
    dlog(8, "user_exp: %s\n", user_exp);
    dlog(8, "num_resources: %ld\n", num_resources);

    //check that the cert is still valid
    json_object_object_get_ex(contract, "startdate", &m_startdate);
    startdate = json_object_get_string(m_startdate);

    json_object_object_get_ex(contract, "period", &m_period);
    period = json_object_get_string(m_period);
    if (check_time_validity(startdate, period) == -1) {
        dlog(5, "not valid: the passport has expired\n");
        res = -1;
        goto cleanup;
    }

    //check appraisal result PASS/FAIL
    json_object_object_get_ex(contract, "result", &m_result);
    result = json_object_get_string(m_result);

    if (strncmp(result, "PASS", strlen("PASS")) != 0) {
        dlog(5, "not valid: third party appraisal failed\n");
        res = -1;
        goto cleanup;
    }

    //check resource that was appraised
    json_object_object_get_ex(contract, "copland phrase", &m_copland);
    copland = json_object_get_string(m_copland);
    json_object_object_get_ex(contract, "resource", &m_resource);
    resource = json_object_get_string(m_resource);

    for (i = 0; i < num_resources; i++) {
        if (strncmp(resource, resources_arr[i], strlen(resource))== 0) {
            found = 0;
            break;
        }
    }
    if (found == -1) {
        dlog(5, "not valid: resource does not match those accepted\n");
        res = -1;
        goto cleanup;
    }

    //checks that targets are the same
    json_object_object_get_ex(contract, "target", &m_target);
    json_object_object_get_ex(m_target, "type", &m_target_type);
    target_type = json_object_get_string(m_target_type);
    json_object_object_get_ex(m_target, "ip", &m_target);
    target_ip = json_object_get_string(m_target);

    index = strlen(appraisal_target);
    if (strncmp(appraisal_target, target_ip, index) != 0) {
        if (strcmp(appraisal_target, "127.0.0.1") == 0) {
            found = resolve_localhost(target_ip);
            if (found == -1) {
                dlog(5, "not valid: targets do not match\n");
                res = -1;
                goto cleanup;
            }
        } else {
            dlog(5, "not valid: targets do not match\n");
            res = -1;
            goto cleanup;
        }
    }

    //verify trusted third party's signature
    json_object_object_get_ex(contract, "signature", &m_signature);
    b64sig = (unsigned char*) json_object_get_string(m_signature);
    signature = b64_decode(b64sig, &signature_sz);
    if (!signature) {
        dlog(3, "could not decode signature\n");
        res = -1;
        goto cleanup;
    }

    passport_sz = strlen(target_type) + strlen(target_ip) + strlen(resource) + strlen(copland) +
                  strlen(result) + strlen(startdate) + strlen(period) + 10; /*account for formatting*/
    passport_buf = malloc(passport_sz);
    if (passport_buf == NULL) {
        dlog(3, "failed to allocate memory for passport\n");
        res = -1;
        goto cleanup;
    }

    snprintf(passport_buf, passport_sz, "%s,%s,%s,%s,%s,%s,%s",
             target_type, target_ip, resource, copland, result, startdate, period);
    passport_sz = strlen(passport_buf);
    passport_buf[passport_sz] = '\0';

    int verified;
    for (i = 0; i < num_certfiles; i++) {
        certfile_path = get_certfile(i);
        verified = verify_buffer_openssl((unsigned char*)passport_buf, passport_sz, signature, signature_sz, certfile_path, cacert_file);

        ret_val = remove(certfile_path);
        if (ret_val != 0) {
            dlog(4, "unable to delete %s\n", certfile_path);
        }
        g_free(certfile_path);

        if (verified == 1)
            break;
    }
    if (verified != 1) {
        dlog(5, "not valid: third party appraiser's signature verification failed\n");
        res = -1;
        goto cleanup;
    }

cleanup:
    free(user_exp);

    for (i = 0; i < num_certfiles; i++) {
        free(certfiles_arr[i]);
    }
    free(certfiles_arr);

    return res;
}


static int appraise_node(measurement_graph *mg, char *graph_path, node_id_t node, struct scenario *scen)
{
    int appraisal_stat = 0;
    measurement_data *data = NULL;
    blob_data *bdata = NULL;

    struct json_object *parsed_json;
    struct json_object *contract;

    //extract the data
    if (measurement_node_get_rawdata(mg, node, &blob_measurement_type, &data) != 0) {
        dlog(3, "failed to get blob data from node\n");
        return -1;
    }
    bdata = container_of(data, blob_data, d);

    if (bdata->size > 0 && bdata->buffer != NULL) {
        parsed_json = json_tokener_parse(bdata->buffer);
        json_object_object_get_ex(parsed_json, "passport", &contract);

        appraisal_stat = appraise_passport(contract);
    }

    return appraisal_stat;
}


static int appraise(struct scenario *scen, GList *values UNUSED, void *msmt, size_t msmtsize)
{
    int ret_val = -1;
    struct measurement_graph *mg = NULL;
    char *mspec_dir = NULL;
    char *graph_path = NULL;
    node_iterator *it = NULL;

    //load measurement specs
    mspec_dir = getenv(ENV_MAAT_MEAS_SPEC_DIR);
    if (mspec_dir == NULL) {
        dlog(4, "Warning: environment variable " ENV_MAAT_MEAS_SPEC_DIR
             " not set. Using default path " DEFAULT_MEAS_SPEC_DIR "\n");
        mspec_dir = DEFAULT_MEAS_SPEC_DIR;
    }

    //unserialize measurement
    mg = parse_measurement_graph(msmt, msmtsize);
    if (!mg) {
        dlog(3, "Error parsing measurement graph\n");
        destroy_measurement_graph(mg);
        return ret_val;
    }

    graph_path = measurement_graph_get_path(mg);

    for (it = measurement_graph_iterate_nodes(mg); it != NULL; it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        measurement_iterator *data_it;

        for (data_it = measurement_node_iterate_data(mg, node); data_it != NULL; data_it = measurement_iterator_next(data_it)) {
            ret_val = appraise_node(mg, graph_path, node, scen);
        }

    }
    free(graph_path);

    destroy_measurement_graph(mg);

    return ret_val;
}


int apb_execute(struct apb *apb, struct scenario *scen,
                uuid_t meas_spec_uuid UNUSED, int peerchan,
                int resultchan, char *target,
                char *target_type, char *resource,
                struct key_value **arg_list UNUSED, int argc UNUSED)
{
    dlog(6, "Hello from PASSPORT_APPRAISER\n");

    int ret_val = 0;
    int failed = 0;

    xmlChar *evaluation;
    unsigned char *response_buf;
    size_t sz = 0;

    if ( (ret_val = register_types()) ) {
        return ret_val;
    }

    //get passport from attester
    ret_val = receive_measurement_contract(peerchan, scen, 10000000);
    if (ret_val) {
        dlog(3, "Unable to recieve measurement contract\n");
        return ret_val;
    }

    //save target and ca for appraisal
    appraisal_target = target;
    cacert_file = scen->cacert;

    //call appraise() to check for measurement contract
    if(scen->contract == NULL) {
        dlog(3, "appraiser APB has no measurement contract\n");
        failed = -1;
    } else {
        failed = 0;
        handle_measurement_contract(scen, appraise, &failed);
    }

    if(failed == 0) {
        evaluation = (xmlChar*)"PASS";
    } else {
        evaluation = (xmlChar*)"FAIL";
    }

    //generate and send integrity check response to client
    ret_val = create_integrity_response(
                  parse_target_id_type((xmlChar*)target_type),
                  (xmlChar*)target,
                  (xmlChar*)resource, evaluation, NULL,
                  scen->certfile, scen->keyfile, scen->keypass, NULL,
                  scen->tpmpass, (xmlChar **)&response_buf, &sz);

    if(ret_val < 0 || response_buf == NULL) {
        dlog(3, "Error: created_intergrity_response returned %d\n", ret_val);
        free(response_buf);
        return ret_val;
    }

    if(sz == 0) {
        sz = (size_t)xmlStrlen(response_buf);
        dlog(4, "Error: sz is 0, using strlen (Need to fix this! Why is xmlDocDumpMemory not giving back the size!?\n");
    }

    size_t bytes_written = 0;
    dlog(8, "Send response from appraiser APB: %s.\n", response_buf);
    sz = sz+1; // include the terminating '\0'
    ret_val = maat_write_sz_buf(resultchan, response_buf, sz, &bytes_written, 5);

    if(ret_val != 0) {
        dlog(3, "Failed to send response from appraiser!: %s\n",
             strerror(ret_val<0 ? -ret_val : ret_val));
        return -EIO;
    }
    if(bytes_written != sz+sizeof(uint32_t)) {
        dlog(3, "Error: appraiser wrote %zu bytes (expected to write %zd)\n",
             bytes_written, sz);
        return -EIO;
    }
    dlog(8, "Appraiser wrote %zd byte(s)\n", bytes_written);

    dlog(6, "Good-bye from PASSPORT_APPRAISER\n");
    return 0;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
