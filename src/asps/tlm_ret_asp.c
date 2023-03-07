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

/*! \file
 * This ASP requests and appraises telemetry data from present -> ( present - x )
 * from a telemetry retrieval client, where x is the value provided in
 * the address space.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <assert.h>

#include <util/util.h>
#include <util/signfile.h>
#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>

#include <maat-basetypes.h>
#include <graph/graph-core.h>

#include <client/maat-client.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <util/maat-io.h>

#define ASP_NAME        "tlm_ret_asp"

// XXX: should put all of these in config file
#define MAX_TIMESPAN_DELTA 604800  // one week
#define CONFIG_FILE_PATH "/tmp/quiot_sample_request.config"
#define TR_CLIENT_JAR "/FIXME/insert/path/to/tr.jar"
#define TR_CLIENT_LIB "FIXME.insert.java.path.to.trclient"
#define TR_SERVER "localhost"
#define TR_SERVER_PORT "14610"
#define QUIOT_APID 151  // 151 decimal == 0x97

// Delta last is returned in subseconds (ss) which is ( seconds * (2^-32) )
// Delta last of 107374182 ss = 0.025 seconds, or 40Hz
static int DELTA_MAX = 107374182;
static int DELTA_MIN = 0;

static int MSG_CNT_MAX = 55;
static int MSG_CNT_MIN = 44;

static float FREQ_MAX = 50.0;
static float FREQ_MIN = 40.0;

/*XXX: These aren't being used yet
static float VAR_MAX   = 0.0;
static float VAR_MIN   = 0.0;
*/

static char *CONFIG_FILE = "FIXME: WRITE YOUR CONFIG FILE HERE";

typedef enum ids {
    DELTA_LAST=11413,
    FREQ=11414,
    MAX_DELTA=11415,
    MIN_DELTA=11416,
    MSG_CNT=11417,
    VAR=11418
} ids;



int asp_init(int argc, char *argv[])
{
    int ret_val = 0;
    asp_loginfo("Initialized telemetry retrieval ASP\n");

    if( (ret_val = register_address_space(&time_delta_address_space)) ) {
        return ret_val;
    }
    if( (ret_val = register_measurement_type(&report_measurement_type)) ) {
        return ret_val;
    }

    return ASP_APB_SUCCESS;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting telemetry retrieval ASP\n");
    return ASP_APB_SUCCESS;
}

/**
 * Gets the time delta address from the node
 * of node_id in graph g.
 * It is the caller's responsibility to free the returned address
 * Returns 0 on success, < 0 on error
 */
static int get_addr_data_from_node(measurement_graph *graph, node_id_t nid, time_delta_address **out)
{
    address *address         = NULL;
    time_delta_address *va   = NULL;
    int time_delta           = 0;
    int ret_val = 0;

    if( (address = measurement_node_get_address(graph, nid)) == NULL) {
        asp_logerror("Failed to get time delta details: %s\n", strerror(errno));
        dlog(0, "couldn't get addr\n");
        ret_val = -EIO;
        goto error;
    }

    if(address->space != &time_delta_address_space) {
        dlog(0, "wrong addr type\n");
        asp_logerror("Time delta has unexpected address type %s\n", address->space->name);
        ret_val = -EINVAL;
        goto space_error;
    }
    va = container_of(address, time_delta_address, a);

    *out = va;
    return 0;

value_error:
space_error:
    free_address(address);
error:
    return ret_val;
}

/**
 * Executes the telemetry retrieval client and sends its output to the returned
 * FILE pointer
 */
static FILE *exec_tr_client()
{
    FILE *fp = NULL;
    int fds[2];
    pid_t p;
    if(pipe(fds) < 0) {
        dlog(0, "Error: failed to open pipe\n");
        goto error_pipe;
    }

    if((p = fork()) < 0) {
        dlog(0, "Error: failed to fork\n");
        goto error_fork;
    } else if (p == 0) {
        close(fds[0]);

        if(dup2(fds[1], STDOUT_FILENO) < 0) {
            dlog(0, "Error: failed to dup %s\n", strerror(errno));
            goto child_error;
        }

        // Execute the telemetry retrieval client
        dlog(6, "Running Telemetry Retrieval Client with generated config file\n");
        if(execl("/usr/bin/java", "/usr/bin/java", "-cp", TR_CLIENT_JAR, TR_CLIENT_LIB,
                 TR_SERVER, TR_SERVER_PORT, CONFIG_FILE_PATH, NULL) < 0) {
            dlog(0, "Error: failed to exec retrieval client %s\n", strerror(errno));
            goto child_error;
        }

child_error:
        close(fds[1]);
        exit(-1);
    }

    close(fds[1]);

    if((fp = fdopen(fds[0], "r")) == NULL) {
        dlog(0, "Error: failed to open file descriptor\n");
        goto error_fdopen;
    }

    return fp;

error_fork:
    close(fds[1]);
error_fdopen:
    close(fds[0]);
error_pipe:
    return fp;
}

/**
 * Makes a telemetry retrieval client request config file for the
 * passed delta (in SECONDS) from present at the passed path
 *
 * Returns 0 on success, -1 on error
 */
static int create_tr_config_file(int delta, char *path, long int *start, long int *end)
{
    struct timeval present_tv;
    struct timeval past_tv;

    char *begin_span;
    char *end_span;
    FILE *config_fp = NULL;

    if((gettimeofday(&past_tv, NULL) != 0) || (gettimeofday(&present_tv, NULL) != 0)) {
        dlog(0, "Error: failed to get current time of day\n");
        goto error;
    }

    //Account for testbed time difference
    present_tv.tv_sec = present_tv.tv_sec + 120;

    // Check delta validity
    if(delta <= 0 || delta > MAX_TIMESPAN_DELTA || delta > present_tv.tv_sec) {
        dlog(0, "Error: invalid delta %d\n", delta);
        goto error;
    }

    past_tv.tv_sec = present_tv.tv_sec - delta;

    dlog(6, "Found delta of %d seconds\n", delta);
    dlog(6, "Asking for telemetry in span %ld%06ld - %ld%06ld\n", (long int)past_tv.tv_sec, (long int) past_tv.tv_usec,
         (long int) present_tv.tv_sec, (long int) present_tv.tv_usec);

    // This all just to print human readable for demo
    char present_buf[64];
    char past_buf[64];
    time_t tmptime;
    struct tm *tmptm;
    tmptime = present_tv.tv_sec;
    tmptm = localtime(&tmptime);
    strftime(present_buf, sizeof present_buf, "%a %b %d %Y %H:%M:%S", tmptm);
    tmptime = past_tv.tv_sec;
    tmptm = localtime(&tmptime);
    strftime(past_buf, sizeof past_buf, "%a %b %d %Y %H:%M:%S", tmptm);
    dlog(6, "( %s.%06ld - %s.%06ld )\n", past_buf, (long int) past_tv.tv_usec, present_buf, (long int) present_tv.tv_usec);
    //////////////////////////////////////

    if(asprintf(&begin_span, "%ld%06ld", (long int)past_tv.tv_sec, (long int)past_tv.tv_usec) < 0) {
        dlog(0, "Failed to print begin time to string\n");
        goto error;
    }

    if(asprintf(&end_span, "%ld%06ld", (long int) present_tv.tv_sec, (long int)present_tv.tv_usec) < 0) {
        dlog(0, "Failed to print time to string\n");
        free(begin_span);
        goto error;
    }

    // Make config file
    config_fp = fopen(path, "w+");
    if(!config_fp)  {
        dlog(0, "Error opening retrieval Config file\n");
        goto fopen_error;
    }

    if(fprintf(config_fp, CONFIG_FILE, begin_span, end_span) < 0) {
        dlog(0, "Error: failed to write to config file\n");
        goto print_error;
    }

    // Give values back in long int format
    sscanf(begin_span, "%ld", start);
    sscanf(end_span, "%ld", end);

    fclose(config_fp);
    free(begin_span);
    free(end_span);
    return 0;

print_error:
    fclose(config_fp);
fopen_error:
    free(begin_span);
    free(end_span);
error:
    return -1;
}

static char *get_start_of_value(char *line, char *key)
{
    char * delim_index  = NULL;
    char * value = NULL;

    if((delim_index = strchr(line, ':')) == NULL) {
        return NULL;
    }

    value = delim_index+1;
    *delim_index = '\0';

    // Notice line string should now end where ':' was
    // XXX should improve ability to handle whitespace
    if(strcmp(line, key) != 0) {
        return NULL;
    }

    return value;
}

static int get_float_value(char *line, float *out)
{
    int ret = 0;
    float value;
    char *value_start =  get_start_of_value(line, "      double_value");
    if(value_start == NULL) {
        return -1;
    }
    value = atof(value_start);
    *out = value;
    return 0;
}

static int get_uint32_value(char *line, uint32_t *out)
{
    int ret = 0;
    uint32_t value;
    char *value_start =  get_start_of_value(line, "      sint_value");
    if(value_start == NULL) {
        return -1;
    }

    sscanf(value_start, "%"SCNu32, &value);

    *out = value;

    return 0;
}

static int get_uint64_value(char *line, uint64_t *out)
{
    int ret = 0;
    uint64_t value;
    char *value_start =  get_start_of_value(line, "      sint_value");
    if(value_start == NULL) {
        return -1;
    }

    sscanf(value_start, "%"SCNu64, &value);

    *out = value;

    return 0;
}

/**
 * Appaises the telemetry at @fp by reading each line and
 * changing state based on which part of telemetry output you're in.
 *
 * This is simply parsing and appraising on the spot.
 *
 * Notice that if you want to change this to put telemetry in graph, could
 * just change functionality of bits of state machine for parsing/adding to
 * graph. Appraise during process, or walk graph later.
 *
 * Returns 0 on PASS, -1 on ERROR, 1 on FAIL
 */
static int appraise_telemetry(FILE *fp, long int start_time, long int end_time)
{
    char *line = NULL;
    size_t len = 0;
    int appraisal_passed = 0;
    int ret = 0;

    typedef enum tlm_state {
        IDLE,
        SAMPLES,
        POINT_SAMPLES,
        POINT_VALUE,
        VALUE
    } tlm_state;

    long int max_time = 0;
    long int min_time = end_time+1; // XXX check this

    tlm_state t_state = IDLE;
    int id_number = 0;
    int checked_value = -1;
    int checked_source = -1;
    long int time_stamp = 0;

    while(getline(&line, &len, fp) != -1) {

        switch(t_state) {
        case IDLE:                                                          // This state's job is to look for Samples
            if(strcmp(line, "Samples:\n") == 0) {                           // header, then pass to SAMPLES state
                t_state = SAMPLES;
            }
            break;

        case SAMPLES: ;                                           	    // This state's job is to get and check the
            char * time_start   = NULL;                                     // timestamp. Returns failed appraisal if
            time_stamp = 0;                                                 // timestamp outside expected span, passes
            // to POINT_SAMPLES state if good.
            time_start = get_start_of_value(line, "  creationUtc");         // Also keeps track of min and max timestamp
            if(time_start == NULL) {                                        // to check if covered entire span by end.
                break;
            }

            sscanf(time_start, "%ld", &time_stamp);
            if(time_stamp > end_time || time_stamp < start_time) {
                dlog(0, "Found an invalid time stamp: %ld\n", time_stamp);
                return -1;
            }

            // Save off min and maxes
            if(time_stamp < min_time) {
                min_time = time_stamp;
            } else if(time_stamp > max_time) {
                max_time = time_stamp;
            }

            t_state = POINT_SAMPLES;

            break;

        case POINT_SAMPLES:                                                 // This state's job is to pass to POINT_SAMPLE
            if(strcmp(line, "pointSample {\n") == 0) {                      // when it finds one. Once encounter empty line
                t_state = POINT_VALUE;                                      // AND all ids passed exactly once, pass back
            } else if(strcmp(line, "\n") == 0) {                            // to idle
                t_state = IDLE;
            }
            break;

        case POINT_VALUE: ;                                                 // This state's job is to get the id and pass
            char *id_start = NULL;                                          // to VALUE state

            id_start = get_start_of_value(line, "  id");
            if(!id_start) {
                break;
            }

            id_number = atoi(id_start);

            t_state = VALUE;
            break;

        case VALUE:                                                         // This state's job is to evaluate the value,
            if((checked_value == 0) && (checked_source == 0)) {                   // based on id. Either exit on fail, or pass
                dlog(7, "Validated value for %d\n", id_number);             // back to POINT_SAMPLES for more eval.
                t_state = POINT_SAMPLES;
                id_number = 0;
                checked_value = -1;
                checked_source = -1;
            } else if(checked_value != 0) {
                switch(id_number) {
                case(DELTA_LAST):
                    ;
                    uint64_t dl_value; // used to be uint64
                    if((ret = get_uint64_value(line, &dl_value)) != 0) {
                        ;
                        break;
                    }
                    if((dl_value < DELTA_MIN) || (dl_value > DELTA_MAX)) {
                        dlog(0, "Error: at time %ld, found delta last outside threshold (%"PRIu64")\n", time_stamp, dl_value);
                        appraisal_passed = -1;
                    } else {
                        dlog(5, "VALIDATED delta last value of %"PRIu64"\n", dl_value);
                    }
                    checked_value = 0;
                    break;
                case(FREQ):
                    ;
                    float freq_value;
                    if((ret = get_float_value(line, &freq_value)) != 0) {
                        break;
                    }
                    if((freq_value < FREQ_MIN) || (freq_value > FREQ_MAX)) {
                        dlog(0, "Error: at time %ld, found frequency outside threshold (%lf)\n", time_stamp, freq_value);
                        appraisal_passed = -1;
                    } else {
                        dlog(5, "VALIDATED frequency value of %lf\n", freq_value);
                    }
                    checked_value = 0;
                    break;
                case(MAX_DELTA):
                    ;
                    /* XXX: not yet enabled
                     *
                    uint64_t mxd_value;
                    if((ret= get_uint64_value(line, &mxd_value)) != 0) {
                    break;
                    }
                    if((mxd_value < DELTA_MIN) || (mxd_value > DELTA_MAX)) {
                    dlog(0, "Error: at time %ld, found delta max outside threshold (%"PRIu64")\n", time_stamp, mxd_value);
                    appraisal_passed = -1;
                    } else {
                    dlog(5, "VALIDATED delta max value of %"PRIu64"\n", mxd_value);
                    }
                    */
                    checked_value = 0;
                    break;
                case(MIN_DELTA):
                    ;
                    /* XXX: not yet enabled
                     *
                    uint64_t mnd_value;
                    if((ret= get_uint64_value(line, &mnd_value)) != 0) {
                    break;
                    }
                    if((mnd_value < DELTA_MIN) || (mnd_value > DELTA_MAX)) {
                    dlog(0, "Error: at time %ld, found delta min outside threshold (%"PRIu64")\n", time_stamp, mnd_value);
                    appraisal_passed = -1;
                    } else {
                    dlog(5, "VALIDATED delta min value of %"PRIu64"\n", mnd_value);
                    }
                    */
                    checked_value = 0;
                    break;
                case(MSG_CNT):
                    ;
                    uint32_t mc_value;
                    if((ret = get_uint32_value(line, &mc_value)) != 0) {
                        break;
                    }
                    if((mc_value < MSG_CNT_MIN) || (mc_value > MSG_CNT_MAX)) {
                        dlog(0, "Error: at time %ld, found message count outside threshold (%"PRIu32")\n", time_stamp, mc_value);
                        appraisal_passed = -1;
                    } else {
                        dlog(5, "VALIDATED message count value of %"PRIu32"\n", mc_value);
                    }
                    checked_value = 0;
                    break;
                case(VAR):
                    ;
                    /* XXX: not yet enabled
                     *
                    float var_value;
                    if((ret = get_float_value(line, &var_value)) != 0) {
                    break;
                    }
                    if((var_value < VAR_MIN) || (var_value > VAR_MAX)) {
                    dlog(0, "Error: at time %ld, found variance outside threshold (%lf)\n", time_stamp, var_value);
                    appraisal_passed = -1;
                    } else {
                    dlog(5, "VALIDATED variance value of %lf\n", var_value);
                    }
                    */
                    checked_value = 0;
                    break;
                default:
                    dlog(0, "Error: unknown id number %d\n", id_number);
                }
            } else {
                int source_apid = 0;
                char *source_start = get_start_of_value(line, "      apid");
                if(source_start == NULL) {
                    break;
                }
                source_apid = atoi(source_start);

                if(source_apid == QUIOT_APID) {
                    dlog(5, "Validated SOURCE\n");
                } else {
                    dlog(0, "Error: got telemetry that's the wrong source\n");
                    appraisal_passed = -1;
                }
                checked_source = 0;
            }
            break;
        }
    }
    free(line);

    // Validate that time span was covered
    // XXX: currently passes as long as telemetry was found in time span
    dlog(0, "Asked for telemetry in time span %ld to %ld\n", start_time, end_time);
    if(max_time == 0) {
        dlog(0, "ERROR: No telemetry returned for the selected time period\n" );
        appraisal_passed = -1;
    } else {
        dlog(6, "Received telemetry spanning %ld to %ld\n", min_time, max_time);
        dlog(7, "TODO: validate that time span is _covered_ using min and max\n");
    }

    if(appraisal_passed == 0) {
        dlog(6, "Appraisal Passed \n");
    } else {
        dlog(6, "Appraisal Failed (%d)\n", appraisal_passed);
    }

    return appraisal_passed;
}

/**
 * Adds report data to the passed node; according to appraisal_passed value
 * passed.
 *
 * Returns 0 on success; -1 on Error
 */
static int add_tlm_report_data(measurement_graph *graph, node_id_t node_id, int appraisal_passed)
{
    report_data *rdata = NULL;
    char *pass_msg    = "PASS";
    char *fail_msg    = "FAIL";

    if(appraisal_passed == 0) {
        rdata = report_data_with_level_and_text(REPORT_INFO, strdup(pass_msg), strlen(pass_msg)+1);
    } else {
        rdata = report_data_with_level_and_text(REPORT_ERROR, strdup(fail_msg), strlen(fail_msg)+1);
    }

    if(measurement_node_add_rawdata(graph, node_id, &rdata->d) != 0) {
        asp_logerror("Failed to add report data to node\n");
        free_measurement_data(&rdata->d);
        return -1;
    }

    return 0;
}

int asp_measure(int argc, char *argv[])
{
    dlog(6, "In telemetry retrieval ASP\n");
    measurement_graph *graph;
    node_id_t node_id;

    time_delta_address *ta = NULL;
    long int start_span;
    long int end_span;

    int ret_val = 0;
    int appraisal_status = 0;

    // Parse args
    if((argc < 3) ||
            ((node_id = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    asp_logdebug("nodeid "ID_FMT"\n", node_id);

    ret_val = get_addr_data_from_node(graph, node_id, &ta);
    if(ret_val < 0) {
        dlog(0, "Failed to get time delta data from node\n");
        goto addr_error;
    }

    if(create_tr_config_file(ta->delta, CONFIG_FILE_PATH, &start_span, &end_span) != 0) {
        dlog(0, "Error creating TR client config file\n");
        goto config_file_error;
    }

    // Exec the telemetry retrieval client and appraise telemetry output
    FILE *fp = NULL;
    fp = exec_tr_client();
    if(!fp) {
        dlog(0, "Error exec'ing\n");
        ret_val = -EIO;
        goto exec_error;
    }

    appraisal_status = appraise_telemetry(fp, start_span, end_span);
    fclose(fp);

    ret_val = add_tlm_report_data(graph, node_id, appraisal_status);
    if(ret_val != 0) {
        dlog(0, "Error adding result to graph\n");
        goto add_data_error;
    }
    free_address(&ta->a);

    return 0;

add_data_error:
exec_error:
config_file_error:
    free_address(&ta->a);
addr_error:
    unmap_measurement_graph(graph);
    return ret_val;
}


