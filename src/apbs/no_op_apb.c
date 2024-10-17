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
 * This APB will read data written on the in file descriptor and create an
 * integrity response
 */

#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include <util/util.h>
#include <util/maat-io.h>

#include <common/apb_info.h>

#include <measurement_spec/measurement_spec.h>
#include <common/measurement_spec.h>
#include <apb/apb.h>
#include <common/asp.h>
#include <maat-envvars.h>
#include <apb/contracts.h>

#include "apb-common.h"


static GList *report_data_list = NULL;

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec_uuid UNUSED, int peerchan, int resultchan,
                char *target UNUSED, char *target_type UNUSED,
                char *resource UNUSED, struct key_value **arg_list UNUSED,
                int argc UNUSED)
{
    dlog(4, "Hello from the No-Op APB\n");
    int ret_val = 0, eof_encountered;
    size_t msg_len, bytes_read, bytes_written;
    unsigned char *msg;
    unsigned char *response_buf;
    size_t sz = 0;
    struct key_value *kv;

    //Rather than using "PASS" or "FAIL", we use a new evaluation value to represent that no appraisal has been done.
    xmlChar *evaluation = (xmlChar*)"UNKN";

    ret_val = maat_read_sz_buf(peerchan, &msg, &msg_len, &bytes_read, &eof_encountered, 10000, 0);
    if(ret_val != 0) {
        dlog(1, "Error reading response. Returned status is %d: %s\n", ret_val,
             strerror(ret_val < 0 ? -ret_val : ret_val));
        return -1;
    } else if(eof_encountered != 0) {
        dlog(0, "Error: unexpected EOF encountered reading result from appraiser\n");
        free(msg);
        return -1;
    } else if(msg_len > INT_MAX) {
        dlog(0, "Error reading response. Response is too long (%zu bytes)\n", msg_len);
        free(msg);
        return -1;
    }

    kv = calloc(1, sizeof(struct key_value));
    if (!kv) {
        dlog(1, "Warning, failed to malloc the kv pair\n");
        return -1;
    }

    kv->key = "No-op appraisal";
    kv->value = (char *)msg;

    report_data_list = g_list_append(report_data_list, kv);
    if(report_data_list == NULL) {
        dlog(1, "Failed to add report data to output list\n");
        return -1;
    }


    ret_val = create_integrity_response(parse_target_id_type((xmlChar*)target_type),
                                        (xmlChar*)target,
                                        (xmlChar*)resource, evaluation, report_data_list,
                                        scen->certfile, scen->keyfile, scen->keypass, NULL,
                                        scen->tpmpass, scen->akctx, scen->sign_tpm,
                                        (xmlChar **)&response_buf, &sz);

    if(ret_val < 0 || response_buf == NULL) {
        dlog(0, "Error: created_intergrity_response returned %d\n", ret_val);
        free(response_buf);
        return ret_val;
    }

    dlog(4, "Resp contract(%zd): %s\n", sz, response_buf);
    if(sz == 0) {
        sz = (size_t)xmlStrlen(response_buf) + 1;
        dlog(0, "Error: sz is 0, using strlen (Need to fix this! Why is xmlDocDumpMemory not giving back the size!?\n");
    }

    bytes_written = 0;
    dlog(4,"Send response from appraiser APB: %s.\n", response_buf);
    ret_val = write_response_contract(resultchan, response_buf, sz,
                                      &bytes_written, 5);

    if(ret_val != 0) {
        dlog(0, "Failed to send response from appraiser!: %s\n",
             strerror(ret_val<0 ? -ret_val : ret_val));
        return -EIO;
    }
    if(bytes_written != sz+sizeof(uint32_t)) {
        dlog(0, "Error: appraiser wrote %zu bytes (expected to write %zd)\n",
             bytes_written, sz);
        return -EIO;
    }

    dlog(3, "Appraiser wrote %zd byte(s)\n", bytes_written);

    dlog(4, "Leaving the No-Op APB\n");
    return ret_val;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
