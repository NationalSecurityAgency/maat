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
 * This APB will read data written on the in file descriptor and write it out
 * to the out file descriptor. This supports the ability to forward a raw
 * measurement to a measurement client instead of appraising it.
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

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec_uuid UNUSED, int peerchan, int resultchan,
                char *target UNUSED, char *target_type UNUSED,
                char *resource UNUSED, struct key_value **arg_list UNUSED,
                int argc UNUSED)
{
    dlog(4, "Hello from the Forwarding APB\n");
    int ret_val = 0, eof_encountered;
    size_t msg_len, bytes_read, bytes_written;
    char *msg;

    ret_val = maat_read_sz_buf(peerchan, &msg, &msg_len, &bytes_read, &eof_encountered, 10000, -1);
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

    ret_val = maat_write_sz_buf(resultchan, msg, msg_len, &bytes_written, 20);
    free(msg);
    if(ret_val < 0) {
        dlog(0, "Unable to forward along peer channel\n");
        return -1;
    }

    dlog(4, "Leaving the Forwarding APB\n");
    return ret_val;
}

/* Local Variables:	*/
/* c-basic-offset: 4	*/
/* End:			*/
