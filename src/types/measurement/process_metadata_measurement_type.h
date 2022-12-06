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
#ifndef __PROCESSMETADATA_TYPE_H__
#define __PROCESSMETADATA_TYPE_H__

/*! \file
 * measurement_type for OVAL process meta data
 * specializes the measurement_type structure for OVAL process meta data
 * implements functions for measurement_type.
 */



#include <glib.h>

#include <measurement_spec/meas_spec-api.h>


/**
 *  OVAL process metadata measurement_type universally unique 'magic' id number
 */
#define PROCESSMETADATA_TYPE_MAGIC	(3200)

/**
 *  OVAL process metadata measurement_type universally unique name
 */
#define PROCESSMETADATA_TYPE_NAME	"process_metadata"

/**
 * custom built OVAL process metadata measurement_data
 */
typedef struct process_metadata_measurement {
    struct measurement_data d;
    char command_line[1024];
    char executable[1024];
    uint64_t exec_time; /* = utime + stime */
    int64_t pid;
    int64_t ppid;
    char scheduling_class[16];
    char start_time[16];
    char tty[16];
    struct {
        int real;
        int effective;
        int saved_set;
        int filesystem;
    } user_ids;
    struct {
        int real;
        int effective;
        int saved_set;
        int filesystem;
    } group_ids;

    int exec_shield;
    int loginuid;
    uint64_t posix_capability;
    char selinux_domain_label[64];
    int session_id;
} process_metadata_measurement;

measurement_data *process_metadata_type_alloc_data(void);
void process_metadata_type_free_data(measurement_data *d);

/**
 * name for file data measurement_type
 */
extern struct measurement_type process_metadata_measurement_type;

#endif /* __PROCESSMETADATA_TYPE_H__ */

/* To add to the structure contents later

   filesystem namespace mtab
   network namespace network devices
   netfilter rules
   sockets/network ports
   UTS ns
   PID ns
   PTS ns
   UID ns
   cgroup
   cpu set limits
   personality
   system call filtering

   process group
   all u/gids
   extended attributes?

   environment
   open file descriptors
   executable
   shared libraries
   running threads
   children
   cwd
*/
