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
 * This ASP lists (and gathers metadata) on all running processes on the system
 */

#define _GNU_SOURCE

#include <errno.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define ASP_NAME "lsproc"

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <util/util.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <common/asp-errno.h>
#include <measurement/process_metadata_measurement_type.h>
#include <address_space/pid_as.h>
#include <target/process.h>
#include <linux/sched.h>
#include <string.h>

/* Apparently SCHED_DEADLINE isn't in some recent distro kernels */
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE  6
#endif

int asp_init(int argc, char *argv[])
{
    asp_loginfo("Initialized "ASP_NAME" ASP\n");
    return 0;
}

int asp_exit(int status)
{
    asp_loginfo("Exiting "ASP_NAME" ASP\n");
    return 0;
}

static int parse_stats(char *stats, process_metadata_measurement *out)
{
    int pid, ppid, pgrp, session, tty_nr, tpgid;
    char state, comm[256];
    unsigned flags;
    unsigned long minflt, cminflt, majflt, cmajflt, utime, stime;
    long cutime, cstime, priority, nice, num_threads, itrealvalue;
    unsigned long long starttime;
    unsigned long vsize;
    long rss;
    unsigned long rsslim, startcode, endcode, startstack, kstkesp, kstkeip, signal, blocked;
    unsigned long sigignore, sigcatch, wchan, nswap, cnswap;
    int exit_signal, processor;
    unsigned int rt_priority;
    unsigned int policy;
    unsigned long long delayacct_blkio_ticks;
    unsigned long guest_time;
    long cguest_time;
    unsigned long start_data, end_data, start_brk, arg_start, arg_end, env_start, env_end;
    int exit_code;

    if((sscanf(stats,
               /* pid    comm      state   ppid        pgrp        session   tty_nr tpgid   */
               "%d %255s %c %d %d %d %d %d"
               /* flags  minflt    cminflt majflt      cmajflt     utime     stime  cutime  */
               "%u %lu %lu %lu %lu %lu %lu %ld"
               /* cstime priority  nice    num_threads itrealvalue starttime vsize  rss     */
               "%ld %ld %ld %ld %ld %llu %lu %ld"
               /* rsslim startcode endcode startstack  kstkesp     kstkeip   signal blocked */
               "%lu %lu %lu %lu %lu %lu %lu %lu"
               /* sigignore sigcatch wchan nswap cnswap exit_signal processor rt_priority  */
               "%lu %lu %lu %lu %lu %d %d %u"
               /* policy delayacct_blkio_ticks guest_time cguest_time start_data end_data start_brk arg_start */
               "%u %llu %lu %ld %lu %lu %lu %lu"
               /* arg_end env_start env_end exit_code */
               "%lu %lu %lu %d",
               &pid, comm, &state, &ppid, &pgrp, &session, &tty_nr, &tpgid,
               &flags, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime, &cutime,
               &cstime, &priority, &nice, &num_threads, &itrealvalue, &starttime, &vsize, &rss,
               &rsslim, &startcode, &endcode, &startstack, &kstkesp, &kstkeip, &signal, &blocked,
               &sigignore, &sigcatch, &wchan, &nswap, &cnswap, &exit_signal, &processor, &rt_priority,
               &policy, &delayacct_blkio_ticks, &guest_time, &cguest_time, &start_data, &end_data, &start_brk, &arg_start,
               &arg_end, &env_start, &env_end, &exit_code)) != 52) {
        return -1;
    }
    if(pid != out->pid) {
        return -1;
    }

    switch(policy) {
    case SCHED_NORMAL:
        strcpy(out->scheduling_class, "TS");
        break;
    case SCHED_FIFO:
        strcpy(out->scheduling_class, "FIFO");
        break;
    case SCHED_RR:
        strcpy(out->scheduling_class, "RR");
        break;
    case SCHED_BATCH:
        strcpy(out->scheduling_class, "BATCH");
        break;
    case SCHED_DEADLINE:
        strcpy(out->scheduling_class, "DEADLINE");
        break;
    default:
        sprintf(out->scheduling_class, "UNK%08x", policy);
        break;
    }

    /* seriously?! the major number is bits [15,8]
     * and the minor is ([31,20] >> 12) & [7,0]
     */
    int rc = snprintf(out->tty, 16, "(%02x,%06x)", (tty_nr & 0xff00) >> 8,
                      ((tty_nr & 0xfff00000) >> 12) & (tty_nr & 0xff));
    if(rc >= 16 || rc < 0) {
        return -1;
    }
    out->exec_time = utime + stime;
    return 0;
}

static int parse_process_status_line(char *status, process_metadata_measurement *out)
{
    char *colon;
    int i = 0;
    char *field = status;

    colon = strchr(field, ':');
    if(colon == NULL) {
        /* just skip malformed lines without whinging. */
        return 0;
    }

    *colon = '\0';
    if(strcmp(field, "Pid") == 0) {
        long tmppid;
        if(sscanf(colon+1, " %ld", &tmppid) != 1) {
            if(tmppid != out->pid) {
                return -1;
            }
        }
    } else if(strcmp(field, "PPid") == 0) {
        if(sscanf(colon+1, " %"PRIi64, &out->ppid) != 1) {
            return -1;
        }
    } else if(strcmp(field, "CapEff") == 0) {
        if(sscanf(colon+1, " %"PRIx64, &out->posix_capability) != 1) {
            return -1;
        }
    } else if(strcmp(field, "Uid") == 0) {
        if(sscanf(colon+1, " %d %d %d %d",
                  &out->user_ids.real,
                  &out->user_ids.effective,
                  &out->user_ids.saved_set,
                  &out->user_ids.filesystem) != 4) {
            return -1;
        }
    } else if(strcmp(field, "Gid") == 0) {
        if(sscanf(colon+1, " %d %d %d %d",
                  &out->group_ids.real,
                  &out->group_ids.effective,
                  &out->group_ids.saved_set,
                  &out->group_ids.filesystem) != 4) {
            return -1;
        }
    }
    return 0;
}

static int read_process_metadata(long p, process_metadata_measurement **out,
                                 int *is_root)
{
    char path[PATH_MAX];
    char buf[1024];
    measurement_data *data = NULL;
    process_metadata_measurement *proc_data = NULL;
    int rc = 0;
    FILE *f = NULL;

    data = alloc_measurement_data(&process_metadata_measurement_type);

    if(data == NULL) {
        dlog(0, "Failed to allocate process metadata structure\n");
        goto error;
    }

    proc_data = container_of(data, process_metadata_measurement, d);
    proc_data->pid = p;

    rc = snprintf(path, PATH_MAX, "/proc/%ld/stat", p);
    if(rc < 0 || rc >= PATH_MAX) {
        dlog(0, "snprintf of process stat file failed with code: %d\n", rc);
        goto error;
    }
    if((f = fopen(path, "r")) == NULL) {
        dlog(0, "Failed to open file %s\n", path);
        goto error;
    }
    if(fgets(buf, sizeof(buf), f) == NULL) {
        dlog(0, "Failed to read file %s\n", path);
        goto error;
    }
    if(parse_stats(buf, proc_data) != 0) {
        dlog(0, "Failed to parse process stat file\n");
        goto error;
    }
    fclose(f);
    f = NULL;

    rc = snprintf(path, PATH_MAX, "/proc/%ld/status", p);
    if(rc < 0 || rc >= PATH_MAX) {
        dlog(0, "snprintf of process status file failed with code: %d\n", rc);
        goto error;
    }

    if((f = fopen(path, "r")) == NULL) {
        dlog(0, "Failed to open file %s\n", path);
        goto error;
    }
    while(!feof(f)) {
        if(fgets(buf, sizeof(buf), f) == NULL) {
            if(!feof(f)) {
                dlog(0, "Failed to read line from file %s\n", path);
                goto error;
            }
            continue;
        }
        if(parse_process_status_line(buf, proc_data) != 0) {
            dlog(0, "Failed to parse process status file\n");
            goto error;
        }
    }
    fclose(f);
    f = NULL;

    /* Populate is_root flag if any uids are 0 */
    if (proc_data->user_ids.real == 0 || proc_data->user_ids.effective == 0 ||
            proc_data->user_ids.saved_set == 0 ||
            proc_data->user_ids.filesystem == 0) {
        *is_root = 1;
    } else {
        *is_root = 0;
    }

    /*
     * Read /proc/[pid]/exe symlink into executable
     */
    rc = snprintf(path, PATH_MAX, "/proc/%ld/exe", p);
    if (rc < 0 || rc >= PATH_MAX) {
        dlog(0, "snprintf of process exe link failed with code: %d\n", rc);
        goto error;
    }
    memset(proc_data->executable, 0, sizeof(proc_data->executable));
    rc = readlink(path, proc_data->executable, sizeof(proc_data->executable)-1);
    if (rc < 0 || rc >= sizeof(proc_data->executable)-1) {
        dlog(0, "Error reading proc exe link name for path (%s). rc=%d\n", path, rc);
        if(rc == -1) {
            dlog(0, "Errno: %d (%s)\n", errno, strerror(errno));
        }
        goto error;
    }
    /*
     * To be extra safe in case readlink clobbered the rest
     * of the buffer:
     */
    proc_data->executable[rc] = 0;

    /*
      /proc/pid/cmdline has the argv array with each element
      separated by a '\0' and with an extra '\0' at the end
    */
    rc = snprintf(path, PATH_MAX, "/proc/%ld/cmdline", p);
    if(rc < 0 || rc >= PATH_MAX) {
        dlog(0, "snprintf of process cmdline file failed with code: %d\n", rc);
        goto error;
    }
    if((f = fopen(path, "r")) == NULL) {
        dlog(0, "Failed to open file %s\n", path);
        goto error;
    }

    size_t len =0;

    if(fgets(buf, sizeof(buf), f) != NULL) {
        int nullcnt = 0;
        int i;

        memset(proc_data->command_line, 0, sizeof(proc_data->command_line));

        for (i=0; i<sizeof(proc_data->command_line)-2; i++) {
            if (buf[i] == 0) {
                nullcnt++;
                if (nullcnt == 2) {
                    break;
                }
                proc_data->command_line[i] = ' ';
                continue;
            } else {
                nullcnt = 0;
            }

            proc_data->command_line[i] = buf[i];
        }

    } else {
        asp_logwarn("Warning: Failed to read command line for process %ld\n", p);
        memcpy(proc_data->command_line, "UNKNOWN", strlen("UNKNOWN")+1);
    }
    fclose(f);
    f = NULL;

    rc = snprintf(path, PATH_MAX, "/proc/%ld/attr/current", p);
    if(rc < 0 || rc >= PATH_MAX) {
        dlog(0, "snprintf of process security context file failed with code: %d\n",
             rc);
        goto error;
    }

    if((f = fopen(path, "r")) != NULL) {
        if(fgets(buf, sizeof(buf), f) == NULL) {
            dlog(0, "Warning: failed to read security context file.\n");
        } else {
            len = strlen(buf)+1;

            if(len > sizeof(proc_data->selinux_domain_label)) {
                memcpy(proc_data->selinux_domain_label, buf,
                       sizeof(proc_data->selinux_domain_label)-1);
                proc_data->selinux_domain_label[
                    sizeof(proc_data->selinux_domain_label)-1] = '\0';
            } else {
                memcpy(proc_data->selinux_domain_label, buf, len);
            }
        }
        fclose(f);
        f = NULL;
    }

    *out = proc_data;
    return 0;

error:
    if(f != NULL) {
        fclose(f);
    }
    free_measurement_data(data);
    return -1;
}

#ifdef ENABLE_TESTS
int test_only_read_process_metadata(long p, process_metadata_measurement **out)
{
    int ignore;
    return read_process_metadata(p, out, &ignore);
}
#endif


int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    DIR *d = NULL;
    struct dirent *dent;
    int rc = 0;
    node_id_t root_node = INVALID_NODE_ID;

    if((argc < 3) ||
            ((root_node = node_id_of_str(argv[2])) == INVALID_NODE_ID) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    errno = 0;
    if((d = opendir("/proc")) == NULL) {
        asp_logerror("Failed to open /proc filesystem");
        unmap_measurement_graph(graph);
        if(errno != 0) {
            return -errno;
        }
        return -1;
    }

    errno = 0;
    while((dent = readdir(d)) != NULL) {
        long pid = LONG_MAX;
        char *endptr;
        int is_root = 0;
        process_metadata_measurement *m = NULL;
        marshalled_data *md = NULL;
        measurement_variable mvar;
        node_id_t new_node;
        edge_id_t new_edge;

        if(dent->d_type != DT_DIR) {
            goto not_a_dir;
        }

        errno = 0;
        pid = strtol(dent->d_name, &endptr, 10);
        if((dent->d_name[0] == '\0') ||
                ((pid > LONG_MAX) && (errno != 0)) ||
                (pid < 0) ||
                (pid != (pid_t)pid) || /* wacky check to ensure
				   * that pid fits in pid_t */
                (*endptr != '\0')) {
            asp_loginfo("/proc directory entry \"%s\" is not a pid\n",
                        dent->d_name);
            goto not_a_pid;
        }

        if((mvar.address = alloc_address(&pid_address_space)) == NULL) {
            asp_logwarn("Warning failed to allocate address for process "
                        "metadata measurement\n");
            goto alloc_address_failed;
        }

        pid_address *paddr      = container_of(mvar.address, pid_address, a);
        paddr->pid    	        = (pid_t)pid;
        mvar.type		= &process_target_type;

        if(measurement_graph_add_node(graph, &mvar, NULL, &new_node) < 0) {
            asp_logwarn("Warning: failed to add graph node for process %ld\n",
                        pid);
            goto add_node_failed;
        }

        announce_node(new_node);


        if(measurement_graph_add_edge(graph, root_node, "process_metadata.pids", new_node, &new_edge) < 0) {
            asp_logwarn("Warning: failed to add graph edge for process %ld\n",
                        pid);
        } else {
            announce_edge(new_edge);
        }

        if(read_process_metadata((pid_t)pid, &m, &is_root) != 0) {
            asp_logwarn("Warning: failed to read metadata for process %ld\n",
                        pid);
            goto read_metadata_failed;
        }

        if (is_root) {
            if(measurement_graph_add_edge(graph, root_node, "process_metadata.root_pids", new_node, &new_edge) < 0) {
                asp_logwarn("Warning: failed to add root_pids edge for process %ld\n",
                            pid);
            } else {
                announce_edge(new_edge);
            }
        }

        if((md = marshall_measurement_data(&m->d)) == NULL) {
            asp_logwarn("Warning: failed to marshall metadata measurement for "
                        "process %ld\n", pid);
            goto marshall_data_failed;
        }

        if(measurement_node_add_data(graph, new_node, md) != 0) {
            asp_logwarn("Warning: failed to add metadata measurement to node for "
                        "process %ld\n", pid);
            goto add_data_failed;
        }

add_data_failed:
        free_measurement_data(&md->meas_data);
marshall_data_failed:
        free_measurement_data(&m->d);
read_metadata_failed:
add_node_failed:
        free_address(mvar.address);
alloc_address_failed:
not_a_pid:
not_a_dir:
        errno = 0;
        continue;
    }

    if(errno != 0) {
        asp_logerror("Failed to read directory entries from /proc");
        rc = -errno;
    }

    closedir(d);

    unmap_measurement_graph(graph);
    return rc;
}
