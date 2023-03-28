#define ASP_NAME "lsmod"

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

#include <stdio.h>

#include <util/util.h>
#include <measurement_spec/find_types.h>
#include <common/asp-errno.h>
#include <asp/asp-api.h>
#include <graph/graph-core.h>
#include <address_space/kernel_as.h>
#include <measurement/kmod_measurement_type.h>
#include <target/module.h>
#include <maat-basetypes.h>

/*! \file
 *
 * Collect the list and information about loaded modules from /proc/modules
 *
 */

int asp_init(int argc UNUSED, char *argv[] UNUSED)
{
    asp_logdebug("Initializing "ASP_NAME" ASP\n");

    register_types();

    asp_logdebug("Done initializing "ASP_NAME" ASP\n");
    return ASP_APB_SUCCESS;
}

int asp_exit(int status UNUSED)
{
    asp_logdebug("Exiting "ASP_NAME" ASP\n");
    return ASP_APB_SUCCESS;
}



int asp_measure(int argc, char *argv[])
{
    measurement_graph *graph;
    int rc		   = 0;
    FILE *fp		   = NULL;


    if((argc < 2) ||
            (map_measurement_graph(argv[1], &graph) != 0)) {
        asp_logerror("Usage: "ASP_NAME" <graph path> <node id>\n");
        return -EINVAL;
    }

    fp = fopen("/proc/modules", "r");
    if (fp == NULL) {
        asp_logerror("Failed to open /proc/modules: %s\n", strerror(errno));
        goto open_failed;
    }

    uint64_t modcnt = 0;
    while (!feof(fp)) {
        char mod_name[64] = {0};
        uint32_t size;
        uint32_t refcnt;
        char status[10] = {0};
        uint64_t load_address;
        char *deps;
        int ret;
        measurement_data *meas = NULL;
        kmod_data *m = NULL;
        measurement_variable mvar;
        node_id_t node;

        ret = fscanf(fp, "%31s %u %u %ms %9s %"PRIx64"", mod_name, &size,
                     &refcnt, &deps, status, &load_address);

        if (ret != 6)
            continue;

        asp_loginfo("MODULE: %s (0x%"PRIx64")\n", mod_name, load_address);

        if (load_address == 0) {
            load_address = modcnt++;
            dlog(2, "adjsting non-root load address to be unique\n");
        }

        mvar.address = alloc_address(&kernel_address_space);
        if (mvar.address == NULL) {
            asp_logwarn("Failed to allocate address for module pid\n");
            free(deps);
            continue;
        }

        kernel_address *ka = container_of(mvar.address, kernel_address, a);
        ka->kaddr = load_address;
        mvar.type = &module_target_type;

        if(measurement_graph_add_node(graph, &mvar, NULL, &node) < 0) {
            asp_logwarn("Warning: failed to add graph node for module %ld\n",
                        load_address);
            free(deps);
            continue;
        }

        meas = alloc_measurement_data(&kmod_measurement_type);

        if (meas == NULL) {
            dlog(0, "Failed to allocate kmod measurement data\n");
            free(deps);
            continue;
        }

        m = container_of(meas, kmod_data, d);
        strcpy(m->name, mod_name);
        strcpy(m->status, status);
        m->load_address = load_address;
        m->size = size;
        m->refcnt = refcnt;

        rc = measurement_node_add_rawdata(graph, node, &m->d);
        if (rc != 0) {
            asp_logwarn("failed to add node data\n");
        }

        free_measurement_data(&m->d);
        free_address(mvar.address);
    }

    fclose(fp);
open_failed:
    unmap_measurement_graph(graph);
    return 0;

}
