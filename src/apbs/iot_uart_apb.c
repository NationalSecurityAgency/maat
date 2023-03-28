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
 * This APB collects evidence from IoT devices.
*/

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <util/util.h>
#include <graph/graph-core.h>
#include <maat-basetypes.h>
#include <common/apb_info.h>
#include <common/asp-errno.h>
#include <common/asp.h>
#include <common/asp_info.h>
#include <apb/contracts.h>
#include <common/measurement_spec.h>
#include <measurement_spec/measurement_spec.h>
#include <maat-envvars.h>

#include <address_space/simple_file.h>
#include <target/device_target_type.h>


GList *apb_asps = NULL;

/**
 * Create a new evidence graph, and then create nodes for each IP
 * discovered. Launch the ASP on each node to collect the measurement.
 */
int apb_execute(struct apb *apb, struct scenario *scen, uuid_t meas_spec_uuid UNUSED,
                int peerchan, int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED, struct key_value **arg_list UNUSED,
                int argc UNUSED)
{

    dlog(6, "Hello from IOTA UART APB.\n");

    int ret = -1;
    char *asp_argv[2];
    struct asp *iota_uart_asp = NULL;
    GList *iter = NULL;
    measurement_graph *graph = NULL;
    unsigned char *evidence = NULL;
    size_t evidence_size;
    node_id_str nstr;

    apb_asps = apb->asps;

    if((ret == register_types()) < 0) {
        return ret;
    }

    dlog(5, "ASPs list length = %d\n", g_list_length(apb_asps));
    dlog(6, "Performing IOTA APB measurement\n");
    for (iter = g_list_first(apb_asps); iter != NULL && iter->data != NULL;
            iter = g_list_next(iter)) {
        struct asp *tmp = (struct asp *)iter->data;
        if (strcmp(tmp->name, "iot_uart_asp") == 0) {
            iota_uart_asp = tmp;
            break;
        }
    }
    if (iota_uart_asp == NULL) {
        dlog(0, "Couldn't find iot_uart_asp in APB's ASP list\n");
        return -1;
    }

    /* Allocate a new measurement graph */
    if ((graph = create_measurement_graph(NULL)) == NULL) {
        dlog(0, "Failed to create a measurement graph.\n");
        return ASP_APB_ERROR_NOMEM;
    }

    // try measurement over UART
    // TODO:: read UART filename(s) and config from config file
    int i;
    int num_addresses = 1;
    char *addresses[num_addresses];
    addresses[0] = strdup("/dev/ttyUSB0");
    for (i = 0; i < num_addresses; i++) {
        node_id_t n;
        measurement_variable *var;
        simple_file_address *sfa = (simple_file_address*)
                                   address_from_human_readable(&simple_file_address_space, addresses[i]);
        if (sfa == NULL) {
            dlog(0, "Failed to parse filename of UART device\n");
            return -1;
        }
        dlog(2, "Adding node for UART-connected device at %s\n",
             simple_file_address_space.human_readable(&sfa->a));
        var = new_measurement_variable(&device_target_type, &sfa->a);
        if (!var) {
            dlog(1, "Failed to allocate new measurement variable\n");
            free_address(&sfa->a);
            continue;
        }

        ret = measurement_graph_add_node(graph, var, NULL, &n);
        free_measurement_variable(var);
        if (ret < 0) {
            dlog(1, "Failed adding simple file address node to graph\n");
            free_address(&sfa->a);
            continue;
        }
        str_of_node_id(n, nstr);
        asp_argv[0] = measurement_graph_get_path(graph);
        asp_argv[1] = nstr;

        ret = run_asp(iota_uart_asp, -1, -1, false, 2, asp_argv, -1);
        if (ret != 0) {
            dlog(1, "IoTA UART ASP returned in ERROR: %d\n", ret);
            return ret;
        }

    }

    serialize_measurement_graph(graph, &evidence_size, &evidence);
    dlog(3,"evidence: %s\n", evidence);

    ret = generate_and_send_back_measurement_contract(peerchan, scen,
            evidence, evidence_size);

    g_list_free_full(apb_asps, free);
    unmap_measurement_graph(graph);
    return ret;
}

/* Local Variables: */
/* c-basic-offset: 4 */
/* End: */
