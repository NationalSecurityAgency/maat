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

#include <config.h>

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <check.h>

#ifdef HAVE_LIBSELINUX
#include <selinux/selinux.h>
#endif

#include <asp/asp-api.h>

#include <graph/graph-core.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <measurement_spec/find_types.h>
#include <measurement/elfheader_measurement_type.h>
#include <maat-basetypes.h>
#include <util/util.h>
#include <common/apb_info.h>

#include <maat-basetypes.h>

void setup(void)
{
    libmaat_init(0,4);
    register_types();
}

void teardown(void)
{
}

int test_only_read_process_metadata(long p, process_metadata_measurement **out);

static void check_self_measurement(process_metadata_measurement *msmt)
{
    fail_if(msmt->pid != getpid(),
            "PID returned by inspection doesn't match getpid(). "
            "Expected %ld got %ld",
            getpid(), msmt->pid);
    fail_if(msmt->ppid != getppid(),
            "PPID returned by inspection doesn't match getppid(). "
            "Expected %ld got %ld",
            getppid(), msmt->ppid);
    fail_if(msmt->user_ids.real != getuid(),
            "UID returned by inspection doesn't match getuid(). "
            "Expected %d got %d",
            getuid(), msmt->user_ids.real);
    fail_if(msmt->user_ids.effective != geteuid(),
            "UID returned by inspection doesn't match geteuid(). "
            "Expected %d got %d",
            geteuid(), msmt->user_ids.effective);

    fail_if(msmt->group_ids.real != getgid(),
            "GID returned by inspection doesn't match getgid(). "
            "Expected %d got %d",
            getgid(), msmt->group_ids.real);

    fail_if(msmt->group_ids.effective != getegid(),
            "EGID returned by inspection doesn't match getegid(). "
            "Expected %d got %d",
            getegid(), msmt->group_ids.effective);

#ifdef HAVE_LIBSELINUX
    char *context = NULL;
    if(getcon(&context) == 0) {
        fail_if(strcmp(msmt->selinux_domain_label, context) != 0,
                "SELinux context doesn't match. Expected %s got %s",
                context, msmt->selinux_domain_label);
        freecon(context);
    }
#endif
}
START_TEST(test_read_process_metadata)
{
    long p = (long)getpid();
    process_metadata_measurement *msmt = NULL;

    fail_if(test_only_read_process_metadata(p, &msmt) != 0,
            "Failed to read process metadata for self.");

    check_self_measurement(msmt);
}
END_TEST

START_TEST(test_lsproc_asp)
{
    address *paddr = alloc_address(&unit_address_space);
    fail_if(paddr == NULL, "Failed to allocate address for root of lsproc asp\n");
    measurement_variable var = {.type = &process_target_type, .address = paddr };

    measurement_graph *g = create_measurement_graph(NULL);
    fail_if(g == NULL, "Failed to create measurement graph\n");
    char *path = measurement_graph_get_path(g);
    node_id_t root_node = INVALID_NODE_ID;
    node_id_str nstr;
    fail_if(path == NULL, "Failed to get path to measurement graph\n");
    int rc = measurement_graph_add_node(g, &var, NULL, &root_node);
    fail_if(rc < 0, "Failed to add lsproc root node to graph\n");
    str_of_node_id(root_node, nstr);

    char *aspargv[] = {"lsproc", path, nstr};

    fail_if(asp_init(3, aspargv) != 0, "ASP Init call failed\n");
    fail_if(asp_measure(3, aspargv) != 0, "ASP Measure call failed.\n");
    fail_if(asp_exit(0) != 0, "ASP Exit failed\n");

    node_iterator *it = NULL;
    int found_self = 0;
    for(it = measurement_graph_iterate_nodes(g); it != NULL; it = node_iterator_next(it)) {
        node_id_t node = node_iterator_get(it);
        if(node == root_node) {
            continue;
        }

        target_type *type = measurement_node_get_target_type(g, node);
        dlog(3, "Examining node: "ID_FMT"\n", node);
        fail_if(type == NULL, "Failed to get type of node");
        if(type != &process_target_type) {
            continue;
        }
        address *addr = measurement_node_get_address(g, node);
        fail_if(addr == NULL, "Failed to get address of node");
        fail_if(addr->space != &pid_address_space,
                "After measuring, node of type process has address "
                "in space \"%s\" (should be a pid)\n",
                addr->space->name);
        pid_address *pa = container_of(addr, pid_address, a);
        marshalled_data *mmsmt = NULL;
        measurement_data *msmt = NULL;
        int rc = measurement_node_get_data(g, node, &process_metadata_measurement_type,
                                           &mmsmt);
        if(rc != 0) {
            fail_if(pa->pid == getpid(),
                    "After measurement, failed to get process metadata for process node with self pid.");
            goto next;
        }

        msmt = unmarshall_measurement_data(mmsmt);
        fail_if(msmt == NULL, "Failed to unmarshall measurement data.\n");

        if(pa->pid == getpid()) {
            free_measurement_data(&mmsmt->meas_data);
            process_metadata_measurement *pmsmt = container_of(msmt, process_metadata_measurement, d);
            found_self = 1;
            check_self_measurement(pmsmt);
        }
next:
        free_measurement_data(msmt);
        free_address(addr);

    }

    fail_if(found_self == 0, "No measurement found for self pid.\n");
    destroy_measurement_graph(g);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *lsprocservice;
    int nfail;

    s = suite_create("lsproc");
    lsprocservice = tcase_create("lsproc");
    tcase_add_checked_fixture(lsprocservice, setup, teardown);
    tcase_add_test(lsprocservice, test_read_process_metadata);
    tcase_add_test(lsprocservice, test_lsproc_asp);
    tcase_set_timeout(lsprocservice, 1000);
    suite_add_tcase(s, lsprocservice);

    r = srunner_create(s);
    srunner_set_log(r, "test_lsproc.log");
    srunner_set_xml(r, "test_lsproc.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
