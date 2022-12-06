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
#include <maat-basetypes.h>
#include <util/util.h>
#include <common/apb_info.h>

#include <maat-basetypes.h>

struct kernel_measurement_data *get_kernel_msmt(void);

void setup(void)
{
    libmaat_init(0,4);
    register_types();
}

void teardown(void)
{
}

START_TEST(test_get_kernel_msmt)
{
    struct kernel_measurement_data *kmd = NULL;

    kmd = get_kernel_msmt();

    fail_if(kmd == NULL);
    fail_if(strlen(kmd->version) == 0);
    fail_if(strlen(kmd->cmdline) == 0);

    dlog(3, "first type bytes hash: %02x,%02x\n", kmd->vmlinux_hash[0], kmd->vmlinux_hash[1]);
    dlog(3, "cmdline: %s\n", kmd->cmdline);
    dlog(3, "version: %s\n", kmd->version);

    free_measurement_data(&kmd->meas_data);
}
END_TEST

int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *kernel_msmt;
    int nfail;

    s = suite_create("kernel_msmt");
    kernel_msmt = tcase_create("kernel_msmt");
    tcase_add_checked_fixture(kernel_msmt, setup, teardown);
    tcase_add_test(kernel_msmt, test_get_kernel_msmt);
    tcase_set_timeout(kernel_msmt, 1000);
    suite_add_tcase(s, kernel_msmt);

    r = srunner_create(s);
    srunner_set_log(r, "test_kernel_msmt.log");
    srunner_set_xml(r, "test_kernel_msmt.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
