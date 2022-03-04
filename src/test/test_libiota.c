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


#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <check.h>
#include <graph/graph-core.h>
#include <common/asp_info.h>

#include <common/asp.h>
#include <asp/asp-api.h>
#include <measurement_spec/find_types.h>
#include <util/util.h>
#include <common/apb_info.h>

#include <maat-basetypes.h>

#include <../asps/libiota.h>
#include <../asps/libiota_helper.h>
#include <../asps/iota_certs.h>

measurement_graph *graph;
node_id_t path_node;
iota iota_inst_req;
iota iota_inst_resp;
iota_msg *req;
iota_msg *resp;
unsigned char* req_ser;
int req_ser_ln;

int apb_execute(struct apb *apb UNUSED, struct scenario *scen UNUSED,
                uuid_t meas_spec UNUSED, int peerchan UNUSED,
                int resultchan UNUSED, char *target UNUSED,
                char *target_type UNUSED, char *resource UNUSED,
                char **arg_list UNUSED, int argc UNUSED)
{
    return -1;
}

iota_meas_func meas_funcs[] = {
    {
        .type = 0,
        .name = "",
        .func = NULL,
        .free_func = NULL
    }
};

GList *asps = NULL;
measurement_graph *graph = NULL;
measurement_variable *var = NULL;
node_id_t proc_node;
struct asp *iot_uart_asp;
struct asp *iot_appraise_asp;
unsigned char nonce[64];

void setup(void)
{

}

void teardown(void)
{
    destroy_measurement_graph(graph);
    unload_all_asps(asps);
}

START_TEST(test_uart_request)
{
    iota_ret ret = iota_init(&iota_inst_req, meas_funcs, 0,
                             (uint8_t*)tz_pubcert_pem, tz_pubcert_pem_sz);

    fail_unless(ret == IOTA_OK, "libiota failed to initialize iota instance for request with code: %s\n", ret);

    int c = 0;

    for (c = 0; c < sizeof(nonce); c++) {
        nonce[c] = c;
    }

    //IOTA_SIGNED_FLAG | IOTA_ENCRYPTED_FLAG

    ret = iota_req_init(&iota_inst_req, &req,
                        IOTA_ENCRYPTED_FLAG, IOTA_ACTION_MEAS,
                        0, NULL, 0, nonce, sizeof(nonce), (uint8_t*)tz_pubcert_pem,
                        tz_pubcert_pem_sz);

    fail_unless(ret == IOTA_OK, "libiota failed to initialize request with code: %s\n", ret);

    ret = iota_serialize(&iota_inst_req, req, &req_ser, (uint32_t*)&req_ser_ln);

    fail_unless(ret == IOTA_OK, "libiota failed to serialize request with code: %s\n", ret);

    iota_msg *resp;
    resp = malloc(sizeof(iota_msg));

    ret = iota_init(&iota_inst_resp, meas_funcs, 0,
                    (uint8_t*)tz_pubcert_pem, tz_pubcert_pem_sz);

    fail_unless(ret == IOTA_OK, "libiota failed to initialize iota instance for response with code: %s\n", ret);

    ret = iota_req_init(&iota_inst_resp, &resp,
                        IOTA_ENCRYPTED_FLAG, IOTA_ACTION_MEAS,
                        0, NULL, 0, nonce, sizeof(nonce), (uint8_t*)tz_pubcert_pem,
                        tz_pubcert_pem_sz);

    fail_unless(ret == IOTA_OK, "libiota failed to initialize response with code: %s\n", ret);

    ret = iota_deserialize(&iota_inst_resp, req_ser, req_ser_ln, resp);

    fail_unless(ret == IOTA_OK, "libiota failed to deserialize response with code: %s\n", ret);

    int comp = memcmp(nonce, resp->nonce, 64);

    fail_unless(comp == 0, "deserialized response could not be verified...\n");

}
END_TEST


int main(void)
{
    Suite *s;
    SRunner *r;
    TCase *iot_uart_request;
    int nfail;

    s = suite_create("iot_uart_request");
    iot_uart_request = tcase_create("iot_uart_request");
    tcase_add_checked_fixture(iot_uart_request, setup, teardown);
    tcase_add_test(iot_uart_request, test_uart_request);
    tcase_set_timeout(iot_uart_request, 10);
    suite_add_tcase(s, iot_uart_request);

    r = srunner_create(s);
    srunner_set_log(r, "iot_uart_request.log");
    srunner_set_xml(r, "iot_uart_request.xml");
    srunner_run_all(r, CK_VERBOSE);
    nfail = srunner_ntests_failed(r);
    if(r) srunner_free(r);
    return nfail;
}
