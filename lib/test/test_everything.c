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

#include <config.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <glib.h>
#include <check.h>

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <glib.h>

#include <config.h>
#include <uuid/uuid.h>
#include <common/asp_info.h>
#include <common/asp.h>
#include <common/apb_info.h>
#include <common/measurement_spec.h>

#include <util/util.h>
#include <util/xml_util.h>
#include <util/maat-io.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>

#include "test-data.h"
#include <client/maat-client.h>

struct attestation_manager *am = NULL;
int the_pipe[2];

#define WORKDIR_CLIENT "workdir-client"
#define WORKDIR_SERVER "workdir-server"

void unchecked_setup(void)
{
    mkdir(WORKDIR_CLIENT, 0755);
    mkdir(WORKDIR_SERVER, 0755);
    setup();
}

void unchecked_teardown(void)
{
    close(the_pipe[0]);
    close(the_pipe[1]);
    free_attestation_manager(am);
    libmaat_exit();
}


START_TEST(test_exampleam)
{
    int ret;
    struct scenario *attester_scen = malloc(sizeof(struct scenario));
    struct scenario *appraiser_scen = malloc(sizeof(struct scenario));
    xmlChar *request_contract;
    size_t request_sz;

    am = new_attestation_manager(ASP_DIR, SPEC_DIR, APB_DIR, "XML", SELECTOR_CFG,
                                 EXECCON_RESPECT_DESIRED, EXECCON_SET_UNIQUE_CATEGORIES);
    fail_if(am == NULL, "Failed to initialize attestation manager\n");

    bzero(attester_scen, sizeof(typeof(*attester_scen)));
    bzero(appraiser_scen, sizeof(typeof(*appraiser_scen)));

    fail_if(pipe(the_pipe),
            "Failed to create pipe connecting attester and appraiser APBs: %s",
            strerror(errno));

    fail_if(create_integrity_request(TARGET_TYPE_HOST_PORT,
                                     (xmlChar*)"127.0.0.1", (xmlChar*)"2342",
                                     (xmlChar*)"test", NULL, NULL, NULL, NULL,
                                     &request_contract, &request_sz) != 0,
            "Failed to create integrity request contract");

    init_scenario(attester_scen,
                  CA_CERT,
                  ATTESTER_CERT,
                  ATTESTER_KEY,
                  NULL,
                  TPMPASS,
                  AKCTX,
                  AKPUB,
                  1,
                  1,
                  NULL,
                  NULL,
                  0,
                  ATTESTER);

    attester_scen->workdir		= WORKDIR_CLIENT;
    attester_scen->peer_chan            = maat_io_channel_new(the_pipe[1]);
    attester_scen->state                = IDLE;

    init_scenario(appraiser_scen,
                  CA_CERT,
                  APPRAISER_CERT,
                  APPRAISER_KEY,
                  NULL,
                  TPMPASS,
                  AKCTX,
                  AKPUB,
                  1,
                  1,
                  NULL,
                  (char*)request_contract,
                  (size_t)request_sz,
                  APPRAISER);


    appraiser_scen->workdir	        = WORKDIR_SERVER;
    appraiser_scen->peer_chan    	= maat_io_channel_new(the_pipe[0]);
    attester_scen->state                = IDLE;
    ret					= handle_request_contract(am, appraiser_scen);
    printf("Initial contract size: %zd\n",appraiser_scen->respsize);
    fail_if(ret != 0, "Failed to create initial contract: %d", ret);
    free(request_contract);

    /* "send" the initial contract to the attester */
    attester_scen->contract	= (char*)appraiser_scen->response;
    attester_scen->size		= appraiser_scen->respsize;
    attester_scen->response	= NULL;
    attester_scen->respsize	= 0;
    ret				= handle_initial_contract(am, attester_scen);
    printf("Modified contract size: %zd\n",attester_scen->respsize);
    fail_if(ret != 0, "Failed to create modified contract: %d", ret);

    free(attester_scen->contract);
    attester_scen->contract         = NULL;

    /* "send" the modified contract to the appraiser */
    appraiser_scen->contract	= (char*)attester_scen->response;
    appraiser_scen->size        = attester_scen->respsize;
    appraiser_scen->response	= NULL;
    appraiser_scen->respsize	= 0;
    ret			       	= handle_modified_contract(am, appraiser_scen);
    /* appraiser APB has been spawned here */
    printf("Execute contract size: %zd\n",appraiser_scen->respsize);
    fail_if(ret != 0, "Failed to create execute contract: %d", ret);

    free(appraiser_scen->contract);
    appraiser_scen->contract       = NULL;

    /* "send the execute contract back to the attester */
    attester_scen->contract	= (char*)appraiser_scen->response;
    appraiser_scen->response    = NULL;
    attester_scen->size		= appraiser_scen->respsize;
    attester_scen->response	= NULL;
    attester_scen->respsize	= 0;
    ret				= handle_execute_contract(am, attester_scen);


    close(attester_scen->peer_chan);
    close(appraiser_scen->peer_chan);

    attester_scen->peer_chan = -1;
    appraiser_scen->peer_chan = -1;

    free_scenario(attester_scen);
    free_scenario(appraiser_scen);

    /* attester APB has been spawned here */
    fail_if(ret != 0, "Failed to handle execute contract: %d", ret);

    /* reap both of the APB children. */
    int status;
    pid_t p;
    while((p = wait(&status)) > 0) {
        fail_if(WEXITSTATUS(status) != 0, "APB[%d] exited with status %d",
                p, WEXITSTATUS(status));
    }

    fail_if(errno != ECHILD, "Error received while reaping APBs: %s",
            strerror(errno));
    return;
}
END_TEST

int main(void)
{
    Suite *everything;
    SRunner *runner;
    TCase *exampleam;
    int nfail;

    everything = suite_create("everything");
    exampleam = tcase_create("exampleam");
    tcase_add_unchecked_fixture(exampleam, unchecked_setup,
                                unchecked_teardown);
    tcase_add_test(exampleam, test_exampleam);
    suite_add_tcase(everything, exampleam);

    runner = srunner_create(everything);
    srunner_set_log(runner, "test_results_everything.log");
    srunner_set_xml(runner, "test_results_everything.xml");
    srunner_run_all(runner, CK_VERBOSE);

    nfail = srunner_ntests_failed(runner);

    srunner_free(runner);

    return nfail;
}

