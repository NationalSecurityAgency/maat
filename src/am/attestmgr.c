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

#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <inttypes.h>
#include <glib.h>
#include <common/asp.h>
#include <common/asp_info.h>
#include <util/inet-socket.h>
#include <util/unix-socket.h>
#include <util/util.h>
#include <util/maat-io.h>
#include <common/apb_info.h>
#include "contracts.h"

#include <config.h>
#include <uuid/uuid.h>
#include <util/xml_util.h>
#include <util/keyvalue.h>
#include "am.h"
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <apb/contracts.h>

#include <common/measurement_spec.h>
#include <maat-envvars.h>

#include "am_config.h"
#include "sighandling.h"

typedef void (*transition_fn)(struct am_config *config, struct scenario *scen);
typedef void (*error_reporter)(struct am_config *config, struct scenario *scen);

static int check_send_result(int status, char *contract)
{
    int rc = -1;
    switch(status) {
    case 0:
        rc = 0;
        break;
    case EAGAIN:
        dlog(0, "Error while sending %s contract: timeout occurred\n", contract);
        break;
    default:
        dlog(0, "Error while sending %s contract: %s\n", contract,
             strerror(status));
        break;
    }
    return rc;
}

static int check_receive_result(struct scenario *scen, int status)
{
    int rc = -1;
    switch(status) {
    case 0:
        rc = 0;
        break;
    case EAGAIN:
        if(scen != NULL) {
            scen->error_message = strdup("Error while receiving contract: timeout occurred");
        }
        dlog(0, "Error while receiving contract: timeout occurred\n");
        break;
    default:
        if(scen != NULL) {
            scen->error_message = g_strdup_printf("Error while receiving contract: %s", strerror(status));
        }
        dlog(0, "Error while receiving contract: %s\n", strerror(status));
        break;
    }
    return rc;
}

static inline int connect_to_attester(struct scenario *scen)
{
    struct hostent *host = NULL;
    scen->peer_chan = -1;

    dlog(3, "Request targets host %s\n", scen->attester_hostname);
    if(scen->attester_tunnel_path != NULL) { //unix sock connection
        dlog(1,"connecting to: %s\n", scen->attester_tunnel_path);
        if(strcmp(":receive:", scen->attester_tunnel_path) == 0) {
            dlog(6, "Tunnel path is :receive: attempt to read fd from socket\n");
            struct msghdr msg = {0};
            char m_buffer[256];
            char c_buffer[256];
            struct iovec io = {.iov_base = m_buffer, .iov_len = sizeof(m_buffer) };
            int rc;
            msg.msg_iov     = &io;
            msg.msg_iovlen  = 1;
            msg.msg_control = c_buffer;
            msg.msg_controllen = sizeof(c_buffer);
            if((rc = maat_wait_on_channel(scen->requester_chan, 1, 5)) < 0) {
                scen->error_message = g_strdup_printf(
                                          "Error while waiting to receive tunnel socket: %s",
                                          strerror(errno));
                dlog(0, "%s\n", scen->error_message ?
                     scen->error_message : "(error)");
                return -1;
            } else if(rc == 0) {
                scen->error_message = strdup(
                                          "Timed out waiting to receive tunnel socket");
                dlog(0, "%s\n", scen->error_message ?
                     scen->error_message : "(error)");
                return -1;
            }
            if(recvmsg(scen->requester_chan, &msg, 0) < 0) {
                scen->error_message = g_strdup_printf(
                                          "Failed to receive tunnel socket: %s",
                                          strerror(errno));
                dlog(0, "%s\n", scen->error_message ?
                     scen->error_message : "(error)");
                return -1;
            }
            struct cmsghdr * cmsg = CMSG_FIRSTHDR(&msg);
            if(cmsg == NULL) {
                scen->error_message = g_strdup_printf(
                                          "Failed to receive tunnel socket: "
                                          "No control data present in message");
                dlog(0, "%s\n", scen->error_message ?
                     scen->error_message : "(error)");
                return -1;
            }

            unsigned char *data = CMSG_DATA(cmsg);

            scen->peer_chan = maat_io_channel_new(*((int*)data));
        } else {
            scen->peer_chan = open_unix_client(scen->attester_tunnel_path);
            if(scen->peer_chan < 0) {
                scen->error_message = g_strdup_printf(
                                          "Failed to open connection to attester: %s",
                                          scen->attester_tunnel_path);
                dlog(0, "%s\n", scen->error_message ?
                     scen->error_message : "(error)");
                return -1;
            }
        }
        return 0;
    } else { //inet sock connnection
        if(scen->attester_portnum > UINT16_MAX) {
            scen->error_message = g_strdup_printf(
                                      "Error: attester port number > max port number %"PRId16,
                                      UINT16_MAX);
            dlog(0, "%s\n", scen->error_message ?
                 scen->error_message : "(error)");
            return -1;
        }

        host = gethostbyname(scen->attester_hostname);
        if(host == NULL || host->h_addr_list[0] == NULL) {
            scen->error_message = g_strdup_printf(
                                      "Error getting target host entry from name \"%s\"",
                                      scen->attester_hostname);
            dlog(0, "%s\n", scen->error_message ?
                 scen->error_message : "(error)");
            return -1;
        }

        dlog(1,"connecting to: %s(%s)(%s)\n",scen->attester_hostname, host->h_name,
             inet_ntoa(*((struct in_addr *)host->h_addr_list[0])));

        // connect to attester
        scen->peer_chan = connect_to_server(
                              inet_ntoa(*((struct in_addr *)host->h_addr_list[0])),
                              (uint16_t)scen->attester_portnum);
        if(scen->peer_chan < 0) {
            scen->error_message = g_strdup_printf(
                                      "Failed to open connection to attester %s:%lu",
                                      host->h_name, scen->attester_portnum);
            dlog(0, "%s\n", scen->error_message ?
                 scen->error_message : "(error)");
            return -1;
        }
        return 0;
    }
    return -1;
}

static struct attestation_manager *am;

static void handle_appraiser(am_config *config, struct scenario *scen)
{
    am_contract_type ctype = 0;
    int res;

    if(parse_contract_type(scen->contract, scen->size, &ctype)) {
        dlog(0, "Failed to parse contract type\n");
        scen->state = AM_ERROR;
        goto out;
    }

    dlog(2, "Appraiser: in state %s handling contract type %s\n",
         scenario_state_name(scen->state), get_contract_name(ctype));

    switch(scen->state) {
    case IDLE:
        if(ctype != AM_CONTRACT_REQUEST) {
            dlog(0, "Expected REQUEST contract, but got %s\n",
                 get_contract_name(ctype));
            scen->state = AM_ERROR;
            goto out;
        }
        scen->state = REQUEST_RECEIVED;

        if((handle_request_contract(am, scen)) != 0) {
            dlog(0, "Failed to generate initial contract\n");
            scen->state = AM_ERROR;
            goto out;
        }

        if((connect_to_attester(scen)) != 0) {
            dlog(0, "Failed to connect to attester\n");
            scen->state = AM_ERROR;
            goto out;
        }
        dlog(2, "Sending INITIAL contract\n");
        res = write_initial_contract(scen->peer_chan, scen->response,
                                     scen->respsize, NULL,
                                     config->am_comm_timeout);
        if(check_send_result(res, "initial") != 0) {
            scen->state = AM_ERROR;
            dlog(1, "sending INITIAL contract failed: %d\n", res);
            goto out;
        }
        scen->state = INITIAL_SENT;
        break;

    case INITIAL_SENT:
        if(ctype != AM_CONTRACT_MODIFIED) {
            dlog(0, "Expected MODIFIED contract but got %s\n",
                 get_contract_name(ctype));
            scen->state = AM_ERROR;
            goto out;
        }
        scen->state = MODIFIED_RECEIVED;
        dlog(5, "PRESENTATION MODE (in): Appraiser received modified contract with subset of measurements\n");
        //TODO pass in the resource and target_id_type also for run_apb_async
        if((handle_modified_contract(am, scen)) != 0) {
            dlog(0, "Failure while handling modified contract\n");
            scen->state = AM_ERROR;
            goto out;
        }
        dlog(2, "Sending EXECUTE contract\n");
        res = write_execute_contract(scen->peer_chan, scen->response,
                                     scen->respsize, NULL,
                                     config->am_comm_timeout);

        if(check_send_result(res, "execute") != 0) {
            scen->state = AM_ERROR;
            goto out;
        }
        scen->state = EXECUTE_SENT;
        scen->state = IDLE;
        break;

    default:
        dlog(0, "Unexpected appraiser state %s\n",
             scenario_state_name(scen->state));
        scen->state = AM_ERROR;
        goto out;
    }

out:
    free(scen->contract);
    free(scen->response);
    scen->contract	= NULL;
    scen->size            = 0;
    scen->response	= NULL;
    scen->respsize	= 0;
    return;
}

void report_attestation_error(struct am_config *config, struct scenario *scen)
{
    //send fail message to the entity who initiated the
    //attestation and let it know a failure has occured.
    int err = 0;

    int iostatus;
    err = create_error_response(scen);
    if(err < 0) {
        dlog(0, "Error: creating integrity response\n");
        free(scen->response);
    } else {
        /* Generate and send integrity check response */
        size_t bytes_written = 0;
        iostatus = maat_write_sz_buf(scen->requester_chan, scen->response, scen->respsize,
                                     &bytes_written, config->am_comm_timeout);

        if(iostatus != 0) {
            dlog(0, "Failed to send response from attestmgr!: %s\n",
                 strerror(iostatus < 0 ? -iostatus : iostatus));
        }
        if(bytes_written != scen->respsize+sizeof(uint32_t)) {
            dlog(0, "Error: appraiser wrote %zu bytes (expected to write %zd)\n",
                 bytes_written, scen->respsize);
        }
        dlog(3, "Appraiser wrote %zd byte(s)\n", bytes_written);
    }
}

/**
 * Advance the attester one step in the protocol.
 */
static void handle_attester(struct am_config *config, struct scenario *scen)
{
    am_contract_type ctype = 0;
    int rc, res;

    if(parse_contract_type(scen->contract, scen->size, &ctype)) {
        dlog(0, "Attester: Failed to parse contract type\n");
        scen->state = AM_ERROR;
        goto out;
    }

    dlog(2, "Attester: in state %s handling contract type %s\n",
         scenario_state_name(scen->state), get_contract_name(ctype));

    switch(scen->state) {
    case IDLE:
        if(ctype == AM_CONTRACT_INITIAL) {
            scen->state = INITIAL_RECEIVED;
            rc = handle_initial_contract(am, scen);
            dlog(3,"Attester: Handled initial contract. ret = %d\n", rc);
            if(rc < 0) {
                scen->state = AM_ERROR;
                goto out;
            }

            //Attester sends a modified contract back to Appraiser
            //****************************************************
            dlog(1,"Attester: Sending Modified Contract (size = %zu)\n", scen->respsize);
            res = write_modified_contract(scen->peer_chan, scen->response,
                                          scen->respsize,
                                          NULL,
                                          config->am_comm_timeout);
            if(check_send_result(res, "modified") != 0) {
                scen->state = AM_ERROR;
                goto out;
            }
            scen->state = MODIFIED_SENT;
            break;
        } else if (ctype == AM_CONTRACT_EXECUTE) {
            if(scen->association == CACHE_HIT) {
                rc = handle_execute_cache_hit_setup(am, scen);
                dlog(3, "Attester: Set up for execute cache hit. ret = %d\n", rc);
                if(rc < 0) {
                    scen->state = AM_ERROR;
                    goto out;
                }
                scen->state = MODIFIED_SENT;
                /* notice NOT breaking by design */
            } else {
                dlog(0, "Error: attempted negotiation skip without CACHE_HIT association\n");
                scen->state = AM_ERROR;
                goto out;
            }
        } else {
            dlog(0, "Attester: Expected INITIAL contract, but got %s\n",
                 get_contract_name(ctype));
            scen->state = AM_ERROR;
            goto out;
        }
        /*
         * GCC 7+ decided implicit fallthroughs are a bug with -Wall, unless
         * you explicitly tell the compiler you meant it.
         *
         * See: https://developers.redhat.com/blog/2017/03/10/wimplicit-fallthrough-in-gcc-7/
         */
        __attribute__ ((fallthrough));
    case MODIFIED_SENT:
        if(ctype != AM_CONTRACT_EXECUTE) {
            dlog(0, "Attester: Expected EXECUTE contract but got %s\n",
                 get_contract_name(ctype));
            scen->state = AM_ERROR;
            goto out;
        }
        scen->state = EXECUTE_RECEIVED;
        rc = handle_execute_contract(am, scen);
        if(rc < 0) {
            scen->state = AM_ERROR;
            goto out;
        }
        scen->state = IDLE;
        break;
    default:
        dlog(0, "Attester: Unexpected attester state %s\n",
             scenario_state_name(scen->state));
        scen->state = AM_ERROR;
        goto out;
    }

out:
    free(scen->contract);
    free(scen->response);

    scen->contract	= NULL;
    scen->response	= NULL;
    scen->respsize	= 0;
    return;
}

void execute_scenario(struct am_config *config,
                      struct scenario *scen,
                      transition_fn transfn,
                      error_reporter error_handler)
{
    int res;
    scenario_state state;

    transfn(config, scen);
    state = scenario_get_state(scen);

    while(state != IDLE && state != AM_ERROR) {
        size_t csize;
        int eof_encountered;
        /* Cast is justified because the function does not regard the signedness of the argument */
        res = maat_read_sz_buf(scenario_get_peerchan(scen),
                               (unsigned char **) &scen->contract,
                               &csize, NULL,
                               &eof_encountered,
                               config->am_comm_timeout, 0);
        if(check_receive_result(scen, res) < 0) {
            state = AM_ERROR;
            continue;
        }
        if(csize > INT_MAX) {
            scen->error_message = g_strdup_printf("Error: received contract is too large (%zu bytes)", csize);
            dlog(0, "Error: received contract is too big (%zu bytes)\n", csize);
            state = AM_ERROR;
            continue;
        }
        if(eof_encountered) {
            scen->error_message = g_strdup_printf("Error: unexpected EOF encountered from peer\n");
            dlog(0, "Error: unexpected EOF encountered from peer\n");
            state = AM_ERROR;
            continue;
        }
        scen->size = csize;
        transfn(config, scen);
        state = scenario_get_state(scen);
    }

    if(state == AM_ERROR && error_handler != NULL) {
        error_handler(config, scen);
    }

    free_scenario(scen);
}

static int handle_connection(am_config *config, int clientfd, int may_skip_negotiation)
{
    /* child process should handle this client */
    char workdir[PATH_MAX];
    int clientchan;
    int res;
    int rc = 0;
    char *contract = NULL;
    size_t contract_size;
    am_contract_type ctype = -1;
    struct scenario *scenario = calloc(1, sizeof(struct scenario));
    int eof_encountered = 0;

    workdir[0] = '\0';
    if(scenario == NULL) {
        dlog(0, "Failed to allocate attester scenario\n");
        rc = -1;
        goto out_alloc_scenario;
    }


    rc = snprintf(workdir, PATH_MAX, "%s/%d", config->workdir, getpid());
    if(rc < 0 || rc >= PATH_MAX) {
        dlog(0, "Failed to create working directory for connection\n");
        rc = -1;
        goto out_gen_workdir;
    }

    if(mkdir(workdir, 0700) < 0) {
        dlog(0, "Failed to create working directory (%s) for connection: %s\n",
             workdir, strerror(errno));
        rc = -1;
        goto out_mk_workdir;
    }

    dlog(1, "Handling connection (workdir = %s)\n", workdir);

    clientchan = maat_io_channel_new(clientfd);
    if(clientchan < 0) {
        dlog(0, "Failed to initialize IO channel for client communication\n");
        rc = -1;
        goto out_mk_client_channel;
    }
    clientfd = -1;

    /* Cast is justified because the signedness of the argument is not regarded */
    res = maat_read_sz_buf(clientchan, (unsigned char **) &contract, &contract_size, NULL,
                           &eof_encountered,
                           config->am_comm_timeout, 0);
    if(check_receive_result(NULL, res) < 0 || eof_encountered != 0) {
        dlog(1, "Failed to receive contract from peer\n");
        rc = -1;
        goto out;
    }

    dlog(3, "Read %zd bytes from new connection. Checking contract type\n", contract_size);

    if((rc = parse_contract_type(contract, contract_size, &ctype)) != 0) {
        dlog(0, "Failed to get contract type\n");
        rc = -1;
        goto out;
    }

    dlog(3, "Contract type is %s (%d)\n", get_contract_name(ctype), ctype);

    if(ctype == AM_CONTRACT_INITIAL) {

        dlog(5, "PRESENTATION MODE (in): Attester receives initial contract\n");
        dlog(3, "Received INITIAL contract...I must be an attester\n");
        init_scenario(scenario, config->cacert_file, config->cert_file,
                      config->privkey_file, config->privkey_pass, config->tpmpass,
                      config->akctx, config->akpubkey, config->sign_tpm, config->verify_tpm,
                      config->place_file, contract, contract_size, ATTESTER);
        scenario->workdir      	= workdir;
        scenario->peer_chan	= clientchan;
        scenario->state	       	= IDLE;
        execute_scenario(config, scenario, handle_attester, NULL);
        scenario                = NULL;
        close(clientchan);
        contract   = NULL;
        clientchan = -1;
    } else if(ctype == AM_CONTRACT_REQUEST) {
        dlog(3, "Received REQUEST...I must be an appraiser\n");
        init_scenario(scenario, config->cacert_file, config->cert_file,
                      config->privkey_file, config->privkey_pass, config->tpmpass,
                      config->akctx, config->akpubkey, config->sign_tpm, config->verify_tpm,
                      config->place_file, contract, contract_size, APPRAISER);
        scenario->workdir          = workdir;
        scenario->requester_chan   = clientchan;
        scenario->state	           = IDLE;
        execute_scenario(config, scenario, handle_appraiser,
                         report_attestation_error);
        scenario                = NULL;
        contract   = NULL;
        close(clientchan);
        clientchan = -1;
    } else if(may_skip_negotiation && ctype == AM_CONTRACT_EXECUTE) {
        dlog(3, "Received skip-negotiation EXECUTE contract...off to the races\n");
        init_scenario(scenario, config->cacert_file, config->cert_file,
                      config->privkey_file, config->privkey_pass, config->tpmpass,
                      config->akctx, config->akpubkey, config->sign_tpm, config->verify_tpm,
                      config->place_file, contract, contract_size, ATTESTER);
        scenario->state	       	= IDLE;
        scenario->workdir      	= workdir;
        scenario->peer_chan	= clientchan;
        /*
          XXX: future should implement cache and phase out
          may_skip_negotiation work-around
        */
        scenario->association   = CACHE_HIT;
        execute_scenario(config, scenario, handle_attester, NULL);
        scenario                = NULL;
        contract	       	= NULL;
        close(clientchan);
        clientchan     		= -1;
    } else {
        dlog(1, "Error: Invalid contract received!");
        scenario->error_message = strdup("Unexpected contract");
        report_attestation_error(config, scenario);
        close(clientchan);
        contract = NULL;
        clientchan = 1;
    }

out:
    wait_for_children();
    free(contract);

    if(clientchan >= 0) {
        close(clientchan);
    }

out_mk_client_channel:
    if(!config->keep_workdir) {
        dlog(6, "Clearing out workdir %s\n", workdir);
        rmrf(workdir);
    }
out_mk_workdir:
out_gen_workdir:
    free_scenario(scenario);
out_alloc_scenario:
    if(clientfd >= 0) {
        close(clientfd);
    }
    return rc;
}

typedef struct am_iface {
    am_iface_config *cfg;
    int fd;
} am_iface;

/**
 * Using pselect, monitor the inet and unix file descriptors (passed
 * in as parameters) that were setup in the setup_dispath_loop. When
 * one of the file descriptors is ready for I/O without blocking it
 * will be returned to the setup_dispath_loop.
 *
 * Preference is given to the signal fd @sigfd, then @inet_fd, then
 * @unix_fd.
 *
 * Will return -1 if error.
 */
static am_iface *wait_for_connection(am_iface *ifaces, size_t nr_fds, am_iface *sigif)
{
    fd_set fdset;
    int rc, max_fd = -1;
    size_t i = 0;

    FD_ZERO(&fdset);

    for(i=0; i<nr_fds; i++) {
        dlog(4, "setting fd %d\n", ifaces[i].fd);
        FD_SET(ifaces[i].fd, &fdset);
        max_fd = max_fd > ifaces[i].fd ? max_fd : ifaces[i].fd;
    }

    /* no file descriptors given to listen on. */
    if(max_fd == -1) {
        return NULL;
    }

    if (sigif->fd > 0) {
        FD_SET(sigif->fd, &fdset);
        if(sigif->fd > max_fd) {
            max_fd = sigif->fd;
        }
    }

    while((rc = select(max_fd+1, &fdset, NULL, NULL, NULL)) <= 0) {
        if(rc < 0 && errno != EINTR) {
            /* signalfd is not available, fall back to exiting on !EINTR */
            dperror("select returned");

            return sigif;
        }
    }

    if(sigif->fd > 0 && FD_ISSET(sigif->fd, &fdset) == 1) {
        return sigif;
    }

    for(i=0; i<nr_fds; i++) {
        if(FD_ISSET(ifaces[i].fd, &fdset) == 1) {
            return &ifaces[i];
        }
    }

    dlog(1, "Select returned %d but no file descriptors are ready?\n", rc);
    return NULL;

}

int setup_interfaces(am_config *cfg, am_iface **listeners, size_t *nr_listeners)
{
    guint len		= g_list_length(cfg->interfaces);
    am_iface *ifaces;
    *listeners		= NULL;
    *nr_listeners	= 0;

    if(len > INT_MAX) {
        dlog(0, "Error: unable to open %"PRIu32" listen interfaces\n", len);
        return -1;
    }

    ifaces = malloc(sizeof(am_iface)*len);
    if(ifaces == NULL) {
        dlog(0, "Error allocating interface list\n");
        return -ENOMEM;
    }

    GList *iter = NULL;

    for(iter = g_list_first(cfg->interfaces); iter != NULL; iter = g_list_next(iter)) {
        am_iface_config *iface_cfg = (am_iface_config *)iter->data;

        if(iface_cfg->type == INET) {
            dlog(4, "Listening on INET interface %s:%hu\n", iface_cfg->address, iface_cfg->port);
            ifaces[*nr_listeners].fd = setup_listen_server(iface_cfg->address, iface_cfg->port);
            if(ifaces[*nr_listeners].fd < 0) {
                dlog(2, "Warning: failed to open inet listen interface %s:%hd\n",
                     iface_cfg->address, iface_cfg->port);
                continue;
            }
        } else {
            dlog(4, "Listening on UNIX interface %s\n", iface_cfg->address);
            ifaces[*nr_listeners].fd = setup_local_listen_server(iface_cfg->address);
            if(ifaces[*nr_listeners].fd < 0) {
                dlog(2, "Warning failed to open UNIX listen interface %s\n",
                     iface_cfg->address);
                continue;
            }
            /*
               If we're going to setuid()/setgid(), attempt to set the
               owner and group of the socket so that we can clean them
               up later. Failure here isn't a big deal, it just
               prevents unlink()ing the path at clean up time.
            */
            if(cfg->uid_set != 0) {
                if(chown(iface_cfg->address, cfg->uid, (gid_t)-1) != 0) {
                    dlog(2, "Warning: failed to chown UNIX socket at path %s. File may be leaked at exit.\n",
                         iface_cfg->address);
                }
            }
            if(cfg->gid_set != 0) {
                if(chown(iface_cfg->address, (gid_t)-1, cfg->gid) != 0) {
                    dlog(2, "Warning: failed to chown UNIX socket at path %s. File may be leaked at exit.\n",
                         iface_cfg->address);
                }
            }
        }
        ifaces[*nr_listeners].cfg = iface_cfg;
        *nr_listeners = *nr_listeners + 1;
    }

    *listeners = ifaces;
    return (int)*nr_listeners;
}

void close_all(am_iface *ifaces, size_t nrfds)
{
    size_t i;
    for(i=0; i<nrfds; i++) {
        close(ifaces[i].fd);
    }
}

static int create_root_workdir(am_config *cfg)
{
    struct stat st;
    errno = 0;
    if(stat(cfg->workdir, &st) < 0 && errno == ENOENT) {
        if(mkdir(cfg->workdir, 0700) != 0) {
            dlog(0, "Error: failed to create work directory %s: %s\n",
                 cfg->workdir, strerror(errno));
            return -1;
        }
    }
    return 0;
}

/**
 * Main function to handle the initial call to the attester/appraiser and to
 * hand the process off to handle_invoke_appraiser or handle_invoke_attester
 */
int setup_dispatch_loop(int argc, char **argv)
{
    am_config cfg	= {0};
    int rc		= 0;
    am_iface sigif	= {0};
    am_iface *listeners = NULL;
    size_t nr_listeners = 0;

    printf("Attestation Manager initializing\n");

    // initialize server
    libmaat_init(1, 4);

    signal(SIGCHLD, handle_sigchld);

    rc = attestmgr_getopt(argc, argv, &cfg);
    if(rc < 0) {
        goto getopt_failed;
    }

    /* Listen on interfaces prior to calling setuid()/setgid()
       Otherwise we wouldn't be allowed to bind to well known
       ports
    */
    if( (sigif.fd = setup_signalfd()) < 0) {
        dlog(2, "Non-fatal Error: failed to setup signal handling: %s\n", strerror(sigif.fd));
        dlog(2, "Artifacts could be left on exit\n");
    }

    if(setup_interfaces(&cfg, &listeners, &nr_listeners) <= 0) {
        dlog(0, "Error setting up interfaces, exiting\n");
        goto setup_interfaces_failed;
    }

    if(cfg.gid_set) {
        if(setgid(cfg.gid) != 0) {
            dlog(0, "Error: failed to setgid(): %s\n", strerror(errno));
            goto setgid_failed;
        }
    }

    if(cfg.uid_set) {
        if(setuid(cfg.uid) != 0) {
            dlog(0, "Error: failed to setuid(): %s\n", strerror(errno));
            goto setuid_failed;
        }
    }

    create_root_workdir(&cfg);

    /* This selector creation method is NOT sustainable.  We should
     * codify this as having to be a string or we need another way to
     * declare more complex selector configs
     */

    am = new_attestation_manager(cfg.asp_metadata_dir,
                                 cfg.mspec_dir,
                                 cfg.apb_metadata_dir,
                                 cfg.selector_source.method,
                                 cfg.selector_source.loc,
                                 cfg.execcon_behavior,
                                 cfg.use_unique_categories);

    if(am == NULL) {
        dlog(0, "Error: failed to create attestation manager!\n");
        rc = -1;
        goto new_attestmgr_failed;
    }

    rc = 0;
    dlog(3, "Entering wait_on_connection loop on %zd listen interfaces!\n", nr_listeners);

    printf("Attestation Manager is ready to start accepting requests\n");

    am_iface *conn_if;
    while((conn_if = wait_for_connection(listeners, nr_listeners, &sigif)) != NULL) {
        int clientfd;
        dlog(4, "Data pending on fd %d\n", conn_if->fd);

        if(conn_if == &sigif) {
            if (sigif.fd < 0) {
                dlog(0, "ERROR: Caught unsupported signal, exiting");
                rc = -errno;
                goto cleanup;
            }
            struct signalfd_siginfo sig = {0};
            ssize_t bread;
            bread = read(sigif.fd, &sig, sizeof(sig));
            if(bread!= sizeof(sig)) {
                dlog(0, "ERROR: Failed to process signal. Aborting.\n");
                rc = errno;
            } else {
                dlog(0, "Caught signal %d. Cleaning up and exiting\n", sig.ssi_signo);
                rc = (int)sig.ssi_signo;
            }
            goto cleanup;
        }

        dlog(2, "Accepting a connection\n");
        clientfd = accept(conn_if->fd, NULL, NULL);
        if(clientfd < 0) {
            dlog(2, "Error accept() failed: %s\n", strerror(errno));
            continue;
        }

        rc = fork();
        if(rc == 0) {
            /*
              We're the child process, close the listening
              descriptors and handle the connection and exit.
            */
            cleanup_signalfd(sigif.fd);
            close_all(listeners, nr_listeners);
            return handle_connection(&cfg, clientfd, conn_if->cfg->skip_negotiation);
        } else if(rc < 0) {
            dlog(0, "Error: unable to spawn handler for new connection");
        }
        /*
           Only the parent process is going to get here. Just close
           the client descriptor and wait for the next connection.
        */
        close(clientfd);
    }

cleanup:
    printf("Attestation Manager is shutting down\n");
    wait_for_children();
    close_all(listeners, nr_listeners);

    GList *iter;
    for(iter = g_list_first(cfg.interfaces); iter != NULL; iter = g_list_next(iter)) {
        am_iface_config *iface = (am_iface_config *)iter->data;
        if(iface->type == UNIX) {
            dlog(3, "Unlinking unix socket %s\n", iface->address);
            unlink(iface->address);
        }
    }
new_attestmgr_failed:
    if(!cfg.keep_workdir) {
        rmrf(cfg.workdir);
    }

setuid_failed:
setgid_failed:
setup_interfaces_failed:
    free(listeners);
    cleanup_signalfd(sigif.fd);
    free_attestation_manager(am);
getopt_failed:
    free_am_config_data(&cfg);
    return rc;
}
