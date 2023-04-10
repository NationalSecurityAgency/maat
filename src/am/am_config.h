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

#ifndef __MAAT_AM_CONFIG_H__
#define __MAAT_AM_CONFIG_H__

#include <stdint.h>
#include <stdlib.h>
#include <glib.h>
#include <common/exe_sec_ctxt.h>
/* maximum timeout = 1 day */
#define MAX_AM_COMM_TIMEOUT 86400
#define DEFAULT_AM_COMM_TIMEOUT 20

typedef struct am_iface_config {
    enum {INET, UNIX} type;

    /**
     * For UNIX interfaces, specifies the path of the interface.
     *
     * For INET interfaces, specifies the bind address either in dot
     * notation or hostname.
     */
    char *address;

    /**
     * Only valid/used for INET sockets. Port on which to listen
     * (host-order).
     */
    uint16_t port;

    /**
     * Should only be used for protected UNIX interfaces!!
     * Allow peers to skip negotiation and just send an
     * execute contract.
     */
    int skip_negotiation;
} am_iface_config;

static inline void free_am_iface_config(am_iface_config *cfg)
{
    if(cfg != NULL) {
        free(cfg->address);
        free(cfg);
    }
}

#define SELECTOR_MONGO "MONGO"
#define SELECTOR_COPL "COPLAND"

typedef struct am_config {
    /**
     * GList of am_iface_config specifying
     * listening interface.
     */
    GList *interfaces;

    /**
     * When other selector sources are supported, it
     * may make sense to break this out.
     */
    struct {
        char *method;
        char *loc;
    } selector_source;

    char *cacert_file;
    char *cert_file;
    char *privkey_file;
    char *privkey_pass;
    char *tpmpass;
    char *akctx;
    char *akpubkey;
    int sign_tpm;
    int verify_tpm;


    char *asp_metadata_dir;
    char *apb_metadata_dir;
    char *mspec_dir;

    int uid_set;
    int gid_set;

    uid_t uid;
    gid_t gid;

    char *place_file;

    char *workdir;
    int keep_workdir;

    time_t am_comm_timeout;
    int timeout_set;

    respect_desired_execcon_t execcon_behavior;
    execcon_unique_categories_t use_unique_categories;
} am_config;

void free_am_config_data(am_config *cfg);
int am_config_add_inet_iface(char *addr, uint16_t port, int skip_negotiation, am_config *cfg);
int am_config_add_unix_iface(char *path, int skip_negotiation, am_config *cfg);
int attestmgr_load_config(const char *cfg_path, am_config *cfg);
int attestmgr_getopt(int argc, char **argv, am_config *cfg);

#endif
