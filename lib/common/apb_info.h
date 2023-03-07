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
 * Descriptor information about an Attestation Protocol Block (APB) and
 * functions for the Attestation Manager (AM) to use the APBs.
 */
#include <stdbool.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <common/asp_info.h>
#include <common/exe_sec_ctxt.h>
#include <glib.h>
#include <uuid/uuid.h>

#ifndef __MAAT_AM_APB_INFO_H__
#define __MAAT_AM_APB_INFO_H__

#define apb_log(x, ...)

/**
 * Descriptor of APB
 */
struct apb {
    uint8_t metadata_version;
    uuid_t uuid;
    char *filename;
    char *name;
    struct xml_file_info *file;
    char *desc;
    struct asp *initial;
    bool valid;
    GList *asps;        /**
			 * list of ASPs that may be invoked by this
			 * APB (not including recursive dependencies
			 * from sub-APBs)
			 */
    GList *apbs;        /**
			 * list of sub-APBs that may be invoked by
			 * this APB.
			 */
    GList *meas_specs;  /**
			 * list of struct measurement_spec supperted
			 * by this APB
			 */
    GList *phrase_specs; /**
                          * List of all the copland phrase/measurement
                          * spec pairs supported by this ABP
                          */
    GList *place_permissions; /**
                             * List of information that this APB has with
                             * respect to each place it interacts with
			     */

    exe_sec_ctxt desired_sec_ctxt;
};

/**
 * Loads APB info.  Return descriptor struct apb instance on success
 * or NULL on failure.  @xmlfile contains description of APB
 * configuration @asps is list of available ASPs for use by APB.
 */
struct apb *load_apb_info(const char *xmlfile, GList *asps, GList *meas_specs);

/* Find an APB based upon the script that it executes */
struct apb *find_apb_exe(GList *apbs, char *filename);

/**
 * Finds APB from list of available APBs and the specific UUID for one
 * APB.
 *
 * Return struct apb instance on success or NULL on failure.
 * @apbs is list of available APBs for use by AM.  uuid is ID of
 * desired APB.
 */
struct apb *find_apb_uuid(GList *apbs, uuid_t uuid);

/**
 * Loads APB info for every APB xml descriptor located in dir.
 *
 * Return a list of struct apb instances on success or NULL on failure.
 *
 * @asps is list of available ASPs for use by APBs, @meas_specs is
 * list of available measurement specifications for use by APB.
 */
GList *load_all_apbs_info(const char *dirname, GList *asps, GList *meas_specs);

/**
 * Unloads APB.
 * @apb is instance of APB descriptor to unload.
 */
void unload_apb(struct apb *apb);

/**
 * Finds all APBs which make use of the specified asp.
 * Return list of decriptor struct apb.
 * dirname is dir which contains APB xml decriptors.
 * all_asps is a list of all available ASPs.
 * asp_target is the desired ASP for which the APBs are sought which make use of it.
 */
GList *find_apbs_with_asp(const char *dirname, GList *all_asps, char *asp_target);

/**
 * Determines if the specified APB uses the specified asp.
 * Return 1 on success, 0 on failure.
 * apb is the struct apb descriptor of the APB in question.
 * asp_name is the name of the ASP which the APB is queried about its use.
 */
int has_asp(struct apb *apb, char *asp_name);

/**
 * launches the APB and executes it.  This blocks until the APB is
 * finished.  Returns the exit value of the APB process. The scenario,
 * meas_spec, peerchan, and resultchan are passed to the ->execute()
 * method of the APB.
 */
int run_apb(struct apb *apb,
            respect_desired_execcon_t execcon_behavior,
            execcon_unique_categories_t set_categories,
            struct scenario *scen, uuid_t meas_spec,
            int peerchan, int resultchan, char *args);

/**
 * Asynchronous version of run_apb. It launches the APB and then
 * returns immediately.  returns 0 on success. The caller is then
 * responsible for reading the result from the channel and calling
 * waitpid when complete.
 */
int run_apb_async(struct apb *apb,
                  respect_desired_execcon_t execcon_behavior,
                  execcon_unique_categories_t set_categories,
                  struct scenario *scen, uuid_t meas_spec,
                  int peerchan, int resultchan, char *target,
                  char *target_type, char *resource, char *args);

#endif /* __APB_INFO_H__ */
