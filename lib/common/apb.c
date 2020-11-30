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

/**
 * am/apb.c: Routines for AM to interact with APBs. Load APB metadata,
 * find an APB by UUID, and spawn an APB.
 */
#include <config.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <dirent.h>

#include <glib.h>
#include <uuid/uuid.h>

#include <util/util.h>
#include <util/keyvalue.h>
#include <util/xml_util.h>

#include <common/apb_info.h>
#include <common/measurement_spec.h>
#include <common/asp.h>
#include <common/copland.h>
#include <signal.h>

void parse_asps(struct apb *apb, GList *asps, xmlNode *asps_node)
{
    xmlNode *asp;
    uuid_t uuid;
    char *tmp, *stripped;
    struct asp *a;
    int ret;

    apb->valid = true;

    for (asp = asps_node->children; asp; asp = asp->next) {
        char *aspname = validate_cstring_ascii(asp->name, SIZE_MAX);
        if (asp->type != XML_ELEMENT_NODE || aspname == NULL ||
                strcasecmp(aspname, "asp") != 0) {
            continue;
        }

        tmp = xmlGetPropASCII(asp, "uuid");
        if (tmp == NULL) {
            dlog(3, "Error: ASP entry without UUID, skipping\n");
            continue;
        }

        ret = strip_whitespace(tmp, &stripped);
        free(tmp);
        tmp = NULL;
        if (ret) {
            dlog(1, "Unable to strip whitespace from UUID read from ASP entry\n");
            continue;
        }

        ret = uuid_parse(stripped, uuid);
        if (ret) {
            dlog(1, "Error: Invalid UUID in entry, skipping\n");
            apb->valid = false;
            continue;
        }

        a = find_asp_uuid(asps, uuid);
        if (!a) {
            dlog(2, "ASP with UUID %s not found in ASPs list\n", stripped);
            free(stripped);
            stripped = NULL;
            uuid_clear(uuid);
            apb->valid = false;
            continue;
        }
        free(stripped);
        stripped = NULL;
        apb->asps = g_list_append(apb->asps, a);

        tmp = xmlGetPropASCII(asp, "initial");
        if (!tmp) {
            continue;
        }

        ret = strip_whitespace(tmp, &stripped);
        free(tmp);
        if (ret) {
            dlog(1, "Unable to strip whitespace from UUID read from ASP entry\n");
            continue;
        }

        if (strcasecmp(stripped, "true") == 0) {
            apb->initial = a;
        }
        free(stripped);
    }

    return;
}

struct apb *load_apb_info(const char *xmlfile, GList *asps, GList *meas_specs)
{
    xmlDoc *doc = NULL;
    xmlNode *root = NULL;
    xmlNode *tmp = NULL;
    int ret;
    struct apb *apb;
    char *rootname, *unstripped, *stripped;
    int apb_copland_set = 0;
    dlog(6, "Parsing file %s\n", xmlfile);

    apb = (struct apb *)malloc(sizeof(*apb));
    if (!apb) {
        dperror("Error allocating memory for APB struct");
        goto error;
    }
    memset(apb, 0, sizeof(*apb));
    doc = xmlReadFile(xmlfile, NULL, 0);

    if (doc == NULL) {
        dlog(0, "Error parsing APB xml file\n");
        goto error;
    }
    root     = xmlDocGetRootElement(doc);
    rootname = validate_cstring_ascii(root->name, SIZE_MAX);

    if (rootname == NULL || strcasecmp(rootname, "apb") != 0) {
        dlog(1, "WARNING: XML file %s is not a valid APB XML metafile\n", xmlfile);
        goto error;
    }

    apb->metadata_version = 0;
    char *version_str = xmlGetPropASCII(root, "version");
    if(version_str != NULL) {
        if(sscanf(version_str, "%hhu", &apb->metadata_version) != 1) {
            dlog(1, "WARNING: parsing APB metadata: invalid version specified \"%s\""
                 " (defaulting to 0)\n", version_str);
        }
        free(version_str);
    }

    apb->filename = strdup(xmlfile);
    apb->valid = true;

    for (tmp = root->children; tmp; tmp = tmp->next) {
        char *tmpname = validate_cstring_ascii(tmp->name, SIZE_MAX);
        if (tmp->type != XML_ELEMENT_NODE || tmpname == NULL) {
            dlog(2, "Unknown child of APB XML\n");
            continue;
        }

        if (strcasecmp(tmpname, "name") == 0) {
            unstripped = xmlNodeGetContentASCII(tmp);
            ret = strip_whitespace(unstripped, &stripped);
            free(unstripped);
            if(ret < 0) {
                dlog(2, "Failed to strip whitespace from input %s\n", unstripped);
                continue;
            }

            apb->name = stripped;
            continue;
        }

        if (strcasecmp(tmpname, "desc") == 0) {
            unstripped = xmlNodeGetContentASCII(tmp);
            ret = strip_whitespace(unstripped, &stripped);
            free(unstripped);
            if(ret < 0) {
                dlog(2, "Failed to strip whitespace from input %s\n", unstripped);
                continue;
            }

            apb->desc = stripped;
            continue;
        }

        if (strcasecmp(tmpname, "copland") == 0) {
            parse_copland(doc, apb, tmp, meas_specs);
            apb_copland_set = 1;
            continue;
        }

        if (strcasecmp(tmpname, "file") == 0) {
            if(apb->file != NULL)
                continue;
            apb->file =(struct xml_file_info *) malloc(sizeof(struct xml_file_info));
            if(apb->file == NULL) {
                dlog(0, "ERROR: Failed to allocate memory for APB metadata\n");
                goto error;
            }

            unstripped = xmlNodeGetContentASCII(tmp);
            ret = strip_whitespace(unstripped, &stripped);
            free(unstripped);
            if(ret < 0) {
                dlog(2, "Failed to strip whitespace from input %s\n", unstripped);
                continue;
            }

            apb->file->full_filename = stripped;
            if(apb->file->full_filename == NULL) {
                dlog(0, "ERROR: Failed to get APB full file name\n");
                goto error;
            }

            apb->file->hash = xmlGetPropASCII(tmp,"hash");
            dlog(6, "file: %s\n",apb->file->full_filename);
            continue;
        }

        if (strcasecmp(tmpname, "uuid") == 0) {
            unstripped = xmlNodeGetContentASCII(tmp);
            ret = strip_whitespace(unstripped, &stripped);
            free(unstripped);
            if(ret < 0) {
                dlog(2, "Failed to strip whitespace from input %s\n", unstripped);
                continue;
            }

            ret = uuid_parse(stripped, apb->uuid);
            free(stripped);
            if (ret) {
                dlog(2, "Warning: UUID did not parse, skipping\n");
                uuid_clear(apb->uuid);
            }
            continue;
        }

        if (strcasecmp(tmpname, "asps") == 0) {
            parse_asps(apb, asps, tmp);

            if(apb->valid == false) {
                dlog(3, "An error was reached parsing the ASP list\n");
                goto error;
            }

            continue;
        }

        if (strcasecmp(tmpname, "security_context") == 0) {
            parse_exe_sec_ctxt(&apb->desired_sec_ctxt, tmp);
            continue;
        }
    }
    xmlFreeDoc(doc);
    doc = NULL;

    if(apb->name == NULL) {
        dlog(0, "Failed to register APB: no name provided\n");
        goto error;
    }

    if(apb->file == NULL) {
        dlog(0, "Failed to register APB %s: no file specified\n", apb->name);
        goto error;
    }

    if(!apb_copland_set) {
        dlog(0, "Failed to register APB %s: no copland phrase specified\n", apb->name);
        goto error;
    }

    dlog(6, "Registering APB: %s\n", apb->name);

    return apb;

error:
    unload_apb(apb);
    if(doc) {
        xmlFreeDoc(doc);
    }
    return NULL;
}

int run_apb(struct apb *apb,
            respect_desired_execcon_t execcon_behavior,
            execcon_unique_categories_t set_categories,
            struct scenario *scen, uuid_t meas_spec,
            int peerchan, int resultchan, char *args)
{
    pid_t apb_pid, pid;
    int status;

    apb_pid = run_apb_async(apb, execcon_behavior, set_categories,
                            scen, meas_spec, peerchan, resultchan, NULL, NULL, NULL, args);
    if(apb_pid < 0)
        return apb_pid;

    while(((pid = wait(&status)) > 0) && !(pid == apb_pid)) {
        /* should call the normal signal handler */
        dlog(3, "Unexpected: wait() returned %d (expected %d) exited: %d status: %d\n",
             pid, apb_pid, WIFEXITED(status), WEXITSTATUS(status));
    }

    return WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
}

int run_apb_async(struct apb *apb,
                  respect_desired_execcon_t execcon_behavior,
                  execcon_unique_categories_t set_categories,
                  struct scenario *scen, uuid_t meas_spec,
                  int peerchan, int resultchan, char *target,
                  char *target_typ, char *resource, char *args)
{
    dlog(6, "Running APB of name: %s\n", apb->name);
    pid_t pid;

    pid = fork();
    if (pid < 0) {
        dperror("Error forking APB");
        return pid;
    }
    if (pid == 0) {
        char peerfd_buf[17];
        char resultfd_buf[17];
        uuid_str_t meas_spec_str;
        char *contract_buf;

        snprintf(peerfd_buf,   17, "%d", peerchan);
        snprintf(resultfd_buf, 17, "%d", resultchan);
        uuid_unparse(meas_spec, meas_spec_str);

        /* The contract is not guaranteed to be NULL terminated */
        if(scen->size == SIZE_MAX) {
            dlog(0, "Contract of size %zu is too big\n", scen->size);
            return -1;
        }

        contract_buf = malloc(scen->size+1);
        if(contract_buf == NULL) {
            dlog(0, "Failed to allocate buffer of size %zu for contract\n", scen->size+1);
            return -1;
        }

        memcpy(contract_buf, scen->contract, scen->size);
        contract_buf[scen->size] = '\0';
        dlog(6, "Calling exec() on apbmain (%s)\n", apb->file->full_filename);

        char *info_file = g_strdup_printf("%s/info", scen->workdir);

        if(scen->info != NULL) {
            if(buffer_to_file(info_file, scen->info, scen->info_size) < 0) {
                dlog(0, "Error writing appraisal info to temp file.\n");
                free(contract_buf);
                g_free(info_file);
                return -1;
            }
        } else {
            if(buffer_to_file(info_file, (unsigned char*)"", 0) < 0) {
                dlog(0, "Error writing (empty) info to temp file %s.\n", info_file);
                free(contract_buf);
                g_free(info_file);
                return -1;
            }
        }

        exe_sec_ctxt_set_execcon(apb->file->full_filename,
                                 &apb->desired_sec_ctxt,
                                 execcon_behavior,
                                 set_categories,
                                 0, 256, 511);

        execl(apb->file->full_filename, apb->file->full_filename,
              "--workdir",          scen->workdir      ? scen->workdir : "",
              "--cacert",           scen->cacert       ? scen->cacert  : "",
              "--certfile",         scen->certfile     ? scen->certfile : "",
              "--keyfile",          scen->keyfile      ? scen->keyfile  : "",
              "--keypass",          scen->keypass      ? scen->keypass  : "",
              "--partner-cert",     scen->partner_cert ? scen->partner_cert : "",
              "--sign-tpm",         scen->sign_tpm     ? "yes" : "no",
              "--verify-tpm",       scen->verify_tpm   ? "yes" : "no",
              "--tpm-pass",         scen->tpmpass      ? scen->tpmpass : "",
              "--target",     		target      	   ? target : "",
              "--target_type",     	target_typ         ? target_typ : "",
              "--resource",     	resource           ? resource : "",
              "--contract",         contract_buf,
              "--nonce",            scen->nonce        ? scen->nonce : "",
              "--peerfd",           peerfd_buf,
              "--resultfd",         resultfd_buf,
              "--measurement-spec", meas_spec_str,
              "--execcon-respect-desired", execcon_behavior == EXECCON_RESPECT_DESIRED ? "1" : "0",
              "--execcon-set-unique-categories", set_categories == EXECCON_SET_UNIQUE_CATEGORIES ? "1" : "0",
              "--info-file",        info_file,
              "--execute",          apb->file->full_filename,
              "--apb-args",         args               ? args : "",
              NULL);

        /* if we get here, exec() must have failed. */
        dlog(0, "Failed to exec() apbmain: %s\n", strerror(errno));
        free(contract_buf);
        g_free(info_file);
    }
    return pid;
}


void unload_apb(struct apb *apb)
{
    if(!apb) {
        return;
    }

    if(apb->filename) {
        free(apb->filename);
    }

    if(apb->file) {
        free_xml_file_info(apb->file);
    }

    if(apb->name) {
        free(apb->name);
    }

    if(apb->desc) {
        free(apb->desc);
    }

    if(apb->meas_specs) {
        g_list_free(apb->meas_specs);
    }

    if(apb->asps) {
        g_list_free(apb->asps);
    }

    free_exe_sec_ctxt(&apb->desired_sec_ctxt);

    free(apb);
}

/* Find an APB based upon the script that it executes */
struct apb *find_apb_exe(GList *apbs, char *filename)
{
    struct apb *p;
    GList *l;

    for (l = apbs; l && l->data; l = g_list_next(l)) {
        p = (struct apb *)l->data;
        if(!strcmp(filename, p->file->full_filename)) {
            return p;
        }
    }

    return NULL;
}

//Should this take a uuid pointer to be in line with other searches?
struct apb *find_apb_uuid(GList *apbs, uuid_t uuid)
{
    GList *l;

    for (l = apbs; l && l->data; l = g_list_next(l)) {
        struct apb *p = (struct apb *)l->data;

        if (uuid_compare(p->uuid, uuid) == 0)
            return p;
    }
    return NULL;
}

GList *load_all_apbs_info(const char *dirname, GList *asps, GList *meas_specs)
{
    if(dirname==NULL)
        return NULL;
    struct dirent *dent;
    DIR *dir;
    GList *apbs = NULL;
    char scratch[256];

    dir = opendir(dirname);
    if (!dir) {
        dlog(0, "Error opening directory %s\n", dirname);
        return NULL;
    }
    for (dent = readdir(dir) ; dent; dent = readdir(dir)) {
        char *xml_suffix = strstr(dent->d_name, ".xml");
        if (xml_suffix && *(xml_suffix + 4) == '\0') {
            struct apb *p;
            int rc;
            rc = snprintf(scratch, 256, "%s/%s", dirname, dent->d_name);
            if(rc < 0 || rc >= 256) {
                dlog(3, "Error creating path string %s/%s?", dirname, dent->d_name);
                continue;
            }
            p = load_apb_info(scratch, asps, meas_specs);
            if (p)
                apbs = g_list_append(apbs, p);
        }
    }

    closedir(dir);
    return apbs;
}

/*
 * Given the directory containing all APBs, all ASPs,
 * and a target ASP, return which APBs call ASP.
 */
GList *find_apbs_with_asp(const char *dirname, GList *all_asps,  char *asp_target)
{
    struct apb *tmp;
    GList *ret_apbs = NULL, *iter;
    //loop through all APBs
    for(iter = load_all_apbs_info(dirname,all_asps, NULL); iter && iter->data; iter = iter->next) {
        tmp = (struct apb*)iter->data;
        if(has_asp(tmp,asp_target)) {
            ret_apbs = g_list_append(ret_apbs, tmp);
        }
        //TODO:loop through all APBs within tmp too
    }
    return ret_apbs;
}

/*
 * Determines whether a given asp is in the list of asps for an APB.
 */
int has_asp(struct apb *apb, char *asp_name)
{
    struct asp *tmp;
    GList *iter;
    for(iter = apb->asps; iter && iter->data; iter = iter->next) {
        tmp = iter->data;
        //dlog(0, "\n%s : %s\n", asp_name, tmp->name);
        //y. fixed string comparison
        if(strncmp(asp_name, tmp->name, strlen(asp_name)) == 0 &&
                strlen(asp_name) == strlen(tmp->name)) {
            dlog(0,"found a match in %s.\n",apb->name);
            return 1;
        }
    }
    return 0;
}



/* Local Variables:  */
/* mode: c           */
/* c-basic-offset: 4 */
/* End:              */
